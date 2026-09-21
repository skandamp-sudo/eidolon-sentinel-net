/**
 * WebSocket connection manager for Sentinel-NET event stream.
 *
 * SECURITY:
 * - Authenticates via auth message (Phase 5 protocol), NOT URL params
 * - API key never logged or exposed in error messages
 * - Credentials never placed in WebSocket URL
 *
 * CONNECTION MANAGEMENT:
 * - Exponential backoff: 1s → 2s → 4s → 8s → 16s → 30s max
 * - Automatic reconnection on disconnect
 * - Bounded event buffer (100 events max)
 * - Duplicate event detection by ID
 * - Heartbeat awareness
 */

import type { DetectionEvent, WebSocketConnectionState, WSServerMessage } from './types';

const MAX_RECONNECT_DELAY_MS = 30_000;
const INITIAL_RECONNECT_DELAY_MS = 1_000;
const MAX_LIVE_EVENTS = 100;

export interface WebSocketManagerOptions {
  url: string;
  apiKey: string;
  onEvent: (event: DetectionEvent) => void;
  onStateChange: (state: WebSocketConnectionState) => void;
  onError?: (error: string) => void;
}

export class WebSocketManager {
  private ws: WebSocket | null = null;
  private reconnectDelay = INITIAL_RECONNECT_DELAY_MS;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private intentionalClose = false;
  private seenEventIds = new Set<string>();
  private state: WebSocketConnectionState = 'disconnected';

  constructor(private readonly options: WebSocketManagerOptions) {}

  connect(): void {
    if (this.ws?.readyState === WebSocket.OPEN || this.ws?.readyState === WebSocket.CONNECTING) {
      return;
    }

    this.intentionalClose = false;
    this.setState('connecting');

    // SECURITY: Never include credentials in the WebSocket URL
    this.ws = new WebSocket(this.options.url);

    this.ws.onopen = () => {
      this.setState('authenticating');
      // Send auth message per Phase 5 protocol
      this.ws?.send(JSON.stringify({
        type: 'auth',
        api_key: this.options.apiKey,
      }));
    };

    this.ws.onmessage = (event: MessageEvent) => {
      try {
        const msg = JSON.parse(String(event.data)) as WSServerMessage;
        this.handleMessage(msg);
      } catch {
        // Ignore malformed messages
      }
    };

    this.ws.onclose = () => {
      if (!this.intentionalClose) {
        this.setState('reconnecting');
        this.scheduleReconnect();
      } else {
        this.setState('disconnected');
      }
    };

    this.ws.onerror = () => {
      this.options.onError?.('WebSocket connection error');
    };
  }

  disconnect(): void {
    this.intentionalClose = true;
    this.clearReconnectTimer();
    if (this.ws) {
      this.ws.close(1000);
      this.ws = null;
    }
    this.setState('disconnected');
  }

  getState(): WebSocketConnectionState {
    return this.state;
  }

  /** Number of unique live events received */
  getBufferSize(): number {
    return this.seenEventIds.size;
  }

  private handleMessage(msg: WSServerMessage): void {
    switch (msg.type) {
      case 'auth_ok':
        this.setState('connected');
        this.reconnectDelay = INITIAL_RECONNECT_DELAY_MS; // Reset on success
        break;

      case 'auth_failed':
        this.options.onError?.('Authentication failed');
        this.intentionalClose = true; // Don't reconnect on auth failure
        this.ws?.close();
        this.setState('disconnected');
        break;

      case 'event':
        this.handleEvent(msg.data as Record<string, unknown>);
        break;

      case 'ping':
        // Heartbeat — connection is alive, nothing to do
        break;
    }
  }

  private handleEvent(data: Record<string, unknown>): void {
    const eventId = data['id'] as string | undefined;
    if (!eventId) return;

    if (data['event_schema_version'] === '2.0.0' && (
      data['event_id'] !== eventId || data['threat_class'] !== data['threat_type'] ||
      !Object.hasOwn(data, 'classification_score') || !Object.hasOwn(data, 'evidence')
    )) {
      this.options.onError?.('Invalid detection event contract');
      return;
    }

    // Deduplicate
    if (this.seenEventIds.has(eventId)) return;

    // Bound the set
    if (this.seenEventIds.size >= MAX_LIVE_EVENTS) {
      // Remove oldest (first inserted)
      const first = this.seenEventIds.values().next().value;
      if (first) this.seenEventIds.delete(first);
    }
    this.seenEventIds.add(eventId);

    // Convert to typed event
    const event: DetectionEvent = {
      ...data, // Preserve the complete versioned record, including evidence/provenance.
      id: String(data['id'] ?? ''),
      timestamp: Number(data['timestamp'] ?? 0),
      flow_id: data['flow_id'] as string | null ?? null,
      severity: (data['severity'] as DetectionEvent['severity']) ?? 'info',
      threat_type: (data['threat_type'] as DetectionEvent['threat_type']) ?? 'unknown',
      anomaly_score: data['anomaly_score'] as number | null ?? null,
      model_version: data['model_version'] as string | null ?? null,
      feature_schema_version: data['feature_schema_version'] as string | null ?? null,
      explanation_version: data['explanation_version'] as string | null ?? null,
      rationale: String(data['rationale'] ?? ''),
      metadata: (data['metadata'] as Record<string, unknown>) ?? {},
      created_at: Number(data['created_at'] ?? 0),
    };

    this.options.onEvent(event);
  }

  private setState(state: WebSocketConnectionState): void {
    this.state = state;
    this.options.onStateChange(state);
  }

  private scheduleReconnect(): void {
    this.clearReconnectTimer();
    this.reconnectTimer = setTimeout(() => {
      this.connect();
    }, this.reconnectDelay);
    // Exponential backoff with cap
    this.reconnectDelay = Math.min(this.reconnectDelay * 2, MAX_RECONNECT_DELAY_MS);
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }
}
