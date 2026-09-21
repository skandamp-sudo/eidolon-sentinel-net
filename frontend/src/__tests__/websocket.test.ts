/**
 * Tests for the WebSocket manager.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { WebSocketManager } from '@/api/websocket';
import replayEvent from './fixtures/rw1-event.json';
// Types not directly referenced; we test via WebSocketManager API

// Mock WebSocket
class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  readyState = MockWebSocket.CONNECTING;
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  sentMessages: string[] = [];
  closeCode: number | undefined;

  constructor(public url: string) {
    // Simulate connection
    setTimeout(() => {
      this.readyState = MockWebSocket.OPEN;
      this.onopen?.();
    }, 0);
  }

  send(data: string) {
    this.sentMessages.push(data);
  }

  close(code?: number) {
    this.closeCode = code;
    this.readyState = MockWebSocket.CLOSED;
    this.onclose?.();
  }

  // Simulate receiving a message
  simulateMessage(data: unknown) {
    this.onmessage?.({ data: JSON.stringify(data) });
  }
}

describe('WebSocketManager', () => {
  let onEvent: ReturnType<typeof vi.fn>;
  let onStateChange: ReturnType<typeof vi.fn>;
  let onError: ReturnType<typeof vi.fn>;
  let mockWs: MockWebSocket;

  beforeEach(() => {
    onEvent = vi.fn();
    onStateChange = vi.fn();
    onError = vi.fn();

    // Replace global WebSocket
    vi.stubGlobal('WebSocket', class extends MockWebSocket {
      constructor(url: string) {
        super(url);
        mockWs = this;
      }
    });

    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  function createManager() {
    return new WebSocketManager({
      url: 'ws://localhost:8000/api/v1/ws/events',
      apiKey: 'test-key',
      onEvent,
      onStateChange,
      onError,
    });
  }

  it('sends auth message on connect', async () => {
    const manager = createManager();
    manager.connect();

    // Trigger onopen
    await vi.advanceTimersByTimeAsync(10);

    expect(onStateChange).toHaveBeenCalledWith('connecting');
    expect(onStateChange).toHaveBeenCalledWith('authenticating');
    expect(mockWs.sentMessages).toHaveLength(1);

    const authMsg = JSON.parse(mockWs.sentMessages[0]!);
    expect(authMsg.type).toBe('auth');
    expect(authMsg.api_key).toBe('test-key');
  });

  it('preserves every field of a real replay event delivered by the backend', async () => {
    const manager = createManager();
    manager.connect();
    await vi.advanceTimersByTimeAsync(10);
    mockWs.simulateMessage({ type: 'auth_ok' });
    mockWs.simulateMessage({ type: 'event', data: replayEvent });
    expect(onEvent).toHaveBeenCalledWith(replayEvent);
    expect(onError).not.toHaveBeenCalled();
    manager.disconnect();
  });

  it('reports inconsistent event identity without silently translating it', async () => {
    const manager = createManager();
    manager.connect();
    await vi.advanceTimersByTimeAsync(10);
    mockWs.simulateMessage({ type: 'auth_ok' });
    mockWs.simulateMessage({ type: 'event', data: { ...replayEvent, event_id: 'different' } });
    expect(onEvent).not.toHaveBeenCalled();
    expect(onError).toHaveBeenCalledWith('Invalid detection event contract');
    manager.disconnect();
  });

  it('credentials never appear in WebSocket URL', async () => {
    const manager = createManager();
    manager.connect();
    await vi.advanceTimersByTimeAsync(10);

    expect(mockWs.url).not.toContain('test-key');
    expect(mockWs.url).not.toContain('api_key');
  });

  it('transitions to connected on auth_ok', async () => {
    const manager = createManager();
    manager.connect();
    await vi.advanceTimersByTimeAsync(10);

    mockWs.simulateMessage({ type: 'auth_ok' });
    expect(onStateChange).toHaveBeenCalledWith('connected');
  });

  it('handles auth_failed without reconnecting', async () => {
    const manager = createManager();
    manager.connect();
    await vi.advanceTimersByTimeAsync(10);

    mockWs.simulateMessage({ type: 'auth_failed' });
    expect(onError).toHaveBeenCalledWith('Authentication failed');
    expect(onStateChange).toHaveBeenCalledWith('disconnected');
  });

  it('deduplicates events by ID', async () => {
    const manager = createManager();
    manager.connect();
    await vi.advanceTimersByTimeAsync(10);
    mockWs.simulateMessage({ type: 'auth_ok' });

    const event = {
      type: 'event',
      data: { id: 'evt-1', timestamp: 1234, severity: 'high', threat_type: 'ddos' },
    };

    mockWs.simulateMessage(event);
    mockWs.simulateMessage(event); // duplicate
    mockWs.simulateMessage(event); // duplicate

    expect(onEvent).toHaveBeenCalledTimes(1);
  });

  it('ignores ping messages without error', async () => {
    const manager = createManager();
    manager.connect();
    await vi.advanceTimersByTimeAsync(10);
    mockWs.simulateMessage({ type: 'auth_ok' });

    mockWs.simulateMessage({ type: 'ping' });
    expect(onError).not.toHaveBeenCalled();
    expect(onEvent).not.toHaveBeenCalled();
  });

  it('attempts reconnect on unexpected close', async () => {
    const manager = createManager();
    manager.connect();
    await vi.advanceTimersByTimeAsync(10);
    mockWs.simulateMessage({ type: 'auth_ok' });

    // Simulate unexpected close
    mockWs.readyState = MockWebSocket.CLOSED;
    mockWs.onclose?.();

    expect(onStateChange).toHaveBeenCalledWith('reconnecting');
  });

  it('does not reconnect on intentional disconnect', async () => {
    const manager = createManager();
    manager.connect();
    await vi.advanceTimersByTimeAsync(10);

    manager.disconnect();
    expect(onStateChange).toHaveBeenLastCalledWith('disconnected');
  });

  it('bounds event buffer to 100', async () => {
    const manager = createManager();
    manager.connect();
    await vi.advanceTimersByTimeAsync(10);
    mockWs.simulateMessage({ type: 'auth_ok' });

    // Send 110 unique events
    for (let i = 0; i < 110; i++) {
      mockWs.simulateMessage({
        type: 'event',
        data: { id: `evt-${i}`, timestamp: 1234 + i, severity: 'info', threat_type: 'benign' },
      });
    }

    expect(onEvent).toHaveBeenCalledTimes(110);
    expect(manager.getBufferSize()).toBeLessThanOrEqual(100);
  });
});
