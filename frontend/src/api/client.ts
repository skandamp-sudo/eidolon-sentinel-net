/**
 * Typed API client for Sentinel-NET REST endpoints.
 *
 * SECURITY:
 * - API key stored in closure, never logged or rendered
 * - All requests go through centralized fetch wrapper
 * - No eval(), no dynamic code execution
 * - Backend is the sole source of truth for all data
 */

import type {
  DetectionEvent, Investigation, Assurance,
  EventListResponse,
  Flow,
  FlowListResponse,
  HealthResponse,
  StatsResponse,
  StatusResponse,
} from './types';

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export interface EventFilters {
  limit?: number;
  offset?: number;
  threat_type?: string;
  severity?: string;
  since?: number;
  flow_id?: string;
}

export interface FlowFilters {
  limit?: number;
  offset?: number;
  since?: number;
}

/**
 * Creates a typed API client bound to a base URL and API key.
 *
 * The API key is captured in the closure and never exposed.
 */
export function createApiClient(baseUrl: string, apiKey: string) {
  async function request<T>(path: string, params?: Record<string, string | number | undefined>, signal?: AbortSignal): Promise<T> {
    const url = new URL(path, baseUrl);
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          url.searchParams.set(key, String(value));
        }
      });
    }

    const response = await fetch(url.toString(), {
      signal,
      headers: {
        'X-API-Key': apiKey,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const body = await response.text();
      let message = `HTTP ${response.status}`;
      try {
        const json = JSON.parse(body) as { detail?: string };
        if (json.detail) message = json.detail;
      } catch {
        // Use status text
      }
      throw new ApiError(response.status, message);
    }

    return response.json() as Promise<T>;
  }

  async function boundedRequest<T>(path: string): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20000);
    try { return await request<T>(path, undefined, controller.signal); }
    finally { clearTimeout(timer); }
  }

  return {
    // ─── Health ────────────────────────────────────────────────
    getHealth: () => request<HealthResponse>('/health'),
    getReadiness: () => request<{ status: string }>('/readiness'),

    // ─── Events ───────────────────────────────────────────────
    getEvents: (filters?: EventFilters) =>
      request<EventListResponse>('/api/v1/events', filters as Record<string, string | number | undefined>),

    getEvent: (eventId: string) =>
      request<DetectionEvent>(`/api/v1/events/${encodeURIComponent(eventId)}`),

    getInvestigation: (eventId: string) =>
      boundedRequest<Investigation>(`/api/v1/events/${encodeURIComponent(eventId)}/investigation`),
    getAssurance: () => boundedRequest<Assurance>('/api/v1/assurance'),
    exportInvestigation: async (eventId: string) => {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 20000);
      try {
        const response = await fetch(new URL(`/api/v1/events/${encodeURIComponent(eventId)}/export`, baseUrl), {
          headers: { 'X-API-Key': apiKey }, signal: controller.signal,
        });
        if (!response.ok) throw new ApiError(response.status, 'Evidence export unavailable');
        if (Number(response.headers.get('Content-Length')) > 1048576) throw new Error('Export exceeds size limit');
        const reader = response.body?.getReader();
        if (!reader) throw new Error('Export body unavailable');
        const chunks: Uint8Array[] = []; let size = 0;
        try {
          while (true) {
            const {done, value} = await reader.read();
            if (done) break;
            size += value.byteLength;
            if (size > 1048576) throw new Error('Export exceeds size limit');
            chunks.push(value);
          }
        } finally { await reader.cancel(); }
        const bytes = new Uint8Array(size); let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
        const expected = response.headers.get('X-Content-SHA256');
        const hash = await crypto.subtle.digest('SHA-256', bytes);
        const digest = Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, '0')).join('');
        if (digest !== expected) throw new Error('Export integrity check failed');
        return { blob: new Blob([bytes], { type: 'application/json' }), digest };
      } finally { clearTimeout(timeout); controller.abort(); }
    },

    // ─── Flows ────────────────────────────────────────────────
    getFlows: (filters?: FlowFilters) =>
      request<FlowListResponse>('/api/v1/flows', filters as Record<string, string | number | undefined>),

    getFlow: (flowId: string) =>
      request<Flow>(`/api/v1/flows/${encodeURIComponent(flowId)}`),

    // ─── Stats ────────────────────────────────────────────────
    getStats: () => request<StatsResponse>('/api/v1/stats'),

    // ─── Status ───────────────────────────────────────────────
    getStatus: () => request<StatusResponse>('/api/v1/status'),

    // ─── Connection Test ──────────────────────────────────────
    testConnection: async (): Promise<boolean> => {
      try {
        await request<HealthResponse>('/health');
        return true;
      } catch {
        return false;
      }
    },
  };
}

export type ApiClient = ReturnType<typeof createApiClient>;
