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
  DetectionEvent,
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
  async function request<T>(path: string, params?: Record<string, string | number | undefined>): Promise<T> {
    const url = new URL(path, baseUrl);
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          url.searchParams.set(key, String(value));
        }
      });
    }

    const response = await fetch(url.toString(), {
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

  return {
    // ─── Health ────────────────────────────────────────────────
    getHealth: () => request<HealthResponse>('/health'),
    getReadiness: () => request<{ status: string }>('/readiness'),

    // ─── Events ───────────────────────────────────────────────
    getEvents: (filters?: EventFilters) =>
      request<EventListResponse>('/api/v1/events', filters as Record<string, string | number | undefined>),

    getEvent: (eventId: string) =>
      request<DetectionEvent>(`/api/v1/events/${encodeURIComponent(eventId)}`),

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
