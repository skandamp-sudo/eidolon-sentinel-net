/**
 * Tests for the API client.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createApiClient, ApiError } from '@/api/client';
import replayEvent from './fixtures/rw1-event.json';

// Mock global fetch
const mockFetch = vi.fn();
globalThis.fetch = mockFetch;

describe('API Client', () => {
  const baseUrl = 'http://localhost:8000';
  const apiKey = 'test-key-123';

  beforeEach(() => {
    mockFetch.mockReset();
  });

  function mockJsonResponse(data: unknown, status = 200) {
    mockFetch.mockResolvedValueOnce({
      ok: status >= 200 && status < 300,
      status,
      json: () => Promise.resolve(data),
      text: () => Promise.resolve(JSON.stringify(data)),
    });
  }

  it('sends X-API-Key header on every request', async () => {
    mockJsonResponse({ status: 'healthy', version: '0.6.0', timestamp: '' });
    const client = createApiClient(baseUrl, apiKey);
    await client.getHealth();

    expect(mockFetch).toHaveBeenCalledOnce();
    const [, init] = mockFetch.mock.calls[0]!;
    expect(init.headers['X-API-Key']).toBe(apiKey);
  });

  it('retains the complete real replay REST record', async () => {
    mockJsonResponse(replayEvent);
    const event = await createApiClient(baseUrl, apiKey).getEvent(replayEvent.id);
    expect(event).toEqual(replayEvent);
  });

  it('throws ApiError on 401', async () => {
    mockJsonResponse({ detail: 'Invalid API key' }, 401);
    const client = createApiClient(baseUrl, apiKey);

    await expect(client.getHealth()).rejects.toThrow(ApiError);
    await expect(client.getHealth()).rejects.toThrow();
  });

  it('throws ApiError on 404', async () => {
    mockJsonResponse({ detail: 'Event not found' }, 404);
    const client = createApiClient(baseUrl, apiKey);

    try {
      await client.getEvent('nonexistent');
      expect.fail('Should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(ApiError);
      expect((e as ApiError).status).toBe(404);
    }
  });

  it('fetches events with filters', async () => {
    mockJsonResponse({ events: [], total: 0, limit: 50, offset: 0 });
    const client = createApiClient(baseUrl, apiKey);
    await client.getEvents({ severity: 'high', limit: 10 });

    const [url] = mockFetch.mock.calls[0]!;
    expect(url).toContain('severity=high');
    expect(url).toContain('limit=10');
  });

  it('fetches flows', async () => {
    mockJsonResponse({ flows: [], total: 0, limit: 50, offset: 0 });
    const client = createApiClient(baseUrl, apiKey);
    await client.getFlows();

    const [url] = mockFetch.mock.calls[0]!;
    expect(url).toContain('/api/v1/flows');
  });

  it('fetches stats', async () => {
    const stats = { threat_types: { ddos: 5 }, severities: { high: 3 }, total_events: 5 };
    mockJsonResponse(stats);
    const client = createApiClient(baseUrl, apiKey);
    const result = await client.getStats();

    expect(result.total_events).toBe(5);
    expect(result.threat_types).toEqual({ ddos: 5 });
  });

  it('testConnection returns true on success', async () => {
    mockJsonResponse({ status: 'healthy' });
    const client = createApiClient(baseUrl, apiKey);
    const result = await client.testConnection();
    expect(result).toBe(true);
  });

  it('testConnection returns false on failure', async () => {
    mockFetch.mockRejectedValueOnce(new Error('Network error'));
    const client = createApiClient(baseUrl, apiKey);
    const result = await client.testConnection();
    expect(result).toBe(false);
  });

  it('encodes event ID in URL', async () => {
    mockJsonResponse({ id: 'test-123' });
    const client = createApiClient(baseUrl, apiKey);
    await client.getEvent('test/123');

    const [url] = mockFetch.mock.calls[0]!;
    expect(url).toContain('test%2F123');
  });

  it('omits undefined filter params', async () => {
    mockJsonResponse({ events: [], total: 0, limit: 50, offset: 0 });
    const client = createApiClient(baseUrl, apiKey);
    await client.getEvents({ severity: undefined, threat_type: 'ddos' });

    const [url] = mockFetch.mock.calls[0]!;
    expect(url).not.toContain('severity');
    expect(url).toContain('threat_type=ddos');
  });
});
