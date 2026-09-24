import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { AppContext } from '@/hooks/useAppContext';
import { createApiClient } from '@/api/client';
import { Sensor } from '@/pages/Sensor';

afterEach(cleanup);

function show(state: string, mode: string, reasons: string[] = []) {
  const api = createApiClient('http://localhost:8000', 'test-key');
  api.getStatus = vi.fn().mockResolvedValue({ sensor_state: state, sensor_mode: mode,
    operational_health: { state, mode, reasons }, metrics: {}, uptime_sec: 10,
    feature_count: 52, feature_schema_version: '2.0.0', websocket_subscribers: 0 });
  render(<AppContext.Provider value={{ api, isConfigured: true, liveEvents: [], wsState: 'connected' }}><Sensor /></AppContext.Provider>);
}

it('shows degraded live operation and safe reasons without calling it replay', async () => {
  show('degraded', 'live_passive_sensor', ['persistence_errors']);
  expect(await screen.findByText('LIVE PASSIVE SENSOR')).toBeInTheDocument();
  expect(screen.getByRole('status', { name: 'Sensor operational status' })).toHaveTextContent('Processing continues');
  expect(screen.getByText('Operational reasons: persistence_errors')).toBeInTheDocument();
  expect(screen.queryByText('PCAP REPLAY — RECORDED TRAFFIC')).not.toBeInTheDocument();
});

it('preserves the distinct recorded-traffic label', async () => {
  show('replaying', 'recorded_traffic_replay');
  expect(await screen.findByText('PCAP REPLAY — RECORDED TRAFFIC')).toBeInTheDocument();
  expect(screen.queryByText('LIVE PASSIVE SENSOR')).not.toBeInTheDocument();
});

it('shows failed live operation as an error', async () => {
  show('failed', 'live_passive_sensor', ['capture_worker_failed']);
  expect(await screen.findByText('SENSOR ERROR')).toBeInTheDocument();
  expect(screen.getByText('failed')).toBeInTheDocument();
});


it('renders replay with no operational-health reasons and unavailable counters', async () => {
  const api = createApiClient('http://localhost:8000', 'test-key');
  api.getStatus = vi.fn().mockResolvedValue({ sensor_state: 'replay_complete', sensor_mode: 'recorded_traffic_replay',
    operational_health: {}, metrics: {}, uptime_sec: 10, feature_count: 52,
    feature_schema_version: '2.0.0', websocket_subscribers: 0 });
  render(<AppContext.Provider value={{ api, isConfigured: true, liveEvents: [], wsState: 'connected' }}><Sensor /></AppContext.Provider>);
  expect(await screen.findByText('RECORDED TRAFFIC REPLAY')).toBeInTheDocument();
  expect(screen.getAllByText('—').length).toBeGreaterThan(0);
  expect(screen.queryByText('Operational reasons:')).not.toBeInTheDocument();
});


it('keeps unavailable kernel drops and exact-history limits explicit', async () => {
  show('running', 'live_passive_sensor');
  expect(await screen.findByText(/Kernel capture drops: Unavailable from capture backend/)).toBeInTheDocument();
  expect(screen.getByText(/Per-flow memory is not strictly bounded/)).toBeInTheDocument();
  expect(screen.getByText(/Deleting rows does not necessarily shrink/)).toBeInTheDocument();
});
