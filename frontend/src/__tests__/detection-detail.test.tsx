import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { AppContext } from '@/hooks/useAppContext';
import { createApiClient } from '@/api/client';
import type { DetectionEvent } from '@/api/types';
import { DetectionDetail } from '@/pages/DetectionDetail';
import replayEvent from './fixtures/rw1-event.json';

afterEach(cleanup);

function renderEvent(record: unknown) {
  const api = createApiClient('http://localhost:8000', 'test-key');
  api.getEvent = vi.fn().mockResolvedValue(record as DetectionEvent);
  render(
    <AppContext.Provider value={{ api, isConfigured: true, liveEvents: [], wsState: 'connected' }}>
      <MemoryRouter initialEntries={['/detections/'+replayEvent.id]}>
        <Routes><Route path="/detections/:eventId" element={<DetectionDetail />} /></Routes>
      </MemoryRouter>
    </AppContext.Provider>,
  );
}

describe('Detection investigation contract', () => {
  it('renders the real backend event, flow link, scores, provenance and evidence', async () => {
    renderEvent(replayEvent);
    expect(await screen.findByText(replayEvent.id)).toBeInTheDocument();
    expect(screen.getByText('Classification Score')).toBeInTheDocument();
    expect(screen.getByText(replayEvent.detection_source.join(', '))).toBeInTheDocument();
    expect(screen.getByRole('link', { name: replayEvent.flow_id })).toHaveAttribute('href', '/flows/'+replayEvent.flow_id);
    expect(screen.getAllByText('statistical').length).toBeGreaterThan(0);
    expect(screen.getByText('Feature Schema')).toBeInTheDocument();
    expect(screen.queryByText('Evidence Unavailable')).not.toBeInTheDocument();
  });

  it('distinguishes an available empty explanation from an unavailable one', async () => {
    renderEvent({ ...replayEvent, evidence: { items: [], explanation_available: true, unavailable_reason: null } });
    expect(await screen.findByText('No Significant Evidence')).toBeInTheDocument();
    expect(screen.queryByText('Evidence Unavailable')).not.toBeInTheDocument();
  });

  it('shows the recorded reason when explanations are unavailable', async () => {
    renderEvent({ ...replayEvent, evidence: { items: [], explanation_available: false, unavailable_reason: 'Training baseline unavailable.' } });
    expect(await screen.findByText('Training baseline unavailable.')).toBeInTheDocument();
  });
});


it.each([
  ['LIVE', 'LIVE PASSIVE SENSOR'],
  ['REPLAY', 'RECORDED TRAFFIC REPLAY'],
  [null, 'Not recorded'],
])('shows honest traffic provenance for %s events', async (mode, label) => {
  renderEvent({ ...replayEvent, source_mode: mode });
  expect(await screen.findByText(label as string)).toBeInTheDocument();
});

it('renders streaming evidence from the shared frozen runtime without calling it confidence', async () => {
  const { default: record } = await import('./fixtures/f3-event.json');
  renderEvent(record);
  expect(await screen.findByRole('region', { name: 'Behavioral evidence table' })).toBeInTheDocument();
  expect(screen.getByText('PORT_FANOUT')).toBeInTheDocument();
  expect(screen.getByText('stream_recon')).toBeInTheDocument();
  expect(screen.getByText(/Passive streaming heuristics are contextual observations/)).toBeInTheDocument();
  expect(screen.getByText('Classification Score')).toBeInTheDocument();
});

it.each([
  ['not_recorded', 'Behavioral evidence was not recorded for this event.'],
  ['available', 'No streaming signals were emitted for the retained observations.'],
  ['disabled', 'Streaming intelligence was disabled for this event.'],
  ['unavailable_processing_error', 'Streaming evidence unavailable due to an operational processing error.'],
])('distinguishes streaming evidence status %s', async (status, message) => {
  renderEvent({ ...replayEvent, behavioral_evidence: [], behavioral_evidence_status: status });
  expect(await screen.findByText(message)).toBeInTheDocument();
});
