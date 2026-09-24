import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { AppContext } from '@/hooks/useAppContext';
import { createApiClient } from '@/api/client';
import { InvestigationOperations } from '@/components/InvestigationOperations';
import { AssurancePanel } from '@/components/AssurancePanel';
import type { Investigation, Assurance } from '@/api/types';

const view: Investigation = {
  export_schema_version: '1.0.0', investigation_id: 'a'.repeat(64), anchor_event_id: 'event-1',
  correlation: { label: 'CORRELATED OBSERVATION', summary: 'Multiple evidence sources; not confirmation.',
    source_count: 2, evidence_count: 2, contributing_event_ids: ['event-1'],
    contributing_signal_types: ['ML classification', 'TLS metadata'], first_seen: 1000, last_seen: 1000, time_basis: 'recorded event.timestamp' },
  timeline: [{ timestamp: 1000, clock: 'capture_event_time', signal_type: 'tls',
    description: '<script>alert(1)</script>', source: 'REPLAY', event_id: 'event-1', reference: 'tls_observation' }],
  limitations: ['No statistical independence established.'], integrity_semantics: 'SHA-256 is not a digital signature.',
};
const assurance: Assurance = { rows: [{ property: 'Physical data-diode validation', status: 'NOT VERIFIED', detail: 'Software simulation only.' }],
  model_identity: null, feature_schema_version: '2.0.0', science: { status: 'MEASURED', accuracy: .75943992227575,
  macro_f1: .2675121989116243, c2_recall: 0, ddos_recall: .2667833205743122, benign_to_malicious_fpr: 276/267851,
  iforest_roc_auc: .8184012477471853, candidate_status: 'CANDIDATE — NOT APPROVED — NOT PUBLISHED',
  limitations: ['Behavioral/DNS/TLS evidence is evaluated separately and is not included in these ML accuracy values.',
    'All threshold-dependent anomaly results remain exploratory.'] } };
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
function setup() {
  const api = createApiClient('http://localhost:8000', 'test-key');
  api.getInvestigation = vi.fn().mockResolvedValue(view);
  api.getAssurance = vi.fn().mockResolvedValue(assurance);
  api.exportInvestigation = vi.fn().mockResolvedValue({ blob: new Blob(['{}']), digest: 'a'.repeat(64) });
  const show = (child: React.ReactNode) => render(<AppContext.Provider value={{ api, isConfigured: true, liveEvents: [], wsState: 'disconnected' }}>{child}</AppContext.Provider>);
  return { api, show };
}
it('renders correlation and actual clock/source labels, escaping stored text', async () => {
  const {show} = setup(); const {container} = show(<InvestigationOperations eventId="event-1" />);
  expect(await screen.findByText('CORRELATED OBSERVATION')).toBeInTheDocument();
  expect(screen.getByText(/RECORDED TRAFFIC REPLAY · capture event time/)).toBeInTheDocument();
  expect(screen.getByText('<script>alert(1)</script>')).toBeInTheDocument();
  expect(container.querySelector('script')).toBeNull();
  expect(screen.getByRole('button', {name:'Download evidence JSON'})).toBeEnabled();
});
it('does not synthesize a timeline when no timestamp exists', async () => {
  const {api, show} = setup(); api.getInvestigation = vi.fn().mockResolvedValue({...view, timeline: []});
  show(<InvestigationOperations eventId="event-1" />);
  expect(await screen.findByText('No timestamped observations available.')).toBeInTheDocument();
});
it('shows unavailable investigation and offers no export on failure', async () => {
  const {api, show} = setup(); api.getInvestigation = vi.fn().mockRejectedValue(new Error());
  show(<InvestigationOperations eventId="missing" />);
  expect(await screen.findByText(/Investigation unavailable/)).toBeInTheDocument();
  expect(screen.queryByRole('button')).toBeNull();
});
it('downloads only verified bytes and uses an application-generated filename', async () => {
  const {api, show} = setup();
  URL.createObjectURL = vi.fn().mockReturnValue('blob:test'); URL.revokeObjectURL = vi.fn();
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
  show(<InvestigationOperations eventId="event-1" />);
  fireEvent.click(await screen.findByRole('button', {name:'Download evidence JSON'}));
  expect(await screen.findByText(/Export SHA-256 verified:/)).toBeInTheDocument();
  expect(api.exportInvestigation).toHaveBeenCalledWith('event-1'); expect(click).toHaveBeenCalledOnce();
});
it('reports export failure without claiming a verified download', async () => {
  const {api, show} = setup(); api.exportInvestigation = vi.fn().mockRejectedValue(new Error());
  show(<InvestigationOperations eventId="event-1" />);
  fireEvent.click(await screen.findByRole('button', {name:'Download evidence JSON'}));
  expect(await screen.findByText(/Export failed/)).toBeInTheDocument();
});
it('retains weak science, unavailable model, and browser WebSocket state', async () => {
  const {show} = setup(); show(<AssurancePanel />);
  expect(await screen.findByText('NOT VERIFIED')).toBeInTheDocument();
  for (const value of ['0.000%', '26.678%', '0.103%', '0.2675', '75.944%']) expect(screen.getByText(value)).toBeInTheDocument();
  expect(screen.getByText('Loaded model: UNAVAILABLE')).toBeInTheDocument();
  expect(screen.getByText(/WebSocket — DISCONNECTED/)).toBeInTheDocument();
  expect(screen.getByText(/evaluated separately/)).toBeInTheDocument();
  expect(screen.getByText(/remain exploratory/)).toBeInTheDocument();
});
it('does not display measured readiness when the API is unavailable', async () => {
  const {api, show} = setup(); api.getAssurance = vi.fn().mockRejectedValue(new Error());
  show(<AssurancePanel />);
  expect(await screen.findByText(/Assurance UNAVAILABLE/)).toBeInTheDocument();
  expect(screen.queryByText('MEASURED')).toBeNull();
});
it('rejects export bytes with a mismatched digest', async () => {
  const api = createApiClient('http://localhost:8000', 'test-key');
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('{}', {headers:{'X-Content-SHA256':'wrong'}})));
  await expect(api.exportInvestigation('event-1')).rejects.toThrow('Export integrity check failed');
});
it('bounds export download bytes before keeping an oversized response', async () => {
  const api = createApiClient('http://localhost:8000', 'test-key');
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(new Uint8Array(1048577))));
  await expect(api.exportInvestigation('event-1')).rejects.toThrow('Export exceeds size limit');
});
it('does not download an old export after the selected event changes', async () => {
  const {api} = setup();
  let finish!: (v: {blob: Blob; digest: string}) => void;
  api.exportInvestigation = vi.fn().mockReturnValue(new Promise(resolve => { finish = resolve; }));
  const make = (id: string) => <AppContext.Provider value={{ api, isConfigured:true, liveEvents:[], wsState:'connected' }}><InvestigationOperations eventId={id} /></AppContext.Provider>;
  const {rerender} = render(make('event-1'));
  URL.createObjectURL = vi.fn();
  fireEvent.click(await screen.findByRole('button', {name:'Download evidence JSON'}));
  rerender(make('event-2'));
  finish({blob:new Blob(['{}']), digest:'b'.repeat(64)});
  await screen.findByRole('button', {name:'Download evidence JSON'});
  expect(URL.createObjectURL).not.toHaveBeenCalled();
  expect(screen.queryByText(/Export SHA-256 verified/)).toBeNull();
});
