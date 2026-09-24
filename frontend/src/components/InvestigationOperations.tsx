import { useEffect, useState, useRef } from 'react';
import { useAppContext } from '@/hooks/useAppContext';
import type { Investigation } from '@/api/types';
import { formatTimestamp } from '@/utils/format';

export function InvestigationOperations({ eventId }: { eventId: string }) {
  const { api } = useAppContext();
  const exportButton = useRef<HTMLButtonElement>(null);
  const generation = useRef(0);
  const [view, setView] = useState<Investigation | null>(null);
  const [state, setState] = useState('Loading persisted investigation…');
  const [busy, setBusy] = useState(false);
  const [exportState, setExportState] = useState('');
  useEffect(() => {
    let active = true;
    generation.current++; setBusy(false);
    setView(null); setState('Loading persisted investigation…'); setExportState('');
    if (!api) { setState('Investigation unavailable — API not configured.'); return; }
    api.getInvestigation(eventId).then(data => {
      if (active) { setView(data); setState(''); }
    }).catch(() => { if (active) setState('Investigation unavailable. Evidence may be missing, expired, malformed, or above the bounded export limit.'); });
    return () => { active = false; generation.current++; };
  }, [api, eventId]);
  async function download() {
    if (!api) return;
    const started = generation.current;
    setBusy(true); setExportState('');
    try {
      const result = await api.exportInvestigation(eventId);
      if (started !== generation.current) return;
      const url = URL.createObjectURL(result.blob);
      const link = document.createElement('a');
      link.href = url; link.download = `sentinel-evidence-${result.digest.slice(0, 16)}.json`;
      link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
      setExportState(`Export SHA-256 verified: ${result.digest}`);
    } catch { if (started === generation.current) setExportState('Export failed. No verified evidence file was downloaded.'); }
    finally { if (started === generation.current) { setBusy(false); requestAnimationFrame(() => exportButton.current?.focus()); } }
  }
  return <section className="card detail-section analyst-operations" aria-label="Analyst operations">
    <h2 className="detail-section__title">CORRELATED EVIDENCE</h2>
    {state && <p role="status">{state}</p>}
    {view && <>
      <p><strong>{view.correlation.label}</strong> · {view.correlation.source_count} source types · {view.correlation.evidence_count} evidence references</p>
      <p>{view.correlation.summary}</p>
      <ul>{view.correlation.contributing_signal_types.map(source => <li key={source}>{source}</li>)}</ul>
      <details><summary>Correlation rules and limitations</summary><ul>{view.limitations.map(text => <li key={text}>{text}</li>)}</ul></details>
      <h3>Investigation timeline</h3>
      <p>Capture and processing times are labelled separately. Recorded traffic replay is not live activity at the capture date.</p>
      <ol className="investigation-timeline">{view.timeline.map((item, index) => <li key={`${item.event_id}-${item.reference}-${index}`}>
        <time>{formatTimestamp(item.timestamp)}</time>
        <strong>{item.description}</strong>
        <span>{item.source === 'REPLAY' ? 'RECORDED TRAFFIC REPLAY' : item.source === 'LIVE' ? 'LIVE' : 'SOURCE NOT RECORDED'} · {item.clock.replaceAll('_', ' ')}</span>
        <small>Event {item.event_id} · {item.reference}</small>
      </li>)}</ol>
      {view.timeline.length === 0 && <p>No timestamped observations available.</p>}
      <h3>Forensic evidence export</h3>
      <p>{view.integrity_semantics}</p>
      <button ref={exportButton} className="btn btn--secondary" disabled={busy} onClick={download}>{busy ? 'Verifying export…' : 'Download evidence JSON'}</button>
      <p role="status" className="detail-value">{exportState}</p>
    </>}
  </section>;
}
