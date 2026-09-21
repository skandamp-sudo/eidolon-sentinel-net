/**
 * Detections page — Detection event table with filters and pagination.
 *
 * Uses backend filtering via query params. No client-side data download.
 * All data from REST API.
 */

import { useEffect, useState, useCallback } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useAppContext } from '@/hooks/useAppContext';
import type { DetectionEvent, Severity, ThreatType } from '@/api/types';
import { formatTimestamp, severityClass, formatScore } from '@/utils/format';

const LIMIT = 50;

const SEVERITY_OPTIONS: Array<{ value: Severity | ''; label: string }> = [
  { value: '', label: 'All Severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Info' },
];

const THREAT_OPTIONS: Array<{ value: ThreatType | ''; label: string }> = [
  { value: '', label: 'All Threats' },
  { value: 'ddos', label: 'DDoS' },
  { value: 'scan', label: 'Scan' },
  { value: 'reconnaissance', label: 'Reconnaissance' },
  { value: 'exfiltration', label: 'Exfiltration' },
  { value: 'c2', label: 'C2' },
  { value: 'dns_tunneling', label: 'DNS Tunneling' },
  { value: 'brute_force', label: 'Brute Force' },
  { value: 'benign', label: 'Benign' },
  { value: 'unknown', label: 'Unknown' },
];

function SeverityDot({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: 'var(--severity-critical)',
    high: 'var(--severity-high)',
    medium: 'var(--severity-medium)',
    low: 'var(--severity-low)',
    info: 'var(--severity-info)',
  };
  return (
    <span
      style={{
        display: 'inline-block',
        width: 8,
        height: 8,
        borderRadius: '50%',
        background: colors[severity] ?? 'var(--text-muted)',
        marginRight: 6
      }}
    />
  );
}

function formatNumber(n: number): string {
  return n.toLocaleString();
}

export function Detections() {
  const { api } = useAppContext();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const [events, setEvents] = useState<DetectionEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [severity, setSeverity] = useState('');
  const [threatType, setThreatType] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Check for flow_id filter from URL params
  const flowIdFilter = searchParams.get('flow_id') ?? undefined;

  const fetchEvents = useCallback(async () => {
    if (!api) return;
    setLoading(true);
    try {
      const res = await api.getEvents({
        limit: LIMIT,
        offset,
        severity: severity || undefined,
        threat_type: threatType || undefined,
        flow_id: flowIdFilter,
      });
      setEvents(res.events ?? []);
      setTotal(res.total ?? 0);
      setError(null);
    } catch {
      setError('Failed to load detections');
      setEvents([]);
    } finally {
      setLoading(false);
    }
  }, [api, offset, severity, threatType, flowIdFilter]);

  useEffect(() => { fetchEvents(); }, [fetchEvents]);

  const handleFilterChange = (setter: (v: string) => void, value: string) => {
    setter(value);
    setOffset(0); // Reset to first page on filter change
  };

  const showStart = total > 0 ? offset + 1 : 0;
  const showEnd = Math.min(offset + LIMIT, total);

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">
          DETECTIONS <span className="badge" style={{ marginLeft: '12px', fontSize: 'var(--font-size-sm)', verticalAlign: 'middle' }}>{formatNumber(total)} Total</span>
        </h1>
      </div>

      {/* ─── Filters ──────────────────────────────────── */}
      <div className="filters" style={{ display: 'flex', gap: '16px', alignItems: 'center', marginBottom: '24px' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
          <label style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Severity</label>
          <select
            className="filter-select"
            value={severity}
            onChange={e => handleFilterChange(setSeverity, e.target.value)}
            aria-label="Filter by severity"
            style={{ padding: '6px 12px', borderRadius: '4px', background: 'var(--bg-surface)', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
          >
            {SEVERITY_OPTIONS.map(opt => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
          <label style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Threat Type</label>
          <select
            className="filter-select"
            value={threatType}
            onChange={e => handleFilterChange(setThreatType, e.target.value)}
            aria-label="Filter by threat type"
            style={{ padding: '6px 12px', borderRadius: '4px', background: 'var(--bg-surface)', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }}
          >
            {THREAT_OPTIONS.map(opt => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>

        {flowIdFilter && (
          <span style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', alignSelf: 'flex-end', paddingBottom: '8px' }}>
            Filtered by flow: {flowIdFilter.slice(0, 8)}…
          </span>
        )}
      </div>

      {/* ─── Content States ───────────────────────────── */}
      {loading && (
        <div className="state-message" role="status"><div className="state-message__title">Loading…</div></div>
      )}

      {error && (
        <div className="state-message">
          <div className="state-message__title">Error</div>
          <div className="state-message__text">{error}</div>
        </div>
      )}

      {!loading && !error && events.length === 0 && (
        <div className="state-message">
          <div className="state-message__title">No Detections</div>
          <div className="state-message__text">No detections match current filters.</div>
        </div>
      )}

      {/* ─── Table ────────────────────────────────────── */}
      {!loading && !error && events.length > 0 && (
        <div className="card">
          <div className="data-table-container" role="region" aria-label="Results table" tabIndex={0}><table className="data-table">
            <thead>
              <tr>
                <th>TIME</th>
                <th>SEVERITY</th>
                <th>THREAT TYPE</th>
                <th>ANOMALY SCORE</th><th>TRAFFIC MODE</th>
                <th>SOURCE</th>
                <th>DESTINATION</th>
                <th>MODEL</th>
              </tr>
            </thead>
            <tbody>
              {events.map(e => (
                <tr key={e.id} className="clickable" onClick={() => navigate(`/detections/${e.id}`)}>
                  <td className="mono"><Link to={`/detections/${e.id}`}>{formatTimestamp(e.timestamp)}</Link></td>
                  <td>
                    <span className={severityClass(e.severity)} style={{ display: 'flex', alignItems: 'center' }}>
                      <SeverityDot severity={e.severity} /> {e.severity.toUpperCase()}
                    </span>
                  </td>
                  <td><span className="badge badge--threat">{e.threat_type}</span></td>
                  <td className="mono">{formatScore(e.anomaly_score)}</td><td className="mono">{e.source_mode ?? "Not recorded"}</td>
                  <td className="mono">{e.src_ip ?? '—'}</td>
                  <td className="mono">{e.dst_ip ?? '—'}</td>
                  <td className="mono" style={{ fontSize: 'var(--font-size-xs)' }}>{e.model_name && e.deployment_model_version ? `${e.model_name} / ${e.deployment_model_version}` : 'Not recorded'}</td>
                </tr>
              ))}
            </tbody>
          </table></div>

          {/* ─── Pagination ─────────────────────────── */}
          <div className="pagination">
            <span style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-muted)' }}>Showing {showStart}–{showEnd} of {formatNumber(total)}</span>
            <div className="pagination__controls">
              <button
                className="pagination__btn"
                onClick={() => setOffset(Math.max(0, offset - LIMIT))}
                disabled={offset === 0}
              >
                ← Prev
              </button>
              <button
                className="pagination__btn"
                onClick={() => setOffset(offset + LIMIT)}
                disabled={offset + LIMIT >= total}
              >
                Next →
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
