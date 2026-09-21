/**
 * Overview — SOC Command Center main view.
 *
 * All data from backend REST API. No fabricated metrics.
 * Shows UNAVAILABLE when API is unreachable.
 */

import { useEffect, useState, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAppContext } from '@/hooks/useAppContext';
import type { StatusResponse, StatsResponse, DetectionEvent } from '@/api/types';
import { formatNumber, formatTimestamp, formatDuration } from '@/utils/format';

function SeverityDot({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: 'var(--severity-critical)',
    high: 'var(--severity-high)',
    medium: 'var(--severity-medium)',
    low: 'var(--severity-low)',
    info: 'var(--severity-info)',
  };
  return <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: colors[severity.toLowerCase()] ?? 'var(--text-muted)', marginRight: 6, flexShrink: 0 }} />;
}

export function Overview() {
  const { api } = useAppContext();
  const navigate = useNavigate();

  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [recentDetections, setRecentDetections] = useState<DetectionEvent[]>([]);
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    if (!api) return;
    try {
      const [statusData, statsData, eventsData] = await Promise.all([
        api.getStatus(),
        api.getStats(),
        api.getEvents({ limit: 10, offset: 0 }),
      ]);
      setStatus(statusData);
      setStats(statsData);
      setRecentDetections(eventsData.events ?? []);
      setError(null);
      setUpdatedAt(new Date());
    } catch {
      setError('UNAVAILABLE');
    } finally {
      setLoading(false);
    }
  }, [api]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30_000);
    return () => clearInterval(interval);
  }, [fetchData]);

  if (loading && !status) {
    return <div className="state-message" role="status"><div className="state-message__title">Loading…</div></div>;
  }

  if (error) {
    return (
      <div className="state-message">
        <div className="state-message__title">API Unavailable</div>
        <div className="state-message__text">Cannot reach the Sentinel-NET backend. Check connection settings.</div>
        <p className="page-description">{updatedAt ? `Last successful update: ${updatedAt.toLocaleTimeString()}. Previous data is stale and hidden.` : 'No current data available.'}</p>
        <button className="btn btn--secondary" onClick={() => fetchData()}>Retry</button>
      </div>
    );
  }

  const m = status?.metrics;
  const sensorState = status?.sensor_state ?? 'unknown';
  
  const stateBorderColor = sensorState === 'running' 
    ? 'var(--accent-success)' 
    : sensorState === 'stopped' 
      ? 'var(--accent-warning)' 
      : 'var(--accent-primary)';

  const hasThreatData = stats && Object.keys(stats.threat_types).length > 0;
  const maxThreatCount = hasThreatData ? Math.max(...Object.values(stats.threat_types)) : 1;

  const hasSeverityData = stats && Object.keys(stats.severities).length > 0;
  const maxSeverityCount = hasSeverityData ? Math.max(...Object.values(stats.severities)) : 1;
  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];

  return (
    <div>
      <p className="refresh-note">{updatedAt ? `Updated ${updatedAt.toLocaleTimeString()}` : "Waiting for data"}</p>
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 className="page-title" style={{ marginBottom: 0 }}>SOC COMMAND CENTER</h1>
          <div style={{ color: 'var(--text-muted)', fontSize: 'var(--font-size-sm)', marginTop: 'var(--space-1)' }}>
            Passive network security operations
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)' }}>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end' }}>
            <span style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Sensor State</span>
            <span className="badge" style={{ marginTop: 'var(--space-1)', borderColor: stateBorderColor, color: stateBorderColor }}>{sensorState.replaceAll('_', ' ')}</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end' }}>
            <span style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Uptime</span>
            <span className="mono" style={{ marginTop: 'var(--space-1)', color: 'var(--text-primary)' }}>{formatDuration(status?.uptime_sec)}</span>
          </div>
        </div>
      </div>

      <p className="source-banner">{status?.sensor_mode === 'recorded_traffic_replay' ? 'RECORDED TRAFFIC REPLAY' : status?.sensor_mode === 'live_passive_sensor' ? 'LIVE PASSIVE SENSOR' : 'STANDBY — NO ACTIVE SOURCE'}</p>
      {/* ─── Metrics Cards ────────────────────────────── */}
      <div className="overview-metrics">
        <div className="card" style={{ borderTop: `1px solid var(--border-active)` }}>
          <div className="card__title">ACTIVE FLOWS</div>
          <div className="card__value mono" style={{ fontSize: 'var(--font-size-xl)' }}>{formatNumber(m?.flows_active)}</div>
          <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', marginTop: 'var(--space-2)' }}>Currently tracked sessions</div>
        </div>
        <div className="card" style={{ borderTop: `1px solid var(--border-active)` }}>
          <div className="card__title">PACKETS OBSERVED</div>
          <div className="card__value mono" style={{ fontSize: 'var(--font-size-xl)' }}>{formatNumber(m?.packets_observed)}</div>
          <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', marginTop: 'var(--space-2)' }}>Total ingress traffic</div>
        </div>
        <div className="card" style={{ borderTop: `1px solid var(--border-active)` }}>
          <div className="card__title">TOTAL DETECTIONS</div>
          <div className="card__value mono" style={{ fontSize: 'var(--font-size-xl)' }}>{formatNumber(stats?.total_events)}</div>
          <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', marginTop: 'var(--space-2)' }}>Alerts across all severity levels</div>
        </div>
        <div className="card" style={{ borderTop: `2px solid ${stateBorderColor}` }}>
          <div className="card__title">SENSOR STATE</div>
          <div className="card__value mono" style={{ fontSize: 'var(--font-size-xl)', color: stateBorderColor }}>{sensorState.replaceAll('_', ' ')}</div>
          <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', marginTop: 'var(--space-2)' }}>Capture engine status</div>
        </div>
      </div>

      {/* ─── Distributions ────────────────────────────── */}
      <div className="overview-distributions">
        <div className="card">
          <div className="card__title" style={{ marginBottom: 'var(--space-4)' }}>THREAT DISTRIBUTION</div>
          {hasThreatData ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              {Object.entries(stats.threat_types)
                .sort(([, a], [, b]) => b - a)
                .map(([threat, count]) => (
                  <div key={threat} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-1)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 'var(--font-size-sm)' }}>
                      <span style={{ color: 'var(--text-primary)' }}>{threat}</span>
                      <span className="mono" style={{ color: 'var(--text-primary)' }}>{formatNumber(count)}</span>
                    </div>
                    <div style={{ width: '100%', height: 6, background: 'var(--bg-lighter)', borderRadius: 3, overflow: 'hidden' }}>
                      <div style={{ width: `${(count / maxThreatCount) * 100}%`, height: '100%', background: 'var(--primary-color)', borderRadius: 3 }} />
                    </div>
                  </div>
                ))}
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: 'var(--font-size-sm)' }}>
              No threat data in current session
              <div style={{ fontSize: 'var(--font-size-xs)', marginTop: 'var(--space-1)' }}>Awaiting anomaly detection events</div>
            </div>
          )}
        </div>

        <div className="card">
          <div className="card__title" style={{ marginBottom: 'var(--space-4)' }}>SEVERITY DISTRIBUTION</div>
          {hasSeverityData ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              {severityOrder.map(sev => {
                const count = stats.severities[sev] || 0;
                if (count === 0 && !stats.severities[sev]) return null;
                return (
                  <div key={sev} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-1)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 'var(--font-size-sm)' }}>
                      <span style={{ display: 'flex', alignItems: 'center', color: 'var(--text-primary)', textTransform: 'uppercase' }}>
                        <SeverityDot severity={sev} />
                        {sev}
                      </span>
                      <span className="mono" style={{ color: 'var(--text-primary)' }}>{formatNumber(count)}</span>
                    </div>
                    <div style={{ width: '100%', height: 6, background: 'var(--bg-lighter)', borderRadius: 3, overflow: 'hidden' }}>
                      <div style={{ width: `${(count / maxSeverityCount) * 100}%`, height: '100%', background: `var(--severity-${sev}, var(--primary-color))`, borderRadius: 3 }} />
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: 'var(--font-size-sm)' }}>
              No threat data in current session
              <div style={{ fontSize: 'var(--font-size-xs)', marginTop: 'var(--space-1)' }}>Awaiting anomaly detection events</div>
            </div>
          )}
        </div>
      </div>

      {/* ─── Recent Detections ────────────────────────── */}
      <div className="card">
        <div className="card__title" style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
          RECENT DETECTIONS
          {recentDetections.length > 0 && (
            <span className="badge" style={{ background: 'var(--bg-lighter)' }}>{recentDetections.length}</span>
          )}
        </div>
        {recentDetections.length === 0 ? (
          <div style={{ padding: 'var(--space-6) 0', textAlign: 'center', color: 'var(--text-muted)' }}>
            <div style={{ fontSize: 'var(--font-size-lg)', color: 'var(--text-primary)', marginBottom: 'var(--space-2)', letterSpacing: '1px' }}>
              NO DETECTIONS RECORDED
            </div>
            <div style={{ fontSize: 'var(--font-size-sm)', marginBottom: 'var(--space-1)' }}>
              No detections have been observed in the current session.
            </div>
            <div style={{ fontSize: 'var(--font-size-sm)', marginBottom: 'var(--space-4)' }}>
              The sensor is currently {sensorState.replaceAll('_', ' ')}. Detections will appear here when network traffic is being processed.
            </div>
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)', fontSize: 'var(--font-size-xs)', background: 'var(--bg-lighter)', padding: 'var(--space-2) var(--space-4)', borderRadius: 4 }}>
              <span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: '#22c55e' }} />
              API Connection OK
            </div>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>TIME</th>
                  <th>SEVERITY</th>
                  <th>THREAT TYPE</th>
                  <th>SOURCE</th>
                  <th>DESTINATION</th>
                  <th>ANOMALY SCORE</th>
                </tr>
              </thead>
              <tbody>
                {recentDetections.map(d => (
                  <tr key={d.id} className="clickable" onClick={() => navigate(`/detections/${d.id}`)}>
                    <td className="mono"><Link to={`/detections/${d.id}`}>{formatTimestamp(d.timestamp)}</Link></td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', textTransform: 'uppercase', fontSize: 'var(--font-size-sm)' }}>
                        <SeverityDot severity={d.severity} />
                        {d.severity}
                      </div>
                    </td>
                    <td><span className="badge badge--threat">{d.threat_type}</span></td>
                    <td className="mono">{d.src_ip ?? '—'}</td>
                    <td className="mono">{d.dst_ip ?? '—'}</td>
                    <td className="mono">{d.anomaly_score !== null ? d.anomaly_score.toFixed(3) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
