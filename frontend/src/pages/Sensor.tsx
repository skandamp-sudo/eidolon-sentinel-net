/**
 * Sensor page — Read-only observability dashboard.
 *
 * Displays operational metrics from GET /api/v1/status.
 * NO controls that transmit, inject, or modify traffic.
 * Auto-refreshes every 10 seconds.
 */

import { useEffect, useState, useCallback } from 'react';
import { useAppContext } from '@/hooks/useAppContext';
import type { StatusResponse } from '@/api/types';
import { formatNumber, formatDuration } from '@/utils/format';

export function Sensor() {
  const { api } = useAppContext();
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchStatus = useCallback(async () => {
    if (!api) return;
    try {
      const data = await api.getStatus();
      setStatus(data);
      setError(null);
      setUpdatedAt(new Date());
    } catch {
      setError('Cannot reach sensor');
    } finally {
      setLoading(false);
    }
  }, [api]);

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 10_000);
    return () => clearInterval(interval);
  }, [fetchStatus]);

  if (loading && !status) {
    return <div className="state-message" role="status"><div className="state-message__title">Loading…</div></div>;
  }

  if (error) {
    return (
      <div className="state-message">
        <div className="state-message__title">Sensor Unavailable</div>
        <div className="state-message__text">{error}</div>
        <p className="page-description">{updatedAt ? `Last successful update: ${updatedAt.toLocaleTimeString()}. Previous data is stale and hidden.` : 'No current data available.'}</p>
        <button className="btn btn--secondary" onClick={() => fetchStatus()}>Retry</button>
      </div>
    );
  }

  const m = status?.metrics;
  const sensorState = (status?.sensor_state ?? 'unknown').toLowerCase();
  
  const getStateColor = (state: string) => {
    switch(state) {
      case 'running': return 'var(--accent-success, #22c55e)';
      case 'replaying': return 'var(--accent-primary, #3b82f6)';
      case 'replay_complete': return 'var(--accent-success, #22c55e)';
      case 'degraded':
      case 'starting': return 'var(--accent-warning, #f59e0b)';
      case 'failed':
      case 'error': return 'var(--accent-error, #ef4444)';
      default: return 'var(--text-muted, #6b7280)'; // stopped / unknown
    }
  };

  const isRunning = sensorState === 'running';
  const isReplaying = sensorState === 'replaying';
  const isReplayComplete = sensorState === 'replay_complete';
  const isStopped = sensorState === 'stopped';
  const isError = sensorState === 'error' || sensorState === 'failed';
  const stateColor = getStateColor(sensorState);

  return (
    <div>
      <p className="refresh-note">{updatedAt ? `Updated ${updatedAt.toLocaleTimeString()}` : "Waiting for data"}</p>
      <div className="page-header">
        <h1 className="page-title">PASSIVE SENSOR</h1>
        <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)' }}>
          Read-only observability • Auto-refreshes every 10s
        </div>
      </div>

      {/* Sensor State Hero */}
      <div className="card" style={{ marginBottom: 'var(--space-6)', padding: 'var(--space-5)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)', marginBottom: isStopped || isRunning || isReplaying || isError ? 'var(--space-4)' : '0' }}>
          <div style={{ position: 'relative', display: 'flex', alignItems: 'center', justifyContent: 'center', width: '24px', height: '24px' }}>
            <span 
              style={{ 
                position: 'absolute',
                width: '16px', 
                height: '16px', 
                borderRadius: '50%',
                backgroundColor: stateColor,

              }} 
            />
          </div>
          <span style={{ 
            fontFamily: 'var(--font-mono)', 
            fontWeight: 700, 
            fontSize: 'var(--font-size-xl)', 
            textTransform: 'uppercase',
            color: stateColor,
            letterSpacing: '1px'
          }}>
            {sensorState.replaceAll('_', ' ')}
          </span>
        </div>

        {(status?.sensor_mode === 'recorded_traffic_replay' || isReplaying || isReplayComplete) && <p className="source-banner">RECORDED TRAFFIC REPLAY</p>}
        {status?.sensor_mode === 'live_passive_sensor' && <p>LIVE PASSIVE SENSOR</p>}
        {sensorState === 'degraded' && <p role="status">Processing continues with operational errors or drops. Review the counters below.</p>}
        {!!status?.operational_health?.reasons?.length && <p>Operational reasons: {status.operational_health.reasons.join(', ')}</p>}

        {isStopped && (
          <div style={{ borderTop: '1px solid var(--border-color, #333)', paddingTop: 'var(--space-3)' }}>
            <div style={{ fontWeight: 600, marginBottom: 'var(--space-1)' }}>PASSIVE SENSOR — STANDBY</div>
            <div style={{ color: 'var(--text-muted)' }}>
              No traffic is currently being processed. This is a normal operational state when the capture interface is not active.
            </div>
          </div>
        )}

        {isRunning && (
          <div style={{ borderTop: '1px solid var(--border-color, #333)', paddingTop: 'var(--space-3)' }}>
            <div style={{ color: 'var(--text-muted)', fontSize: 'var(--font-size-sm)', textTransform: 'uppercase' }}>Uptime</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--font-size-lg)' }}>
              {formatDuration(status?.uptime_sec ?? 0)}
            </div>
          </div>
        )}

        {isReplaying && (
          <div style={{ borderTop: '1px solid var(--border-color, #333)', paddingTop: 'var(--space-3)' }}>
            <div style={{ fontWeight: 600, marginBottom: 'var(--space-1)', color: 'var(--accent-primary)' }}>PCAP REPLAY — RECORDED TRAFFIC</div>
            <div style={{ color: 'var(--text-muted)', marginBottom: 'var(--space-2)' }}>
              Processing recorded traffic through the production ML pipeline. This is a PCAP file replay, not live network capture. All detections are produced by real ML inference.
            </div>
            <div style={{ color: 'var(--text-muted)', fontSize: 'var(--font-size-sm)', textTransform: 'uppercase' }}>Elapsed</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--font-size-lg)' }}>
              {formatDuration(status?.uptime_sec ?? 0)}
            </div>
          </div>
        )}

        {isReplayComplete && (
          <div style={{ borderTop: '1px solid var(--border-color, #333)', paddingTop: 'var(--space-3)' }}>
            <div style={{ fontWeight: 600, marginBottom: 'var(--space-1)', color: 'var(--accent-success)' }}>PCAP REPLAY — COMPLETE</div>
            <div style={{ color: 'var(--text-muted)' }}>
              Replay has finished successfully. The dashboard displays the final results of the recorded traffic analysis.
            </div>
          </div>
        )}

        {isError && (
          <div style={{ borderTop: '1px solid var(--border-color, #333)', paddingTop: 'var(--space-3)' }}>
            <div style={{ fontWeight: 600, color: 'var(--accent-error)', marginBottom: 'var(--space-1)' }}>SENSOR ERROR</div>
            <div style={{ color: 'var(--text-muted)' }}>
              The sensor encountered a critical error and could not continue processing traffic.
            </div>
          </div>
        )}
      </div>

      <div className="runtime-identity detail-grid">
        <span className="detail-label">Approved Model</span><span className="detail-value">{status?.model_identity ? `${status.model_identity.model_name} / ${status.model_identity.model_version}` : 'Not loaded / unavailable'}</span>
        <span className="detail-label">Schema</span><span className="detail-value">{status?.feature_schema_version ?? 'Unavailable'} · {status?.feature_count ?? 'Unavailable'} features</span>
        <span className="detail-label">Capture Interface</span><span className="detail-value">{status?.capture_interface ?? 'Not applicable / unavailable'}</span>
        <span className="detail-label">Run Duration</span><span className="detail-value">{formatDuration(status?.uptime_sec)}</span>
      </div>
      {/* Metrics Section: CAPTURE */}
      <div className="section-header">Capture</div>
      <div className="card-grid">
        <MetricCard title="Packets Observed" value={m?.packets_observed} />
        <MetricCard title="Packets Parsed" value={m?.packets_parsed} />
        <MetricCard title="Packets Processed" value={m?.packets_processed} />
        <MetricCard title="Packet Errors" value={m?.packet_errors} warn />
        <MetricCard title="Packets Malformed" value={m?.packets_malformed} warn />
        <MetricCard title="Packets Dropped" value={m?.packets_dropped} warn />
      </div>

      {/* Metrics Section: FLOW PROCESSING */}
      <div className="section-header">Flow Processing</div>
      <div className="card-grid">
        <MetricCard title="Flows Created" value={m?.flows_created} />
        <MetricCard title="Flows Active" value={m?.flows_active} />
        <MetricCard title="Flows Completed" value={m?.flows_completed} />
        <MetricCard title="Flows Evicted" value={m?.flows_evicted} />
      </div>

      {/* Metrics Section: DETECTION */}
      <div className="section-header">Detection</div>
      <div className="card-grid">
        <MetricCard title="Features Generated" value={m?.features_generated} />
        <MetricCard title="Detections Generated" value={m?.detections_generated} />
      </div>

      {/* Metrics Section: PERSISTENCE */}
      <div className="section-header">Persistence</div>
      <div className="card-grid">
        <MetricCard title="Events Persisted" value={m?.events_persisted} />
        <MetricCard title="WS Deliveries" value={m?.events_delivered} />
        <MetricCard title="Delivery Copies Dropped" value={m?.events_dropped} warn />
        <MetricCard title="Persistence Errors" value={m?.persistence_errors} warn />
        <MetricCard title="Processing Errors" value={m?.processing_errors} warn />
        <MetricCard title="Source Errors" value={m?.source_errors} warn />
        <MetricCard title="Output Errors" value={m?.output_errors} warn />
      </div>

      {/* Metrics Section: QUEUES */}
      <div className="section-header">Queues</div>
      <div className="card-grid">
        <MetricCard title="Capture Queue" value={m?.capture_queue_depth} />
        <MetricCard title="Detection Queue" value={m?.detection_queue_depth} />
        <MetricCard title="Capture Errors" value={m?.capture_errors} warn />
      </div>

      <div className="section-header">Storage &amp; delivery health</div>
      <div className="card-grid">
        <MetricCard title="Retention Errors" value={m?.retention_failures} warn />
        <MetricCard title="Events Removed" value={m?.retention_events_removed} />
        <MetricCard title="Orphan Flows Removed" value={m?.retention_flows_removed} />
        <MetricCard title="Database Bytes" value={m?.database_bytes ?? undefined} />
        <MetricCard title="WAL Bytes" value={m?.wal_bytes ?? undefined} />
        <MetricCard title="Subscriber Queue Peak" value={m?.subscriber_queue_peak} />
        <MetricCard title="Subscriber Rejections" value={m?.subscriber_rejections} warn />
      </div>
      <p className="page-description">Last successful cleanup: {m?.retention_last_success ? new Date(m.retention_last_success * 1000).toLocaleString() : 'Unavailable'}. Cleanup duration: {m?.retention_duration_sec == null ? 'Unavailable' : `${m.retention_duration_sec.toFixed(3)} s`}. Deleting rows does not necessarily shrink database or WAL files.</p>
      <p className="page-description">Kernel capture drops: {m?.kernel_capture_drops == null ? 'Unavailable from capture backend' : formatNumber(m.kernel_capture_drops)}. Packets dropped counts application capture-queue saturation; delivery drops count subscriber copies.</p>
      <p className="page-description">v2.0.0 limitation: continuously active tuples retain growing exact timestamp and packet-size histories. Per-flow memory is not strictly bounded.</p>

      <div className="section-header">Streaming intelligence</div>
      <div className="card-grid">
        <MetricCard title="Intelligence Keys" value={m?.intelligence_keys} />
        <MetricCard title="Intelligence Key Peak" value={m?.intelligence_keys_peak} />
        <MetricCard title="Intelligence Evictions" value={m?.intelligence_evictions} warn />
        <MetricCard title="Behavioral Signals" value={m?.intelligence_evidence_generated} />
        <MetricCard title="Intelligence Errors" value={m?.intelligence_processing_errors} warn />
        <MetricCard title="Membership Overflows" value={m?.intelligence_member_overflows} warn />
        <MetricCard title="Late Observations" value={m?.intelligence_late_observations} />
      </div>
      {/* System Info */}
      <div className="section-header">System Information</div>
      <div className="card">
        <div className="detail-grid">
          <span className="detail-label">Feature Schema Version</span>
          <span className="detail-value">{status?.feature_schema_version ?? '—'}</span>

          <span className="detail-label">Feature Count</span>
          <span className="detail-value">{status?.feature_count ?? '—'}</span>

          <span className="detail-label">WebSocket Subscribers</span>
          <span className="detail-value">{status?.websocket_subscribers ?? 0}</span>
        </div>
      </div>
    </div>
  );
}

function MetricCard({ title, value, warn = false }: { title: string; value?: number; warn?: boolean }) {
  const v = value;
  const isNonZeroWarn = warn && v !== undefined && v > 0;

  return (
    <div className="sensor-metric">
      <div className="card__title">{title}</div>
      <div className="card__value" style={isNonZeroWarn ? { color: 'var(--accent-warning, #f59e0b)' } : undefined}>
        {formatNumber(v)}
      </div>
    </div>
  );
}
