/**
 * FlowDetail — Single flow investigation view.
 *
 * READ-ONLY. No raw payload display. No active network controls.
 */

import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useAppContext } from '@/hooks/useAppContext';
import type { Flow } from '@/api/types';
import { formatTimestamp, formatDuration, formatBytes, formatNumber, protocolName } from '@/utils/format';

export function FlowDetail() {
  const { flowId } = useParams<{ flowId: string }>();
  const navigate = useNavigate();
  const { api } = useAppContext();

  const [flow, setFlow] = useState<Flow | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchFlow = useCallback(async () => {
    if (!api || !flowId) return;
    try {
      setLoading(true);
      const data = await api.getFlow(flowId);
      setFlow(data);
      setError(null);
    } catch {
      setError('Flow not found');
    } finally {
      setLoading(false);
    }
  }, [api, flowId]);

  useEffect(() => { fetchFlow(); }, [fetchFlow]);

  if (loading) {
    return <div className="state-message" role="status"><div className="state-message__title">Loading…</div></div>;
  }

  if (error || !flow) {
    return (
      <div className="state-message">
        <div className="state-message__title">Flow Not Found</div>
        <button className="btn btn--secondary" onClick={() => navigate('/flows')} style={{ marginTop: 'var(--space-4)' }}>
          ← Back to Flows
        </button>
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Flow Detail</h1>
        <button className="btn btn--secondary" onClick={() => navigate('/flows')}>
          ← Back to Flows
        </button>
      </div>

      <div className="card detail-section">
        <div className="detail-section__title">Flow Information</div>
        <div className="detail-grid">
          <span className="detail-label">Flow Key</span>
          <span className="detail-value">{flow.flow_key}</span>

          <span className="detail-label">Flow ID</span>
          <span className="detail-value">{flow.id}</span>

          <span className="detail-label">Source IP</span>
          <span className="detail-value">{flow.src_ip}</span>

          <span className="detail-label">Source Port</span>
          <span className="detail-value">{flow.src_port ?? '—'}</span>

          <span className="detail-label">Destination IP</span>
          <span className="detail-value">{flow.dst_ip}</span>

          <span className="detail-label">Destination Port</span>
          <span className="detail-value">{flow.dst_port ?? '—'}</span>

          <span className="detail-label">Protocol</span>
          <span className="detail-value">{protocolName(flow.protocol)} ({flow.protocol})</span>

          <span className="detail-label">Direction</span>
          <span className="detail-value">{flow.direction}</span>

          <span className="detail-label">Start Time</span>
          <span className="detail-value">{formatTimestamp(flow.start_time)}</span>

          <span className="detail-label">End Time</span>
          <span className="detail-value">{formatTimestamp(flow.end_time)}</span>

          <span className="detail-label">Duration</span>
          <span className="detail-value">{formatDuration(flow.duration_sec)}</span>

          <span className="detail-label">Packet Count</span>
          <span className="detail-value">{formatNumber(flow.packet_count)}</span>

          <span className="detail-label">Byte Count</span>
          <span className="detail-value">{formatBytes(flow.byte_count)}</span>

          <span className="detail-label">Payload Bytes</span>
          <span className="detail-value">{formatBytes(flow.payload_byte_count)}</span>
        </div>
      </div>

      <div style={{ marginTop: 'var(--space-4)' }}>
        <Link to={`/detections?flow_id=${flow.id}`} className="btn btn--secondary">
          View Related Detections →
        </Link>
      </div>
    </div>
  );
}
