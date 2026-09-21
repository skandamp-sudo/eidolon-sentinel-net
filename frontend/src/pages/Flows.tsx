/**
 * Flows page — Network flow investigation table.
 *
 * All data from backend REST API. No raw payload display.
 */

import { useEffect, useState, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAppContext } from '@/hooks/useAppContext';
import type { Flow } from '@/api/types';
import { formatDuration, formatBytes, protocolName, formatNumber } from '@/utils/format';

const LIMIT = 50;

function DirectionIcon({ direction }: { direction: string }) {
  if (direction.toLowerCase() === 'inbound') {
    return <span style={{ color: 'var(--severity-info)' }}>↓ IN</span>;
  }
  if (direction.toLowerCase() === 'outbound') {
    return <span style={{ color: 'var(--severity-medium)' }}>↑ OUT</span>;
  }
  return <span style={{ color: 'var(--text-muted)' }}>⟷ INT</span>;
}

export function Flows() {
  const { api } = useAppContext();
  const navigate = useNavigate();

  const [flows, setFlows] = useState<Flow[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchFlows = useCallback(async () => {
    if (!api) return;
    setLoading(true);
    try {
      const res = await api.getFlows({ limit: LIMIT, offset });
      setFlows(res.flows ?? []);
      setTotal(res.total ?? 0);
      setError(null);
    } catch {
      setError('Failed to load flows');
      setFlows([]);
    } finally {
      setLoading(false);
    }
  }, [api, offset]);

  useEffect(() => { fetchFlows(); }, [fetchFlows]);

  if (loading) {
    return <div className="state-message" role="status"><div className="state-message__title">Loading…</div></div>;
  }

  if (error) {
    return (
      <div className="state-message">
        <div className="state-message__title">Error</div>
        <div className="state-message__text">{error}</div>
      </div>
    );
  }

  const showStart = total > 0 ? offset + 1 : 0;
  const showEnd = Math.min(offset + LIMIT, total);

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">
          NETWORK FLOWS <span className="badge" style={{ marginLeft: '12px', fontSize: 'var(--font-size-sm)', verticalAlign: 'middle' }}>{formatNumber(total)} Total</span>
        </h1>
      </div>

      {flows.length === 0 ? (
        <div className="state-message">
          <div className="state-message__title">No Flows</div>
          <div className="state-message__text">No network flows recorded yet.</div>
        </div>
      ) : (
        <div className="card">
          <div className="data-table-container" role="region" aria-label="Results table" tabIndex={0}><table className="data-table">
            <thead>
              <tr>
                <th>SOURCE</th>
                <th>DESTINATION</th>
                <th>PROTOCOL</th>
                <th>DURATION</th>
                <th>PACKETS</th>
                <th>BYTES</th>
                <th>DIRECTION</th>
              </tr>
            </thead>
            <tbody>
              {flows.map(f => (
                <tr key={f.id} className="clickable" onClick={() => navigate(`/flows/${f.id}`)}>
                  <td className="mono" style={{ lineHeight: '1.2' }}>
                    <div><Link to={`/flows/${f.id}`}>{f.src_ip}</Link></div>
                    <div style={{ color: 'var(--text-muted)', fontSize: 'var(--font-size-xs)' }}>
                      {f.src_port !== null ? `:${f.src_port}` : ''}
                    </div>
                  </td>
                  <td className="mono" style={{ lineHeight: '1.2' }}>
                    <div>{f.dst_ip}</div>
                    <div style={{ color: 'var(--text-muted)', fontSize: 'var(--font-size-xs)' }}>
                      {f.dst_port !== null ? `:${f.dst_port}` : ''}
                    </div>
                  </td>
                  <td><span className="badge">{protocolName(f.protocol)}</span></td>
                  <td className="mono">{formatDuration(f.duration_sec)}</td>
                  <td className="mono">{formatNumber(f.packet_count)}</td>
                  <td className="mono">{formatBytes(f.byte_count)}</td>
                  <td className="mono" style={{ fontSize: 'var(--font-size-xs)', fontWeight: 'bold' }}>
                    <DirectionIcon direction={f.direction} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>

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
