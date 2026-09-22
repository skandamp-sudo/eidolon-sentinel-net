import { EncryptedSession } from '@/components/EncryptedSession';
/**
 * Detection Detail — Single detection investigation view.
 *
 * Displays the complete backend explanation chain:
 * DetectionEvent → Evidence → Rationale → ATT&CK Mapping → Limitations
 *
 * SECURITY: All data from backend API. No ML inference or ATT&CK mapping in frontend.
 * No dangerouslySetInnerHTML. Backend text rendered as text nodes only.
 */

import '@/styles/investigation.css';
import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useAppContext } from '@/hooks/useAppContext';
import type { DetectionEvent, EvidenceItem, EvidenceCollection, ATTACKMapping } from '@/api/types';
import { formatTimestamp, formatScore } from '@/utils/format';

function SeverityDot({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: 'var(--severity-critical)', high: 'var(--severity-high)',
    medium: 'var(--severity-medium)', low: 'var(--severity-low)',
    info: 'var(--severity-info)',
  };
  return <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: colors[severity] ?? 'var(--text-muted)', marginRight: 6 }} />;
}

export function DetectionDetail() {
  const { eventId } = useParams<{ eventId: string }>();
  const navigate = useNavigate();
  const { api } = useAppContext();

  const [event, setEvent] = useState<DetectionEvent | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchEvent = useCallback(async () => {
    if (!api || !eventId) return;
    try {
      setLoading(true);
      const data = await api.getEvent(eventId);
      setEvent(data);
      setError(null);
    } catch {
      setError('Unable to load this detection. It may be unavailable, or the API connection failed.');
    } finally {
      setLoading(false);
    }
  }, [api, eventId]);

  useEffect(() => { fetchEvent(); }, [fetchEvent]);

  if (loading) {
    return <div className="state-message" role="status"><div className="state-message__title">Loading…</div></div>;
  }

  if (error || !event) {
    return (
      <div className="state-message">
        <div className="state-message__title">Detection Unavailable</div>
        <div className="state-message__text">{error ?? 'The requested detection event does not exist.'}</div>
        <button className="btn btn--secondary" onClick={() => navigate('/detections')} style={{ marginTop: 'var(--space-4)' }}>
          ← Back to Detections
        </button>
      </div>
    );
  }

  // Extract explanation data from metadata (enriched by backend)
  const meta = event.metadata ?? {};
  const explanation = meta['explanation'] as Record<string, unknown> | undefined;
  const classifierEvidence = (explanation?.['classifier_evidence'] ?? meta['classifier_evidence']) as EvidenceCollection | undefined;
  const anomalyEvidence = (explanation?.['anomaly_evidence'] ?? meta['anomaly_evidence']) as EvidenceCollection | undefined;
  const attackMappings = (explanation?.['attack_mappings'] ?? meta['attack_mappings'] ?? []) as ATTACKMapping[];
  const explanationRationale = (explanation?.['rationale'] ?? '') as string;

  // Collect all evidence items
  const allEvidence: EvidenceItem[] = event.evidence?.items ?? [
    ...(classifierEvidence?.items ?? []),
    ...(anomalyEvidence?.items ?? []),
  ].sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution));

  const maxContribution = allEvidence.length > 0
    ? Math.max(...allEvidence.map(e => Math.abs(e.contribution)), 0.01)
    : 1;

  return (
    <article className="investigation">
      <div className="page-header">
        <div><p className="eyebrow">Detection investigation</p><h1 className="page-title">{event.threat_type === "ddos" ? "DDoS" : event.threat_type?.replaceAll("_", " ") ?? "Unclassified detection"}</h1><p className="page-description">Model assessment and the evidence behind it.</p></div>
        <button className="btn btn--secondary" onClick={() => navigate('/detections')}>
          ← Back to Detections
        </button>
      </div>

      <div className="investigation-status" aria-label="Detection summary">
        <span className={`badge badge--${event.severity}`}>{event.severity} severity</span>
        <span>{event.source_mode === 'REPLAY' ? 'RECORDED TRAFFIC REPLAY' : event.source_mode === 'LIVE' ? 'LIVE PASSIVE SENSOR' : 'TRAFFIC SOURCE NOT RECORDED'}</span>
        <span>{formatTimestamp(event.timestamp)}</span>
      </div>
      {/* ─── THREAT ASSESSMENT ──────────────────────── */}
      <div className="card detail-section">
        <h2 className="detail-section__title">THREAT ASSESSMENT</h2>
        <div className="detail-grid">
          <span className="detail-label">Threat Type</span>
          <span><span className="badge badge--threat">{event.threat_type}</span></span>

          <span className="detail-label">Severity</span>
          <span>
            <span style={{ color: 'var(--text-primary)', textTransform: 'uppercase', fontSize: 'var(--font-size-sm)', fontWeight: 600, display: 'flex', alignItems: 'center' }}>
              <SeverityDot severity={event.severity} /> {event.severity}
            </span>
          </span>

          <span className="detail-label">Anomaly Score</span>
          <span className="detail-value">{formatScore(event.anomaly_score)} (normalized)</span>

          <span className="detail-label">Classification Score</span>
          <span className="detail-value">{formatScore(event.classification_score ?? null)} (uncalibrated)</span>

          <span className="detail-label">Detection Source</span>
          <span className="detail-value">{event.detection_source?.join(', ') || '—'}</span>

          <span className="detail-label">Traffic Source</span>
          <span className="detail-value">{event.source_mode ?? 'Not recorded'}</span>

          {event.capture_interface && <><span className="detail-label">Capture Interface</span><span className="detail-value">{event.capture_interface}</span></>}
          {event.replay_file_identifier && <><span className="detail-label">Replay Identifier</span><span className="detail-value">{event.replay_file_identifier}</span></>}

          <span className="detail-label">Timestamp</span>
          <span className="detail-value">{formatTimestamp(event.timestamp)}</span>

          <span className="detail-label">Event ID</span>
          <span className="detail-value">{event.id}</span>
        </div>
      </div>

      {/* ─── MODEL PROVENANCE ───────────────────────── */}
      <div className="card detail-section">
        <h2 className="detail-section__title">MODEL PROVENANCE</h2>
        <div className="detail-grid">
          <span className="detail-label">Approved Model</span>
          <span className="detail-value">{event.model_name && event.deployment_model_version ? `${event.model_name} / ${event.deployment_model_version}` : 'Not recorded for this event'}</span>
          <span className="detail-label">Classifier Version</span>
          <span className="detail-value">{event.model_version ?? '—'}</span>

          <span className="detail-label">Feature Schema</span>
          <span className="detail-value">{event.feature_schema_version ?? '—'}</span>

          <span className="detail-label">Explanation Version</span>
          <span className="detail-value">{event.explanation_version ?? '—'}</span>
        </div>
      </div>

      {/* ─── FLOW CONTEXT ───────────────────────────── */}
      <div className="card detail-section">
        <h2 className="detail-section__title">FLOW CONTEXT</h2>
        <div className="detail-grid">
          <span className="detail-label">Flow ID</span>
          <span className="detail-value">
            {event.flow_id ? (
              <Link to={`/flows/${event.flow_id}`}>{event.flow_id}</Link>
            ) : '—'}
          </span>

          <span className="detail-label">Source IP</span>
          <span className="detail-value">{event.src_ip ?? '—'}{event.src_port != null ? `:${event.src_port}` : ''}</span>

          <span className="detail-label">Destination IP</span>
          <span className="detail-value">{event.dst_ip ?? '—'}{event.dst_port != null ? `:${event.dst_port}` : ''}</span>
        </div>
      </div>

      {/* ─── MODEL EVIDENCE ─────────────────────────── */}
      {allEvidence.length > 0 && (
        <div className="card detail-section">
          <h2 className="detail-section__title">MODEL EVIDENCE</h2>
          <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', marginBottom: 'var(--space-3)' }}>
            Model contributions and statistical deviations are distinct evidence types. Statistical deviations do not establish model causality or operational risk. Values use standardized model inputs when indicated by the explanation metadata.
          </div>
          <div className="data-table-container" role="region" aria-label="Model evidence table" tabIndex={0}><table className="data-table">
            <thead>
              <tr>
                <th>Feature</th>
                <th>Observed</th>
                <th>Reference</th>
                <th>Contribution</th>
                <th>Direction</th>
                <th>Type</th>
              </tr>
            </thead>
            <tbody>
              {allEvidence.map((item, idx) => {
                const barWidth = Math.min((Math.abs(item.contribution) / maxContribution) * 100, 100);
                const isPositive = item.direction === 'increase';

                return (
                  <tr key={idx}>
                    <td className="mono">{item.feature_name}</td>
                    <td className="mono">{item.observed_value.toFixed(4)}</td>
                    <td className="mono">{item.reference_value !== null ? item.reference_value.toFixed(4) : '—'}</td>
                    <td>
                      <div className="evidence-bar">
                        <div className="evidence-bar__track">
                          <div
                            className={`evidence-bar__fill ${isPositive ? 'evidence-bar__fill--positive' : 'evidence-bar__fill--negative'}`}
                            style={{ width: `${barWidth}%` }}
                          />
                        </div>
                        <span className="evidence-bar__value">
                          {item.contribution >= 0 ? '+' : ''}{item.contribution.toFixed(4)}
                        </span>
                      </div>
                    </td>
                    <td>
                      <span className="badge" style={{ background: isPositive ? 'rgba(239,68,68,0.1)' : 'rgba(59,130,246,0.1)', color: isPositive ? 'var(--severity-critical)' : 'var(--accent-primary)' }}>
                        {item.direction === 'increase' ? '↑ INCREASE' : '↓ DECREASE'}
                      </span>
                    </td>
                    <td>
                      <span className="badge" style={{ background: 'rgba(99,102,241,0.1)', color: 'var(--accent-secondary)' }}>
                        {item.evidence_type}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table></div>
        </div>
      )}

      {/* Evidence unavailable notice */}
      {allEvidence.length === 0 && (
        <div className="card detail-section">
          <h2 className="detail-section__title">MODEL EVIDENCE</h2>
          <div className="state-message">
            <div className="state-message__title">{event.evidence?.explanation_available ? 'No Significant Evidence' : 'Evidence Unavailable'}</div>
            <div className="state-message__text">
              {event.evidence?.explanation_available ? 'The available explanation found no significant feature deviations or contributions.' : (event.evidence?.unavailable_reason ?? classifierEvidence?.unavailable_reason ?? anomalyEvidence?.unavailable_reason ?? 'No structured evidence data available for this detection.')}
            </div>
          </div>
        </div>
      )}

      <div className="card detail-section">
        <h2 className="detail-section__title">BEHAVIORAL EVIDENCE</h2>
        <p className="page-description">Passive streaming heuristics are contextual observations, not attack confirmations or probabilities. ML scores and severity remain separate.</p>
        {event.behavioral_policy?.action && <p>Operational policy: {event.behavioral_policy.action.replaceAll('_', ' ')}{event.behavioral_policy.behavioral_alert ? ' · Behavioral review requested' : ''}</p>}
        {event.behavioral_evidence?.length ? <div className="data-table-container" role="region" aria-label="Behavioral evidence table" tabIndex={0}>
          <table className="data-table"><thead><tr><th>Signal / source</th><th>Observed</th><th>Window</th><th>Policy threshold</th><th>Supporting context</th></tr></thead>
          <tbody>{event.behavioral_evidence.map((signal, index) => <tr key={index}>
            <td>{signal.signal_type}<br /><small>{signal.detector}</small></td>
            <td>{signal.observed_value.toLocaleString(undefined, { maximumFractionDigits: 4 })} {signal.unit}</td>
            <td>{signal.observation_window.duration_sec} s<br /><small>{formatTimestamp(signal.observation_window.start)} — {formatTimestamp(signal.observation_window.end)}<br />Capture event time; latest bucket may be partial</small></td>
            <td>{signal.comparison} {signal.reference_threshold}</td>
            <td><details><summary>Context and limitations</summary><dl>{Object.entries(signal.supporting_context).map(([key, value]) => <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{typeof value === 'object' ? JSON.stringify(value) : String(value)}</dd></div>)}</dl><p>{signal.interpretation}</p><p>{signal.confidence_semantics}</p></details></td>
          </tr>)}</tbody></table>
        </div> : <p className="page-description">{event.behavioral_evidence_status === 'unavailable_processing_error' ? 'Streaming evidence unavailable due to an operational processing error.' : event.behavioral_evidence_status === 'available' ? 'No streaming signals were emitted for the retained observations.' : event.behavioral_evidence_status === 'disabled' ? 'Streaming intelligence was disabled for this event.' : 'Behavioral evidence was not recorded for this event.'}</p>}
        {event.behavioral_attack_context?.map((mapping, index) => <p key={index}>{mapping.technique_id} · {mapping.technique_name} — {mapping.qualification}: {mapping.rationale}</p>)}
      </div>

      <div className="card detail-section">
        <h2 className="detail-section__title">DNS OBSERVATION</h2>
        <p className="page-description">Passive DNS metadata and derived heuristics are contextual evidence, not attack probabilities. CDN, cloud services, telemetry and security records can produce similar patterns.</p>
        <p>Parser status: {event.dns_status ?? 'not_recorded'}</p>
        {event.dns_observation?.message ? <>
          <p>Visibility: {event.dns_observation.visibility.replaceAll('_', ' ')} · Contextual evidence</p>
          <p>{event.dns_observation.message.reason}</p>
          <div className="data-table-container" role="region" aria-label="DNS observations table" tabIndex={0}>
            <table className="data-table"><thead><tr><th>MEASURED · Domain / QTYPE</th><th>DERIVED · Length</th><th>DERIVED · Entropy</th></tr></thead>
            <tbody>{event.dns_observation.message.questions?.map((question, i) => <tr key={i}>
              <td style={{ overflowWrap: 'anywhere', maxWidth: '28rem' }}>{question.name || '(root)'}<br />{question.qtype_name} ({question.qtype}) · Class {question.qclass}</td>
              <td>{event.dns_observation?.lexical?.[i] ? <>QNAME: {event.dns_observation.lexical[i].qname_length} characters<br />Longest label: {event.dns_observation.lexical[i].longest_label}</> : 'UNAVAILABLE'}</td>
              <td>{event.dns_observation?.lexical?.[i] ? <>{event.dns_observation.lexical[i].character_entropy.toFixed(3)} bits/character<br /><small>Lowercase name; dots excluded · {event.dns_observation.lexical[i].sample_characters} characters</small></> : 'UNAVAILABLE'}</td>
            </tr>)}</tbody></table>
          </div>
          <p>MEASURED · {event.dns_observation.message.message_length ?? 'UNAVAILABLE'} message bytes · Response code: {event.dns_observation.message.qr ? event.dns_observation.message.rcode : 'UNAVAILABLE — query observation'}</p>
          <p>MEASURED · Response record types: {event.dns_observation.message.qr ? event.dns_observation.message.response_record_types?.join(', ') || 'None observed' : 'UNAVAILABLE'}</p>
          {event.dns_observation.observation_window && <p>Window: {event.dns_observation.observation_window.duration_sec} s · Capture event time; latest bucket may be partial</p>}
          <p>{event.dns_observation.retention}. {event.dns_observation.parent_semantics}.</p>
          <p>Missing responses are unobserved, not inferred failures.</p>
          <details><summary>DERIVED · Bounded window measurements</summary>
            {[['Source', event.dns_observation.source_window], ['Server', event.dns_observation.server_window], ['Parent proxy', event.dns_observation.parent_window]].map(([label, value]) => <div key={String(label)}><h3>{String(label)}</h3><dl>{value && typeof value === 'object' ? Object.entries(value).map(([key, item]) => <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{item === null ? 'UNAVAILABLE' : typeof item === 'object' ? JSON.stringify(item) : String(item)}</dd></div>) : 'UNAVAILABLE'}</dl></div>)}
          </details>
        </> : <p className="page-description">{event.dns_status === 'disabled' ? 'DNS intelligence was disabled for this event.' : event.dns_status === 'unavailable_processing_error' ? 'DNS evidence unavailable due to an operational processing error.' : event.dns_status === 'unavailable_or_not_observed' ? 'UNAVAILABLE — no retained observable DNS metadata for this flow. Encrypted DNS cannot be identified or decoded here.' : 'DNS metadata was not recorded for this event.'}</p>}
        {event.dns_evidence?.length ? <div className="data-table-container" role="region" aria-label="DNS evidence table" tabIndex={0}>
          <table className="data-table"><thead><tr><th>DERIVED · Contextual signal</th><th>Observed / reference</th><th>Scope and limits</th></tr></thead><tbody>{event.dns_evidence.map((signal, i) => <tr key={i}>
            <td>{signal.signal_type}</td><td>{signal.observed_value.toLocaleString(undefined, { maximumFractionDigits: 4 })} {signal.unit}<br />Reference: {signal.comparison} {signal.reference_threshold}</td>
            <td><details><summary>Supporting observations</summary><dl>{Object.entries(signal.supporting_context).map(([key, value]) => <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd style={{ overflowWrap: 'anywhere' }}>{typeof value === 'object' ? JSON.stringify(value) : String(value)}</dd></div>)}</dl><p>{signal.confidence_semantics}</p><p>{signal.interpretation}</p></details></td>
          </tr>)}</tbody></table>
        </div> : <p>No DNS heuristic signals were recorded.</p>}
        {event.dns_attack_context?.map((mapping, i) => <p key={i}>{mapping.technique_id} · {mapping.technique_name} — {mapping.qualification}: {mapping.rationale}</p>)}
      </div>

      <EncryptedSession event={event} />

      {/* ─── RATIONALE ──────────────────────────────── */}
      <div className="card detail-section">
        <h2 className="detail-section__title">RATIONALE</h2>
        {(explanationRationale || event.rationale) ? (
          <div className="rationale-block">
            {explanationRationale || event.rationale}
          </div>
        ) : (
          <div className="state-message">
            <div className="state-message__text">No rationale provided for this detection.</div>
          </div>
        )}
      </div>

      {/* ─── ATT&CK MAPPING ─────────────────────────── */}
      <div className="card detail-section">
        <h2 className="detail-section__title">ATT&CK CONTEXTUAL MAPPING</h2>
        <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-muted)', marginBottom: 'var(--space-3)' }}>
          ATT&CK mappings are generated by the backend intelligence engine based on the ML classification.
          These are potential mappings, not confirmed techniques.
        </div>
        {attackMappings.length > 0 ? (
          attackMappings.map((mapping, idx) => {
            const qualClass = mapping.qualification === 'likely'
              ? 'attack-card__qualification--likely'
              : mapping.qualification === 'observed indicators consistent with'
                ? 'attack-card__qualification--observed'
                : 'attack-card__qualification--possible';

            return (
              <div key={idx} className="attack-card">
                <div className="attack-card__header">
                  <span className="attack-card__id">{mapping.technique_id}</span>
                  <span className="attack-card__name">{mapping.technique_name}</span>
                </div>
                <div className="attack-card__tactic">Tactic: {mapping.tactic}</div>
                <div className="attack-card__rationale">{mapping.rationale}</div>
                <span className={`attack-card__qualification ${qualClass}`}>
                  {mapping.qualification.toUpperCase()}
                </span>
              </div>
            );
          })
        ) : (
          <div className="state-message">
            <div className="state-message__text">No ATT&CK mappings available for this detection.</div>
          </div>
        )}
      </div>

      {/* ─── LIMITATIONS ────────────────────────────── */}
      <div className="card detail-section">
        <h2 className="detail-section__title">LIMITATIONS</h2>
        <div style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)', lineHeight: 1.7 }}>
          Classification is based on observable network metadata only.
          Encrypted payload contents are not inspected.
          This is a model classification, not a confirmed attack.
          Model confidence values represent classifier output scores, not calibrated probabilities.
        </div>
      </div>
    </article>
  );
}
