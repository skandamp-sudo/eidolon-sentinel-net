import { useEffect, useState } from 'react';
import { useAppContext } from '@/hooks/useAppContext';
import type { Assurance } from '@/api/types';

export function AssurancePanel() {
  const { api, wsState } = useAppContext();
  const [data, setData] = useState<Assurance | null>(null);
  useEffect(() => {
    let active = true; let pending = false;
    setData(null);
    const refresh = async () => {
      if (!api || pending) return;
      pending = true;
      try { const value = await api.getAssurance(); if (active) setData(value); }
      catch { if (active) setData(null); }
      finally { pending = false; }
    };
    refresh(); const timer = setInterval(refresh, 10000);
    return () => { active = false; clearInterval(timer); };
  }, [api]);
  const s = data?.science;
  const pct = (v?: number) => v == null ? 'UNAVAILABLE' : `${(v * 100).toFixed(3)}%`;
  return <section className="card assurance-panel" aria-label="System readiness and assurance">
    <h2>System readiness &amp; assurance</h2>
    <p>Current operational state and explicit validation limits.</p>
    <p>WebSocket — {wsState.toUpperCase()} (this browser connection)</p>
    {!data ? <p role="status">Assurance UNAVAILABLE — no current API snapshot.</p> : <>
      <dl className="assurance-rows">{data.rows.map(row => <div key={row.property}>
        <dt>{row.property}</dt><dd><strong>{row.status}</strong><br />{row.detail}</dd>
      </div>)}</dl>
      <p>Feature schema: {data.feature_schema_version}</p>
      <p>Loaded model: {data.model_identity ? `${data.model_identity.model_name} / ${data.model_identity.model_version}` : 'UNAVAILABLE'}</p>
      <p className="detail-value">Manifest SHA-256: {data.model_identity?.manifest_sha256 ?? 'UNAVAILABLE'}</p>
      <h3>Scientific evaluation — {s?.status ?? 'UNAVAILABLE'}</h3>
      {s?.status === 'MEASURED' && <>
        <p>{s.evaluation} · {s.test_rows?.toLocaleString()} TEST rows</p>
        <dl className="assurance-rows">
          <div><dt>XGBoost accuracy</dt><dd>{pct(s.accuracy)}</dd></div>
          <div><dt>XGBoost macro-F1</dt><dd>{s.macro_f1?.toFixed(4) ?? 'UNAVAILABLE'}</dd></div>
          <div><dt>Benign → malicious false positives</dt><dd>{pct(s.benign_to_malicious_fpr)}</dd></div>
          <div><dt>C2 recall</dt><dd>{pct(s.c2_recall)}</dd></div>
          <div><dt>DDoS recall</dt><dd>{pct(s.ddos_recall)}</dd></div>
          <div><dt>Isolation Forest ROC-AUC</dt><dd>{s.iforest_roc_auc?.toFixed(3) ?? 'UNAVAILABLE'}</dd></div>
        </dl>
        <p>{s.candidate_status}</p>
        <ul>{s.limitations?.map(text => <li key={text}>{text}</li>)}</ul>
      </>}
    </>}
  </section>;
}
