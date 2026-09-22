import type { DetectionEvent } from '@/api/types';

function version(value: number): string {
  const names: Record<number, string> = { 768: 'SSL 3.0', 769: 'TLS 1.0', 770: 'TLS 1.1', 771: 'TLS 1.2', 772: 'TLS 1.3' };
  return names[value] ?? `0x${value.toString(16).padStart(4, '0')}`;
}

export function EncryptedSession({ event }: { event: DetectionEvent }) {
  const entries = [
    { name: 'TLS', status: event.tls_status, observation: event.tls_observation, evidence: event.tls_evidence },
    { name: 'QUIC', status: event.quic_status, observation: event.quic_observation, evidence: event.quic_evidence },
  ];
  return <section className="card detail-section" aria-label="Encrypted session metadata">
    <h2 className="detail-section__title">ENCRYPTED SESSION</h2>
    <p className="page-description">Contextual metadata only. No TLS or QUIC application payload is decrypted or inspected. Fingerprints identify observed handshake profiles; they do not establish malware, C2 or compromise.</p>
    {entries.map(({ name, status, observation, evidence }) => <div key={name}>
      <h3>{name} metadata</h3><p>{name} status: {status ?? 'not_recorded'}</p>
      {!observation?.directions?.length ? <p>{status === 'disabled' ? `${name} metadata collection was disabled.` : status === 'unavailable_processing_error' ? `${name} metadata unavailable due to an operational processing error.` : status === 'not_recorded' || status === undefined ? `${name} metadata was not recorded for this event.` : `UNAVAILABLE — no retained ${name} observation for this flow.`}</p> : <>
        <p>{name} visibility: {observation.visibility.replaceAll('_', ' ')}</p>
        {observation.directions.map((direction, i) => <div key={i} style={{ overflowWrap: 'anywhere' }}>
          <p>MEASURED · {direction.source_ip}:{direction.source_port} · {direction.status}</p>
          {direction.reason && <p>{direction.reason}</p>}
          {direction.latest_packet_status && <p>Latest packet: {direction.latest_packet_status} · Earlier visible long-header metadata retained. {direction.latest_packet_reason}</p>}
          {direction.hello && <>
            <p>MEASURED · {direction.hello.handshake_type === 1 ? 'ClientHello' : 'ServerHello'} · Legacy hello field: {version(direction.hello.legacy_version)}</p>
            <p>MEASURED · Versions {direction.hello.handshake_type === 1 ? 'offered' : 'selected'}: {direction.hello.supported_versions.length ? direction.hello.supported_versions.map(version).join(', ') : direction.hello.selected_version !== null ? version(direction.hello.selected_version) : 'UNAVAILABLE — supported_versions extension not observed'}</p>
            <p>MEASURED · Visible SNI: {direction.hello.sni ?? 'UNAVAILABLE'}<br /><small>Normalized lowercase ASCII · {direction.hello.sni_status.replaceAll('_', ' ')}</small></p>
            <p>MEASURED · ALPN: {direction.hello.alpn.length ? direction.hello.alpn.map(v => `${v.value}${v.encoding === 'hex' ? ' (hex)' : ''}`).join(', ') : 'UNAVAILABLE'}</p>
            <p>MEASURED · {direction.hello.cipher_suites.length} cipher suites · {direction.hello.extension_ids.length} extensions</p>
            <p>DERIVED · {direction.hello.fingerprint.family}: <code>{direction.hello.fingerprint.digest}</code></p>
            <details><summary>Fingerprint canonical input and visible profiles</summary>
              <p>{direction.hello.fingerprint.canonical}</p><p>Ciphers: {direction.hello.cipher_suites.join(', ')}</p>
              <p>Extensions: {direction.hello.extension_ids.join(', ')}</p><p>Groups: {direction.hello.supported_groups.join(', ') || 'UNAVAILABLE'}</p>
              <p>Signature algorithms: {direction.hello.signature_algorithms.join(', ') || 'UNAVAILABLE'}</p><p>{direction.hello.fingerprint.semantics}</p>
            </details>
          </>}
          {name === 'QUIC' && <>
            <p>MEASURED · Version: {direction.version_hex ?? 'UNAVAILABLE'} · Header: {direction.packet_type ?? 'UNAVAILABLE'}</p>
            <p>MEASURED · Destination CID length: {direction.destination_cid_length ?? 'UNAVAILABLE'} · Source CID length: {direction.source_cid_length ?? 'UNAVAILABLE'}</p>
            <p>DERIVED · Destination CID SHA-256: {direction.destination_cid_sha256 ?? 'UNAVAILABLE / empty CID'}</p>
            <p>DERIVED · Source CID SHA-256: {direction.source_cid_sha256 ?? 'UNAVAILABLE / empty CID'}</p>
            <p>MEASURED · Token length: {direction.token_length ?? 'UNAVAILABLE'} · Declared protected length: {direction.declared_packet_length ?? 'UNAVAILABLE'}</p>
            {direction.supported_versions && <p>MEASURED · Version negotiation: {direction.supported_versions.map(v => `0x${v.toString(16).padStart(8, '0')}`).join(', ')} · Not authenticated</p>}
            <p>Encrypted QUIC payload: Not inspected</p>
          </>}
        </div>)}
        <details><summary>{name} packet-size and timing context</summary><dl>{Object.entries(observation.timing).map(([key, value]) => <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{value === null ? 'UNAVAILABLE' : String(value)}</dd></div>)}</dl></details>
        <p>{observation.limits}</p>
      </>}
      {evidence?.length ? <details><summary>{name} contextual evidence ({evidence.length})</summary><ul>{evidence.map((signal, i) => <li key={i}>{signal.signal_type} · {signal.detector}<p>{signal.confidence_semantics}</p></li>)}</ul></details> : null}
    </div>)}
    <p>Missing peer handshakes are unobserved, not inferred failures. SNI may be absent or hidden; an ECH outer name does not disclose the inner name.</p>
    <p>JA4 NOT IMPLEMENTED — no verified local specification and test vectors.</p>
  </section>;
}
