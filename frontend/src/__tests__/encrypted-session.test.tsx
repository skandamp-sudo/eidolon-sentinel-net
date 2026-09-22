import { afterEach, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { EncryptedSession } from '@/components/EncryptedSession';
import type { DetectionEvent } from '@/api/types';
import tls from './fixtures/f5-tls-event.json';
import quic from './fixtures/f5-quic-event.json';

afterEach(cleanup);
const tlsEvent = tls as unknown as DetectionEvent;
const quicEvent = quic as unknown as DetectionEvent;

it('renders actual persisted TLS handshake metadata and identifiers without a verdict', () => {
  render(<EncryptedSession event={tlsEvent} />);
  expect(screen.getByRole('region', { name: 'Encrypted session metadata' })).toBeInTheDocument();
  expect(screen.getByText('TLS visibility: BOTH')).toBeInTheDocument();
  expect(screen.getAllByText(/DERIVED · JA3/)).toHaveLength(2);
  expect(screen.getByText(/MEASURED · ALPN: h2, http\/1.1/)).toBeInTheDocument();
  expect(screen.getByText(/Visible SNI: example.test/)).toBeInTheDocument();
  expect(screen.getByText(/JA4 NOT IMPLEMENTED/)).toBeInTheDocument();
  expect(screen.getByText(/they do not establish malware, C2 or compromise/)).toBeInTheDocument();
});

it('renders real QUIC headers and hashed CIDs with an explicit no-decryption boundary', () => {
  render(<EncryptedSession event={quicEvent} />);
  expect(screen.getByText('QUIC visibility: ONE DIRECTION OBSERVED')).toBeInTheDocument();
  expect(screen.getByText(/Version: 0x00000001 · Header: INITIAL/)).toBeInTheDocument();
  expect(screen.getByText('Encrypted QUIC payload: Not inspected')).toBeInTheDocument();
  expect(screen.getByText(/Destination CID SHA-256:/)).toBeInTheDocument();
});

it.each(['CLIENT_ONLY', 'SERVER_ONLY'])('shows %s without assuming handshake failure', visibility => {
  render(<EncryptedSession event={{ ...tlsEvent, tls_observation: { ...tlsEvent.tls_observation!, visibility } }} />);
  expect(screen.getByText('TLS visibility: '+visibility.replaceAll('_', ' '))).toBeInTheDocument();
  expect(screen.getByText(/Missing peer handshakes are unobserved, not inferred failures/)).toBeInTheDocument();
});

it.each(['INCOMPLETE', 'TRUNCATED', 'MALFORMED', 'UNSUPPORTED', 'UNAVAILABLE'])('shows %s metadata without manufactured fingerprints', status => {
  render(<EncryptedSession event={{ ...tlsEvent, tls_status: status, tls_evidence: [], tls_observation: { visibility: 'INCOMPLETE', directions: [{ source_ip: '192.0.2.1', source_port: 42000, status }], timing: {}, limits: 'No complete hello observed' } }} />);
  expect(screen.getByText('TLS status: '+status)).toBeInTheDocument();
  expect(screen.queryByText(/DERIVED · JA3:/)).not.toBeInTheDocument();
});

it.each(['not_recorded', 'disabled', 'unavailable_processing_error'])('distinguishes %s from observed empty data', status => {
  render(<EncryptedSession event={{ ...tlsEvent, tls_status: status, tls_observation: undefined, tls_evidence: [] }} />);
  expect(screen.getByText('TLS status: '+status)).toBeInTheDocument();
  expect(screen.queryByText(/DERIVED · JA3:/)).not.toBeInTheDocument();
});

it('keeps ECH inner SNI unavailable and does not invent an empty hostname', () => {
  const observation = structuredClone(tlsEvent.tls_observation!);
  observation.directions[0]!.hello!.sni = null;
  observation.directions[0]!.hello!.sni_status = 'unavailable_ech_extension_observed';
  render(<EncryptedSession event={{ ...tlsEvent, tls_observation: observation }} />);
  expect(screen.getAllByText(/Visible SNI: UNAVAILABLE/).length).toBeGreaterThan(0);
  expect(screen.getByText(/unavailable ech extension observed/)).toBeInTheDocument();
});

it('marks later QUIC short headers unavailable while retaining the earlier measured header', () => {
  const observation = structuredClone(quicEvent.quic_observation!);
  observation.directions[0]!.latest_packet_status = 'UNSUPPORTED';
  render(<EncryptedSession event={{ ...quicEvent, quic_observation: observation }} />);
  expect(screen.getByText(/Earlier visible long-header metadata retained/)).toBeInTheDocument();
});
