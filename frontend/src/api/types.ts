/**
 * TypeScript type definitions matching Sentinel-NET backend API contracts.
 *
 * IMPORTANT: These types must match the backend Pydantic schemas exactly.
 * The frontend NEVER duplicates ML inference, scoring, or classification.
 * All data originates from backend REST/WebSocket responses.
 */

// ─── Enums ───────────────────────────────────────────────────────────

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type ThreatType =
  | 'benign'
  | 'ddos'
  | 'scan'
  | 'reconnaissance'
  | 'exfiltration'
  | 'c2'
  | 'dns_tunneling'
  | 'brute_force'
  | 'other'
  | 'unknown'
  | 'unsupported';

export type SensorState = 'stopped' | 'starting' | 'running' | 'replaying' | 'replay_complete' | 'stopping' | 'error' | 'degraded' | 'failed';

export type EvidenceType = 'model' | 'statistical' | 'heuristic';

export type ATTACKQualification = 'possible' | 'likely' | 'observed indicators consistent with';

// ─── Evidence ────────────────────────────────────────────────────────

export interface EvidenceItem {
  feature_name: string;
  observed_value: number;
  reference_value: number | null;
  contribution: number;
  direction: 'increase' | 'decrease';
  evidence_type: EvidenceType;
  source: string;
  model_name: string;
  model_version: string;
  feature_schema_version: string;
}

export interface EvidenceCollection {
  items: EvidenceItem[];
  explanation_available: boolean;
  unavailable_reason: string | null;
}

// ─── ATT&CK Mapping ─────────────────────────────────────────────────

export interface ATTACKMapping {
  technique_id: string;
  technique_name: string;
  tactic: string;
  rationale: string;
  applicability: 'high' | 'medium' | 'low';
  qualification: ATTACKQualification;
}

// ─── Events ──────────────────────────────────────────────────────────

export interface BehavioralEvidence {
  signal_type: string;
  observed_value: number;
  unit: string;
  reference_threshold: number | null;
  comparison: string;
  observation_window: { start: number; end: number; duration_sec: number; clock: string; alignment: string };
  supporting_context: Record<string, unknown>;
  detector: string;
  confidence_semantics: string;
  interpretation: string;
}

export interface DNSObservation {
  timestamp: number;
  visibility: string;
  disposition: string;
  retention: string;
  parent_semantics: string;
  message: { status: string; reason?: string; questions?: { name: string; qtype: number; qtype_name: string; qclass: number }[]; qr?: boolean; rcode?: number; response_record_types?: number[]; message_length?: number };
  lexical: { qname_length: number; longest_label: number; character_entropy: number; max_label_entropy: number; label_count: number; sample_characters: number }[];
  observation_window?: { start: number; end: number; duration_sec: number };
  source_window?: Record<string, unknown> | null;
  parent_window?: Record<string, unknown> | null;
  server_window?: Record<string, unknown> | null;
}

export interface TLSHello {
  handshake_type: number; legacy_version: number; supported_versions: number[]; selected_version: number | null;
  cipher_suites: number[]; extension_ids: number[]; supported_groups: number[]; signature_algorithms: number[];
  sni: string | null; sni_status: string; alpn: { value: string; encoding: string }[];
  fingerprint: { family: string; digest: string; canonical: string; semantics: string };
}
export interface EncryptedDirection {
  source_ip: string; source_port: number; status: string; reason?: string; hello?: TLSHello;
  timestamp?: number; last_packet_timestamp?: number; latest_packet_status?: string; latest_packet_reason?: string;
  version_hex?: string; packet_type?: string; long_header?: boolean;
  destination_cid_length?: number; destination_cid_sha256?: string | null;
  source_cid_length?: number; source_cid_sha256?: string | null;
  token_length?: number; declared_packet_length?: number; supported_versions?: number[];
}
export interface EncryptedObservation {
  visibility: string; directions: EncryptedDirection[]; timing: Record<string, unknown>; limits: string;
}

export interface DetectionEvent {
  tls_status?: string; tls_observation?: EncryptedObservation; tls_evidence?: BehavioralEvidence[];
  quic_status?: string; quic_observation?: EncryptedObservation; quic_evidence?: BehavioralEvidence[];
  dns_status?: string;
  dns_observation?: DNSObservation;
  dns_evidence?: BehavioralEvidence[];
  dns_attack_context?: ATTACKMapping[];
  behavioral_evidence_status?: string;
  behavioral_evidence?: BehavioralEvidence[];
  behavioral_policy?: { action?: string; behavioral_alert?: boolean; semantics?: string };
  behavioral_attack_context?: ATTACKMapping[];
  model_name?: string | null;
  deployment_model_version?: string | null;
  model_manifest_sha256?: string | null;
  event_schema_version?: string;
  event_id?: string;
  threat_class?: ThreatType | null;
  classification_score?: number | null;
  classification_score_type?: string | null;
  classification_score_class?: string | null;
  anomaly_score_type?: string | null;
  detection_source?: string[];
  source_mode?: 'LIVE' | 'REPLAY' | null;
  capture_interface?: string | null;
  replay_file_identifier?: string | null;
  anomaly_model_version?: string | null;
  evidence?: EvidenceCollection;
  id: string;
  timestamp: number;
  flow_id: string | null;
  severity: Severity;
  threat_type: ThreatType;
  anomaly_score: number | null;
  model_version: string | null;
  feature_schema_version: string | null;
  explanation_version: string | null;
  rationale: string;
  metadata: Record<string, unknown>;
  created_at: number;
  // Joined from flows table (may be absent in some queries)
  src_ip?: string;
  dst_ip?: string;
  src_port?: number | null;
  dst_port?: number | null;
  protocol?: number;
}

export interface EventExplanation {
  explanation_id: string;
  detection_event_id: string;
  explanation_version: string;
  generation_timestamp: number;
  threat_type: string;
  anomaly_score: number | null;
  confidence: number | null;
  severity: string;
  rationale: string;
  classifier_evidence: EvidenceCollection;
  anomaly_evidence: EvidenceCollection;
  attack_mappings: ATTACKMapping[];
}

export interface EventListResponse {
  events: DetectionEvent[];
  total: number;
  limit: number;
  offset: number;
}

// ─── Flows ───────────────────────────────────────────────────────────

export interface Flow {
  id: string;
  flow_key: string;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: number;
  direction: 'forward' | 'reverse' | 'unknown';
  start_time: number;
  end_time: number;
  duration_sec: number;
  packet_count: number;
  byte_count: number;
  payload_byte_count: number;
  created_at: number;
}

export interface FlowListResponse {
  flows: Flow[];
  total: number;
  limit: number;
  offset: number;
}

// ─── Stats ───────────────────────────────────────────────────────────

export interface StatsResponse {
  threat_types: Record<string, number>;
  severities: Record<string, number>;
  total_events: number;
}

// ─── Status ──────────────────────────────────────────────────────────

export interface SensorMetrics {
  tls_records_observed?: number;
  tls_client_hello?: number;
  tls_server_hello?: number;
  tls_malformed?: number;
  tls_truncated?: number;
  tls_reassembly_evictions?: number;
  tls_reassembly_bytes_peak?: number;
  tls_evidence_generated?: number;
  quic_packets_observed?: number;
  quic_long_headers?: number;
  quic_unknown_versions?: number;
  quic_malformed?: number;
  quic_evidence_generated?: number;
  encrypted_metadata_state?: number;
  encrypted_metadata_state_peak?: number;
  encrypted_metadata_processing_errors?: number;
  dns_messages_observed?: number;
  dns_messages_parsed?: number;
  dns_malformed?: number;
  dns_truncated?: number;
  dns_unavailable?: number;
  dns_state_keys?: number;
  dns_keys_peak?: number;
  dns_evictions?: number;
  dns_evidence_generated?: number;
  dns_processing_errors?: number;
  intelligence_keys?: number;
  intelligence_keys_peak?: number;
  intelligence_evictions?: number;
  intelligence_evidence_generated?: number;
  intelligence_processing_errors?: number;
  intelligence_member_overflows?: number;
  intelligence_late_observations?: number;
  kernel_capture_drops?: number | null;
  retention_failures?: number;
  retention_events_removed?: number;
  retention_flows_removed?: number;
  retention_duration_sec?: number;
  retention_last_success?: number | null;
  database_bytes?: number | null;
  wal_bytes?: number | null;
  subscriber_queue_peak?: number;
  subscriber_rejections?: number;

  source_errors?: number;
  output_errors?: number;
  last_error_kind?: string;
  processing_time_sec?: number;
  packets_received?: number;
  packets_processed?: number;
  packet_errors?: number;
  flows_created?: number;
  subscriber_count?: number;
  sensor_uptime?: number;
  packets_observed: number;
  packets_parsed: number;
  packets_malformed: number;
  packets_dropped: number;
  flows_active: number;
  flows_completed: number;
  flows_evicted: number;
  features_generated: number;
  detections_generated: number;
  events_persisted: number;
  events_enqueued: number;
  events_delivered: number;
  persistence_errors: number;
  processing_errors: number;
  events_dropped: number;
  capture_errors: number;
  capture_queue_depth: number;
  detection_queue_depth: number;
  start_time: number;
}

export interface StatusResponse {
  model_identity?: { model_name: string; model_version: string; feature_schema_version: string } | null;
  capture_interface?: string | null;
  sensor_mode?: 'live_passive_sensor' | 'recorded_traffic_replay' | 'standby';
  operational_health?: { state: string; mode: string; reasons: string[] };
  sensor_state: SensorState;
  metrics: SensorMetrics;
  uptime_sec: number;
  feature_schema_version: string;
  feature_count: number;
  websocket_subscribers: number;
}

// ─── Health ──────────────────────────────────────────────────────────

export interface HealthResponse {
  status: string;
  version: string;
  timestamp: string;
}

// ─── WebSocket ───────────────────────────────────────────────────────

export type WebSocketConnectionState =
  | 'connecting'
  | 'authenticating'
  | 'connected'
  | 'disconnected'
  | 'reconnecting';

export interface WSAuthMessage {
  type: 'auth';
  api_key: string;
}

export interface WSEventMessage {
  type: 'event';
  data: Record<string, unknown>;
}

export interface WSPingMessage {
  type: 'ping';
}

export interface WSAuthOkMessage {
  type: 'auth_ok';
}

export interface WSAuthFailedMessage {
  type: 'auth_failed';
  reason?: string;
}

export type WSServerMessage =
  | WSAuthOkMessage
  | WSAuthFailedMessage
  | WSEventMessage
  | WSPingMessage;

export interface Investigation {
  export_schema_version: string;
  investigation_id: string;
  anchor_event_id: string;
  correlation: {
    label: string; summary: string; source_count: number; evidence_count: number;
    contributing_event_ids: string[]; contributing_signal_types: string[];
    first_seen: number; last_seen: number; time_basis: string;
  };
  timeline: { timestamp: number; clock: string; signal_type: string; description: string;
    source: 'LIVE' | 'REPLAY' | null; event_id: string; reference: string }[];
  limitations: string[];
  integrity_semantics: string;
}
export interface Assurance {
  rows: { property: string; status: string; detail: string }[];
  model_identity: { model_name: string; model_version: string; manifest_sha256: string } | null;
  feature_schema_version: string;
  science: {
    status: string; evaluation?: string; test_rows?: number; accuracy?: number; macro_f1?: number;
    benign_to_malicious_fpr?: number; c2_recall?: number; ddos_recall?: number;
    iforest_roc_auc?: number; iforest_pr_auc?: number; candidate_status?: string;
    limitations?: string[]; candidate_manifest_sha256?: string;
  };
}
