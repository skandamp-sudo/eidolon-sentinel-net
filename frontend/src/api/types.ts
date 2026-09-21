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

export interface DetectionEvent {
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
