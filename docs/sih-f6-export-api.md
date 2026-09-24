# Analyst investigation / forensic export API

All routes below require the existing `X-API-Key` authentication. Never put the key into a URL. Event authorization scope is the existing shared-key scope; this is not a multi-tenant permission model.

- `GET /api/v1/events/{event_id}/investigation`: canonical JSON projection consumed by Detection Detail.
- `GET /api/v1/events/{event_id}/export`: same content with an application-generated attachment filename.
- `GET /api/v1/assurance`: current sensor/database/model readiness plus the qualified scientific summary.

Investigation/export schema version is `1.0.0`. The envelope is documented in `sih-f6-export-schema.json` and in OpenAPI. It includes anchor/investigation IDs, unchanged allowlisted event records, correlation, evidence references, timeline, limits, and integrity semantics. Nested event fields are projected through the explicit allowlist in `operations/investigation.py`; arbitrary metadata is not part of this schema. Score values remain uncalibrated MODEL CONFIDENCE SCORE and normalized anomaly score, not attack probabilities. Risk is retained only if already present; no risk is derived.

Canonical serialization: Python JSON with sorted object keys, comma/colon compact separators, ASCII escaping, finite numbers, UTF-8-compatible ASCII bytes, and no trailing newline. Arrays retain deterministic projection order. The `X-Content-SHA256` response header is the lowercase hexadecimal SHA-256 of the **exact response bytes**. Hash those downloaded bytes directly; do not reformat JSON before checking. Different serialization bytes have a different hash even if JSON values are equivalent. This is a project canonicalization profile, not an RFC 8785 interoperability claim.

The digest is outside the content to avoid a circular self-hash. It is integrity checking, not a digital signature, authorship proof, trusted timestamp, or legal chain of custody. The browser verifies SHA-256 before saving and displays it for recording. CORS exposes only the digest and safe attachment headers in addition to existing behavior. The server never writes an export file.

Responses: 200 for success; 401 for unauthorized requests; 404 for missing/retained-away anchors; 422 for invalid identifiers or malformed/over-bound persisted evidence; 429 for four active exports/investigations already in progress; 503 for read timeout. Unexpected failures retain the existing generic API error contract. Snapshots may change as retention or legitimate records change. No export-time wall-clock value is injected, so unchanged persisted evidence yields identical bytes.

Limits and clock semantics are detailed in `sih-f6-architecture.md`. Export JSON must be treated as untrusted text by downstream tools; do not inject it into HTML. DNS names, SNI and endpoint identifiers require normal analyst data handling.
