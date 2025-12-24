# KMS Health Gateway API

mTLS only. Client cert/key/CA live at `/opt/mtls` on the main app box.
IP allow-list: requests must originate from allowed CIDRs.
LOCK_TTL=5m - to prevent brut-force if main project get compromised.
Redis stores per-answer locks using the key pattern: lock:unwrap:{user_id}:{answer_fp}.

## Endpoints
- `POST /kms/wrap` → `{ results: { kms1: { ok, w_b64 } } }`
- `POST /kms/unwrap` → `{ dek_b64, results: { kms1: { ok } } }`
    - Rate limit: 429 with `Retry-After` and body `{ error: "rate_limited", retry_after_seconds, key, scope }`
- `GET /kms/health/check` → `{ statuses: { kms1: "ok|fail|timeout" }, ts }`

See full schema in `docs/openapi.yaml`.
