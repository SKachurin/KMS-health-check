# KMS-health-check
KMS health check for Digital Heir

---
## Purpose

This service acts as a secure KMS proxy layer for the Digital Heir platform.

It:
- Wraps DEKs using AWS KMS replicas
- Unwraps DEKs with strict rate limiting
- Enforces IP allow-listing
- Requires mutual TLS authentication

It prevents direct KMS access from the main application and isolates key operations in a hardened service.

---

## API Endpoints

### POST /kms/wrap
Wraps a DEK using configured KMS replicas.

### POST /kms/unwrap
Attempts unwrap using provided replicas.
Rate-limited per (user_id + answer_fp).

### POST /kms/health/check
Performs real wrap + unwrap validation across replicas.

---

## Host

- Ubuntu 22.04.5 LTS
- Docker running
- Service: `kms-healthcheck` (Go) + `redis` + `autoheal`
- Repo path: `/opt/kms-healthcheck`
- mTLS certs mounted from: `/opt/mtls → /certs (ro)`

---

## Network / Security

- Docker publishes: `8443:8443` (public)
- Internal health endpoint (container only):
    - `http://localhost:8080/live`
    - Used by Docker healthcheck only
- App IP allow-list via env:
    - `ALLOW_IPS=5.180.181.53/32`
- `TRUST_PROXY=false`

### UFW (Firewall)

- Installed + enabled
- Default:
    - `deny incoming`
    - `allow outgoing`
- Allow:
    - `22/tcp` (temporary SSH access)
    - `8443/tcp` only from `5.180.181.53`

### Outbound Required

- AWS KMS: `kms.eu-north-1.amazonaws.com:443`
- Redis: internal Docker network (`redis:6379`)

---

## Containers

- `kms-healthcheck:local` (built locally)
- `redis:7-alpine`
    - AOF enabled
    - Volume: `redis-data`
- `willfarrell/autoheal`
    - Enabled via label: `autoheal=true`

---

# Project Update Flow

Since the remote uses HTTPS, `git pull` works even if inbound SSH (22) is later closed (because it uses outbound 443).

---

## Typical Safe Update Procedure

From `/opt/kms-healthcheck`:

```bash
cd /opt/kms-healthcheck

# Optional: inspect changes first
git fetch --all
git status
git pull
```

---

## Environment Variables

- KMS1_URL
- KMS1_REGION
- KMS1_KEY_ID
- KMS1_ACCESS_KEY_ID
- KMS1_SECRET_ACCESS_KEY
- REDIS_URL
- ALLOW_IPS
- TRUST_PROXY
- LOCK_TTL
- NONCE_TTL
- REQ_TIMEOUT
- HEALTH_INTERVAL
- SIG_SKEW