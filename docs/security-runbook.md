# Security Runbook: Incident Response (CX-02)

**Version:** 1.0  
**Status:** Operational  
**Confidentiality:** Internal Use Only

---

## 1. Introduction

This runbook defines the incident response procedures for AgentKMS security events. It is intended for use by the Platform Security Team and On-call Engineers.

## 2. Incident Scenario: Certificate Compromise

**Symptoms:**
- Unauthorized operations detected in audit logs with a valid certificate.
- Developer reports lost or stolen hardware containing `~/.agentkms/`.

**Response Steps:**
1. **Identify the compromised certificate:** Extract the Serial Number, CN, or Fingerprint from the audit log or the developer's enrollment record.
2. **Revoke the certificate:**
   - If using OpenBao PKI: Call the revoke endpoint for the team's intermediate CA.
   - `vault write pki_team_X/revoke serial_number=<SN>`
3. **Invalidate active sessions:**
   - Identify all active session tokens associated with the certificate fingerprint.
   - Revoke each token via `POST /auth/revoke`.
4. **Notify the user:** Force re-enrollment for the affected developer.
5. **Audit review:** Perform a full sweep of all operations performed by the compromised identity in the 24 hours prior to revocation.

## 3. Incident Scenario: Session Token Leak

**Symptoms:**
- Session token found in plaintext logs, shared screen, or accidental Git commit.
- Unexpected operations from an IP address not associated with the developer.

**Response Steps:**
1. **Revoke the token immediately:**
   - Use the `agentkms-admin` tool or call the API directly: `POST /auth/revoke` with the leaked token.
2. **Verify revocation:** Check that subsequent calls with the leaked token return `401 Unauthorized` or `403 Forbidden`.
3. **Identity re-validation:** The developer must re-authenticate via mTLS to obtain a new token.
4. **Investigation:** Determine how the token was leaked and update the relevant security control (e.g., adding a secret scanning rule to CI).

## 4. Incident Scenario: Audit Failure

**Symptoms:**
- AgentKMS service reports `500 Internal Server Error` on all operations.
- Logs show "audit flush failed" or "failed to write to audit sink".
- Kibana/Splunk show a drop in event volume.

**Response Steps:**
1. **Check Audit Sink Health:**
   - Verify connectivity to Elasticsearch/Splunk/CloudWatch.
   - Check for disk space issues on the local file audit sink path.
2. **Scale AgentKMS down (optional):** If audit integrity is critical and the sink is unreachable, scale the service to zero to prevent unaudited operations (AgentKMS is "fail-closed" by default).
3. **Restore Sink Connectivity:** Resolve the upstream issue.
4. **Verify Integrity:** Once restored, verify that the AgentKMS internal buffers have flushed and that signing signatures in the audit log are valid.

## 5. Escalation Path

1. **Level 1:** On-call Engineer (Initial Triage)
2. **Level 2:** Platform Security Lead (Revocation & Investigation)
3. **Level 3:** CTO / CISO (Executive Communication)
