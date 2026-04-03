# Key Rotation Runbook (CX-03)

**Version:** 1.0  
**Status:** Operational  
**Confidentiality:** Internal Use Only

---

## 1. Introduction

This runbook defines the procedures for rotating cryptographic keys managed by AgentKMS. It ensures that AgentKMS remains compliant with PCI-DSS, SOC 2, and other enterprise security standards.

## 2. Key Rotation Schedule

| Key Type | Rotation Interval | Responsible Party |
|---|---|---|
| Master LLM Keys | 30 days | Automated Worker (LV-05) |
| Team Signing Keys (Transit) | 90 days | Team Lead / Admin |
| Production Encryption Keys | 1 year | Enterprise Admin |
| Audit Signing Keys | 1 year | Platform Security Team |

## 3. Scheduled Rotation Procedure (Manual)

For keys that are not yet under automated rotation (LV-05), the following manual steps apply:

1. **Identify the Key ID:** Locate the key in the `GET /keys` metadata response.
2. **Review Operations:** Ensure no high-priority workloads are mid-operation (rotation is non-disruptive, but observability is key).
3. **Trigger Rotation:**
   - Call the AgentKMS API: `POST /rotate/{key-id}`
   - *Example:* `curl -X POST https://agentkms.prod/v1/rotate/payments/signing-key -H "Authorization: Bearer <token>"`
4. **Verify Rotation:**
   - Call `GET /keys?prefix=<key-id>`.
   - Confirm that the `version` has incremented by 1.
   - Confirm that `rotated_at` has been updated to the current time.
5. **Monitor for Issues:** Observe the error rate in Grafana for the next 15 minutes.

## 4. Rollback Procedure

AgentKMS uses a "keep-historical" rotation model. When a key is rotated, the old version remains in the backend for decryption and signature verification.

**Scenario: New key version is corrupted or incompatible.**
1. **Identify the issue:** High error rate or "algorithm mismatch" after rotation.
2. **Switch to previous version (Manual Override):**
   - AgentKMS always uses the *latest* version for writes. To "roll back," you must either fix the backend or (if using OpenBao/Vault) set the `min_decryption_version` or `min_encryption_version` config.
   - *Note:* There is no direct "undo" for a rotation in Transit backends. The correct path is to investigate why the new version is failing and resolve it.

## 5. Emergency Rotation

In the event of a suspected key compromise:
1. **Trigger Immediate Rotation:** Follow the manual rotation steps immediately.
2. **Inhibit Old Versions:** 
   - If using OpenBao Transit: `vault write transit/keys/<key-id>/config min_decryption_version=<new-version> min_encryption_version=<new-version>`.
   - *CAUTION:* This will make all data encrypted with previous versions permanently unreadable. Use only in case of catastrophic compromise.

## 6. Audit Trail

Every rotation event is logged in the audit log with:
- `operation`: `rotate_key`
- `key_id`: ID of the rotated key
- `key_version`: The new version number
- `caller_id`: The identity that triggered the rotation
- `outcome`: `success` or `error`
