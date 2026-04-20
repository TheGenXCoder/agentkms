package audit

// InvalidationReason constants define the valid values for the
// AuditEvent.InvalidationReason field.  These are intentionally
// stubbed — the validation logic in Validate() has not been
// implemented yet (see FO-B4).
const (
	ReasonExpired      = "expired"
	ReasonRevokedUser  = "revoked-user"
	ReasonRevokedAdmin = "revoked-admin"
	ReasonRevokedLeak  = "revoked-leak"
)
