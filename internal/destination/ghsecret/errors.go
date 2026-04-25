package ghsecret

import "errors"

// Sentinel errors for destination error classification. The subprocess binary
// uses errors.Is to map these to DestinationErrorCode values, replacing the
// previous string-matching approach.
//
// All errors returned by ghClient methods and Deliverer are wrapped with the
// appropriate sentinel using fmt.Errorf("...%w", ErrXxx) so that errors.Is
// traverses the chain correctly.
var (
	// ErrTargetNotFound — repository or secret not found at GitHub.
	// Maps to DESTINATION_TARGET_NOT_FOUND.
	ErrTargetNotFound = errors.New("ghsecret: target not found")

	// ErrPermissionDenied — writer token lacks permission for the operation.
	// Maps to DESTINATION_PERMISSION_DENIED.
	ErrPermissionDenied = errors.New("ghsecret: permission denied")

	// ErrTransient — temporary failure (rate limit, 5xx, network timeout).
	// Maps to DESTINATION_TRANSIENT.
	ErrTransient = errors.New("ghsecret: transient failure")

	// ErrPermanent — non-retryable failure not covered by the above.
	// Maps to DESTINATION_PERMANENT.
	ErrPermanent = errors.New("ghsecret: permanent failure")

	// ErrGenerationRegression — request generation lower than last delivered.
	// Maps to DESTINATION_GENERATION_REGRESSION.
	ErrGenerationRegression = errors.New("ghsecret: generation regression")
)
