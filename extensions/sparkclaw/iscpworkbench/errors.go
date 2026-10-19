package iscpworkbench

import "errors"

type ErrorCode string

const (
	ErrorInvalidRequest        ErrorCode = "invalid_request"
	ErrorPermissionDenied      ErrorCode = "permission_denied"
	ErrorAuthorizationRevoked  ErrorCode = "authorization_revoked"
	ErrorGrantExpired          ErrorCode = "grant_expired"
	ErrorRenewalUnavailable    ErrorCode = "renewal_unavailable"
	ErrorRevisionConflict      ErrorCode = "revision_conflict"
	ErrorCapabilityUnavailable ErrorCode = "capability_unavailable"
	ErrorThrottled             ErrorCode = "throttled"
	ErrorResourceLimit         ErrorCode = "resource_limit"
	ErrorObjectExpired         ErrorCode = "object_expired"
	ErrorCursorGap             ErrorCode = "cursor_gap"
	ErrorOutcomeUnknown        ErrorCode = "outcome_unknown"
	ErrorNotFound              ErrorCode = "not_found"
	ErrorInternal              ErrorCode = "internal_error"
)

func validErrorCode(code ErrorCode) bool {
	switch code {
	case ErrorInvalidRequest, ErrorPermissionDenied, ErrorAuthorizationRevoked, ErrorGrantExpired, ErrorRenewalUnavailable, ErrorRevisionConflict, ErrorCapabilityUnavailable, ErrorThrottled, ErrorResourceLimit, ErrorObjectExpired, ErrorCursorGap, ErrorOutcomeUnknown, ErrorNotFound, ErrorInternal:
		return true
	}
	return false
}
func CodeForStatus(status int) ErrorCode {
	switch status {
	case 400, 422:
		return ErrorInvalidRequest
	case 401:
		return ErrorGrantExpired
	case 403:
		return ErrorPermissionDenied
	case 404:
		return ErrorNotFound
	case 409:
		return ErrorRevisionConflict
	case 410:
		return ErrorObjectExpired
	case 413:
		return ErrorResourceLimit
	case 429:
		return ErrorThrottled
	case 501, 503:
		return ErrorCapabilityUnavailable
	}
	return ErrorInternal
}

type ObjectReference struct {
	ObjectID  string `json:"object_id"`
	Version   uint64 `json:"version"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Purpose   string `json:"purpose"`
	Name      string `json:"name,omitempty"`
	MediaType string `json:"media_type,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

func (r ObjectReference) Validate() error {
	if !uuidPattern.MatchString(r.ObjectID) || r.Version == 0 || r.Size < 0 || r.Size > 64<<20 || len(r.SHA256) != 64 || len(r.Purpose) == 0 || len(r.Purpose) > 64 {
		return errors.New("invalid object reference")
	}
	for _, c := range r.SHA256 {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return errors.New("invalid object digest")
		}
	}
	return nil
}

// TransportError distinguishes failures proven to precede Relay submission from
// unknown outcomes. Message prose is diagnostic and never a retry contract.
type TransportError struct {
	Code               ErrorCode
	Status             int
	Retryable, NotSent bool
	Message            string
}

func (e *TransportError) Error() string { return e.Message }
