package domain

import "fmt"

type InvalidEnumError struct {
	Field string
	Value string
}

func (e InvalidEnumError) Error() string {
	return fmt.Sprintf("invalid %s: %q", e.Field, e.Value)
}

func ParseRequestStatus(raw string) (RequestStatus, error) {
	switch RequestStatus(raw) {
	case RequestStatusPending,
		RequestStatusApproved,
		RequestStatusDenied,
		RequestStatusAutoApproved,
		RequestStatusExpired:
		return RequestStatus(raw), nil
	default:
		return "", InvalidEnumError{Field: "request_status", Value: raw}
	}
}

// ErrAmbiguousEmail means an email address matched more than one actor, so it
// cannot be used to link an external identity unambiguously (Phase 5.13).
// Email is unique per organization, not globally, so a multi-org deployment
// can legitimately hit this - and resolving it by picking one would let an
// account in one org be claimed by an identity intended for another.
type ErrAmbiguousEmail struct {
	Email string
}

func (e ErrAmbiguousEmail) Error() string {
	return "email matches more than one user: " + e.Email
}
