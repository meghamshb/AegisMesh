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
