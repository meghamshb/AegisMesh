package policy

import (
	"context"

	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/domain"
)

type Decision string

const (
	DecisionDeny    Decision = "deny"
	DecisionAllow   Decision = "allow"
	DecisionPending Decision = "pending"
)

type Request struct {
	AgentID string
	UserID  string
	OrgID   string
	Method  string
	Host    string
	Port    int
	Path    string
	Scheme  string
}

type Engine interface {
	Evaluate(ctx context.Context, req Request) (Decision, *string, error)
}

type DefaultDeny struct{}

func (DefaultDeny) Evaluate(_ context.Context, _ Request) (Decision, *string, error) {
	return DecisionPending, nil, nil
}

func ParseRequestStatus(raw string) (domain.RequestStatus, error) {
	switch domain.RequestStatus(raw) {
	case domain.RequestStatusPending,
		domain.RequestStatusApproved,
		domain.RequestStatusDenied,
		domain.RequestStatusAutoApproved,
		domain.RequestStatusExpired:
		return domain.RequestStatus(raw), nil
	default:
		return "", domain.InvalidEnumError{Field: "request_status", Value: raw}
	}
}
