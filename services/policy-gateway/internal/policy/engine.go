package policy

import (
	"context"

	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/store"
)

type Decision string

const (
	DecisionDeny    Decision = "deny"
	DecisionAllow   Decision = "allow"
	DecisionPending Decision = "pending"
)

type Request struct {
	OrgID  string
	Method string
	Host   string
	Port   int
	Path   string
	Scheme string
}

type Engine interface {
	Evaluate(ctx context.Context, req Request) (Decision, *string, error)
}

type RuleEngine struct {
	store store.Store
}

func NewRuleEngine(st store.Store) *RuleEngine {
	return &RuleEngine{store: st}
}

func (e *RuleEngine) Evaluate(ctx context.Context, req Request) (Decision, *string, error) {
	rules, err := e.store.MatchRules(ctx, store.MatchRulesInput{
		OrgID:  req.OrgID,
		Host:   req.Host,
		Port:   req.Port,
		Method: req.Method,
		Path:   req.Path,
	})
	if err != nil {
		return "", nil, err
	}

	for _, rule := range rules {
		if rule.Effect == domain.RuleEffectDeny {
			return DecisionDeny, &rule.ID, nil
		}
	}

	for _, rule := range rules {
		if rule.Effect == domain.RuleEffectAllow {
			return DecisionAllow, &rule.ID, nil
		}
	}

	return DecisionPending, nil, nil
}

func DecisionToStatus(decision Decision) (domain.RequestStatus, error) {
	switch decision {
	case DecisionAllow:
		return domain.RequestStatusAutoApproved, nil
	case DecisionDeny:
		return domain.RequestStatusDenied, nil
	case DecisionPending:
		return domain.RequestStatusPending, nil
	default:
		var zero domain.RequestStatus
		return zero, domain.InvalidEnumError{Field: "policy_decision", Value: string(decision)}
	}
}
