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
	AgentID string
	OrgID   string
	Method  string
	Host    string
	Port    int
	Path    string
	Scheme  string
}

type Evaluation struct {
	Decision        Decision
	RuleID          *string
	ApprovalGrantID *string
}

type Engine interface {
	Evaluate(ctx context.Context, req Request) (Evaluation, error)
}

type RuleEngine struct {
	store store.Store
}

func NewRuleEngine(st store.Store) *RuleEngine {
	return &RuleEngine{store: st}
}

func (e *RuleEngine) Evaluate(ctx context.Context, req Request) (Evaluation, error) {
	rules, err := e.store.MatchRules(ctx, store.MatchRulesInput{
		OrgID:  req.OrgID,
		Host:   req.Host,
		Port:   req.Port,
		Method: req.Method,
		Path:   req.Path,
	})
	if err != nil {
		return Evaluation{}, err
	}

	for _, rule := range rules {
		if rule.Effect == domain.RuleEffectDeny {
			return Evaluation{Decision: DecisionDeny, RuleID: &rule.ID}, nil
		}
	}

	for _, rule := range rules {
		if rule.Effect == domain.RuleEffectAllow {
			return Evaluation{Decision: DecisionAllow, RuleID: &rule.ID}, nil
		}
	}

	match := store.ApprovalMatchInput{
		AgentID: req.AgentID,
		Host:    req.Host,
		Port:    req.Port,
		Method:  req.Method,
		Path:    req.Path,
	}

	denied, err := e.store.HasDeniedPattern(ctx, match)
	if err != nil {
		return Evaluation{}, err
	}
	if denied {
		return Evaluation{Decision: DecisionDeny}, nil
	}

	approval, err := e.store.FindConsumableApproval(ctx, match)
	if err != nil {
		return Evaluation{}, err
	}
	if approval != nil {
		return Evaluation{Decision: DecisionAllow, ApprovalGrantID: &approval.ID}, nil
	}

	return Evaluation{Decision: DecisionPending}, nil
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

func StatusForEvaluation(eval Evaluation) (domain.RequestStatus, error) {
	switch eval.Decision {
	case DecisionAllow:
		if eval.ApprovalGrantID != nil {
			return domain.RequestStatusApproved, nil
		}
		return domain.RequestStatusAutoApproved, nil
	case DecisionDeny:
		return domain.RequestStatusDenied, nil
	case DecisionPending:
		return domain.RequestStatusPending, nil
	default:
		var zero domain.RequestStatus
		return zero, domain.InvalidEnumError{Field: "policy_decision", Value: string(eval.Decision)}
	}
}
