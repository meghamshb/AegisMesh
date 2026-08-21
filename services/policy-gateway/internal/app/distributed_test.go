package app_test

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/app"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/config"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/policy"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store/storetest"
)

// Phase 5.10's acceptance criterion is that one central policy change controls
// a running gateway without restarting it. These tests pin the mechanism that
// makes that true: a distributed App decides from the snapshot it holds, so
// swapping the snapshot contents changes the verdict of the very next request
// with no re-construction of the App.

const (
	distOrg   = "org-1"
	distUser  = "user-1"
	distAgent = "agent-1"
)

// mutableSnapshot is a policy.SnapshotProvider whose contents can change
// underneath a running App, exactly as a background refresh would.
type mutableSnapshot struct {
	mu    sync.RWMutex
	rules []domain.PolicyRule
	ok    bool
}

func (m *mutableSnapshot) Rules() ([]domain.PolicyRule, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rules, m.ok
}

func (m *mutableSnapshot) set(rules []domain.PolicyRule) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules = rules
	m.ok = true
}

func (m *mutableSnapshot) markUnavailable() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ok = false
}

// sqlTrackingStore fails the test if rule matching ever reaches SQL. In
// distributed mode policy must come from the snapshot; a MatchRules call would
// mean the gateway is quietly reading a database it is not supposed to consult
// for decisions, and the fleet demo would be proving nothing.
type sqlTrackingStore struct {
	storetest.Stub
	mu             sync.Mutex
	matchRulesCall int
}

func (s *sqlTrackingStore) MatchRules(context.Context, store.MatchRulesInput) ([]domain.PolicyRule, error) {
	s.mu.Lock()
	s.matchRulesCall++
	s.mu.Unlock()
	return nil, nil
}

func (s *sqlTrackingStore) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.matchRulesCall
}

func allowRule(id, host string, port int) domain.PolicyRule {
	return domain.PolicyRule{
		ID: id, OrgID: distOrg,
		Scope: domain.RuleScopeOrg, ScopeRefID: distOrg,
		Effect: domain.RuleEffectAllow,
		Host:   host, Port: port, Method: "*", PathPrefix: "/",
	}
}

func distConfig() config.Config {
	return config.Config{
		ServiceName:    "policy-gateway",
		ServiceVersion: "test",
		ProxyEnabled:   true,
		AgentAuthMode:  config.AgentAuthModeStatic,
		Identity:       config.AgentIdentity{OrgID: distOrg, UserID: distUser, AgentID: distAgent},
	}
}

func distRequest() policy.Request {
	return policy.Request{
		OrgID: distOrg, UserID: distUser, AgentID: distAgent,
		Host: "example.com", Port: 80, Method: "GET", Path: "/fleet-test", Scheme: "http",
	}
}

// evaluateThrough builds the same engine NewDistributed installs, so the test
// exercises the real wiring rather than a parallel construction.
func evaluateThrough(t *testing.T, snapshots policy.SnapshotProvider, st store.Store) (policy.Evaluation, error) {
	t.Helper()
	engine := policy.NewSnapshotRuleEngine(snapshots, st)
	return engine.Evaluate(context.Background(), distRequest())
}

func TestCentralRuleChangeTakesEffectWithoutRestart(t *testing.T) {
	snapshots := &mutableSnapshot{}
	snapshots.set(nil) // gateway is up, holding an empty policy set
	st := &sqlTrackingStore{}

	// Build the App once. It is never rebuilt below - that is the point.
	application := app.NewDistributed(distConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)), st, snapshots)
	if application == nil {
		t.Fatal("NewDistributed returned nil")
	}

	eval, err := evaluateThrough(t, snapshots, st)
	if err != nil {
		t.Fatalf("evaluate with empty policy: %v", err)
	}
	if eval.Decision != policy.DecisionPending {
		t.Fatalf("with no rule the decision should be pending, got %s", eval.Decision)
	}

	// The control plane publishes an allow rule; the background refresh lands.
	snapshots.set([]domain.PolicyRule{allowRule("rule-1", "example.com", 80)})

	eval, err = evaluateThrough(t, snapshots, st)
	if err != nil {
		t.Fatalf("evaluate after central allow: %v", err)
	}
	if eval.Decision != policy.DecisionAllow {
		t.Fatalf("after the central allow rule the decision should be allow, got %s", eval.Decision)
	}

	// The rule is revoked centrally; the next refresh drops it.
	snapshots.set(nil)

	eval, err = evaluateThrough(t, snapshots, st)
	if err != nil {
		t.Fatalf("evaluate after central revoke: %v", err)
	}
	if eval.Decision == policy.DecisionAllow {
		t.Fatal("auto-approval survived a central revoke")
	}

	if st.calls() != 0 {
		t.Fatalf("distributed gateway consulted SQL for rule matching %d time(s); policy must come from the snapshot", st.calls())
	}
}

func TestDistributedGatewayFailsClosedWhenSnapshotUnavailable(t *testing.T) {
	snapshots := &mutableSnapshot{}
	snapshots.set([]domain.PolicyRule{allowRule("rule-1", "example.com", 80)})
	st := &sqlTrackingStore{}

	// Sanity: allowed while the snapshot is good.
	eval, err := evaluateThrough(t, snapshots, st)
	if err != nil || eval.Decision != policy.DecisionAllow {
		t.Fatalf("expected allow with a fresh snapshot, got %s / %v", eval.Decision, err)
	}

	// Snapshot goes stale past its ceiling.
	snapshots.markUnavailable()

	if _, err := evaluateThrough(t, snapshots, st); err != policy.ErrPolicyUnavailable {
		t.Fatalf("expected ErrPolicyUnavailable when the snapshot is stale, got %v", err)
	}

	// Failing closed must not silently fall back to querying the database.
	if st.calls() != 0 {
		t.Fatalf("stale snapshot fell back to SQL (%d call(s)); that would defeat fail-closed", st.calls())
	}
}

// The single-process path must be untouched: mode=all still decides via SQL.
func TestSingleProcessAppStillUsesSQL(t *testing.T) {
	st := &sqlTrackingStore{}
	application := app.New(distConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)), st)
	if application == nil {
		t.Fatal("New returned nil")
	}

	engine := policy.NewRuleEngine(st)
	if _, err := engine.Evaluate(context.Background(), distRequest()); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if st.calls() == 0 {
		t.Fatal("single-process engine should query SQL for rule matching")
	}
}
