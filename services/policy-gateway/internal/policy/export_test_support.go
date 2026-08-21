package policy

import (
	"context"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
)

// MatchSnapshotRulesForTest exposes the snapshot matcher to the parity test in
// internal/store, which needs to compare the Go match set against the SQL one
// directly. It is a thin wrapper over the unexported source with no logic of
// its own, so the parity test exercises the real implementation.
//
// This lives in a normal (non-_test.go) file because the consumer is a
// different package's test binary, which cannot see policy's in-package test
// files. It is exported API only in the technical sense - nothing in the
// running service calls it.
func MatchSnapshotRulesForTest(rules []domain.PolicyRule, in store.MatchRulesInput) ([]domain.PolicyRule, error) {
	src := snapshotRuleSource{snapshots: fixedSnapshot{rules: rules}}
	return src.MatchRules(context.Background(), in)
}

type fixedSnapshot struct{ rules []domain.PolicyRule }

func (f fixedSnapshot) Rules() ([]domain.PolicyRule, bool) { return f.rules, true }
