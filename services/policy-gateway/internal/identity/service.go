package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
)

var (
	// ErrInvalidToken means the token does not match any known credential.
	ErrInvalidToken = errors.New("invalid agent token")
	// ErrCredentialRevoked means the token maps to a real but revoked credential.
	ErrCredentialRevoked = errors.New("agent credential revoked")
	// ErrAgentRevoked means the credential is active but its agent is not.
	ErrAgentRevoked = errors.New("agent revoked")
	// ErrOrgSuspended means the agent and credential are active but the
	// owning organization is not.
	ErrOrgSuspended = errors.New("organization suspended")
)

// Store is the subset of store.Store the identity package depends on.
// Keeping it narrow makes unit tests cheap to fake.
type Store interface {
	RegisterAgent(ctx context.Context, in store.RegisterAgentInput, audit store.AuditInput) (domain.Agent, error)
	RevokeAgent(ctx context.Context, agentID string, audit store.AuditInput) (domain.Agent, error)
	GetAgent(ctx context.Context, id string) (domain.Agent, error)
	CreateAgentCredential(ctx context.Context, in store.CreateAgentCredentialInput, audit store.AuditInput) (domain.AgentCredential, error)
	RotateAgentCredential(ctx context.Context, agentID string, in store.CreateAgentCredentialInput, audit store.AuditInput) (domain.AgentCredential, error)
	GetAgentCredentialByHash(ctx context.Context, tokenHash string) (domain.AgentCredential, error)
	TouchAgentCredentialLastUsed(ctx context.Context, credentialID string) error
	TouchAgentLastSeen(ctx context.Context, agentID string) error
	GetOrganization(ctx context.Context, id string) (domain.Organization, error)
}

// Service owns agent registration and the agent credential lifecycle:
// issuing, rotating, revoking, and authenticating opaque agent tokens.
type Service struct {
	store Store
}

func NewService(st Store) *Service {
	return &Service{store: st}
}

type RegisterAgentInput struct {
	OrgID       string
	OwnerUserID string
	Name        string
	ContainerID *string
	Metadata    map[string]any
}

// RegisterAgent creates the agent row and issues its first credential.
// The plaintext token is returned exactly once; only its hash is persisted.
func (s *Service) RegisterAgent(ctx context.Context, in RegisterAgentInput, actorID string) (domain.Agent, string, domain.AgentCredential, error) {
	agent, err := s.store.RegisterAgent(ctx, store.RegisterAgentInput{
		OrgID:       in.OrgID,
		OwnerUserID: in.OwnerUserID,
		Name:        in.Name,
		ContainerID: in.ContainerID,
		Metadata:    in.Metadata,
	}, store.AuditInput{
		EventType: "agent_registered",
		ActorID:   actorID,
		Metadata:  map[string]any{"owner_user_id": in.OwnerUserID},
	})
	if err != nil {
		return domain.Agent{}, "", domain.AgentCredential{}, fmt.Errorf("register agent: %w", err)
	}

	token, cred, err := s.IssueCredential(ctx, agent.ID, actorID)
	if err != nil {
		return domain.Agent{}, "", domain.AgentCredential{}, err
	}

	return agent, token, cred, nil
}

// IssueCredential generates a new credential for an existing agent.
func (s *Service) IssueCredential(ctx context.Context, agentID, actorID string) (string, domain.AgentCredential, error) {
	token, err := GenerateAgentToken()
	if err != nil {
		return "", domain.AgentCredential{}, err
	}

	cred, err := s.store.CreateAgentCredential(ctx, store.CreateAgentCredentialInput{
		AgentID:     agentID,
		TokenPrefix: TokenDisplayPrefix(token),
		TokenHash:   HashAgentToken(token),
		CreatedBy:   actorID,
	}, store.AuditInput{
		EventType: "agent_credential_created",
		ActorID:   actorID,
		Metadata:  map[string]any{},
	})
	if err != nil {
		return "", domain.AgentCredential{}, fmt.Errorf("issue agent credential: %w", err)
	}

	return token, cred, nil
}

// RotateCredential revokes every active credential for the agent and issues
// a new one in the same transaction.
func (s *Service) RotateCredential(ctx context.Context, agentID, actorID string) (string, domain.AgentCredential, error) {
	token, err := GenerateAgentToken()
	if err != nil {
		return "", domain.AgentCredential{}, err
	}

	cred, err := s.store.RotateAgentCredential(ctx, agentID, store.CreateAgentCredentialInput{
		AgentID:     agentID,
		TokenPrefix: TokenDisplayPrefix(token),
		TokenHash:   HashAgentToken(token),
		CreatedBy:   actorID,
	}, store.AuditInput{
		EventType: "agent_credential_rotated",
		ActorID:   actorID,
		Metadata:  map[string]any{},
	})
	if err != nil {
		return "", domain.AgentCredential{}, fmt.Errorf("rotate agent credential: %w", err)
	}

	return token, cred, nil
}

// RevokeAgent revokes the agent and all of its active credentials atomically.
func (s *Service) RevokeAgent(ctx context.Context, agentID, actorID string) (domain.Agent, error) {
	agent, err := s.store.RevokeAgent(ctx, agentID, store.AuditInput{
		EventType: "agent_revoked",
		ActorID:   actorID,
		Metadata:  map[string]any{},
	})
	if err != nil {
		return domain.Agent{}, fmt.Errorf("revoke agent: %w", err)
	}
	return agent, nil
}

// AuthenticatedAgent is the trusted identity resolved from a valid,
// non-revoked agent credential belonging to a non-revoked agent.
type AuthenticatedAgent struct {
	AgentID      string
	OrgID        string
	OwnerUserID  string
	CredentialID string
}

// AuthenticateAgentToken resolves a plaintext token to the trusted identity
// (org, user, agent) it belongs to. This is what the proxy calls, per
// request, to derive identity from Proxy-Authorization instead of trusting
// client-supplied headers.
func (s *Service) AuthenticateAgentToken(ctx context.Context, token string) (AuthenticatedAgent, error) {
	cred, err := s.store.GetAgentCredentialByHash(ctx, HashAgentToken(token))
	if err != nil {
		var notFound domain.ErrNotFound
		if errors.As(err, &notFound) {
			return AuthenticatedAgent{}, ErrInvalidToken
		}
		return AuthenticatedAgent{}, fmt.Errorf("look up agent credential: %w", err)
	}
	if cred.Status != "active" {
		return AuthenticatedAgent{}, ErrCredentialRevoked
	}

	agent, err := s.store.GetAgent(ctx, cred.AgentID)
	if err != nil {
		return AuthenticatedAgent{}, fmt.Errorf("look up agent: %w", err)
	}
	if agent.Status != "active" {
		return AuthenticatedAgent{}, ErrAgentRevoked
	}

	org, err := s.store.GetOrganization(ctx, agent.OrgID)
	if err != nil {
		return AuthenticatedAgent{}, fmt.Errorf("look up organization: %w", err)
	}
	if org.Status != "active" {
		return AuthenticatedAgent{}, ErrOrgSuspended
	}

	if err := s.store.TouchAgentCredentialLastUsed(ctx, cred.ID); err != nil {
		return AuthenticatedAgent{}, fmt.Errorf("touch agent credential: %w", err)
	}
	if err := s.store.TouchAgentLastSeen(ctx, agent.ID); err != nil {
		return AuthenticatedAgent{}, fmt.Errorf("touch agent last_seen_at: %w", err)
	}

	return AuthenticatedAgent{
		AgentID:      agent.ID,
		OrgID:        agent.OrgID,
		OwnerUserID:  agent.OwnerUserID,
		CredentialID: cred.ID,
	}, nil
}
