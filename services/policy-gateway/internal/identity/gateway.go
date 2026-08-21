package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/store"
)

var (
	// ErrInvalidGatewayToken means the token does not match any known gateway.
	ErrInvalidGatewayToken = errors.New("invalid gateway token")
	// ErrGatewayRevoked means the token maps to a real but revoked gateway.
	ErrGatewayRevoked = errors.New("gateway revoked")
)

type RegisterGatewayInput struct {
	OrgID    string
	Name     string
	Metadata map[string]any
}

// RegisterGateway creates the gateway row and issues its one credential.
// Gateway credentials are a distinct trust domain from agent credentials:
// this token authenticates the gateway process to the control plane, not
// an individual Hermes agent.
func (s *Service) RegisterGateway(ctx context.Context, in RegisterGatewayInput) (domain.Gateway, string, error) {
	token, err := GenerateGatewayToken()
	if err != nil {
		return domain.Gateway{}, "", err
	}

	gw, err := s.store.RegisterGateway(ctx, store.RegisterGatewayInput{
		OrgID:            in.OrgID,
		Name:             in.Name,
		CredentialPrefix: GatewayTokenDisplayPrefix(token),
		CredentialHash:   HashToken(token),
		Metadata:         in.Metadata,
	})
	if err != nil {
		return domain.Gateway{}, "", fmt.Errorf("register gateway: %w", err)
	}
	return gw, token, nil
}

// AuthenticateGatewayToken resolves a plaintext gateway credential to the
// gateway's trusted identity (which org it may act for). The proxied
// snapshot/heartbeat/agent-authenticate endpoints all derive org_id this
// way rather than trusting a client-supplied value.
func (s *Service) AuthenticateGatewayToken(ctx context.Context, token string) (domain.AuthenticatedGateway, error) {
	gw, err := s.store.GetGatewayByCredentialHash(ctx, HashToken(token))
	if err != nil {
		var notFound domain.ErrNotFound
		if errors.As(err, &notFound) {
			return domain.AuthenticatedGateway{}, ErrInvalidGatewayToken
		}
		return domain.AuthenticatedGateway{}, fmt.Errorf("look up gateway credential: %w", err)
	}
	if gw.Status != "active" {
		return domain.AuthenticatedGateway{}, ErrGatewayRevoked
	}
	return domain.AuthenticatedGateway{GatewayID: gw.ID, OrgID: gw.OrgID}, nil
}

// Heartbeat records that a gateway is alive and (optionally) which policy
// version/binary version/metadata it currently holds.
func (s *Service) Heartbeat(ctx context.Context, gatewayID string, in store.GatewayHeartbeatInput) (domain.Gateway, error) {
	gw, err := s.store.UpdateGatewayHeartbeat(ctx, gatewayID, in)
	if err != nil {
		return domain.Gateway{}, fmt.Errorf("gateway heartbeat: %w", err)
	}
	return gw, nil
}
