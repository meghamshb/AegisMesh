package policycache

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
)

// HTTPFetcher fetches the policy snapshot from a control-plane's internal
// API, authenticating with a gateway credential (Phase 5.9.6).
type HTTPFetcher struct {
	BaseURL      string
	GatewayToken string
	HTTPClient   *http.Client
}

func NewHTTPFetcher(baseURL, gatewayToken string) *HTTPFetcher {
	return &HTTPFetcher{
		BaseURL:      strings.TrimRight(baseURL, "/"),
		GatewayToken: gatewayToken,
		HTTPClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (f *HTTPFetcher) FetchSnapshot(ctx context.Context) (domain.PolicySnapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.BaseURL+"/api/internal/v1/policies/snapshot", nil)
	if err != nil {
		return domain.PolicySnapshot{}, fmt.Errorf("build snapshot request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+f.GatewayToken)

	resp, err := f.HTTPClient.Do(req)
	if err != nil {
		return domain.PolicySnapshot{}, fmt.Errorf("fetch policy snapshot: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return domain.PolicySnapshot{}, fmt.Errorf("fetch policy snapshot: unexpected status %d", resp.StatusCode)
	}

	var snap domain.PolicySnapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return domain.PolicySnapshot{}, fmt.Errorf("decode policy snapshot: %w", err)
	}
	return snap, nil
}
