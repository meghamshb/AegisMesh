// Package policycache is the data-plane client half of Phase 5.9's gateway
// policy synchronization: it fetches an org-scoped, versioned policy
// snapshot from the control plane, holds it in memory, and refreshes it on
// an interval - failing closed at cold start and falling back to
// last-known-good (up to a configurable staleness ceiling) if the control
// plane becomes temporarily unreachable afterward.
package policycache

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
)

// Fetcher retrieves the current policy snapshot from the control plane.
// The HTTP implementation lives in fetcher.go; tests supply their own.
type Fetcher interface {
	FetchSnapshot(ctx context.Context) (domain.PolicySnapshot, error)
}

// Cache holds the most recently fetched policy snapshot and refreshes it in
// the background. All methods are safe for concurrent use.
type Cache struct {
	fetcher  Fetcher
	maxStale time.Duration
	logger   *slog.Logger

	mu       sync.RWMutex
	snapshot domain.PolicySnapshot
	loadedAt time.Time
	loaded   bool
}

func New(fetcher Fetcher, maxStale time.Duration, logger *slog.Logger) *Cache {
	if logger == nil {
		logger = slog.Default()
	}
	return &Cache{fetcher: fetcher, maxStale: maxStale, logger: logger}
}

// Start performs the initial snapshot fetch and then refreshes on the given
// interval until ctx is done. Per Phase 5.9.9, a gateway must fail closed at
// cold start: if the initial fetch fails, Start returns an error and the
// caller must not begin proxying traffic.
func (c *Cache) Start(ctx context.Context, refreshInterval time.Duration) error {
	if err := c.refresh(ctx); err != nil {
		return fmt.Errorf("initial policy snapshot fetch failed, failing closed: %w", err)
	}

	go func() {
		ticker := time.NewTicker(refreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := c.refresh(ctx); err != nil {
					c.logger.Warn("policy snapshot refresh failed, serving last-known-good policy",
						"error", err, "cache_age", time.Since(c.loadedAtSnapshot()))
				}
			}
		}
	}()
	return nil
}

func (c *Cache) refresh(ctx context.Context) error {
	snap, err := c.fetcher.FetchSnapshot(ctx)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.snapshot = snap
	c.loadedAt = time.Now()
	c.loaded = true
	c.mu.Unlock()
	return nil
}

func (c *Cache) loadedAtSnapshot() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.loadedAt
}

// Rules returns the cached rule set. ok is false if nothing has ever loaded
// successfully, or if the cache has gone stale beyond maxStale - either way
// the caller must fail closed rather than evaluate against unknown/expired
// policy.
func (c *Cache) Rules() (rules []domain.PolicyRule, ok bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.loaded {
		return nil, false
	}
	if c.maxStale > 0 && time.Since(c.loadedAt) > c.maxStale {
		return nil, false
	}
	return c.snapshot.Rules, true
}

// Health reports the cache's current state for a /health-style response.
func (c *Cache) Health() map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.loaded {
		return map[string]any{
			"version": int64(0),
			"stale":   true,
			"loaded":  false,
		}
	}
	age := time.Since(c.loadedAt)
	stale := c.maxStale > 0 && age > c.maxStale
	return map[string]any{
		"version":     c.snapshot.Version,
		"age_seconds": int(age.Seconds()),
		"stale":       stale,
		"loaded":      true,
	}
}
