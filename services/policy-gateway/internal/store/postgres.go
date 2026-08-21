// Package store holds the Postgres persistence layer. The implementation is
// split by domain across postgres_*.go files (requests, rules, audit,
// directory, credentials, gateways); this file holds the pool itself and the
// helpers shared across all of them.
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Postgres struct {
	pool *pgxpool.Pool
}

func NewPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("create postgres pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	return &Postgres{pool: pool}, nil
}

func (p *Postgres) Close() {
	p.pool.Close()
}

func (p *Postgres) Ping(ctx context.Context) error {
	return p.pool.Ping(ctx)
}

// normalizePage applies the default/max limit and floors offset, shared by
// every paginated list endpoint (users, agents, rules, requests, audit).
func normalizePage(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

type queryExecutor interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

type pgxRow interface {
	Scan(dest ...any) error
}

type pgxRows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
}

func isNoRows(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
