package main

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const historyTimeout = 10 * time.Second
const historyCacheTTL = 30 * time.Second

type historyResult struct {
	rows [][]int64
	at   time.Time
}

// Cache only the small, aggregated graph, never all minute samples. A single
// cancellable gate coalesces concurrent dashboards and bounds expensive scans.
type historyCache struct {
	once    sync.Once
	gate    chan struct{}
	entries map[string]historyResult
}

func (a *App) historyRows(ctx context.Context, key, query string, args []any, columns int) ([][]int64, error) {
	key = fmt.Sprintf("%d/%s", a.historyEpoch.Load(), key)
	ctx, cancel := context.WithTimeout(ctx, historyTimeout)
	defer cancel()
	h := &a.history
	h.once.Do(func() { h.gate = make(chan struct{}, 1); h.entries = make(map[string]historyResult) })
	select {
	case h.gate <- struct{}{}:
		defer func() { <-h.gate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cached, ok := h.entries[key]; ok && time.Since(cached.at) < historyCacheTTL {
		return cached.rows, nil
	}
	rows, err := a.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([][]int64, 0, 61)
	for rows.Next() {
		point := make([]int64, columns)
		dest := make([]any, columns)
		for i := range point {
			dest[i] = &point[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		out = append(out, point)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// The map is bounded even if a caller asks for many route/hour combinations.
	for k, v := range h.entries {
		if time.Since(v.at) >= historyCacheTTL {
			delete(h.entries, k)
		}
	}
	if len(h.entries) >= 64 {
		clear(h.entries)
	}
	h.entries[key] = historyResult{rows: out, at: time.Now()}
	return out, nil
}
