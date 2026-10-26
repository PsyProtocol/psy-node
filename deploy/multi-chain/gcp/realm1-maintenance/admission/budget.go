package main

import (
	"context"
	"errors"
	"io"
	"sync"
)

// Charge conservatively for input buffers, JSON decoder copies and batch output.
// Small messages retain headroom even when a large upload consumes bulk capacity.
const bufferBudget = 768 << 20
const smallMessageReserve = 16 << 20
const maxBatch = 1024

type budget struct {
	mu   sync.Mutex
	used int64
}
type leaseKey struct{}
type lease struct {
	mu      sync.Mutex
	pool    *budget
	charged int64
}

func (g *gate) withLease(ctx context.Context) (context.Context, *lease) {
	l := &lease{pool: &g.buffers}
	return context.WithValue(ctx, leaseKey{}, l), l
}

func (l *lease) reserve(n int, large bool) error {
	charge := int64(n) * 8
	l.pool.mu.Lock()
	defer l.pool.mu.Unlock()
	limit := int64(bufferBudget)
	if large {
		limit -= smallMessageReserve
	}
	if l.pool.used+charge > limit {
		return errors.New("admission buffering capacity exceeded")
	}
	l.pool.used += charge
	l.mu.Lock()
	l.charged += charge
	l.mu.Unlock()
	return nil
}

func (l *lease) release() {
	l.pool.mu.Lock()
	defer l.pool.mu.Unlock()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pool.used -= l.charged
	l.charged = 0
}

func bufferedRead(ctx context.Context, r io.Reader, limit int64) ([]byte, error) {
	l, _ := ctx.Value(leaseKey{}).(*lease)
	if l == nil {
		return nil, errors.New("buffer lease required")
	}
	buf := make([]byte, 32<<10)
	var out []byte
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if int64(len(out)+n) > limit {
				return nil, errors.New("payload limit exceeded")
			}
			if e := l.reserve(n, len(out)+n > 64<<10); e != nil {
				return nil, e
			}
			out = append(out, buf[:n]...)
		}
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
}
