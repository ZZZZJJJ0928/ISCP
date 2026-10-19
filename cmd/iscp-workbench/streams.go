package main

import (
	"context"
	"errors"
	"sync"
)

type pipeStreams struct {
	mu   sync.Mutex
	live map[string]context.CancelFunc
	seen map[string]bool
}

func newPipeStreams() *pipeStreams {
	return &pipeStreams{live: map[string]context.CancelFunc{}, seen: map[string]bool{}}
}
func (p *pipeStreams) open(ctx context.Context, id string) (context.Context, func(), error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen[id] {
		return nil, nil, errors.New("reused IPC stream identifier")
	}
	p.seen[id] = true
	ctx, cancel := context.WithCancel(ctx)
	p.live[id] = cancel
	return ctx, func() { cancel(); p.mu.Lock(); delete(p.live, id); p.mu.Unlock() }, nil
}
func (p *pipeStreams) cancel(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if cancel := p.live[id]; cancel != nil {
		cancel()
	}
}
func (p *pipeStreams) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, cancel := range p.live {
		cancel()
	}
}
