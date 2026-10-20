package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestURLTestWaitsForTunnel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var connected atomic.Bool
	changed := make(chan struct{})
	go func() {
		time.Sleep(20 * time.Millisecond)
		connected.Store(true)
		close(changed)
	}()
	err := waitURLTestReady(ctx, func() (bool, error) { return connected.Load(), nil }, func() <-chan struct{} { return changed })
	if err != nil || !connected.Load() {
		t.Fatalf("returned before the tunnel connected: %v", err)
	}
}

func TestURLTestReadinessWithoutNotification(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var connected atomic.Bool
	go func() {
		time.Sleep(20 * time.Millisecond)
		connected.Store(true)
	}()
	err := waitURLTestReady(ctx, func() (bool, error) { return connected.Load(), nil }, func() <-chan struct{} { return nil })
	if err != nil || !connected.Load() {
		t.Fatalf("did not observe late native readiness: %v", err)
	}
}

func TestURLTestReadinessSnapshot(t *testing.T) {
	connected := false
	err := waitURLTestReady(context.Background(), func() (bool, error) { return connected, nil }, func() <-chan struct{} {
		connected = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestURLTestReadinessTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := waitURLTestReady(ctx, func() (bool, error) { return false, nil }, func() <-chan struct{} { return nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected a bounded startup timeout, got %v", err)
	}
}

func TestURLTestReadinessCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := waitURLTestReady(ctx, func() (bool, error) {
		t.Fatal("queried the tunnel after cancellation")
		return false, nil
	}, func() <-chan struct{} { return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestURLTestReadinessAuthenticationFailure(t *testing.T) {
	authFailure := errors.New("authentication rejected")
	err := waitURLTestReady(context.Background(), func() (bool, error) { return false, authFailure }, func() <-chan struct{} { return nil })
	if !errors.Is(err, authFailure) {
		t.Fatalf("authentication failure was hidden: %v", err)
	}
}
