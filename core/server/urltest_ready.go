package main

import (
	"context"
	"time"
)

// Wait before starting latency measurement. Snapshot the notification channel
// first so an update between the readiness check and select cannot be lost.
func waitURLTestReady(ctx context.Context, ready func() (bool, error), updated func() <-chan struct{}) error {
	poll := time.NewTicker(100 * time.Millisecond)
	defer poll.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		changed := updated()
		connected, err := ready()
		if err != nil || connected {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		case <-poll.C:
			// Some native state changes become visible just after notification.
		}
	}
}
