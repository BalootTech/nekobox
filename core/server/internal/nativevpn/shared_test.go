package nativevpn

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

type mockConnection struct{ closes atomic.Int32 }

func (*mockConnection) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("unused")
}
func (*mockConnection) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unused")
}
func (m *mockConnection) Close() error { m.closes.Add(1); return nil }

func TestURLTestReusesActiveNativeVPN(t *testing.T) {
	var calls atomic.Int32
	conn := &mockConnection{}
	pool := connectionPool{connect: func(context.Context, Options, int) (platformConnection, error) { calls.Add(1); return conn, nil }}
	o := Options{Protocol: "l2tp", Server: "vpn.example.com", Username: "alice", PSK: "key", ConnectTimeout: 5}
	active, err := pool.acquire(context.Background(), o, 15)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := pool.acquire(context.Background(), o, 15)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("URL test started a second OS connection")
	}
	if err = probe.Close(); err != nil {
		t.Fatal(err)
	}
	if conn.closes.Load() != 0 {
		t.Fatal("URL test disconnected the active profile")
	}
	_ = probe.Close()
	_ = active.Close()
	if conn.closes.Load() != 1 {
		t.Fatalf("connection cleanup count: %d", conn.closes.Load())
	}
}

func TestDifferentAccountsDoNotShareNativeVPN(t *testing.T) {
	var calls atomic.Int32
	pool := connectionPool{connect: func(context.Context, Options, int) (platformConnection, error) {
		calls.Add(1)
		return &mockConnection{}, nil
	}}
	o := Options{Protocol: "pptp", Server: "vpn.example.com", Username: "alice", ConnectTimeout: 5}
	a, err := pool.acquire(context.Background(), o, 15)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	o.Username = "bob"
	b, err := pool.acquire(context.Background(), o, 15)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if calls.Load() != 2 {
		t.Fatal("different VPN credentials shared a connection")
	}
}

func TestCanceledNativeVPNStartupRollsBack(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	pool := connectionPool{connect: func(ctx context.Context, _ Options, _ int) (platformConnection, error) {
		close(started)
		<-ctx.Done()
		close(stopped)
		return nil, ctx.Err()
	}}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := pool.acquire(ctx, Options{ConnectTimeout: 5}, 15); result <- err }()
	<-started
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("startup cancellation: %v", err)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("orphaned Windows VPN startup")
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if len(pool.sessions) != 0 {
		t.Fatal("canceled VPN session remained registered")
	}
}
