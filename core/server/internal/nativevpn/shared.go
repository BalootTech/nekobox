package nativevpn

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// A URL test in another Box must not disconnect or re-create an active Windows
// connection using the same account. Only the last user releases OS resources.
type connectionPool struct {
	mu       sync.Mutex
	sessions map[[32]byte]*sharedConnection
	connect  func(context.Context, Options, int) (platformConnection, error)
}

type sharedConnection struct {
	refs   int
	ready  chan struct{}
	cancel context.CancelFunc
	conn   platformConnection
	err    error
}

type connectionLease struct {
	platformConnection
	pool *connectionPool
	key  [32]byte
	once sync.Once
}

func (p *connectionPool) acquire(ctx context.Context, options Options, physicalIndex int) (platformConnection, error) {
	encoded, _ := json.Marshal(struct {
		Options
		Interface int
	}{options, physicalIndex})
	key := sha256.Sum256(encoded)
	p.mu.Lock()
	if p.sessions == nil {
		p.sessions = make(map[[32]byte]*sharedConnection)
	}
	session := p.sessions[key]
	if session == nil {
		connectCtx, cancel := context.WithTimeout(context.Background(), time.Duration(options.ConnectTimeout)*time.Second)
		session = &sharedConnection{ready: make(chan struct{}), cancel: cancel}
		p.sessions[key] = session
		go func(s *sharedConnection) {
			conn, err := p.connect(connectCtx, options, physicalIndex)
			cancel()
			p.mu.Lock()
			s.conn, s.err = conn, err
			unused := s.refs == 0
			close(s.ready)
			p.mu.Unlock()
			if unused && conn != nil {
				_ = conn.Close()
			}
		}(session)
	}
	session.refs++
	p.mu.Unlock()
	select {
	case <-ctx.Done():
		p.release(key, session)
		return nil, ctx.Err()
	case <-session.ready:
	}
	if session.err != nil {
		p.release(key, session)
		return nil, session.err
	}
	return &connectionLease{platformConnection: session.conn, pool: p, key: key}, nil
}

func (p *connectionPool) release(key [32]byte, session *sharedConnection) error {
	p.mu.Lock()
	if session == nil {
		session = p.sessions[key]
	}
	if session == nil {
		p.mu.Unlock()
		return nil
	}
	session.refs--
	if session.refs != 0 {
		p.mu.Unlock()
		return nil
	}
	if p.sessions[key] == session {
		delete(p.sessions, key)
	}
	session.cancel()
	var conn platformConnection
	select {
	case <-session.ready:
		conn = session.conn
	default:
	}
	p.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (l *connectionLease) Close() error {
	var err error
	l.once.Do(func() { err = l.pool.release(l.key, nil) })
	if err != nil {
		return fmt.Errorf("release native VPN connection: %w", err)
	}
	return nil
}
