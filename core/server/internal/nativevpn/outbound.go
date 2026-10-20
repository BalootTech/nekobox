package nativevpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// Context registers application-owned native protocols before JSON decoding.
func Context(ctx context.Context) context.Context {
	ctx = include.Context(ctx)
	registry := service.FromContext[adapter.OutboundRegistry](ctx).(*outbound.Registry)
	outbound.Register[Options](registry, "windows-vpn", NewOutbound)
	return ctx
}

type platformConnection interface {
	N.Dialer
	Close() error
}

type Outbound struct {
	outbound.Adapter
	ctx     context.Context
	cancel  context.CancelFunc
	options Options
	logger  log.ContextLogger
	network adapter.NetworkManager
	dns     adapter.DNSRouter
	ready   chan struct{}
	done    chan struct{}
	access  sync.Mutex
	conn    platformConnection
	err     error
	started bool
}

func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options Options) (adapter.Outbound, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	return &Outbound{
		Adapter: outbound.NewAdapter("windows-vpn", tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
		ctx:     ctx, cancel: cancel, options: options, logger: logger,
		network: service.FromContext[adapter.NetworkManager](ctx),
		dns:     service.FromContext[adapter.DNSRouter](ctx),
		ready:   make(chan struct{}), done: make(chan struct{}),
	}, nil
}

func (o *Outbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	var physicalIndex int
	if o.network != nil {
		if iface := o.network.DefaultNetworkInterface(); iface != nil {
			physicalIndex = iface.Index
		}
	}
	// Resolve the VPN gateway before a newly created TUN can capture OS DNS.
	prepareCtx, finishPrepare := context.WithTimeout(o.ctx, 5*time.Second)
	options, physicalIndex, err := preparePlatform(prepareCtx, o.options, physicalIndex)
	finishPrepare()
	if err != nil {
		return err
	}
	o.options = options
	o.access.Lock()
	o.started = true
	o.access.Unlock()
	go func() {
		defer close(o.done)
		ctx, cancel := context.WithTimeout(o.ctx, time.Duration(o.options.ConnectTimeout)*time.Second)
		defer cancel()
		conn, err := connectPlatform(ctx, o.options, physicalIndex)
		o.access.Lock()
		o.conn, o.err = conn, err
		o.access.Unlock()
		close(o.ready)
		if err != nil {
			o.logger.Error("Windows VPN connection failed: ", err)
		} else {
			o.logger.Info("Windows ", o.options.Protocol, " tunnel ready; application routing is active")
		}
	}()
	return nil
}

func (o *Outbound) WaitReady(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-o.ctx.Done():
		return o.ctx.Err()
	case <-o.ready:
	}
	o.access.Lock()
	defer o.access.Unlock()
	return o.err
}

func (o *Outbound) connection(ctx context.Context) (platformConnection, error) {
	if err := o.WaitReady(ctx); err != nil {
		return nil, err
	}
	o.access.Lock()
	defer o.access.Unlock()
	if o.conn == nil {
		return nil, errors.New("Windows VPN has stopped")
	}
	return o.conn, nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := o.connection(ctx)
	if err != nil {
		return nil, err
	}
	if !destination.IsDomain() {
		return conn.DialContext(ctx, network, destination)
	}
	addresses, err := o.dns.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only})
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, addr := range addresses {
		if !addr.Is4() {
			continue
		}
		destination.Addr, destination.Fqdn = addr, ""
		stream, dialErr := conn.DialContext(ctx, network, destination)
		if dialErr == nil {
			return stream, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = errors.New("Windows VPN destination has no IPv4 address")
	}
	return nil, lastErr
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, _, err := o.ListenPacketWithDestination(ctx, destination)
	return conn, err
}

func (o *Outbound) ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	conn, err := o.connection(ctx)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if destination.IsDomain() {
		addresses, lookupErr := o.dns.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only})
		if lookupErr != nil {
			return nil, netip.Addr{}, lookupErr
		}
		if len(addresses) == 0 {
			return nil, netip.Addr{}, errors.New("Windows VPN destination has no IPv4 address")
		}
		destination.Addr, destination.Fqdn = addresses[0], ""
	}
	packet, err := conn.ListenPacket(ctx, destination)
	return packet, destination.Addr, err
}

func (o *Outbound) Close() error {
	o.cancel()
	o.access.Lock()
	started := o.started
	o.access.Unlock()
	if !started {
		return nil
	}
	<-o.done
	o.access.Lock()
	conn := o.conn
	o.conn = nil
	o.access.Unlock()
	if conn != nil {
		if err := conn.Close(); err != nil {
			return fmt.Errorf("close Windows VPN: %w", err)
		}
	}
	return nil
}
