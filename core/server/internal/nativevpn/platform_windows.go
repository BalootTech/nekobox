//go:build windows

package nativevpn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"nekobox_core/internal/boxdns/winipcfg"

	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/sys/windows"
)

var nativeConnections = connectionPool{connect: connectWindows}

// IP_UNICAST_IF from ws2ipdef.h is not exported by x/sys/windows.
const ipUnicastIF = 31

var (
	rasDLL       = windows.NewLazySystemDLL("rasapi32.dll")
	rasDial      = rasDLL.NewProc("RasDialW")
	rasHangUp    = rasDLL.NewProc(rasHangUpName)
	rasStatus    = rasDLL.NewProc("RasGetConnectStatusW")
	rasErrorText = rasDLL.NewProc("RasGetErrorStringW")
	pendingDials sync.Map
	dialID       atomic.Uint64
	rasNotify    = windows.NewCallback(func(id uintptr, _ uint32, _ uintptr, _ uint32, state uint32, code uint32, _ uint32) uintptr {
		if value, ok := pendingDials.Load(id); ok {
			if code != 0 || state == rasConnected {
				select {
				case value.(chan uint32) <- uint32(code):
				default:
				}
			}
			return 1
		}
		return 0
	})
)

const createProfileScript = `
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new()
$o = [Console]::In.ReadToEnd() | ConvertFrom-Json
if (Get-VpnConnection -Name $o.name -ErrorAction SilentlyContinue) { throw 'Generated VPN name already exists' }
$p = @{Name=$o.name; ServerAddress=$o.server; TunnelType=$o.protocol; AuthenticationMethod=$o.authentication; SplitTunneling=$true; RememberCredential=$false; UseWinlogonCredential=$false; Force=$true; ErrorAction='Stop'; WarningAction='SilentlyContinue'}
if ($o.protocol -eq 'L2tp') { $p.L2tpPsk=$o.psk; $p.EncryptionLevel='Optional' } else { $p.EncryptionLevel='Required' }
Add-VpnConnection @p | Out-Null
`

const removeProfileScript = `
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new()
$o = [Console]::In.ReadToEnd() | ConvertFrom-Json
if (Get-VpnConnection -Name $o.name -ErrorAction SilentlyContinue) { Remove-VpnConnection -Name $o.name -Force -ErrorAction Stop | Out-Null }
`

func runPowerShell(ctx context.Context, script string, input any) error {
	units := utf16.Encode([]rune(script))
	encoded := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(encoded[i*2:], unit)
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return err
	}
	program := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	command := exec.CommandContext(ctx, program, "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded))
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	// Account secrets are never command-line arguments or executable script text.
	command.Stdin = strings.NewReader(string(payload))
	output, err := command.CombinedOutput()
	if err != nil {
		message := string(output)
		if secrets, ok := input.(map[string]string); ok {
			for _, key := range []string{"psk", "password"} {
				if secrets[key] != "" {
					message = strings.ReplaceAll(message, secrets[key], "[redacted]")
				}
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("Windows VPN profile operation: %w: %s", err, strings.TrimSpace(message))
	}
	return nil
}

func rasError(code uintptr) error {
	text := make([]uint16, 512)
	if result, _, _ := rasErrorText.Call(code, uintptr(unsafe.Pointer(&text[0])), uintptr(len(text))); result == 0 {
		return fmt.Errorf("Windows VPN error %d: %s", code, windows.UTF16ToString(text))
	}
	return fmt.Errorf("Windows VPN error %d", code)
}

func copyCredential(destination []uint16, value string) error {
	encoded, err := windows.UTF16FromString(value)
	if err != nil || len(encoded) > len(destination) {
		return errors.New("Windows VPN credential exceeds its native field size")
	}
	copy(destination, encoded)
	return nil
}

func dialWindows(ctx context.Context, name string, options Options, physical int) (windows.Handle, error) {
	params := rasDialParams{InterfaceIndex: uint32(physical)}
	params.Size = uint32(unsafe.Sizeof(params))
	username, domain := options.Username, ""
	if before, after, ok := strings.Cut(username, `\`); ok {
		domain, username = before, after
	}
	for _, field := range []struct {
		target []uint16
		value  string
	}{
		{params.EntryName[:], name}, {params.Username[:], username},
		{params.Password[:], options.Password}, {params.Domain[:], domain},
	} {
		if err := copyCredential(field.target, field.value); err != nil {
			return 0, err
		}
	}
	defer func() {
		for i := range params.Password {
			params.Password[i] = 0
		}
	}()
	id := uintptr(dialID.Add(1))
	params.CallbackID.set(id)
	result := make(chan uint32, 1)
	pendingDials.Store(id, result)
	defer pendingDials.Delete(id)
	var handle windows.Handle
	code, _, _ := rasDial.Call(0, 0, uintptr(unsafe.Pointer(&params)), 2, rasNotify, uintptr(unsafe.Pointer(&handle)))
	if code != 0 {
		return handle, rasError(code)
	}
	select {
	case code := <-result:
		if code != 0 {
			return handle, rasError(uintptr(code))
		}
		return handle, nil
	case <-ctx.Done():
		return handle, ctx.Err()
	}
}

// Only normal physical default routes are candidates for the VPN underlay.
// VPN/TUN-specific routes never become the underlay of a new Windows tunnel.
func physicalRoute(preferred int) (winipcfg.MibIPforwardRow2, uint32, error) {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return winipcfg.MibIPforwardRow2{}, 0, err
	}
	var best *winipcfg.MibIPforwardRow2
	var bestCost uint64
	for i := range rows {
		row := &rows[i]
		if row.DestinationPrefix.Prefix() != netip.MustParsePrefix("0.0.0.0/0") || row.NextHop.Addr().IsUnspecified() {
			continue
		}
		iface, lookupErr := net.InterfaceByIndex(int(row.InterfaceIndex))
		if lookupErr != nil || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		ipInterface, lookupErr := row.InterfaceLUID.IPInterface(windows.AF_INET)
		if lookupErr != nil {
			continue
		}
		cost := uint64(row.Metric) + uint64(ipInterface.Metric)
		if best == nil || (int(row.InterfaceIndex) == preferred && int(best.InterfaceIndex) != preferred) || (int(row.InterfaceIndex) == int(best.InterfaceIndex) && cost < bestCost) || (preferred == 0 && cost < bestCost) {
			best, bestCost = row, cost
		}
	}
	if best == nil || bestCost > 1<<30 {
		return winipcfg.MibIPforwardRow2{}, 0, errors.New("cannot find a physical IPv4 default route for Windows VPN")
	}
	return *best, uint32(bestCost) + 10000, nil
}

type routeLease struct {
	key  string
	once sync.Once
}
type leasedRoute struct {
	row   *winipcfg.MibIPforwardRow2
	refs  int
	owned bool
}

var hostRoutes = struct {
	sync.Mutex
	rows map[string]*leasedRoute
}{rows: make(map[string]*leasedRoute)}

func acquireHostRoute(underlay winipcfg.MibIPforwardRow2, server netip.Addr) (*routeLease, error) {
	key := fmt.Sprintf("%d/%s/%s", underlay.InterfaceLUID, server, underlay.NextHop.Addr())
	hostRoutes.Lock()
	defer hostRoutes.Unlock()
	if route := hostRoutes.rows[key]; route != nil {
		route.refs++
		return &routeLease{key: key}, nil
	}
	row := &winipcfg.MibIPforwardRow2{}
	row.Init()
	row.InterfaceLUID = underlay.InterfaceLUID
	_ = row.DestinationPrefix.SetPrefix(netip.PrefixFrom(server, 32))
	row.NextHop = underlay.NextHop
	row.Metric = 0
	err := row.Create()
	owned := err == nil
	if err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return nil, err
	}
	hostRoutes.rows[key] = &leasedRoute{row: row, refs: 1, owned: owned}
	return &routeLease{key: key}, nil
}

func (l *routeLease) close() error {
	var err error
	l.once.Do(func() {
		hostRoutes.Lock()
		defer hostRoutes.Unlock()
		row := hostRoutes.rows[l.key]
		if row == nil {
			return
		}
		row.refs--
		if row.refs == 0 {
			delete(hostRoutes.rows, l.key)
			if row.owned {
				err = row.row.Delete()
			}
		}
	})
	return err
}

type windowsConnection struct {
	name         string
	handle       windows.Handle
	address      netip.Addr
	index        int
	created      bool
	defaultRoute *winipcfg.MibIPforwardRow2
	hostRoute    *routeLease
	closed       atomic.Bool
}

func connectPlatform(ctx context.Context, options Options, physical int) (platformConnection, error) {
	route, _, err := physicalRoute(physical)
	if err != nil {
		return nil, err
	}
	return nativeConnections.acquire(ctx, options, int(route.InterfaceIndex))
}

func preparePlatform(ctx context.Context, options Options, physical int) (Options, int, error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return options, physical, errors.New("PPTP/L2TP routing requires running NekoBox as administrator")
	}
	route, _, err := physicalRoute(physical)
	if err != nil {
		return options, physical, err
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", options.Server)
	if err != nil {
		return options, physical, fmt.Errorf("resolve Windows VPN server: %w", err)
	}
	if len(addresses) == 0 {
		return options, physical, errors.New("Windows VPN server has no IPv4 address")
	}
	options.ResolvedServer = addresses[0].Unmap().String()
	return options, int(route.InterfaceIndex), nil
}

func connectWindows(ctx context.Context, options Options, physical int) (_ platformConnection, resultErr error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return nil, errors.New("PPTP/L2TP routing requires running NekoBox as administrator")
	}
	underlay, metric, err := physicalRoute(physical)
	if err != nil {
		return nil, err
	}
	server, err := netip.ParseAddr(options.ResolvedServer)
	if err != nil || !server.Is4() {
		return nil, errors.New("Windows VPN server was not resolved before starting")
	}
	identifier := make([]byte, 12)
	if _, err = rand.Read(identifier); err != nil {
		return nil, err
	}
	c := &windowsConnection{name: "NekoBox-" + hex.EncodeToString(identifier)}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, c.Close())
		}
	}()
	c.hostRoute, err = acquireHostRoute(underlay, server)
	if err != nil {
		return nil, fmt.Errorf("protect VPN server route: %w", err)
	}
	protocol, auth := "Pptp", "MSChapv2"
	if options.Protocol == "l2tp" {
		protocol = "L2tp"
	}
	if options.Authentication == "pap" {
		auth = "Pap"
	} else if options.Authentication == "chap" {
		auth = "Chap"
	}
	c.created = true
	err = runPowerShell(ctx, createProfileScript, map[string]string{"name": c.name, "server": server.String(), "protocol": protocol, "authentication": auth, "psk": options.PSK})
	if err != nil {
		return nil, err
	}
	c.handle, err = dialWindows(ctx, c.name, options, int(underlay.InterfaceIndex))
	if err != nil {
		return nil, err
	}
	for {
		iface, findErr := net.InterfaceByName(c.name)
		if findErr == nil {
			interfaceAddresses, _ := iface.Addrs()
			for _, value := range interfaceAddresses {
				if prefix, parseErr := netip.ParsePrefix(value.String()); parseErr == nil && prefix.Addr().Is4() {
					c.address = prefix.Addr()
					c.index = iface.Index
					break
				}
			}
			if c.address.IsValid() {
				break
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	luid, err := winipcfg.LUIDFromIndex(uint32(c.index))
	if err != nil {
		return nil, err
	}
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		ipInterface, queryErr := luid.IPInterface(family)
		if queryErr != nil {
			if family == windows.AF_INET {
				return nil, queryErr
			}
			continue
		}
		ipInterface.UseAutomaticMetric = false
		ipInterface.Metric = 5000
		if err = ipInterface.Set(); err != nil && family == windows.AF_INET {
			return nil, fmt.Errorf("set VPN interface metric: %w", err)
		}
	}
	row := &winipcfg.MibIPforwardRow2{}
	row.Init()
	row.InterfaceLUID = luid
	_ = row.DestinationPrefix.SetPrefix(netip.MustParsePrefix("0.0.0.0/0"))
	_ = row.NextHop.SetAddr(netip.IPv4Unspecified())
	row.Metric = metric
	if err = row.Create(); err != nil {
		return nil, fmt.Errorf("create nonpreferred VPN route: %w", err)
	}
	c.defaultRoute = row
	return c, nil
}

func (c *windowsConnection) check() error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	status := rasConnectStatus{}
	status.Size = uint32(unsafe.Sizeof(status))
	code, _, _ := rasStatus.Call(uintptr(c.handle), uintptr(unsafe.Pointer(&status)))
	if code != 0 {
		return rasError(code)
	}
	if status.State != rasConnected {
		return errors.New("Windows VPN is disconnected")
	}
	return nil
}

func (c *windowsConnection) control(_ string, _ string, raw syscall.RawConn) error {
	var err error
	if outer := raw.Control(func(fd uintptr) {
		err = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIF, int(bits.ReverseBytes32(uint32(c.index))))
	}); outer != nil {
		return outer
	}
	return err
}

func (c *windowsConnection) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	if !destination.Addr.Is4() {
		return nil, errors.New("PPTP/L2TP outbound supports IPv4 destinations")
	}
	dialer := net.Dialer{Control: c.control}
	if network == "tcp" {
		dialer.LocalAddr = &net.TCPAddr{IP: c.address.AsSlice()}
		network = "tcp4"
	} else if network == "udp" {
		dialer.LocalAddr = &net.UDPAddr{IP: c.address.AsSlice()}
		network = "udp4"
	} else {
		return nil, fmt.Errorf("unsupported Windows VPN network: %s", network)
	}
	return dialer.DialContext(ctx, network, destination.String())
}

func (c *windowsConnection) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	if destination.Addr.IsValid() && !destination.Addr.Is4() {
		return nil, errors.New("PPTP/L2TP outbound supports IPv4 destinations")
	}
	listener := net.ListenConfig{Control: c.control}
	return listener.ListenPacket(ctx, "udp4", net.JoinHostPort(c.address.String(), "0"))
}

func (c *windowsConnection) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	var errs []error
	if c.defaultRoute != nil {
		if err := c.defaultRoute.Delete(); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
			errs = append(errs, err)
		}
	}
	if c.handle != 0 {
		rasHangUp.Call(uintptr(c.handle))
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			status := rasConnectStatus{}
			status.Size = uint32(unsafe.Sizeof(status))
			if code, _, _ := rasStatus.Call(uintptr(c.handle), uintptr(unsafe.Pointer(&status))); code != 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	if c.created {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := runPowerShell(ctx, removeProfileScript, map[string]string{"name": c.name})
		cancel()
		if err != nil {
			errs = append(errs, err)
		}
	}
	if c.hostRoute != nil {
		if err := c.hostRoute.close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
