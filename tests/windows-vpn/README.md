# Windows PPTP and L2TP/IPsec

The `pptp` and `l2tp` profile editors produce the application-owned
`windows-vpn` outbound. L2TP uses an IPsec pre-shared key. The Windows built-in
VPN client establishes the PPP/IPsec connection; NekoBox's router selects
traffic before the outbound binds TCP and UDP sockets to the VPN interface.
IPv4 destinations are supported. Administrator privileges are required for
interface-specific routing.

Native VPN setup only runs in `Start`, never when importing or checking a
configuration. Each managed connection uses a uniquely named Windows profile
with split tunneling. Account passwords are passed directly to `RasDialW`;
PSKs are passed to the built-in VpnClient cmdlet on standard input, never as
process arguments. On shutdown the application removes its routes and profile.
Connections shared by an active profile and a URL test are reference counted,
so finishing a test does not disconnect the active profile.

The Go tests exercise option validation, configuration-only construction,
shared connection lifetime, separate accounts and startup cancellation:

```sh
cd core/server
go test -tags with_openvpn,with_gvisor ./internal/nativevpn
```

The Windows packaging workflow compiles `ras_abi.cpp` with the installed Windows
SDK and compares its structure sizes and member offsets to the Go RAS bindings.
This catches pointer packing differences before shipping Win64 binaries. The
Qt object compile checks also compile the actual native VPN model and editor.

A supplied PPTP/L2TP server account is still needed for end-to-end tests of
authentication, IPsec negotiation and routing through the provider.
