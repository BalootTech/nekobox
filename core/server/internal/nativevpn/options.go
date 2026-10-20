package nativevpn

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf16"
)

type Options struct {
	Protocol       string `json:"protocol"`
	Server         string `json:"server"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	PSK            string `json:"psk,omitempty"`
	Authentication string `json:"authentication,omitempty"`
	ConnectTimeout int    `json:"connect_timeout,omitempty"`
	Detour         string `json:"detour,omitempty"`
	ResolvedServer string `json:"-"`
}

func (o *Options) validate() error {
	if o.Protocol != "pptp" && o.Protocol != "l2tp" {
		return errors.New("Windows VPN protocol must be pptp or l2tp")
	}
	if o.Detour != "" {
		return errors.New("PPTP/L2TP must be the first connection in a chain")
	}
	if o.Server == "" || strings.ContainsAny(o.Server, "\x00\r\n\t /\\:@") {
		return errors.New("Windows VPN requires a server hostname or IPv4 address without a port")
	}
	if addr, err := netip.ParseAddr(o.Server); err == nil && !addr.Is4() {
		return errors.New("Windows VPN requires an IPv4 server")
	}
	if o.Username == "" {
		return errors.New("Windows VPN username is required")
	}
	for name, value := range map[string]string{"username": o.Username, "password": o.Password, "PSK": o.PSK} {
		if strings.ContainsRune(value, 0) || len(utf16.Encode([]rune(value))) > 256 {
			return fmt.Errorf("Windows VPN %s exceeds the Windows credential limits", name)
		}
	}
	if o.Protocol == "l2tp" && o.PSK == "" {
		return errors.New("L2TP/IPsec pre-shared key is required")
	}
	if o.Authentication == "" {
		o.Authentication = "mschapv2"
	}
	if o.Authentication != "mschapv2" && o.Authentication != "pap" && o.Authentication != "chap" {
		return errors.New("Windows VPN authentication must be mschapv2, pap or chap")
	}
	if o.Protocol == "pptp" && o.Authentication != "mschapv2" {
		return errors.New("PPTP requires MSCHAPv2 for encrypted PPP")
	}
	if o.ConnectTimeout == 0 {
		o.ConnectTimeout = 30
	}
	if o.ConnectTimeout < 5 || o.ConnectTimeout > 120 {
		return errors.New("Windows VPN connection timeout must be between 5 and 120 seconds")
	}
	return nil
}
