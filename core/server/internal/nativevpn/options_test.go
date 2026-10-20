package nativevpn

import (
	"strings"
	"testing"
)

func TestNativeVPNOptions(t *testing.T) {
	for _, protocol := range []string{"pptp", "l2tp"} {
		o := Options{Protocol: protocol, Server: "vpn.example.com", Username: "alice", Password: "secret", PSK: "key"}
		if err := o.validate(); err != nil {
			t.Fatal(err)
		}
		if o.Authentication != "mschapv2" || o.ConnectTimeout != 30 {
			t.Fatal("default connection policy was not applied")
		}
	}
	for _, modify := range []func(*Options){
		func(o *Options) { o.Protocol = "sstp" },
		func(o *Options) { o.Server = "https://vpn.example.com" },
		func(o *Options) { o.Server = "vpn.example.com:1701" },
		func(o *Options) { o.Server = "vpn.example.com\x00evil" },
		func(o *Options) { o.Username = "" },
		func(o *Options) { o.Password = strings.Repeat("x", 257) },
		func(o *Options) { o.Protocol = "l2tp"; o.PSK = "" },
		func(o *Options) { o.ConnectTimeout = 121 },
		func(o *Options) { o.Authentication = "pap" },
		func(o *Options) { o.Detour = "another-proxy" },
	} {
		o := Options{Protocol: "pptp", Server: "vpn.example.com", Username: "alice", Password: "secret", PSK: "key"}
		modify(&o)
		if err := o.validate(); err == nil {
			t.Errorf("unsafe or unsupported options accepted: protocol=%s auth=%s", o.Protocol, o.Authentication)
		}
	}
	for _, auth := range []string{"pap", "chap", "mschapv2"} {
		o := Options{Protocol: "l2tp", Server: "192.0.2.1", Username: "alice", PSK: "key", Authentication: auth}
		if err := o.validate(); err != nil {
			t.Fatal(err)
		}
	}
}
