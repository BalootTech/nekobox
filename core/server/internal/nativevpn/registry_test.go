package nativevpn

import (
	"context"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func TestNativeVPNConfigCheckDoesNotConnect(t *testing.T) {
	ctx := Context(context.Background())
	for _, protocol := range []string{"pptp", "l2tp"} {
		var options option.Options
		raw := []byte(`{"outbounds":[{"type":"windows-vpn","tag":"vpn","protocol":"` + protocol + `","server":"vpn.example.test","username":"test","password":"test-only","psk":"test-only"}],"route":{"final":"vpn"}}`)
		if err := json.UnmarshalContext(ctx, raw, &options); err != nil {
			t.Fatal(err)
		}
		instance, err := box.New(box.Options{Context: ctx, Options: options})
		if err != nil {
			t.Fatal(err)
		}
		outbound, ok := instance.Outbound().Outbound("vpn")
		if !ok || outbound.Type() != "windows-vpn" {
			t.Fatal("native VPN registry did not build the profile")
		}
		if err = instance.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
