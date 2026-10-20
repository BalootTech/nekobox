package boxmain

import "testing"

func TestCheckNativeVPNUsesApplicationRegistry(t *testing.T) {
	for _, protocol := range []string{"pptp", "l2tp"} {
		raw := []byte(`{"outbounds":[{"type":"windows-vpn","tag":"vpn","protocol":"` + protocol + `","server":"vpn.example.test","username":"test","password":"test-only","psk":"test-only"}],"route":{"final":"vpn"}}`)
		if err := Check(raw); err != nil {
			t.Fatalf("check %s without connecting: %v", protocol, err)
		}
	}
}
