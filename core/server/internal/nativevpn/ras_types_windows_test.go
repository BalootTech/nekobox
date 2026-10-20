//go:build windows

package nativevpn

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"
)

func TestRASHangUpExportExists(t *testing.T) {
	dll, err := syscall.LoadDLL(filepath.Join(os.Getenv("SystemRoot"), "System32", "rasapi32.dll"))
	if err != nil {
		t.Fatal(err)
	}
	defer dll.Release()
	if _, err = dll.FindProc(rasHangUpName); err != nil {
		t.Fatal(err)
	}
}

func TestRASMatchesWindowsSDK(t *testing.T) {
	path := os.Getenv("NEKOBOX_RAS_SDK_ABI")
	if path == "" {
		t.Skip("set NEKOBOX_RAS_SDK_ABI to the native SDK probe output")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]uintptr
	if err = json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	params := rasDialParams{}
	status := rasConnectStatus{}
	actual := map[string]uintptr{"dial_size": unsafe.Sizeof(params), "callback": unsafe.Offsetof(params.CallbackID), "interface": unsafe.Offsetof(params.InterfaceIndex), "enc_password": unsafe.Offsetof(params.EncPassword), "status_size": unsafe.Sizeof(status), "local_endpoint": unsafe.Offsetof(status.LocalEndpoint)}
	for field, value := range actual {
		if expected[field] != value {
			t.Errorf("RAS ABI %s: Go %d, Windows SDK %d", field, value, expected[field])
		}
	}
}
