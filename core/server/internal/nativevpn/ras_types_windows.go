//go:build windows

package nativevpn

import "unsafe"

// ras.h uses #pragma pack(4), including on Win64. Represent pointer-sized
// scalar fields as DWORD arrays to preserve its four-byte alignment in Go.
type rasPointer [unsafe.Sizeof(uintptr(0)) / 4]uint32

func (p *rasPointer) set(value uintptr) {
	for i := range p {
		p[i] = uint32(uint64(value) >> (32 * i))
	}
}

type rasDialParams struct {
	Size           uint32
	EntryName      [257]uint16
	PhoneNumber    [129]uint16
	CallbackNumber [129]uint16
	Username       [257]uint16
	Password       [257]uint16
	Domain         [16]uint16
	SubEntry       uint32
	CallbackID     rasPointer
	InterfaceIndex uint32
	EncPassword    rasPointer
}

type rasConnectStatus struct {
	Size           uint32
	State          uint32
	Error          uint32
	DeviceType     [17]uint16
	DeviceName     [129]uint16
	PhoneNumber    [129]uint16
	LocalEndpoint  [5]uint32
	RemoteEndpoint [5]uint32
	SubState       uint32
}

const rasConnected = 0x2000
