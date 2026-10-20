//go:build !windows

package nativevpn

import (
	"context"
	"errors"
)

func connectPlatform(context.Context, Options, int) (platformConnection, error) {
	return nil, errors.New("PPTP and L2TP/IPsec profiles require Windows")
}

func preparePlatform(_ context.Context, options Options, index int) (Options, int, error) {
	return options, index, errors.New("PPTP and L2TP/IPsec profiles require Windows")
}
