package boxmain

import (
	"context"
	"nekobox_core/internal/nativevpn"

	"nekobox_core/internal/boxbox"
)

var ruleset_cachedir string

func Check(content []byte) error {
	ctx := nativevpn.Context(context.Background())
	options, err := parseConfig(ctx, content)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	instance, err := boxbox.New(boxbox.Options{
		Context: ctx,
		Options: *options,
	})
	if err == nil {
		instance.Close()
	}
	cancel()
	return err
}
