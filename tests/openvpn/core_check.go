// Run from core/server with -tags with_openvpn,with_gvisor. Constructs the
// repository-pinned core using actual parser output; does not start a VPN.
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func main() {
	ctx := include.Context(context.Background())
	input := bufio.NewScanner(os.Stdin)
	input.Buffer(make([]byte, 4096), 4*1024*1024)
	count := 0
	for input.Scan() {
		var options option.Options
		if err := json.UnmarshalContext(ctx, input.Bytes(), &options); err != nil {
			panic(err)
		}
		instance, err := box.New(box.Options{Context: ctx, Options: options})
		if err != nil {
			panic(err)
		}
		if err := instance.Close(); err != nil {
			panic(err)
		}
		count++
	}
	if err := input.Err(); err != nil {
		panic(err)
	}
	if count != 2 {
		panic(fmt.Sprintf("expected 2 parser-generated configurations, got %d", count))
	}
	fmt.Println("Core accepted parser-generated OpenVPN UDP and TCP endpoints")
}
