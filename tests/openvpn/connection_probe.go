// Manual connection probe. Reads a complete core configuration from stdin and
// uses a loopback-only proxy; never changes the system proxy or routing table.
// Provider configuration and credentials are supplied locally, never by CI.
package main

import (
	"context"
	stdjson "encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func report(phase string, result any) {
	b, _ := stdjson.Marshal(map[string]any{"phase": phase, "result": result})
	fmt.Println(string(b))
}

func main() {
	if err := run(); err != nil {
		report("error", err.Error())
		os.Exit(1)
	}
}

func run() error {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
	if err != nil {
		return err
	}
	var config map[string]any
	if err = stdjson.Unmarshal(raw, &config); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	config["inbounds"] = []any{map[string]any{"type": "mixed", "tag": "probe-in", "listen": "127.0.0.1", "listen_port": port}}
	config["log"] = map[string]any{"level": "info", "disabled": false, "timestamp": false}
	raw, err = stdjson.Marshal(config)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(include.Context(context.Background()), 110*time.Second)
	defer cancel()
	var options option.Options
	if err = json.UnmarshalContext(ctx, raw, &options); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		return fmt.Errorf("construct: %w", err)
	}
	defer instance.Close()
	report("core_constructed", true)
	if err = instance.Start(); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	report("core_started", true)
	proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), TLSHandshakeTimeout: 15 * time.Second, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	for _, item := range []struct{ name, url string }{
		{"vpn_request", "https://api.ipify.org?format=json"},
		{"direct_rule_request", "https://api64.ipify.org?format=json"},
	} {
		start := time.Now()
		var response *http.Response
		deadline := start.Add(75 * time.Second)
		waitingReported := false
		for {
			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, item.url, nil)
			response, err = client.Do(request)
			if err == nil || item.name != "vpn_request" || time.Now().After(deadline) || ctx.Err() != nil {
				break
			}
			if !waitingReported {
				report("waiting_for_vpn", true)
				waitingReported = true
			}
			select {
			case <-time.After(2 * time.Second):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if err != nil {
			return fmt.Errorf("%s: %w", item.name, err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
		response.Body.Close()
		if readErr != nil {
			return readErr
		}
		if response.StatusCode != 200 {
			return fmt.Errorf("%s: HTTP %d", item.name, response.StatusCode)
		}
		var address map[string]any
		if err = stdjson.Unmarshal(body, &address); err != nil {
			return fmt.Errorf("invalid IP response")
		}
		report(item.name, map[string]any{"ip": address["ip"], "elapsed_ms": time.Since(start).Milliseconds(), "http_status": response.StatusCode})
	}
	return nil
}
