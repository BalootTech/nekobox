# OpenVPN tests

These compile the production parser against real Qt6 Core. No string/JSON
adapters or copied parser implementations are used.

The same CMake build compiles the OpenVPN profile model, Qt editor and profile
factory against the application's real headers as an object library. It does
not link or launch the full GUI. Qt6 Widgets/Network/Concurrent and Boost
and yaml-cpp headers are required for this check.

```sh
cmake -S tests/openvpn -B build-openvpn
cmake --build build-openvpn
ctest --test-dir build-openvpn --output-on-failure
```

Cases cover UDP/TCP and address families, multiple remotes, global option
ordering, inline credentials and certificates, certificate name verification,
TLS control wrapping and key directions, cipher lists, disabled timers,
external material bundling, unknown/unsafe options, invalid input and native
endpoint JSON. Temporary fixture data is synthetic.

The OpenVPN validation workflow additionally creates a temporary certificate,
emits configurations from the real parser, and constructs the pinned
sing-box-extended core with `with_openvpn`. It never starts the core or makes a
VPN connection. A working provider configuration is still needed for end-to-end
connection, routing and DNS testing.

The workflow also builds a Windows connection probe. This manual utility reads
a full core configuration from standard input, creates a proxy listening only
on loopback, and makes two HTTPS IP checks: `api.ipify.org` through the final
route and `api64.ipify.org` through the configured rules. Supply a direct rule
for the second domain to check split routing. It does not modify system proxy
settings or routes. Provider configuration, keys and credentials must remain
local and must never be committed or supplied to the workflow.
