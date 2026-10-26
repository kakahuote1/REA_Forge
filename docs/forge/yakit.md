# Official Yakit request and history adapter

Forge uses the installed official Yak MCP through stdio. It selects only
`httpflow,http_fuzzer` and invokes two fixed tools; it does not forward arbitrary
tool names or expose deletion, scanning, scripts or plugins. Three public Forge
operations use the existing configuration, shared application, CLI/MCP,
Evidence and owned-process infrastructure.

- `forge_yakit_request`: one explicit HTTP(S) destination, method, ordered
  headers and UTF8 body. Wire authority/framing belongs to the fixed builder.
Concurrency is one, repetition is omitted, dynamic tags are literal, system proxies and
  redirects are disabled. A request may affect its destination; it is not a
  read-only static operation and is never automatically retried after failure.
- `forge_yakit_flows`: keyword and bounded pages from a named private Forge
  profile. The tested vendor schema mistakenly advertises script filters for
  this flow tool, so no unadvertised advanced fields are sent. Total/order,
  concurrent changes and bodies omitted upstream remain unknown.
- `forge_read_yakit_result`: digest-bound historical facets, pages and exact
  artifact-file bytes; it does not start Yak or send another request.

The operator selects pinned `yakit.engine` and `yakit.node` files and their
version. `yakit_results` is independent of engine presence. Discovery and
readiness do not start Yak. Profiles live in the explicit data root under
`work/yakit-state/<profile>` with owner/version markers and an OS file lock.
They are not the human Yakit GUI's project databases. New profiles initialize
the vendor's own databases once; no engine binaries or models are copied.

Native calls have a1–30second deadline inside the existing55second/1GiB owned
helper. Request timeout is1–15seconds. Cancellation/timeout does not prove a
request never reached its destination. Retained descriptors and diagnostics
remain available; ambiguous outcomes do not authorize automatic resubmission.

The tested official engine is1.4.2-beta2, MCP0.0.2. Source review used upstream
tag commit `434017b743a76fb8889247834c66417cf863c6d1`; version labels alone do
not authenticate a binary build. The vendor converts raw bytes to UTF8 strings
and Go-quoted flow fields; those values are preserved, not claimed as arbitrary
original network octets. Known error/large-response indicators remain partial.

This is the defined request/history subset, not every Yakit feature or human
GUI control. It does not resolve DudeSuite's separate interface prerequisite.
Actual current verification is recorded in the private delivery checklist.

On the pinned engine, positive `repeatTimes` adds a repeat template to the
request even when tag processing is closed. The fixed adapter omits this
optional field. Actual acceptance observed exactly one unchanged request;
turning tag evaluation on is not a workaround.
