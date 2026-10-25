# Local distribution and shared ownership

Forge is a private local distribution of REA. The upstream npm package metadata
remains for compatibility; it is not a delivery channel for these extensions.
`binary_session` and `doctor` identify this distribution as `forge-local`.
Use package version, actual public launcher path and live catalog digest
together. A matching version alone does not establish the same build.

Production setup registers the current Node executable plus the package's public
`scripts/rea.mjs` launcher and `mcp`, independently of cwd, shell PATH or an
inherited npm/bun invocation. It retains REA's scoped plans, client backup,
readback, idempotence and separate client approval behavior. Production doctor
does not count an upstream package-runner registration as this local build.
Setup of daily clients remains a reviewed cutover, not a side effect of building.

The authored and packaged skill share one managed inventory. Setup binds only
launcher placeholders in `references/forge-local.md`, recording the actual
Node/launcher prefix in the operator's installed skill. It records no provider
configuration contents or credentials. Doctor compares those bound bytes;
moving the build makes the binding stale. Portable conformance commits to the
package templates, while local installation freshness also verifies the bound
reference. This distinction keeps machine paths out of public generated assets.
The generator rejects upstream npm recovery commands in Forge instructions.

The four static families operate through owned no-UI workers and explicit input,
output and backup identities. They do not borrow/save/close a human GUI or run
the input as a program. Their current native receipts cover originals, actual
readback, cancellation and owned cleanup. The bundled
`references/shared-ownership.md` defines the same ownership rules for future
guest and frontend integrations: borrowed user sessions stay intact, persisted
intent is distinct from observed readiness, and important destructive management
still requires individual confirmation. This guidance does not itself implement
the later host/guest enforcement or certify an unintegrated persistent service.
