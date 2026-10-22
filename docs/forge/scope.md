# REA Forge downstream scope

REA Forge is a downstream fork of `morluto/rea`. Its owner requested additional
Windows workflows and migration of an existing local tool collection on
2026-10-22. This is a downstream product decision, not approval from upstream
REA maintainers, and it does not change the upstream project's distribution
or contribution boundaries.

## Integration boundaries

- Preserve existing upstream operation names, effects, target identity,
  Evidence contracts, and read-only provider behavior.
- Add distinct typed contracts for additional analysis and derived-artifact
  editing. Do not turn an upstream read operation into an execution endpoint.
- Reuse inward domain/application boundaries and the existing owned-process
  supervisor. Optional tool discovery must not start an engine.
- Keep workstation paths, private configuration, credentials, commercial
  engines, original samples, models, and local receipts outside Git.
- Retain tool licenses and provenance independently of this fork's MIT code.
  An installed commercial tool is not a redistribution entitlement.
- Runtime target execution, arbitrary scripts, injection and native debugging
  belong to explicitly configured guest environments. Host static adapters
  are not an operating-system sandbox.
- Do not add purpose-built licensing/access-control bypass, anti-debugging
  evasion, credential collection, or offensive autonomous workflows.

## Migration acceptance

Historical evidence establishes only the recorded legacy revision. A migrated
capability requires its own complete affected CLI/MCP workflow on the current
Windows host or selected guest, with original/derived identity, cancellation,
deadlines and observed cleanup. Unavailable engines remain unavailable.

Local progress and engine paths live under ignored `.forge-local/`. The old
framework may be removed only after replacement, reference cutover and data
verification. Retaining every historical runtime bundle is not a migration
strategy.
