import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { ZipWriter, Uint8ArrayWriter, TextReader } from "@zip.js/zip.js";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../../dist/domain/evidence.js";

const root = fileURLToPath(new URL("../../", import.meta.url));
const local = join(root, ".forge-local");
const requireForgeReadiness = process.argv.includes("--forge-readiness");
const execute = promisify(execFile);
const evidenceRoot = join(local, "evidence");
await mkdir(join(local, "tmp"), { recursive: true });
await mkdir(evidenceRoot, { recursive: true });
const fixtureRoot = await mkdtemp(join(local, "tmp", "baseline-fixture-"));
// Keep provider-owned NTFS roots separate from the fixture's retained handles.
const providerTemp = await mkdtemp(join(local, "tmp", "baseline-provider-"));
const fixture = join(fixtureRoot, "baseline.zip");
const zip = new ZipWriter(new Uint8ArrayWriter());
await zip.add(
  "forge-baseline.txt",
  new TextReader("REA Forge source-owned fixture\n"),
);
await writeFile(fixture, await zip.close());
const originalHash = createHash("sha256")
  .update(await readFile(fixture))
  .digest("hex");
const environment = Object.fromEntries(
  Object.entries({
    ...process.env,
    TMPDIR: providerTemp,
    TMP: providerTemp,
    TEMP: providerTemp,
    REA_LOG_LEVEL: "error",
    TURBO_TELEMETRY_DISABLED: "1",
  }).filter(([, value]) => typeof value === "string"),
);
if (requireForgeReadiness) {
  assert.ok(environment.REA_FORGE_STATIC_CONFIG);
  const selectedConfiguration = join(
    fixtureRoot,
    "explicit-static-config.json",
  );
  await writeFile(
    selectedConfiguration,
    await readFile(environment.REA_FORGE_STATIC_CONFIG),
  );
  environment.REA_FORGE_STATIC_CONFIG = selectedConfiguration;
}
const entrypoint = join(root, "scripts", "rea.mjs");
const client = new Client({ name: "rea-forge-baseline", version: "1" });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  cwd: requireForgeReadiness ? fixtureRoot : root,
  env: environment,
  stderr: "pipe",
});
let stderr = "";
let serverPid;
const report = {
  status: "running",
  checks: {},
  target_execution: false,
  gui_started: false,
  network_capture: false,
};
const started = performance.now();
try {
  const cli = await execute(
    process.execPath,
    [entrypoint, "inspect-artifact", fixture, "--format", "json"],
    {
      cwd: requireForgeReadiness ? fixtureRoot : root,
      env: environment,
      windowsHide: true,
      timeout: 30_000,
      maxBuffer: 16 * 1024 * 1024,
    },
  );
  const cliEvidence = parseEvidence(JSON.parse(cli.stdout));
  assert.equal(cliEvidence.subject?.digest.sha256, originalHash);
  assert.ok(
    JSON.stringify(cliEvidence.normalized_result).includes(
      "forge-baseline.txt",
    ),
  );
  report.checks.cli_archive_inventory = true;
  await client.connect(transport, { timeout: 20_000 });
  serverPid = transport.pid;
  transport.stderr?.on("data", (chunk) => {
    stderr = (stderr + chunk.toString()).slice(-8192);
  });
  const catalog = (await client.listTools({}, { timeout: 20_000 })).tools;
  report.advertised_tool_count = catalog.length;
  const call = async (name, args) => {
    const definition = catalog.find((item) => item.name === name);
    assert.ok(
      definition?.outputSchema,
      `${name} must advertise its output schema`,
    );
    const result = await client.callTool(
      { name, arguments: args },
      { timeout: 30_000, toolDefinition: definition },
    );
    assert.notEqual(result.isError, true, JSON.stringify(result));
    const text = result.content.find((item) => item.type === "text")?.text;
    assert.equal(typeof text, "string");
    return JSON.parse(text);
  };
  const initialStatus = await call("binary_session", {});
  report.checks.target_free_session_status = true;
  if (requireForgeReadiness) {
    assert.ok(environment.REA_FORGE_STATIC_CONFIG);
    assert.ok(environment.REA_FORGE_DATA_ROOT);
    const expected = catalog.filter(({ name }) => name.startsWith("forge_"));
    assert.equal(expected.length, 27);
    const groups = initialStatus.result.tool_availability.groups;
    for (const { name } of expected) {
      const observed = groups.find((group) => group.names.includes(name));
      assert.equal(
        observed?.available,
        true,
        `${name}: ${JSON.stringify(observed)}`,
      );
    }
    assert.equal(initialStatus.result.open, false);
    report.checks.all_forge_operations_ready_without_open_binary = true;
    report.checks.external_configuration_and_independent_working_directory = true;
    const snapshot = await readFile(environment.REA_FORGE_STATIC_CONFIG);
    const withoutJava = JSON.parse(
      snapshot.toString("utf8").replace(/^\uFEFF/u, ""),
    );
    delete withoutJava.java;
    try {
      await writeFile(
        environment.REA_FORGE_STATIC_CONFIG,
        JSON.stringify(withoutJava),
      );
      const partial = await call("binary_session", {});
      for (const { name } of expected) {
        const observed = partial.result.tool_availability.groups.find((group) =>
          group.names.includes(name),
        );
        assert.equal(observed?.available, !name.includes("java"), name);
        assert.notEqual(observed?.reason, "target_required");
      }
      report.checks.missing_java_does_not_disable_peer_families = true;
      await writeFile(environment.REA_FORGE_STATIC_CONFIG, "{");
      const malformed = await call("binary_session", {});
      for (const { name } of expected)
        assert.equal(
          malformed.result.tool_availability.groups.find((group) =>
            group.names.includes(name),
          )?.available,
          false,
        );
      report.checks.malformed_optional_configuration_does_not_break_session_status = true;
    } finally {
      await writeFile(environment.REA_FORGE_STATIC_CONFIG, snapshot);
    }
    const restored = await call("binary_session", {});
    for (const { name } of expected)
      assert.equal(
        restored.result.tool_availability.groups.find((group) =>
          group.names.includes(name),
        )?.available,
        true,
      );
    report.checks.configuration_repair_recovers_on_the_same_connection = true;
  }
  await call("open_binary", { path: fixture });
  const inspected = parseEvidence(await call("inspect_artifact", {}));
  assert.equal(inspected.subject?.digest.sha256, originalHash);
  assert.ok(
    JSON.stringify(inspected.normalized_result).includes("forge-baseline.txt"),
  );
  report.checks.stdio_mcp_archive_inventory = true;
  assert.deepEqual(inspected.normalized_result, cliEvidence.normalized_result);
  report.checks.cli_mcp_inventory_parity = true;
  await call("close_binary", {});
  report.checks.explicit_target_close = true;
  assert.equal(
    createHash("sha256")
      .update(await readFile(fixture))
      .digest("hex"),
    originalHash,
  );
  report.checks.original_hash_unchanged = true;
  report.status = "passed";
} catch (cause) {
  report.status = "failed";
  report.error = cause instanceof Error ? cause.message : String(cause);
  process.exitCode = 1;
} finally {
  try {
    await client.close();
    await transport.close();
    report.checks.transport_closed = true;
    if (serverPid !== undefined && serverPid !== null) {
      try {
        process.kill(serverPid, 0);
        throw new Error("MCP server PID remains present after transport close");
      } catch (cause) {
        if (cause?.code !== "ESRCH") throw cause;
      }
    }
    report.checks.server_exit_observed = true;
    await rm(fixtureRoot, { recursive: true });
    await rm(providerTemp, { recursive: true });
    report.checks.owned_temporary_roots_removed = true;
  } catch (cause) {
    report.status = "failed";
    report.cleanup_error =
      cause instanceof Error ? cause.message : String(cause);
    process.exitCode = 1;
  }
  report.node_version = process.version;
  report.elapsed_seconds = Number(
    ((performance.now() - started) / 1000).toFixed(3),
  );
  report.input_sha256 = originalHash;
  if (stderr) report.stderr_tail = stderr;
  await writeFile(
    join(evidenceRoot, `baseline-${Date.now()}.json`),
    JSON.stringify(report, null, 2) + "\n",
  );
  console.log(JSON.stringify(report, null, 2));
}
