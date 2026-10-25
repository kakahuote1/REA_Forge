/** Complete host PE/UPX subset. DiE/emulation execution remains separately tracked. */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import {
  copyFile,
  mkdtemp,
  readFile,
  readdir,
  rmdir,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../../dist/domain/evidence.js";
import { FORGE_PE_OPERATIONS } from "../../dist/domain/forge/peStatic.js";
const root = fileURLToPath(new URL("../../", import.meta.url)),
  local = join(root, ".forge-local");
const sha = (value) => createHash("sha256").update(value).digest("hex");
const resume = process.env.REA_FORGE_PE_RESUME;
const prior = resume ? JSON.parse(await readFile(resume, "utf8")) : undefined;
const fixtures =
  prior?.fixtures ?? (await mkdtemp(join(local, "fixtures/pe-static-")));
const temporary = await mkdtemp(join(local, "tmp/pe-provider-"));
const fixtureRoot = process.env.REA_FORGE_PE_FIXTURE_ROOT;
assert.ok(
  fixtureRoot,
  "explicit installed known-source UPX fixture root required",
);
const paths = {
  original: join(fixtures, "original.exe"),
  packed: join(fixtures, "packed.exe"),
  invalid: join(fixtures, "not-pe.bin"),
};
const originals = { ...prior?.originals };
if (!prior) {
  for (const [name, expected] of Object.entries({
    original:
      "a921abab86c03214ab31e53038b4529317a1b0691aeffe754d315d6f7a348f88",
    packed: "2ed1f5deb98f4db86d8f2d7255f3bf40b8aaae311f042443359fd977fad00433",
  })) {
    const source = join(fixtureRoot, `recore-upx-${name}.exe`);
    assert.equal(sha(await readFile(source)), expected);
    await copyFile(source, paths[name]);
    originals[source] = expected;
    originals[paths[name]] = expected;
  }
  await writeFile(paths.invalid, "not PE fixture");
  originals[paths.invalid] = sha(await readFile(paths.invalid));
}
for (const [path, digest] of Object.entries(originals))
  assert.equal(sha(await readFile(path)), digest);
const report = {
  status: "running",
  scope:
    "G07 host PE facts/dependencies/UPX subset; DiE and emulation not verified",
  fixtures,
  originals,
  checks: { ...prior?.checks },
  values: { ...prior?.values },
  target_execution: false,
  network_used: false,
  gui_started: false,
};
if (prior)
  report.reused_receipt = { path: resume, sha256: sha(await readFile(resume)) };
for (const value of Object.values(report.values)) {
  const reference = value?.result;
  if (!reference?.receipt_path) continue;
  assert.equal(
    sha(await readFile(reference.receipt_path)),
    reference.receipt_sha256,
  );
  assert.equal(
    sha(await readFile(reference.full_result.path)),
    reference.full_result.sha256,
  );
  for (const item of reference.artifacts)
    assert.equal(sha(await readFile(item.path)), item.sha256);
}
const env = Object.fromEntries(
  Object.entries({
    ...process.env,
    TEMP: temporary,
    TMP: temporary,
    TMPDIR: temporary,
    REA_LOG_LEVEL: "error",
  }).filter(([, value]) => typeof value === "string"),
);
const entry = join(root, "scripts/rea.mjs"),
  started = performance.now();
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entry, "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({ name: "forge-pe-static-acceptance", version: "1" });
const ref = (value) => ({
  receipt_path: value.result.receipt_path,
  receipt_sha256: value.result.receipt_sha256,
});
let diagnostics = "";
try {
  await client.connect(transport, { timeout: 20000 });
  report.server_pid = transport.pid;
  transport.stderr?.on("data", (chunk) => {
    diagnostics = (diagnostics + chunk.toString()).slice(-16384);
  });
  const tools = new Map(
    (await client.listTools({}, { timeout: 20000 })).tools.map((tool) => [
      tool.name,
      tool,
    ]),
  );
  for (const name of FORGE_PE_OPERATIONS) assert.ok(tools.has(name));
  report.tool_count = tools.size;
  const raw = (name, input, signal) =>
    client.callTool(
      { name, arguments: input },
      {
        timeout: 65000,
        toolDefinition: tools.get(name),
        ...(signal ? { signal } : {}),
      },
    );
  const call = async (name, input) => {
    const response = await raw(name, input);
    assert.notEqual(response.isError, true, JSON.stringify(response));
    return parseEvidence(
      JSON.parse(response.content.find((part) => part.type === "text").text),
    ).normalized_result;
  };
  const reject = async (name, input) => {
    const response = await raw(name, input);
    assert.equal(response.isError, true, JSON.stringify(response));
    return JSON.parse(
      response.content.find((part) => part.type === "text").text,
    );
  };
  const step = async (name, action) => {
    if (report.checks[name]) return report.values[name];
    const value = await action();
    report.values[name] = value;
    report.checks[name] = true;
    await writeFile(
      join(local, "evidence/pe-static-current.json"),
      JSON.stringify(report, null, 2),
    );
    console.log(
      JSON.stringify({
        phase: name,
        elapsed_seconds: (performance.now() - started) / 1000,
      }),
    );
    return value;
  };
  const facts = await step("pe_facts_and_retained_facets", async () => {
    const value = await call("forge_inspect_pe", { path: paths.original });
    assert.equal(value.result.value.is_pe, true);
    const rawHeader = await readFile(paths.original);
    const peOffset = rawHeader.readUInt32LE(0x3c);
    assert.equal(
      rawHeader.subarray(peOffset, peOffset + 4).toString("hex"),
      "50450000",
    );
    assert.equal(
      value.result.value.format,
      rawHeader.readUInt16LE(peOffset + 24) === 0x20b ? "PE32+" : "PE32",
    );
    assert.equal(
      value.result.value.machine,
      "0x" +
        rawHeader
          .readUInt16LE(peOffset + 4)
          .toString(16)
          .toUpperCase()
          .padStart(4, "0"),
    );
    assert.ok(value.result.value.section_count > 0);
    const sections = await call("forge_read_pe_result", {
      ...ref(value),
      facet: "sections",
    });
    assert.ok(sections.result.rows.length);
    const imports = await call("forge_read_pe_result", {
      ...ref(value),
      facet: "imports",
    });
    assert.ok(imports.result.rows.length);
    const bytes = await call("forge_read_pe_result", {
      ...ref(value),
      artifact_index: 0,
      byte_count: 16,
    });
    assert.ok(
      Buffer.from(bytes.result.bytes.base64, "base64")
        .toString()
        .startsWith("{"),
    );
    return value;
  });
  await step("static_dependencies_and_real_system_snapshots", async () => {
    const value = await call("forge_resolve_pe_dependencies", {
      path: paths.original,
      max_depth: 1,
      max_nodes: 4,
    });
    assert.equal(value.result.metadata.mode, "static_candidate_only");
    assert.ok(value.result.rows.length);
    assert.equal(value.result.metadata.api_set_snapshot.available, true);
    assert.equal(value.result.metadata.known_dll_snapshot.available, true);
    const edges = await call("forge_read_pe_result", {
      ...ref(value),
      facet: "dependencies",
      collection: "edges",
    });
    assert.ok(
      edges.result.rows.some((row) => row.value.dll === "kernel32.dll"),
    );
    assert.ok(value.result.metadata.truncated);
    return value;
  });
  await step("native_independent_pe_readers", async () => {
    const results = {};
    for (const name of [
      "inspect_pe_resources",
      "inspect_pe_certificates",
      "inspect_native_exports",
    ])
      results[name] = await call(name, { path: paths.original });
    return results;
  });
  await step("upx_packed_and_nonpacked_verification", async () => {
    const packed = await call("forge_test_upx", { path: paths.packed });
    assert.equal(packed.result.value.upx.verified_upx_packed, true);
    const ordinary = await call("forge_test_upx", { path: paths.original });
    assert.equal(ordinary.result.value.upx.verified_upx_packed, false);
    return packed;
  });
  const unpacked = await step("ordinary_upx_unpack_and_reread", async () => {
    const value = await call("forge_unpack_upx", { path: paths.packed });
    assert.equal(value.result.artifacts.length, 1);
    const item = value.result.artifacts[0];
    assert.equal(sha(await readFile(item.path)), item.sha256);
    const observed = await call("forge_inspect_pe", { path: item.path });
    assert.equal(observed.result.value.is_pe, true);
    assert.deepEqual(observed.result.value.headers, facts.result.value.headers);
    return value;
  });
  await step("nonpe_and_malformed_selection_refusals", async () => {
    const value = await call("forge_inspect_pe", { path: paths.invalid });
    assert.equal(value.result.value.is_pe, false);
    await reject("forge_resolve_pe_dependencies", { path: paths.invalid });
    await reject("forge_unpack_upx", { path: paths.original });
    await reject("forge_read_pe_result", {
      ...ref(unpacked),
      receipt_sha256: "0".repeat(64),
    });
    await reject("forge_read_pe_result", {
      ...ref(unpacked),
      artifact_index: 100,
    });
    await reject("forge_resolve_pe_dependencies", {
      path: paths.original,
      dependency_roots: ["C:/Windows"],
    });
    return { refused_cases: 5 };
  });
  await step("native_timeout_cancel_recovery", async () => {
    const timeout = await reject("forge_test_upx", {
      path: paths.packed,
      timeout_ms: 1,
    });
    assert.equal(timeout.error.code, "provider_timeout");
    const stop = new AbortController();
    const pending = raw(
      "forge_resolve_pe_dependencies",
      { path: paths.original, max_depth: 10 },
      stop.signal,
    );
    setTimeout(() => stop.abort("owned fixture cancel"), 25);
    await assert.rejects(pending);
    const recovered = await call("forge_read_pe_result", ref(facts));
    assert.equal(recovered.result.value.is_pe, true);
    return { recovered: true };
  });
  await step("cli_mcp_retained_parity", async () => {
    const { stdout } = await promisify(execFile)(
      process.execPath,
      [
        entry,
        "forge-read-pe-result",
        JSON.stringify(ref(facts)),
        "--format",
        "json",
      ],
      { env, windowsHide: true, timeout: 25000, maxBuffer: 1024 * 1024 },
    );
    assert.deepEqual(
      parseEvidence(JSON.parse(stdout)).normalized_result.result.value,
      facts.result.value,
    );
    return { equal: true };
  });
  for (const [path, digest] of Object.entries(originals))
    assert.equal(sha(await readFile(path)), digest);
  report.checks.originals_unchanged = true;
  report.status = "passed";
} catch (cause) {
  report.status = "failed";
  report.failure = String(cause);
  report.diagnostics = diagnostics;
  process.exitCode = 1;
} finally {
  try {
    await client.close();
    report.transport_closed = true;
  } catch (cause) {
    report.status = "failed";
    report.cleanup_failure = String(cause);
    process.exitCode = 1;
  }
  report.provider_temp_empty = (await readdir(temporary)).length === 0;
  if (report.provider_temp_empty) await rmdir(temporary);
  else {
    report.status = "failed";
    process.exitCode = 1;
  }
  report.elapsed_seconds = (performance.now() - started) / 1000;
  const receipt = join(local, "evidence", `pe-static-${Date.now()}.json`);
  await writeFile(receipt, JSON.stringify(report, null, 2));
  console.log(
    JSON.stringify({
      status: report.status,
      scope: report.scope,
      receipt,
      checks: report.checks,
      elapsed_seconds: report.elapsed_seconds,
      provider_temp_empty: report.provider_temp_empty,
      failure: report.failure,
    }),
  );
}
