/** One concentrated real static group. The source-owned PE is never executed. */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  writeFile,
  readdir,
  rm,
} from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../../dist/domain/evidence.js";
import { FORGE_ENRICHMENT_TOOL_CONTRACTS } from "../../dist/contracts/forge/nativeEnrichmentToolContracts.js";

const root = fileURLToPath(new URL("../../", import.meta.url));
const local = join(root, ".forge-local");
for (const name of ["fixtures", "tmp", "evidence"])
  await mkdir(join(local, name), { recursive: true });
const fixtures = await mkdtemp(join(local, "fixtures/enrichment-"));
const temporary = await mkdtemp(join(local, "tmp/enrichment-provider-"));
const marker = "REA_FORGE_STATIC_STRING_2026";
const decodedMarker = "REA_FORGE_XOR_DECODED_STACK_2026";

function fixturePe() {
  const bytes = Buffer.alloc(0x800);
  const w16 = (at, value) => bytes.writeUInt16LE(value, at);
  const w32 = (at, value) => bytes.writeUInt32LE(value, at);
  bytes.write("MZ");
  w32(0x3c, 0x80);
  bytes.write("PE\0\0", 0x80);
  w16(0x84, 0x14c);
  w16(0x86, 3);
  w16(0x94, 0xe0);
  w16(0x96, 0x102);
  const optional = 0x98;
  w16(optional, 0x10b);
  w32(optional + 4, 0x200);
  w32(optional + 8, 0x400);
  w32(optional + 16, 0x1000);
  w32(optional + 20, 0x1000);
  w32(optional + 24, 0x2000);
  w32(optional + 28, 0x400000);
  w32(optional + 32, 0x1000);
  w32(optional + 36, 0x200);
  w16(optional + 40, 4);
  w16(optional + 48, 4);
  w32(optional + 56, 0x4000);
  w32(optional + 60, 0x200);
  w16(optional + 68, 3);
  w16(optional + 70, 0x100);
  w32(optional + 72, 0x100000);
  w32(optional + 76, 0x1000);
  w32(optional + 80, 0x100000);
  w32(optional + 84, 0x1000);
  w32(optional + 92, 16);
  w32(optional + 104, 0x3000);
  w32(optional + 108, 0x100);
  w32(optional + 192, 0x3040);
  w32(optional + 196, 8);
  for (const [index, name, rva, raw, flags] of [
    [0, ".text", 0x1000, 0x200, 0x60000020],
    [1, ".rdata", 0x2000, 0x400, 0x40000040],
    [2, ".idata", 0x3000, 0x600, 0xc0000040],
  ]) {
    const at = 0x178 + index * 40;
    bytes.write(name, at);
    w32(at + 8, 0x200);
    w32(at + 12, rva);
    w32(at + 16, 0x200);
    w32(at + 20, raw);
    w32(at + 36, flags);
  }
  // Entry: call decoder; call imported GetTickCount; return. It is data only.
  Buffer.from("558bece838000000ff154030400031c05dc3", "hex").copy(bytes, 0x200);
  const encoded = Buffer.from(decodedMarker + "\0");
  for (let i = 0; i < encoded.length; i++) encoded[i] ^= 0x5a;
  encoded.copy(bytes, 0x400);
  bytes.write(marker + "\0", 0x480);
  const code = [...Buffer.from("558bec83ec6031c9be002040008d7da0", "hex")];
  const loop = code.length;
  code.push(
    ...Buffer.from("8a040e345a88040f4183f9", "hex"),
    encoded.length,
    0x7c,
    (loop - (code.length + 14)) & 255,
  );
  code.push(0x57, 0xe8);
  const displacement = 0xc0 - (0x40 + code.length + 4);
  const delta = Buffer.alloc(4);
  delta.writeInt32LE(displacement);
  code.push(...delta, ...Buffer.from("83c404c9c3", "hex"));
  Buffer.from(code).copy(bytes, 0x240);
  Buffer.from("558bec8b4508803800740340ebf85dc3", "hex").copy(bytes, 0x2c0);
  w32(0x600, 0x3030);
  w32(0x60c, 0x3060);
  w32(0x610, 0x3040);
  w32(0x630, 0x3080);
  w32(0x640, 0x3080);
  bytes.write("KERNEL32.dll\0", 0x660);
  bytes.write("GetTickCount\0", 0x682);
  return bytes;
}

const sample = join(fixtures, "enrichment-fixture.exe");
const broken = join(fixtures, "broken.exe");
const bytes = fixturePe();
const sha = (value) => createHash("sha256").update(value).digest("hex");
await writeFile(sample, bytes);
await writeFile(broken, "MZbroken");
const report = {
  status: "running",
  checks: {},
  fixture_sha256: sha(bytes),
  sample_execution: false,
  gui_started: false,
  network_used: false,
};
const environment = Object.fromEntries(
  Object.entries({
    ...process.env,
    TEMP: temporary,
    TMP: temporary,
    TMPDIR: temporary,
    REA_LOG_LEVEL: "error",
  }).filter(([, value]) => typeof value === "string"),
);
const client = new Client({
  name: "forge-native-enrichment-acceptance",
  version: "1",
});
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [join(root, "scripts/rea.mjs"), "mcp"],
  env: environment,
  stderr: "pipe",
});
const started = performance.now();
let serverPid;
let diagnostics = "";
try {
  await client.connect(transport, { timeout: 20000 });
  serverPid = transport.pid;
  transport.stderr?.on("data", (chunk) => {
    if (diagnostics.length < 65536) diagnostics += chunk.toString();
  });
  const tools = new Map(
    (await client.listTools({}, { timeout: 20000 })).tools.map((tool) => [
      tool.name,
      tool,
    ]),
  );
  for (const contract of FORGE_ENRICHMENT_TOOL_CONTRACTS)
    assert.ok(tools.has(contract.name));
  const raw = (name, input, signal) =>
    client.callTool(
      { name, arguments: input },
      {
        timeout: 55000,
        toolDefinition: tools.get(name),
        ...(signal === undefined ? {} : { signal }),
      },
    );
  const call = async (name, input) => {
    const response = await raw(name, input);
    assert.notEqual(response.isError, true, JSON.stringify(response));
    const value = parseEvidence(
      JSON.parse(response.content.find((part) => part.type === "text").text),
    ).normalized_result;
    assert.equal(value.network_used, false);
    assert.equal(value.sample_execution, false);
    return value;
  };
  const reject = async (name, input) => {
    const result = await raw(name, input);
    assert.equal(result.isError, true, JSON.stringify(result));
    return result;
  };
  const reuseCapa = process.argv
    .find((value) => value.startsWith("--reuse-capa-receipt="))
    ?.slice("--reuse-capa-receipt=".length);
  const capa =
    reuseCapa === undefined
      ? await call("forge_analyze_capabilities", {
          path: sample,
          format: "pe",
          limit: 100,
        })
      : await call("forge_read_enrichment_result", {
          receipt_path: reuseCapa,
          receipt_sha256: sha(await readFile(reuseCapa)),
          limit: 100,
        });
  assert.equal(capa.target.sha256, report.fixture_sha256);
  assert.equal(capa.result.analysis_parameters.format, "pe");
  assert.ok(capa.result.total > 0, "fixture must produce real rule matches");
  assert.ok(
    capa.result.rows.some((row) => /time|tick|xor|loop/iu.test(row.name)),
    JSON.stringify(capa.result.rows),
  );
  assert.ok(capa.result.rows.some((row) => row.match_addresses.length > 0));
  report.checks.capa_actual_rules_and_addresses = {
    passed: true,
    reused_matching_receipt: reuseCapa ?? null,
  };
  const floss = await call("forge_recover_strings", {
    path: sample,
    format: "pe",
    string_kinds: ["static", "decoded", "stack", "tight"],
    limit: 100,
  });
  assert.ok(
    floss.result.rows.some((row) => row.string.includes(marker)),
    JSON.stringify(floss.result.rows),
  );
  const recoveredDecoded = floss.result.rows.filter(
    (row) => row.kind !== "static" && row.string.includes(decodedMarker),
  );
  assert.ok(
    recoveredDecoded.length > 0,
    "known XOR-created marker must be recovered, not merely a static literal",
  );
  report.checks.floss_known_static_and_xor_marker = recoveredDecoded.map(
    (row) => ({ kind: row.kind, string: row.string }),
  );
  const page = await call("forge_read_enrichment_result", {
    receipt_path: floss.result.receipt_path,
    receipt_sha256: floss.result.receipt_sha256,
    offset: 1,
    limit: 1,
  });
  assert.deepEqual(page.result.rows, floss.result.rows.slice(1, 2));
  assert.equal(page.result.historical_readback, true);
  report.checks.retained_paging_without_rerun = true;
  const types = await call("forge_list_api_hash_types", { limit: 100 });
  assert.ok(types.result.total > 0);
  assert.ok(
    types.result.rows.some((row) =>
      row.hash_name.toLowerCase().includes("ror13"),
    ),
  );
  // Independent classic ROR13+ADD vector for LoadLibraryA, no terminating NUL.
  let vector = 0;
  for (const character of Buffer.from("LoadLibraryA"))
    vector = ((((vector >>> 13) | (vector << 19)) >>> 0) + character) >>> 0;
  assert.equal(vector, 0xec0e4e8e);
  const hashResult = await call("forge_lookup_api_hash", {
    hash_value: vector,
    limit: 100,
  });
  assert.ok(
    hashResult.result.rows.some((row) => row.symbol_name === "LoadLibraryA"),
    JSON.stringify(hashResult.result.rows),
  );
  report.checks.independent_api_hash_vector = {
    hash: "0xec0e4e8e",
    candidates: hashResult.result.total,
  };
  await reject("forge_lookup_api_hash", { hash_value: true });
  await reject("forge_lookup_api_hash", { hash_value: 1, hash_type: 999999 });
  await reject("forge_analyze_capabilities", { path: broken });
  await reject("forge_read_enrichment_result", {
    receipt_path: floss.result.receipt_path,
    receipt_sha256: "0".repeat(64),
  });
  report.checks.negative_inputs = true;
  const timeout = await reject("forge_analyze_capabilities", {
    path: sample,
    timeout_ms: 1,
  });
  const timeoutEnvelope = JSON.parse(
    timeout.content.find((part) => part.type === "text").text,
  );
  assert.equal(timeoutEnvelope.error.code, "provider_timeout");
  assert.equal(timeoutEnvelope.error.details.timeout_ms, 1);
  report.checks.real_native_deadline = true;
  const controller = new AbortController();
  const pending = raw(
    "forge_analyze_capabilities",
    { path: sample },
    controller.signal,
  );
  const timer = setTimeout(
    () => controller.abort(new Error("owned acceptance cancellation")),
    150,
  );
  await assert.rejects(pending);
  clearTimeout(timer);
  const afterCancel = await call("forge_lookup_api_hash", {
    hash_value: vector,
  });
  assert.equal(afterCancel.result.total, hashResult.result.total);
  report.checks.cancel_then_recover = true;
  const cli = await promisify(execFile)(
    process.execPath,
    [
      join(root, "scripts/rea.mjs"),
      "forge-lookup-api-hash",
      JSON.stringify({ hash_value: vector, limit: 100 }),
      "--format",
      "json",
    ],
    {
      env: environment,
      windowsHide: true,
      timeout: 55000,
      maxBuffer: 4 * 1024 * 1024,
    },
  );
  const cliValue = parseEvidence(JSON.parse(cli.stdout)).normalized_result;
  assert.deepEqual(cliValue.result.rows, hashResult.result.rows);
  report.checks.cli_mcp_parity = true;
  assert.equal(sha(await readFile(sample)), report.fixture_sha256);
  report.checks.original_unchanged = true;
  report.engines = {
    capa: capa.engine,
    floss: floss.engine,
    api_hashes: hashResult.engine,
  };
  report.status = "passed";
} catch (cause) {
  report.status = "failed";
  report.failure = String(cause);
  report.diagnostics = diagnostics;
  throw cause;
} finally {
  await client.close();
  report.server_pid = serverPid;
  report.transport_closed = true;
  report.provider_temp_empty = (await readdir(temporary)).length === 0;
  report.elapsed_seconds = (performance.now() - started) / 1000;
  const receipt = join(local, "evidence", `enrichment-${Date.now()}.json`);
  await writeFile(receipt, JSON.stringify(report, null, 2));
  if (report.provider_temp_empty) await rm(temporary, { recursive: true });
  console.log(
    JSON.stringify({
      status: report.status,
      receipt,
      elapsed_seconds: report.elapsed_seconds,
      checks: report.checks,
    }),
  );
}
