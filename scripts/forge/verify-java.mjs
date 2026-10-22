/** Whole Java capability acceptance through the real public stdio MCP + CLI. */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../../dist/domain/evidence.js";
import { FORGE_JAVA_TOOL_CONTRACTS } from "../../dist/contracts/forge/javaToolContracts.js";

const root = fileURLToPath(new URL("../../", import.meta.url));
const local = join(root, ".forge-local");
await mkdir(join(local, "fixtures"), { recursive: true });
await mkdir(join(local, "tmp"), { recursive: true });
await mkdir(join(local, "evidence"), { recursive: true });
const fixtures = await mkdtemp(join(local, "fixtures", "java-"));
const temporary = await mkdtemp(join(local, "tmp", "java-provider-"));
const source = join(fixtures, "ForgeFixture.java");
const companion = join(fixtures, "ForgeCompanion.java");
const invalid = join(fixtures, "Broken.java");
const malformed = join(fixtures, "broken.class");
const assembly = join(fixtures, "replacement.jasm");
await writeFile(
  source,
  `public class ForgeFixture {
  static { if (Boolean.parseBoolean("true")) throw new IllegalStateException("MUST_NOT_EXECUTE"); }
  public int value = 7;
  public String greet(int n) { return "REA_FORGE_FIXTURE_" + (n + value); }
  public int plus(int a, int b) { return a + b; }
  public int twice(int n) { return plus(n, n); }
}\n`,
);
await writeFile(
  companion,
  "public class ForgeCompanion { public int test(ForgeFixture f) { return f.twice(3); } }\n",
);
await writeFile(invalid, "public class Broken { syntax ??? }\n");
await writeFile(malformed, Buffer.from("cafebabe000000340000", "hex"));
await writeFile(
  assembly,
  `.super java/lang/Object
.class public super ForgeFixture {
  .method public static marker ()Ljava/lang/String; {
    code: {
    A:
      ldc "assembled-forge"
      areturn
    B:
    }
  }
}\n`,
);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const originals = new Map(
  await Promise.all(
    [source, companion, invalid, malformed, assembly].map(async (path) => [
      path,
      hash(await readFile(path)),
    ]),
  ),
);
const report = {
  status: "running",
  checks: {},
  decompilers: [],
  disassemblers: [],
  edits: [],
  sample_execution: false,
  gui_started: false,
  network_capture: false,
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
const entrypoint = join(root, "scripts/rea.mjs");
const client = new Client({ name: "rea-forge-java-acceptance", version: "1" });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
const execute = promisify(execFile);
const nativePids = new Set();
let serverPid;
let stderr = "";
const absent = (pid) => {
  try {
    process.kill(pid, 0);
    return false;
  } catch (cause) {
    if (cause.code === "ESRCH") return true;
    throw cause;
  }
};
const started = performance.now();
try {
  await client.connect(transport, { timeout: 20_000 });
  serverPid = transport.pid;
  transport.stderr?.on("data", (data) => {
    stderr = (stderr + data.toString()).slice(-8192);
  });
  const catalog = (await client.listTools({}, { timeout: 20_000 })).tools;
  const tools = new Map(catalog.map((tool) => [tool.name, tool]));
  report.advertised_tool_count = catalog.length;
  for (const contract of FORGE_JAVA_TOOL_CONTRACTS) {
    assert.ok(tools.get(contract.name)?.outputSchema);
    for (const example of contract.examples)
      assert.ok(contract.inputSchema.safeParse(example.input).success);
  }
  const raw = (name, args) =>
    client.callTool(
      { name, arguments: args },
      { timeout: 60_000, toolDefinition: tools.get(name) },
    );
  const call = async (name, args) => {
    const response = await raw(name, args);
    assert.notEqual(
      response.isError,
      true,
      `${name}: ${JSON.stringify(response)}`,
    );
    const evidence = parseEvidence(
      JSON.parse(response.content.find((block) => block.type === "text").text),
    );
    const value = evidence.normalized_result;
    for (const native of value.native) {
      assert.equal(native.owned_wait_completed, true);
      assert.equal(native.exit_code, 0);
      nativePids.add(native.pid);
    }
    assert.equal(value.sample_execution, false);
    assert.equal(value.operation, name);
    return value;
  };
  const reject = async (name, args) => {
    const response = await raw(name, args);
    assert.equal(
      response.isError,
      true,
      `${name} must reject: ${JSON.stringify(response)}`,
    );
  };
  const compiled = await call("forge_edit_java", {
    action: "compile_java",
    source_path: source,
    class_name: "ForgeFixture",
    release: 8,
    output_name: "ForgeFixture.class",
  });
  const input = compiled.result.derived_artifact.path;
  const classHash = hash(await readFile(input));
  report.edits.push("compile_java");
  const inspected = await call("forge_inspect_java", { path: input });
  assert.ok(JSON.stringify(inspected.result).includes("greet"));
  const multi = await call("forge_edit_java", {
    action: "compile_java_set",
    source_paths: [source, companion],
    class_name: "ForgeFixture",
    release: 8,
    output_name: "project.jar",
  });
  const archive = multi.result.derived_artifact.path;
  report.edits.push("compile_java_set");
  const archived = await call("forge_inspect_java", { path: archive });
  assert.ok(JSON.stringify(archived.result).includes("ForgeCompanion"));
  report.checks.real_compilation_and_metadata_readback = true;
  for (const engine of [
    "vineflower",
    "cfr",
    "bcv_procyon",
    "bcv_jd_core",
    "recaf_cfr",
    "recaf_vineflower",
  ]) {
    const result = await call("forge_decompile_java", {
      path: archive,
      class_name: "ForgeFixture",
      engine,
    });
    assert.ok(
      JSON.stringify(result.result).includes("REA_FORGE_FIXTURE_"),
      `${engine}: ${JSON.stringify(result.result)}`,
    );
    report.decompilers.push(engine);
  }
  report.checks.six_real_decompiler_paths = true;
  for (const engine of [
    "javap",
    "recaf_asm",
    "bcv_asm_textifier",
    "bcv_asmifier",
  ]) {
    const result = await call("forge_disassemble_java", {
      path: archive,
      class_name: "ForgeFixture",
      engine,
    });
    assert.ok(JSON.stringify(result.result).includes("greet"));
    report.disassemblers.push(engine);
  }
  report.checks.four_bytecode_fact_renderers = true;
  const searched = await call("forge_search_java", {
    path: archive,
    query: "REA_FORGE_FIXTURE_",
    kind: "string_constant",
  });
  assert.ok(JSON.stringify(searched.result).includes("REA_FORGE_FIXTURE_"));
  const graph = await call("forge_java_call_graph", {
    path: archive,
    class_name: "ForgeFixture",
    method_name: "twice",
    descriptor: "(I)I",
  });
  assert.ok(JSON.stringify(graph.result).includes("plus"));
  report.checks.constant_search_and_exact_method_call_graph = true;
  for (const [action, extra, expected] of [
    ["rename_class", { new_class_name: "ForgeRenamed" }, "ForgeRenamed"],
    [
      "rename_method",
      {
        method_name: "greet",
        descriptor: "(I)Ljava/lang/String;",
        new_name: "welcome",
      },
      "welcome",
    ],
    [
      "rename_field",
      { field_name: "value", descriptor: "I", new_name: "counter" },
      "counter",
    ],
    ["export_class", {}, "greet"],
    ["assemble", { assembly_path: assembly }, "marker"],
  ]) {
    const edited = await call("forge_edit_java", {
      action,
      path: input,
      class_name: "ForgeFixture",
      output_name: `${action}.class`,
      ...extra,
    });
    const result = await call("forge_inspect_java", {
      path: edited.result.derived_artifact.path,
    });
    assert.ok(JSON.stringify(result.result).includes(expected));
    report.edits.push(action);
  }
  for (const transformer of [
    "dead_code_remove",
    "duplicate_annotation_remove",
  ]) {
    const edited = await call("forge_edit_java", {
      action: "transform",
      path: archive,
      transformer,
      output_name: `${transformer}.jar`,
    });
    assert.ok((await readFile(edited.result.derived_artifact.path)).length > 0);
    await call("forge_inspect_java", {
      path: edited.result.derived_artifact.path,
    });
    report.edits.push(transformer);
  }
  const renamed = await call("forge_edit_java", {
    action: "rename_class",
    path: archive,
    class_name: "ForgeFixture",
    new_class_name: "ForgeRenamed",
    output_name: "renamed.jar",
  });
  const diff = await call("forge_compare_java", {
    path: archive,
    right_path: renamed.result.derived_artifact.path,
  });
  assert.ok(JSON.stringify(diff.result).includes("ForgeRenamed"));
  report.checks.all_edit_actions_and_archive_compare = true;
  await reject("forge_edit_java", {
    action: "compile_java",
    source_path: invalid,
    class_name: "Broken",
    release: 8,
    output_name: "Broken.class",
  });
  await reject("forge_inspect_java", { path: malformed });
  await reject("forge_decompile_java", {
    path: input,
    class_name: "Missing",
    engine: "cfr",
  });
  await reject("forge_decompile_java", {
    path: input,
    class_name: "ForgeFixture",
    engine: "arbitrary",
  });
  await reject("forge_edit_java", {
    action: "export_class",
    path: input,
    class_name: "ForgeFixture",
    output_name: "../../escape.class",
  });
  await call("forge_inspect_java", { path: input });
  report.checks.invalid_source_class_engine_path_and_recovery = true;
  const cli = await execute(
    process.execPath,
    [
      entrypoint,
      "forge-inspect-java",
      JSON.stringify({ path: input }),
      "--format",
      "json",
    ],
    {
      cwd: root,
      env: environment,
      windowsHide: true,
      timeout: 40_000,
      maxBuffer: 8 * 1024 * 1024,
    },
  );
  const cliResult = parseEvidence(JSON.parse(cli.stdout)).normalized_result;
  assert.deepEqual(cliResult.result, inspected.result);
  assert.deepEqual(cliResult.target, inspected.target);
  report.checks.real_cli_mcp_fact_parity = true;
  for (const [path, expected] of originals)
    assert.equal(hash(await readFile(path)), expected);
  assert.equal(hash(await readFile(input)), classHash);
  report.checks.original_sources_and_class_unchanged = true;
  report.status = "passed";
} catch (cause) {
  report.status = "failed";
  report.error = cause instanceof Error ? cause.stack : String(cause);
  process.exitCode = 1;
} finally {
  try {
    await client.close();
    await transport.close();
    assert.ok(serverPid == null || absent(serverPid));
    // Historical PIDs can already identify unrelated processes on Windows.
    // Native completion is proved above by wait() on each owned process handle;
    // REA's process-family owner settles before each successful helper reply.
    const pending = (await readdir(join(local, "tmp"))).filter((name) =>
      name.startsWith("forge-java-request-"),
    );
    assert.deepEqual(pending, []);
    report.checks.owned_processes_and_request_roots_closed = true;
    await Promise.all([
      rm(fixtures, { recursive: true }),
      rm(temporary, { recursive: true }),
    ]);
    report.checks.temporary_fixtures_removed = true;
  } catch (cause) {
    report.status = "failed";
    report.cleanup_error = String(cause);
    process.exitCode = 1;
  }
  report.elapsed_seconds = Number(
    ((performance.now() - started) / 1000).toFixed(3),
  );
  report.native_pids_observed = [...nativePids];
  if (stderr) report.stderr_tail = stderr;
  await writeFile(
    join(local, "evidence", `java-${Date.now()}.json`),
    JSON.stringify(report, null, 2) + "\n",
  );
  console.log(JSON.stringify(report, null, 2));
}
