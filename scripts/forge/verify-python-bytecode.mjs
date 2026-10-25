/** One complete native Python group. No target source/bytecode is executed. */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  writeFile,
  copyFile,
  readdir,
  rm,
  rmdir,
} from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../../dist/domain/evidence.js";
import { artifactInspectionResultSchema } from "../../dist/domain/artifactInspection.js";
import { artifactExtractionResultSchema } from "../../dist/domain/artifactGraph.js";
import { FORGE_PYTHON_OPERATIONS } from "../../dist/domain/forge/pythonBytecode.js";

const root = fileURLToPath(new URL("../../", import.meta.url)),
  local = join(root, ".forge-local");
for (const name of ["fixtures", "tmp", "evidence"])
  await mkdir(join(local, name), { recursive: true });
const fixtures = await mkdtemp(join(local, "fixtures/python-bytecode-"));
const temporary = await mkdtemp(join(local, "tmp/python-provider-"));
const extractTemp = await mkdtemp(join(local, "tmp/python-extract-"));
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const originals = new Map(),
  paths = {};
const sourceRoot = process.env.REA_FORGE_PYTHON_FIXTURE_ROOT;
assert.ok(
  sourceRoot,
  "explicit already installed fixture root required; no downloads",
);
for (const [key, leaf] of Object.entries({
  legacy: "uncompyle6/recore_uncompyle6_fixture.pyc",
  py38: "decompyle3/recore_decompyle3_fixture38.pyc",
  disassembly: "xdis/recore_xdis_fixture.pyc",
  packaged: "pyinstaller/recore-pyinstaller-fixture.exe",
})) {
  const source = join(sourceRoot, leaf),
    path = join(fixtures, key + (key === "packaged" ? ".exe" : ".pyc"));
  const digest = sha(await readFile(source));
  await copyFile(source, path);
  assert.equal(sha(await readFile(path)), digest);
  originals.set(source, digest);
  originals.set(path, digest);
  paths[key] = path;
}
paths.invalid = join(fixtures, "invalid.pyc");
await writeFile(paths.invalid, "invalid bytecode");
originals.set(paths.invalid, sha(await readFile(paths.invalid)));
const selected = JSON.parse(
  await readFile(process.env.REA_FORGE_STATIC_CONFIG, "utf8"),
);
const models = JSON.parse(
  await readFile(selected.pylingual.models_manifest.path, "utf8"),
);
const source = join(fixtures, "known-source.py");
await writeFile(source, "def answer(value):\n    return value + 1\n");
originals.set(source, sha(await readFile(source)));
const execute = promisify(execFile);
for (const [version, interpreter] of Object.entries(
  models.verification_interpreters,
)) {
  assert.equal(sha(await readFile(interpreter.path)), interpreter.sha256);
  const path = join(fixtures, "python" + version + ".pyc");
  await execute(
    interpreter.path,
    [
      "-I",
      "-c",
      "import py_compile,sys; py_compile.compile(sys.argv[1],cfile=sys.argv[2],doraise=True)",
      source,
      path,
    ],
    { windowsHide: true, timeout: 10000, maxBuffer: 65536 },
  );
  paths[version] = path;
  originals.set(path, sha(await readFile(path)));
}
const memoryOnly = process.argv.includes("--resource-refusal");
let configurationPath = process.env.REA_FORGE_STATIC_CONFIG;
if (memoryOnly) {
  configurationPath = join(fixtures, "resource-policy.json");
  await writeFile(configurationPath, JSON.stringify({ ...selected, pylingual: { ...selected.pylingual, minimum_free_memory_bytes: 1024 ** 4 } }));
  originals.set(configurationPath, sha(await readFile(configurationPath)));
}
const environment = Object.fromEntries(
  Object.entries({
    ...process.env,
    REA_FORGE_STATIC_CONFIG: configurationPath,
    TEMP: temporary,
    TMP: temporary,
    TMPDIR: temporary,
    REA_LOG_LEVEL: "error",
  }).filter(([, value]) => typeof value === "string"),
);
const entrypoint = join(root, "scripts/rea.mjs");
const client = new Client({
  name: "forge-python-bytecode-acceptance",
  version: "1",
});
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
const report = {
  status: "running",
  checks: {},
  results: [],
  fixture_hashes: Object.fromEntries(originals),
  target_execution: false,
  network_used: false,
  gui_started: false,
};
report.scope = memoryOnly
  ? "non-model subset and resource refusal; model inference not verified"
  : "complete G06 bytecode group";
const resumePath = process.env.REA_FORGE_PYTHON_RESUME;
const prior = resumePath
  ? JSON.parse(await readFile(resumePath, "utf8"))
  : undefined;
if (prior) {
  assert.equal(prior.checks.cli_mcp_route_parity, true);
  assert.equal(prior.provider_temp_empty, true);
  for (const [path, digest] of Object.entries(prior.fixture_hashes))
    assert.equal(sha(await readFile(path)), digest);
  for (const reference of prior.results) {
    const bytes = await readFile(reference.receipt_path);
    assert.equal(sha(bytes), reference.receipt_sha256);
    const retained = JSON.parse(bytes);
    assert.equal(
      sha(await readFile(retained.full_result.path)),
      retained.full_result.sha256,
    );
  }
  report.reused_receipt = {
    path: resumePath,
    sha256: sha(await readFile(resumePath)),
  };
  report.checks = { ...prior.checks };
  report.results = [...prior.results];
  report.retained_extraction = prior.retained_extraction;
}
const started = performance.now();
let diagnostics = "";
try {
  await client.connect(transport, { timeout: 20000 });
  report.server_pid = transport.pid;
  transport.stderr?.on("data", (chunk) => {
    diagnostics = (diagnostics + chunk.toString()).slice(-65536);
  });
  const tools = new Map(
    (await client.listTools({}, { timeout: 20000 })).tools.map((tool) => [
      tool.name,
      tool,
    ]),
  );
  for (const name of FORGE_PYTHON_OPERATIONS) assert.ok(tools.has(name));
  report.tool_count = tools.size;
  const raw = (name, input, signal) =>
    client.callTool(
      { name, arguments: input },
      {
        timeout: name === "forge_decompile_modern_python" ? 145000 : 55000,
        toolDefinition: tools.get(name),
        ...(signal === undefined ? {} : { signal }),
      },
    );
  const call = async (name, input) => {
    const response = await raw(name, input);
    assert.notEqual(response.isError, true, JSON.stringify(response));
    const evidence = parseEvidence(
      JSON.parse(response.content.find((part) => part.type === "text").text),
    );
    const result = evidence.normalized_result;
    if (result.result?.receipt_path)
      report.results.push({
        name,
        input,
        receipt_path: result.result.receipt_path,
        receipt_sha256: result.result.receipt_sha256,
      });
    return result;
  };
  const reject = async (name, input) => {
    const response = await raw(name, input);
    assert.equal(response.isError, true, JSON.stringify(response));
    return JSON.parse(
      response.content.find((part) => part.type === "text").text,
    );
  };
  if (!prior && !memoryOnly) {
    const native = await call("inspect_python_pyc", { path: paths["3.11"] });
    assert.ok(JSON.stringify(native).includes("3.11"));
    assert.ok(JSON.stringify(native).includes("answer"));
    report.checks.native_pyc_facts = true;
    const inspected = await execute(
      process.execPath,
      [entrypoint, "inspect-artifact", paths.packaged, "--format", "json"],
      {
        env: environment,
        windowsHide: true,
        timeout: 35000,
        maxBuffer: 16 * 1024 * 1024,
      },
    );
    const inventory = artifactInspectionResultSchema.parse(
      parseEvidence(JSON.parse(inspected.stdout)).normalized_result,
    );
    assert.equal(inventory.subject.root_format, "pyinstaller");
    report.checks.native_pyinstaller_inventory = true;
    const extractedReply = await execute(
      process.execPath,
      [entrypoint, "extract-artifact", paths.packaged, "--format", "json"],
      {
        env: {
          ...environment,
          TEMP: extractTemp,
          TMP: extractTemp,
          TMPDIR: extractTemp,
        },
        windowsHide: true,
        timeout: 45000,
        maxBuffer: 16 * 1024 * 1024,
      },
    );
    const extracted = artifactExtractionResultSchema.parse(
      parseEvidence(JSON.parse(extractedReply.stdout)).normalized_result,
    );
    assert.equal(extracted.containment_verified, true);
    assert.ok(extracted.artifacts.length > 0);
    for (const artifact of extracted.artifacts)
      assert.equal(
        sha(
          await readFile(join(extracted.output_root, artifact.relative_path)),
        ),
        artifact.sha256,
      );
    report.retained_extraction = {
      output_root: extracted.output_root,
      artifacts: extracted.artifacts.length,
      temporary_parent: extractTemp,
    };
    report.checks.native_pyinstaller_extraction_and_hashes = true;
    for (const format of ["classic", "extended", "xasm"]) {
      const result = await call("forge_disassemble_python", {
        path: paths.disassembly,
        format,
      });
      assert.equal(result.result.analysis_status, "disassembled");
      assert.ok(result.result.text.includes("answer"));
    }
    report.checks.xdis_all_renderings = true;
    for (const [path, engine] of [
      [paths.legacy, "uncompyle6"],
      [paths.py38, "decompyle3"],
    ]) {
      const result = await call("forge_decompile_legacy_python", {
        path,
        engine,
      });
      assert.equal(
        result.result.analysis_status,
        "decompiled",
        JSON.stringify(result),
      );
      assert.equal(result.result.engine, engine);
      assert.ok(result.result.text.includes("def answer"));
      assert.ok(result.result.text.includes("return value + 1"));
      assert.equal(result.result.equivalence_verified, false);
      const reread = await call("forge_read_python_result", {
        receipt_path: result.result.receipt_path,
        receipt_sha256: result.result.receipt_sha256,
        text_offset: 4,
        text_limit: 10,
      });
      assert.equal(reread.result.text, result.result.text.slice(4, 14));
    }
    report.checks.legacy_version_engines_and_retained_text = true;
    const mismatch = await call("forge_decompile_legacy_python", {
      path: paths.py38,
      engine: "uncompyle6",
    });
    assert.equal(mismatch.result.analysis_status, "unsupported_version");
    const modernRefusal = await call("forge_decompile_legacy_python", {
      path: paths["3.11"],
    });
    assert.equal(modernRefusal.result.analysis_status, "unsupported_version");
    const oldRefusal = await call("forge_decompile_modern_python", {
      path: paths.legacy,
    });
    assert.equal(oldRefusal.result.analysis_status, "unsupported_version");
    report.checks.no_wrong_version_fallback = true;
    await reject("forge_disassemble_python", { path: paths.invalid });
    const timeout = await reject("forge_disassemble_python", {
      path: paths.disassembly,
      timeout_ms: 1,
    });
    assert.equal(timeout.error.code, "provider_timeout");
    assert.equal(timeout.error.details.timeout_ms, 1);
    report.checks.actual_library_deadline = true;
    const controller = new AbortController();
    const pending = raw(
      "forge_disassemble_python",
      { path: paths.disassembly },
      controller.signal,
    );
    const timer = setTimeout(
      () => controller.abort(new Error("owned Python request cancellation")),
      150,
    );
    await assert.rejects(pending);
    clearTimeout(timer);
    assert.equal(
      (await call("forge_disassemble_python", { path: paths.disassembly }))
        .result.analysis_status,
      "disassembled",
    );
    report.checks.cancellation_and_same_family_recovery = true;
    const cli = await execute(
      process.execPath,
      [
        entrypoint,
        "forge-decompile-legacy-python",
        JSON.stringify({ path: paths.py38 }),
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
    assert.equal(
      parseEvidence(JSON.parse(cli.stdout)).normalized_result.result.engine,
      "decompyle3",
    );
    report.checks.cli_mcp_route_parity = true;
  }
  // Model inference is last: a real external memory/prerequisite failure preserves
  // the passed non-model subset and does not force its expensive repetition.
  if (memoryOnly) {
    const refusal = await reject("forge_decompile_modern_python", {
      path: paths["3.11"],
    });
    assert.equal(refusal.error.code, "resource_constraint");
    assert.equal(refusal.error.retryable, true);
    assert.equal(refusal.error.details.resource, "memory");
    report.checks.typed_memory_admission_without_model_load = true;
  } else
    for (const version of models.qualified_versions) {
      if (report.checks["pylingual_" + version]) continue;
      const result = await call("forge_decompile_modern_python", {
        path: paths[version],
      });
      assert.equal(result.result.analysis_status, "decompiled");
      assert.equal(result.result.equivalence_verified, true);
      assert.deepEqual(
        result.result.pyc.version,
        version.split(".").map(Number),
      );
      assert.ok(result.result.text.includes("def answer(value):"));
      assert.ok(result.result.text.includes("return value + 1"));
      report.checks["pylingual_" + version] = true;
      await writeFile(
        join(local, "evidence", "python-bytecode-current.json"),
        JSON.stringify(report, null, 2),
      );
      console.log(
        JSON.stringify({
          phase: "model-completed",
          version,
          elapsed_seconds: (performance.now() - started) / 1000,
        }),
      );
    }
  for (const [path, digest] of originals)
    assert.equal(sha(await readFile(path)), digest);
  report.checks.originals_unchanged = true;
  report.status = "passed";
} catch (cause) {
  report.status = "failed";
  report.failure = String(cause);
  report.diagnostics = diagnostics;
  throw cause;
} finally {
  try {
    await client.close();
    report.transport_closed = true;
  } catch (cause) {
    report.status = "failed";
    report.cleanup_failure = String(cause);
  }
  report.provider_temp_empty = (await readdir(temporary)).length === 0;
  if (report.provider_temp_empty) await rm(temporary, { recursive: true });
  else {
    report.status = "failed";
    report.cleanup_failure = "provider temporary root not empty";
  }
  if (
    report.retained_extraction?.temporary_parent !== extractTemp &&
    (await readdir(extractTemp)).length === 0
  )
    await rmdir(extractTemp);
  report.elapsed_seconds = (performance.now() - started) / 1000;
  const receipt = join(local, "evidence", `python-bytecode-${Date.now()}.json`);
  await writeFile(receipt, JSON.stringify(report, null, 2));
  console.log(
    JSON.stringify({
      status: report.status,
      scope: report.scope,
      receipt,
      elapsed_seconds: report.elapsed_seconds,
      checks: report.checks,
      provider_temp_empty: report.provider_temp_empty,
    }),
  );
  if (report.status !== "passed") process.exitCode = 1;
}
