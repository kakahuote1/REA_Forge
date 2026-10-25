/** Complete G05 harmless work-IDB group; successful engines are checkpointed. */
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
import { FORGE_IDA_OPERATIONS } from "../../dist/domain/forge/idaStatic.js";

const root = fileURLToPath(new URL("../../", import.meta.url)),
  local = join(root, ".forge-local");
const sha = (value) => createHash("sha256").update(value).digest("hex");
const resume = process.env.REA_FORGE_IDA_RESUME;
const prior = resume ? JSON.parse(await readFile(resume, "utf8")) : undefined;
const fixtures =
  prior?.fixtures ?? (await mkdtemp(join(local, "fixtures/ida-static-")));
const temporary = await mkdtemp(join(local, "tmp/ida-provider-"));
const paths = {
  crypto: join(fixtures, "findcrypt.exe"),
  imports: join(fixtures, "imports.exe"),
};
const originals = { ...prior?.originals };
if (!prior) {
  const source = process.env.REA_FORGE_IDA_FIXTURES;
  assert.ok(source, "explicit source-owned IDA fixtures directory required");
  for (const [name, leaf, digest] of [
    [
      "crypto",
      "p3_findcrypt_fixture.exe",
      "d00fce30410a8105b77d05b34e127a29f5433d2b24dbfc01418ab03f434e4ae9",
    ],
    [
      "imports",
      "p3_autoenum_fixture.exe",
      "ecdc86a9c164ad74cfe75afc5b4efe6fdb670edf7558fdd88c8fd75a4a2a27e6",
    ],
  ]) {
    const path = join(source, leaf);
    assert.equal(sha(await readFile(path)), digest);
    await copyFile(path, paths[name]);
    originals[path] = digest;
    originals[paths[name]] = digest;
  }
}
for (const [path, digest] of Object.entries(originals))
  assert.equal(sha(await readFile(path)), digest);
const configuration = JSON.parse(
  await readFile(process.env.REA_FORGE_STATIC_CONFIG, "utf8"),
);
const configPath = join(fixtures, "acceptance-tools.json");
await writeFile(configPath, JSON.stringify(configuration));
const report = {
  status: "running",
  scope:
    "G05 native IDA readonly provider and controlled typed work-IDB extensions; no target launch or guest debugging",
  fixtures,
  originals,
  checks: { ...prior?.checks },
  values: { ...prior?.values },
  target_execution: false,
  gui_started: false,
  network_actions_requested: false,
  cpu_time: "unmeasured",
  peak_process_family_memory: "unmeasured",
};
if (prior)
  report.reused_receipt = { path: resume, sha256: sha(await readFile(resume)) };
report.configuration_sha256 = sha(
  JSON.stringify([
    configuration.ida_host,
    configuration.ida_assembly,
    configuration.ida_exchange,
    configuration.ida_results,
  ]),
);
if (prior)
  assert.equal(report.configuration_sha256, prior.configuration_sha256);
report.source_hashes = {};
for (const path of [
  "bridge/forge/ida/worker.py",
  "bridge/forge/ida/engine.py",
  "bridge/forge/ida/host_profile.py",
  "bridge/forge/ida/safe_python.py",
  "bridge/forge/ida/native_supervisor.py",
  "dist/domain/forge/idaStatic.js",
  "dist/forge/ida/IdaStaticAdapter.js",
])
  report.source_hashes[path] = sha(await readFile(join(root, path)));
if (prior)
  report.changed_sources = Object.keys(report.source_hashes).filter(
    (path) => prior.source_hashes[path] !== report.source_hashes[path],
  );
async function verifyRetained(value) {
  if (!value || typeof value !== "object") return;
  const reference = value.result;
  if (reference?.receipt_path) {
    assert.equal(
      sha(await readFile(reference.receipt_path)),
      reference.receipt_sha256,
    );
    const receipt = JSON.parse(await readFile(reference.receipt_path, "utf8"));
    for (const item of [receipt.full_result, ...receipt.artifacts])
      assert.equal(sha(await readFile(item.path)), item.sha256);
  } else
    for (const nested of Object.values(value)) await verifyRetained(nested);
}
for (const value of Object.values(report.values)) await verifyRetained(value);
const env = Object.fromEntries(
  Object.entries({
    ...process.env,
    REA_FORGE_STATIC_CONFIG: configPath,
    TEMP: temporary,
    TMP: temporary,
    TMPDIR: temporary,
    REA_LOG_LEVEL: "error",
  }).filter(([, value]) => typeof value === "string"),
);
assert.ok(env.REA_IDA_MCP_CONFIG, "explicit native IDA registration required");
const entry = join(root, "scripts/rea.mjs"),
  started = performance.now();
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entry, "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({
  name: "forge-ida-static-acceptance",
  version: "1",
});
const ref = (value) => ({
  receipt_path: value.result.receipt_path,
  receipt_sha256: value.result.receipt_sha256,
});
let diagnostics = "";
const checkpoint = () =>
  writeFile(
    join(local, "evidence/ida-static-current.json"),
    JSON.stringify(report, null, 2),
  );
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
  for (const name of FORGE_IDA_OPERATIONS) assert.ok(tools.has(name));
  report.catalog_count = tools.size;
  const raw = (name, input, signal) =>
    client.callTool(
      { name, arguments: input },
      {
        timeout: 65000,
        toolDefinition: tools.get(name),
        ...(signal ? { signal } : {}),
      },
    );
  const evidence = async (name, input) => {
    const value = await raw(name, input);
    assert.notEqual(value.isError, true, JSON.stringify(value));
    return parseEvidence(
      JSON.parse(value.content.find((part) => part.type === "text").text),
    );
  };
  const call = async (name, input) =>
    (await evidence(name, input)).normalized_result;
  const reject = async (name, input) => {
    const value = await raw(name, input);
    assert.equal(value.isError, true, JSON.stringify(value));
    return JSON.parse(value.content.find((part) => part.type === "text").text);
  };
  const step = async (name, action, validate = () => {}) => {
    if (!(name in report.values)) {
      report.values[name] = await action();
      await checkpoint();
    }
    await validate(report.values[name]);
    report.checks[name] = true;
    await checkpoint();
    console.log(
      JSON.stringify({
        phase: name,
        elapsed_seconds: (performance.now() - started) / 1000,
      }),
    );
    return report.values[name];
  };
  const queried = await step(
    "safe_query_and_profile",
    () =>
      call("forge_run_ida_safe_python", {
        path: paths.crypto,
        code: 'result={"probe":db.lookup("p3_findcrypt_probe"),"functions":db.functions(limit=8)}',
        facet: "analysis",
      }),
    (value) => {
      assert.equal(value.result.value.main_thread, true);
      assert.ok(value.result.value.data.result.functions.length > 0);
      assert.ok(
        value.result.value.loaded_plugins_before.every((item) =>
          configuration.ida_host.approved_plugins.some(
            (pin) =>
              pin.path.replaceAll("/", "\\").toLowerCase() ===
              item.path.toLowerCase(),
          ),
        ),
      );
    },
  );
  const functions = queried.result.value.data.result;
  const selected = functions.probe ?? functions.functions[0],
    address = selected.addr;
  report.selected_function = selected;
  const initial = await step(
    "original_mapped_bytes",
    () =>
      call("forge_export_ida_data", {
        path: paths.crypto,
        address,
        length: 8,
        data_kind: "raw_hex",
        render: "text",
        facet: "analysis",
      }),
    (value) => assert.match(value.result.value.data.text, /^[A-F0-9]{16}$/),
  );
  const beforeHex = initial.result.value.data.text.slice(0, 2),
    afterHex = beforeHex === "90" ? "CC" : "90";
  const edited = await step(
    "typed_edits_declarations_enums_definitions",
    () =>
      call("forge_edit_ida_database", {
        path: paths.crypto,
        inspect_types: ["ForgeApiTable", "ForgeTestEnum"],
        facet: "analysis",
        edits: [
          { action: "rename", address, name: "forge_reviewed_entry" },
          { action: "comment", address, text: "Forge current static review" },
          {
            action: "prototype",
            address,
            prototype:
              "unsigned __int64 __fastcall forge_reviewed_entry(unsigned int value);",
          },
          {
            action: "declaration",
            declaration:
              "typedef int ForgeCallback(int); typedef struct ForgeApiTable { void *ForgeCallback_0; void *field_0_ForgeCallback_1; unsigned int untouched; } ForgeApiTable;",
          },
          {
            action: "enum",
            name: "ForgeTestEnum",
            members: [{ name: "FORGE_ENUM_SEVEN", value: 7 }],
          },
          { action: "undefine", address, size: 1 },
          { action: "make_data", address, width: 1 },
          { action: "undefine", address, size: 1 },
          { action: "define_code", address },
        ],
      }),
    (value) => {
      assert.equal(value.result.value.data.changes.length, 9);
      assert.equal(
        value.result.value.data.changes[0].name,
        "forge_reviewed_entry",
      );
      assert.equal(
        value.result.value.data.changes[1].comment,
        "Forge current static review",
      );
      assert.ok(value.result.value.type_observations.length >= 2);
    },
  );
  const database = edited.result.artifacts.find((item) =>
    item.path.endsWith("database.i64"),
  );
  assert.ok(database);
  await step(
    "saved_idb_reopen",
    () =>
      call("forge_run_ida_safe_python", {
        path: database.path,
        expected_sha256: database.sha256,
        inspect_types: ["ForgeApiTable", "ForgeTestEnum"],
        code: 'result=db.lookup("forge_reviewed_entry")',
        facet: "analysis",
      }),
    (value) => {
      assert.equal(value.result.value.data.result.addr, address);
      assert.equal(value.result.value.data.result.name, "forge_reviewed_entry");
      assert.ok(value.result.value.type_observations.length >= 2);
    },
  );
  const patch = await step(
    "exact_preimage_byte_patch",
    () =>
      call("forge_edit_ida_database", {
        path: database.path,
        edits: [
          {
            action: "patch",
            address,
            expected_before_hex: beforeHex,
            data_hex: afterHex,
          },
        ],
        facet: "analysis",
      }),
    (value) =>
      assert.equal(
        value.result.value.data.changes[0].result.after_hex.toUpperCase(),
        afterHex,
      ),
  );
  const patched = patch.result.artifacts.find((item) =>
    item.path.endsWith("database.i64"),
  );
  await step(
    "patched_idb_reopen_bytes",
    () =>
      call("forge_export_ida_data", {
        path: patched.path,
        address,
        length: 1,
        data_kind: "raw_hex",
        render: "text",
        facet: "analysis",
      }),
    (value) => assert.equal(value.result.value.data.text, afterHex),
  );
  const restore = await step(
    "digest_bound_restore",
    () =>
      call("forge_restore_ida_database", {
        ...ref(patch),
        expected_database_sha256: patched.sha256,
      }),
    (value) =>
      assert.equal(
        value.result.artifacts[0].sha256,
        patch.result.artifacts.find((item) => item.path.endsWith("before.i64"))
          .sha256,
      ),
  );
  await step(
    "restored_idb_reopen",
    () =>
      call("forge_export_ida_data", {
        path: restore.result.artifacts[0].path,
        address,
        length: 1,
        data_kind: "raw_hex",
        render: "text",
        facet: "analysis",
      }),
    (value) => assert.equal(value.result.value.data.text, beforeHex),
  );
  for (const [architecture, assembly, hex] of [
    ["x64", "nop", "90"],
    ["arm64", "nop", "1F2003D5"],
    ["mips", "nop", "00000000"],
  ])
    await step(
      `keystone_${architecture}`,
      () =>
        call("forge_assemble_ida", {
          architecture,
          assembly,
          facet: "analysis",
        }),
      (value) => assert.equal(value.result.value.encoding_hex, hex),
    );
  const assembled = await step("exact_preimage_assembly_patch", () =>
    call("forge_edit_ida_database", {
      path: database.path,
      edits: [
        {
          action: "assemble_patch",
          address,
          architecture: "x64",
          assembly: afterHex === "CC" ? "int3" : "nop",
          expected_before_hex: beforeHex,
        },
      ],
      facet: "analysis",
    }),
  );
  await step(
    "assembly_patch_reopen",
    () =>
      call("forge_export_ida_data", {
        path: assembled.result.artifacts.find((item) =>
          item.path.endsWith("database.i64"),
        ).path,
        address,
        length: 1,
        data_kind: "raw_hex",
        render: "text",
        facet: "analysis",
      }),
    (value) => assert.equal(value.result.value.data.text, afterHex),
  );
  const enumPreview = await step(
    "autoenum_preview",
    () =>
      call("forge_ida_enum", {
        path: paths.imports,
        platform: "windows",
        facet: "analysis",
      }),
    (value) => assert.ok(value.result.value.data.preview.candidates.length > 0),
  );
  const enumName = enumPreview.result.value.data.preview.candidates
    .flatMap((item) => item.enum_arguments)
    .map((item) => item.source_enum)[0];
  assert.ok(enumName);
  const enumApplied = await step(
    "explicit_autoenum_apply",
    () =>
      call("forge_ida_enum", {
        path: paths.imports,
        platform: "windows",
        enum_names: [enumName],
        facet: "analysis",
      }),
    (value) => assert.equal(value.result.value.data.applied.applied.length, 1),
  );
  const localEnum = enumApplied.result.value.data.applied.applied[0].local_enum;
  await step(
    "enum_type_saved_readback",
    () =>
      call("forge_snapshot_ida_database", {
        path: enumApplied.result.artifacts.find((item) =>
          item.path.endsWith("database.i64"),
        ).path,
        inspect_types: [localEnum],
        max_functions: 8,
        facet: "analysis",
      }),
    (value) =>
      assert.ok(
        JSON.stringify(value.result.value.type_observations).includes(
          localEnum,
        ),
      ),
  );
  const structPreview = await step(
    "structure_preview",
    () =>
      call("forge_ida_struct_typer", {
        path: database.path,
        struct_name: "ForgeApiTable",
        facet: "analysis",
      }),
    (value) =>
      assert.ok(value.result.value.data.preview.candidates.length >= 1),
  );
  const member =
    structPreview.result.value.data.preview.candidates[0].member_name;
  const structApplied = await step("explicit_structure_apply", () =>
    call("forge_ida_struct_typer", {
      path: database.path,
      struct_name: "ForgeApiTable",
      member_names: [member],
      inspect_types: ["ForgeApiTable"],
      facet: "analysis",
    }),
  );
  await step(
    "structure_saved_readback",
    () =>
      call("forge_ida_struct_typer", {
        path: structApplied.result.artifacts.find((item) =>
          item.path.endsWith("database.i64"),
        ).path,
        struct_name: "ForgeApiTable",
        inspect_types: ["ForgeApiTable"],
        facet: "analysis",
      }),
    (value) =>
      assert.ok(
        !value.result.value.data.preview.candidates.some(
          (item) => item.member_name === member,
        ),
      ),
  );
  const left = await step("function_snapshot_before", () =>
    call("forge_snapshot_ida_database", {
      path: paths.crypto,
      facet: "analysis",
    }),
  );
  const right = await step("function_snapshot_after", () =>
    call("forge_snapshot_ida_database", {
      path: database.path,
      facet: "analysis",
    }),
  );
  await step(
    "offline_function_difference",
    () =>
      call("forge_compare_ida_snapshots", {
        before: ref(left),
        after: ref(right),
        facet: "analysis",
      }),
    (value) =>
      assert.ok(
        value.result.value.matches.some(
          (item) =>
            item.left.addr === address &&
            item.right.name === "forge_reviewed_entry" &&
            !item.changed,
        ),
      ),
  );
  const changed = await step("function_snapshot_byte_changed", () =>
    call("forge_snapshot_ida_database", {
      path: assembled.result.artifacts.find((item) =>
        item.path.endsWith("database.i64"),
      ).path,
      facet: "analysis",
    }),
  );
  await step(
    "offline_byte_difference",
    () =>
      call("forge_compare_ida_snapshots", {
        before: ref(right),
        after: ref(changed),
        facet: "analysis",
      }),
    (value) =>
      assert.ok(
        value.result.value.matches.some(
          (item) => item.changed && item.right.name === "forge_reviewed_entry",
        ),
      ),
  );
  await step(
    "findcrypt_yara_known_candidate",
    () =>
      call("forge_scan_ida_crypto", { path: paths.crypto, facet: "analysis" }),
    (value) =>
      assert.ok(
        value.result.value.data.hits.some(
          (item) => item.rule === "RijnDael_AES_CHAR",
        ),
      ),
  );
  await step(
    "safe_static_batch_effect",
    () =>
      call("forge_run_ida_safe_python", {
        path: database.path,
        code: `f=db.lookup("forge_reviewed_entry")\nif f:\n db.comment(f["addr"],"safe batch marker")\n db.save()\nresult=f`,
        facet: "analysis",
      }),
    (value) =>
      assert.equal(
        value.result.value.data.writes.filter((item) => item.kind === "comment")
          .length,
        1,
      ),
  );
  await step("native_readonly_provider", async () => {
    const opened = await raw("open_binary", {
      path: paths.crypto,
      provider_id: "ida",
    });
    assert.notEqual(opened.isError, true, JSON.stringify(opened));
    try {
      const inventory = await evidence("list_procedures", {});
      assert.equal(inventory.provider.id, "ida");
      const dossier = await evidence("analyze_function", {
        procedure: address,
      });
      assert.equal(dossier.provider.id, "ida");
      return { inventory, dossier };
    } finally {
      const closed = await raw("close_binary", {});
      assert.notEqual(closed.isError, true, JSON.stringify(closed));
    }
  });
  await step("forbidden_facade_and_preimages", async () => ({
    imports: await reject("forge_run_ida_safe_python", {
      path: paths.crypto,
      code: "import os\nresult=0",
    }),
    counter: await reject("forge_run_ida_safe_python", {
      path: paths.crypto,
      code: "_safe_tick=str\nfor i in range(2):\n pass",
    }),
    wrong_input: await reject("forge_snapshot_ida_database", {
      path: paths.crypto,
      expected_sha256: "0".repeat(64),
    }),
    wrong_patch: await reject("forge_edit_ida_database", {
      path: database.path,
      edits: [
        {
          action: "patch",
          address,
          expected_before_hex: "00010203",
          data_hex: "90909090",
        },
      ],
    }),
    wrong_restore: await reject("forge_restore_ida_database", {
      ...ref(patch),
      expected_database_sha256: "0".repeat(64),
    }),
    receipt: await reject("forge_read_ida_result", {
      ...ref(queried),
      receipt_sha256: "0".repeat(64),
    }),
  }));
  await step(
    "actual_idalib_deadline",
    () =>
      reject("forge_snapshot_ida_database", {
        path: paths.crypto,
        timeout_ms: 1,
      }),
    (value) => assert.match(JSON.stringify(value), /timeout|deadline/i),
  );
  await step(
    "actual_keystone_boundary_deadline",
    () =>
      reject("forge_assemble_ida", {
        architecture: "x64",
        assembly: "nop",
        timeout_ms: 1,
      }),
    (value) => assert.match(JSON.stringify(value), /timeout|deadline/i),
  );
  await step("cancel_and_readback_recovery", async () => {
    const stop = new AbortController();
    const pending = raw(
      "forge_snapshot_ida_database",
      { path: paths.crypto },
      stop.signal,
    );
    const timer = setTimeout(
      () => stop.abort("source-owned IDA test cancellation"),
      75,
    );
    try {
      await assert.rejects(pending);
    } finally {
      clearTimeout(timer);
    }
    const recovered = await call("forge_read_ida_result", {
      ...ref(queried),
      facet: "analysis",
    });
    assert.equal(
      recovered.result.value.data.result.functions[0].addr,
      functions.functions[0].addr,
    );
    return { recovered: true };
  });
  await step("missing_ida_isolation", async () => {
    const selected = structuredClone(configuration);
    delete selected.ida_host;
    await writeFile(configPath, JSON.stringify(selected));
    try {
      const failure = await reject("forge_snapshot_ida_database", {
        path: paths.crypto,
      });
      const kept = await call("forge_read_ida_result", ref(queried));
      return { failure, historical_readback: kept.result.historical_readback };
    } finally {
      await writeFile(configPath, JSON.stringify(configuration));
    }
  });
  await step("cli_artifact_parity", async () => {
    const { stdout } = await promisify(execFile)(
      process.execPath,
      [
        entry,
        "forge-read-ida-result",
        JSON.stringify({ ...ref(queried), artifact_index: 1, byte_count: 32 }),
        "--format",
        "json",
      ],
      {
        env,
        cwd: temporary,
        windowsHide: true,
        timeout: 25000,
        maxBuffer: 2 * 1024 * 1024,
      },
    );
    const value = parseEvidence(JSON.parse(stdout)).normalized_result;
    const original = await readFile(queried.result.artifacts[0].path);
    assert.deepEqual(
      Buffer.from(value.result.artifact_read.base64, "base64"),
      original.subarray(0, 32),
    );
    return { equal: true };
  });
  for (const [path, digest] of Object.entries(originals))
    assert.equal(sha(await readFile(path)), digest);
  for (const value of Object.values(report.values)) await verifyRetained(value);
  report.checks.originals_and_retained_files_unchanged = true;
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
  const receipt = join(local, "evidence", `ida-static-${Date.now()}.json`);
  await writeFile(receipt, JSON.stringify(report, null, 2));
  console.log(
    JSON.stringify({
      status: report.status,
      receipt,
      checks: report.checks,
      elapsed_seconds: report.elapsed_seconds,
      provider_temp_empty: report.provider_temp_empty,
      failure: report.failure,
    }),
  );
}
