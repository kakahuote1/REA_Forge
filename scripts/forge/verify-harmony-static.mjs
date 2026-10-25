/** One real G10 group; checkpoint completed engine outputs before assertions. */
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
import { FORGE_HARMONY_OPERATIONS } from "../../dist/domain/forge/harmonyStatic.js";

const root = fileURLToPath(new URL("../../", import.meta.url)),
  local = join(root, ".forge-local");
const sha = (value) => createHash("sha256").update(value).digest("hex");
const resume = process.env.REA_FORGE_HARMONY_RESUME;
const prior = resume ? JSON.parse(await readFile(resume, "utf8")) : undefined;
const fixtures =
  prior?.fixtures ?? (await mkdtemp(join(local, "fixtures/harmony-static-")));
const temporary = await mkdtemp(join(local, "tmp/harmony-provider-"));
const paths = {
  bridge: join(fixtures, "Bridge.hap"),
  contacts: join(fixtures, "contacts.hap"),
  signing: join(fixtures, "signing-fixture.hap"),
  malformed: join(fixtures, "bad.abc"),
  restool: join(fixtures, "restool-v2.index"),
};
const originals = { ...prior?.originals };
if (!prior) {
  const samples = process.env.REA_FORGE_HARMONY_SAMPLES;
  const signing = process.env.REA_FORGE_HARMONY_SIGN_FIXTURE;
  assert.ok(samples && signing, "explicit installed sample paths required");
  for (const [name, source, expected] of [
    [
      "bridge",
      join(samples, "Bridge.hap"),
      "413a75e7c4b2d1c3e71cc1b10f76ec34f1921bface96f0dd294e7d188e5e1527",
    ],
    ["contacts", join(samples, "contacts.hap"), undefined],
    [
      "signing",
      signing,
      "2779a64f9764b588ccafa87cbb60d8ac63ea333415ade33d0699c7ee1bdf292b",
    ],
  ]) {
    const digest = sha(await readFile(source));
    if (expected) assert.equal(digest, expected);
    originals[source] = digest;
    await copyFile(source, paths[name]);
    originals[paths[name]] = digest;
  }
  await writeFile(paths.malformed, "not Panda bytecode");
  await writeFile(paths.restool, "RestoolV2 synthetic unsupported boundary");
  for (const path of [paths.malformed, paths.restool])
    originals[path] = sha(await readFile(path));
}
for (const [path, digest] of Object.entries(originals))
  assert.equal(sha(await readFile(path)), digest);
const report = {
  status: "running",
  scope:
    "G10 installed Windows HAP/ABC/Ark/JADX-HAP and offline local signing; D03 external prerequisites excluded",
  fixtures,
  originals,
  checks: { ...prior?.checks },
  values: { ...prior?.values },
  target_execution: false,
  network_used: false,
  gui_started: false,
  cpu_time: "unmeasured",
  peak_process_family_memory: "unmeasured",
};
if (prior)
  report.reused_receipt = { path: resume, sha256: sha(await readFile(resume)) };
const sourceFiles = [
  "bridge/forge/harmony/worker.py",
  "bridge/forge/harmony/engines.py",
  "bridge/forge/harmony/archive.py",
  "bridge/forge/harmony/signing.py",
  "dist/domain/forge/harmonyStatic.js",
  "dist/forge/harmony/HarmonyStaticAdapter.js",
];
report.source_hashes = {};
for (const path of sourceFiles)
  report.source_hashes[path] = sha(await readFile(join(root, path)));
if (prior) {
  report.reused_source_hashes = prior.source_hashes;
  // Only affected-tail repair can change these; record rather than silently assert equivalence.
  report.changed_source_files = sourceFiles.filter(
    (path) => prior.source_hashes[path] !== report.source_hashes[path],
  );
}
const configuration = JSON.parse(
  await readFile(process.env.REA_FORGE_STATIC_CONFIG, "utf8"),
);
// This process owns the test configuration; the operator's selection is read-only.
const testConfigurationPath = join(fixtures, "acceptance-tools.json");
await writeFile(testConfigurationPath, JSON.stringify(configuration));
const families = [
  "harmony_packages",
  "abcde",
  "ark_disasm",
  "jadx_hap",
  "hap_signing",
  "hap_verification",
  "harmony_results",
];
report.configuration_sha256 = sha(
  JSON.stringify(
    Object.fromEntries(families.map((name) => [name, configuration[name]])),
  ),
);
if (prior)
  assert.equal(
    report.configuration_sha256,
    prior.configuration_sha256,
    "engine configuration changed; explicitly review prior engine reuse",
  );
async function verifyRetained(value) {
  if (!value || typeof value !== "object") return;
  const reference = value.result;
  if (reference?.receipt_path) {
    assert.equal(
      sha(await readFile(reference.receipt_path)),
      reference.receipt_sha256,
    );
    const retained = JSON.parse(await readFile(reference.receipt_path, "utf8"));
    for (const item of [retained.full_result, ...retained.artifacts])
      assert.equal(sha(await readFile(item.path)), item.sha256);
  }
}
for (const value of Object.values(report.values)) await verifyRetained(value);
const env = Object.fromEntries(
  Object.entries({
    ...process.env,
    REA_FORGE_STATIC_CONFIG: testConfigurationPath,
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
const client = new Client({
  name: "forge-harmony-static-acceptance",
  version: "1",
});
const ref = (value) => ({
  receipt_path: value.result.receipt_path,
  receipt_sha256: value.result.receipt_sha256,
});
let diagnostics = "";
const checkpoint = () =>
  writeFile(
    join(local, "evidence/harmony-static-current.json"),
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
  for (const name of FORGE_HARMONY_OPERATIONS) assert.ok(tools.has(name));
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
  const evidence = async (name, input) => {
    const response = await raw(name, input);
    assert.notEqual(response.isError, true, JSON.stringify(response));
    return parseEvidence(
      JSON.parse(response.content.find((part) => part.type === "text").text),
    );
  };
  const call = async (name, input) =>
    (await evidence(name, input)).normalized_result;
  const reject = async (name, input) => {
    const response = await raw(name, input);
    assert.equal(response.isError, true, JSON.stringify(response));
    return JSON.parse(
      response.content.find((part) => part.type === "text").text,
    );
  };
  const step = async (name, action, validate = () => {}) => {
    if (!(name in report.values)) {
      report.values[name] = await action();
      await checkpoint();
    }
    const value = report.values[name];
    await validate(value);
    report.checks[name] = true;
    await checkpoint();
    console.log(
      JSON.stringify({
        phase: name,
        elapsed_seconds: (performance.now() - started) / 1000,
      }),
    );
    return value;
  };
  await step(
    "native_package_graph",
    async () => {
      const opened = await raw("open_binary", { path: paths.bridge });
      assert.notEqual(opened.isError, true, JSON.stringify(opened));
      const inventory = await evidence("inspect_artifact", {});
      return {
        inventory,
        graph: await evidence("project_harmony_application_graph", {
          inventory_evidence: [inventory],
        }),
      };
    },
    (value) => {
      const graph = value.graph.normalized_result;
      assert.equal(graph.root_sha256, originals[paths.bridge]);
      assert.ok(JSON.stringify(graph.components).includes("modules.abc"));
    },
  );
  const extracted = await step(
    "hap_members_and_abc",
    () => call("forge_inspect_hap", { path: paths.bridge, facet: "abc" }),
    (value) => assert.ok(value.result.total > 0),
  );
  const abcPath = extracted.result.rows[0].value.path;
  const bytes = await readFile(abcPath),
    expectedClasses = bytes.readUInt32LE(28);
  assert.equal(expectedClasses, 16);
  const methods = await step(
    "abc_methods",
    () => call("forge_inspect_abc", { path: abcPath, facet: "analysis" }),
    (value) => {
      assert.equal(value.result.value.counts_by_kind.class, expectedClasses);
      assert.equal(value.result.value.counts_by_kind.method, 123);
    },
  );
  await step(
    "abc_classes",
    () =>
      call("forge_inspect_abc", {
        path: abcPath,
        action: "classes",
        facet: "analysis",
      }),
    (value) => assert.equal(value.result.value.row_count, expectedClasses),
  );
  await step(
    "retained_engine_facet",
    () =>
      call("forge_read_harmony_result", { ...ref(methods), facet: "engine" }),
    (value) =>
      assert.equal(
        value.result.value.jar.sha256,
        configuration.abcde.jar.sha256,
      ),
  );
  const rows = [];
  for (let offset = 0; offset < methods.result.value.row_count; offset += 100) {
    const page = await step(`method_page_${offset}`, () =>
      call("forge_read_harmony_result", {
        ...ref(methods),
        artifact_index: 1,
        mode: "jsonl",
        line_offset: offset,
        line_count: 100,
      }),
    );
    rows.push(...page.result.artifact_read.rows);
  }
  const selected = (classSuffix, name) => {
    const method = rows.find(
      (row) =>
        row.kind === "method" &&
        row.class.endsWith(classSuffix) &&
        row.name === name,
    );
    assert.ok(method, `${classSuffix}/${name} must be in actual inventory`);
    return method;
  };
  const flagMain = selected("/FlagUtil", "func_main_0");
  const disassembly = await step("abc_method_disassembly", () =>
    call("forge_render_abc_method", {
      path: abcPath,
      method_offset: flagMain.method_offset,
      facet: "analysis",
    }),
  );
  await step(
    "instruction_readback",
    () =>
      call("forge_read_harmony_result", {
        ...ref(disassembly),
        artifact_index: 1,
        mode: "jsonl",
        line_count: 100,
      }),
    (value) => {
      const ins = value.result.artifact_read.rows.filter(
        (row) => row.kind === "instruction",
      );
      assert.equal(ins.length, 42);
      assert.equal(ins.at(-1).next_offset, flagMain.code_size);
      assert.ok(ins.flatMap((row) => row.referenced_methods).length > 0);
      assert.ok(ins.flatMap((row) => row.referenced_strings).length > 0);
    },
  );
  const jsMethod = selected("/CTFBridge", "#~@0>#setController");
  const js = await step("experimental_js", () =>
    call("forge_render_abc_method", {
      path: abcPath,
      method_offset: jsMethod.method_offset,
      render: "decompile",
      facet: "analysis",
    }),
  );
  await step(
    "experimental_js_readback",
    () =>
      call("forge_read_harmony_result", {
        ...ref(js),
        artifact_index: 1,
        mode: "jsonl",
      }),
    (value) =>
      assert.ok(
        value.result.artifact_read.rows.some(
          (row) =>
            row.kind === "experimental_js" && /function/.test(row.source),
        ),
      ),
  );
  await step(
    "unsupported_opcode_rejected",
    () =>
      reject("forge_render_abc_method", {
        path: abcPath,
        method_offset: selected("/FlagUtil", "#*#readLocalFlagCipher")
          .method_offset,
        render: "decompile",
      }),
    (value) => assert.match(JSON.stringify(value), /ldlocalmodulevar/),
  );
  const official = await step(
    "official_ark",
    () => call("forge_disassemble_ark", { path: abcPath, facet: "analysis" }),
    (value) => {
      assert.equal(value.result.value.function_count, 123);
      assert.equal(value.result.value.record_count, expectedClasses);
    },
  );
  await step(
    "official_ark_byte_readback",
    () =>
      call("forge_read_harmony_result", {
        ...ref(official),
        artifact_index: 1,
        byte_count: 4096,
      }),
    async (value) => {
      const actual = Buffer.from(value.result.artifact_read.base64, "base64");
      const retained = await readFile(official.result.value.artifact.path);
      assert.equal(actual.length, 4096);
      assert.deepEqual(actual, retained.subarray(0, 4096));
    },
  );
  const jadx = await step(
    "jadx_actual_source",
    () =>
      call("forge_decompile_hap", { path: paths.bridge, facet: "analysis" }),
    (value) => assert.ok(value.result.value.source_outputs.length > 0),
  );
  await step("jadx_source_hash", async () => {
    const source = jadx.result.value.source_outputs[0];
    const data = await readFile(source.path);
    assert.equal(sha(data), source.sha256);
    assert.match(data.toString("utf8"), /class |function |import |package /);
    return { source, verified_bytes: data.length };
  });
  const contacts = await step(
    "legacy_resource_extraction",
    () =>
      call("forge_inspect_hap", {
        path: paths.contacts,
        facet: "resources",
        query: "resources.index",
      }),
    (value) => assert.ok(value.result.total > 0),
  );
  await step(
    "legacy_resources",
    () =>
      call("forge_inspect_abc", {
        path: contacts.result.rows[0].value.path,
        action: "resources",
        facet: "analysis",
      }),
    (value) => assert.equal(value.result.value.row_count, 118),
  );
  await step(
    "restoolv2_rejected",
    () =>
      reject("forge_inspect_abc", { path: paths.restool, action: "resources" }),
    (value) => assert.match(JSON.stringify(value), /RestoolV2/),
  );
  const signed = await step(
    "local_test_signing",
    () => call("forge_sign_hap", { path: paths.signing, facet: "analysis" }),
    (value) => {
      assert.equal(value.result.value.verification.verified, true);
      assert.equal(value.result.value.signing_identity.test_only, true);
      assert.ok(
        value.result.artifacts.every(
          (item) => !/private|\.p12$/i.test(item.path),
        ),
      );
    },
  );
  const signedPath = signed.result.artifacts.find((item) =>
    item.path.endsWith("signed.hap"),
  ).path;
  await step(
    "independent_signature_verify",
    () =>
      call("forge_verify_hap_signature", {
        path: signedPath,
        facet: "verification",
      }),
    (value) => {
      assert.equal(value.result.value.verified, true);
      assert.equal(
        value.result.value.certificate_chain.sha256,
        signed.result.value.verification.certificate_chain.sha256,
      );
      assert.equal(
        value.result.value.profile.sha256,
        signed.result.value.verification.profile.sha256,
      );
    },
  );
  await step(
    "configured_local_profile",
    async () => {
      const passwordFile = join(fixtures, "test-profile.password");
      await writeFile(passwordFile, "forge-local-test-password\n");
      const pin = async (name) => {
        const path = join(signed.workspace, name);
        return { path, sha256: sha(await readFile(path)) };
      };
      const selected = structuredClone(configuration);
      selected.hap_signing.profiles.fixture = {
        alias: "forgefixture",
        keystore: await pin("test-store.p12"),
        certificate: await pin("test-cert.pem"),
        provisioning_profile: await pin("test-profile.p7b"),
        password_file: passwordFile,
      };
      await writeFile(testConfigurationPath, JSON.stringify(selected));
      try {
        return await call("forge_sign_hap", {
          path: paths.signing,
          profile: "fixture",
          facet: "analysis",
        });
      } finally {
        await writeFile(testConfigurationPath, JSON.stringify(configuration));
      }
    },
    (value) => {
      assert.equal(value.result.value.verification.verified, true);
      assert.equal(value.result.value.signing_identity.profile, "fixture");
      assert.ok(!JSON.stringify(value).includes("forge-local-test-password"));
    },
  );
  await step(
    "tampered_signature_not_verified",
    async () => {
      const data = await readFile(signedPath);
      assert.equal(data.readUInt32LE(0), 0x04034b50);
      const bodyOffset = 30 + data.readUInt16LE(26) + data.readUInt16LE(28);
      assert.ok(bodyOffset < data.length);
      data[bodyOffset] ^= 1;
      const path = join(fixtures, "tampered-copy.hap");
      await writeFile(path, data);
      return await call("forge_verify_hap_signature", {
        path,
        facet: "verification",
      });
    },
    (value) => assert.equal(value.result.value.status, "not_verified"),
  );
  await step(
    "unsigned_not_verified",
    () =>
      call("forge_verify_hap_signature", {
        path: paths.signing,
        facet: "verification",
      }),
    (value) => assert.equal(value.result.value.status, "not_verified"),
  );
  await step("input_and_receipt_rejection", async () => ({
    malformed: await reject("forge_inspect_abc", { path: paths.malformed }),
    hash: await reject("forge_read_harmony_result", {
      ...ref(methods),
      receipt_sha256: "0".repeat(64),
    }),
    index: await reject("forge_read_harmony_result", {
      ...ref(methods),
      artifact_index: 99999,
    }),
    profile: await reject("forge_sign_hap", {
      path: paths.signing,
      profile: "not-configured",
    }),
    root: await reject("forge_inspect_hap", {
      path: process.env.SystemRoot + "\\win.ini",
    }),
  }));
  await step(
    "actual_jvm_deadline",
    () => reject("forge_inspect_abc", { path: abcPath, timeout_ms: 1 }),
    (value) => assert.match(JSON.stringify(value), /timeout|deadline/i),
  );
  await step(
    "actual_ark_deadline",
    () => reject("forge_disassemble_ark", { path: abcPath, timeout_ms: 1 }),
    (value) => assert.match(JSON.stringify(value), /timeout|deadline/i),
  );
  await step(
    "actual_signature_jvm_deadline",
    () =>
      reject("forge_verify_hap_signature", { path: signedPath, timeout_ms: 1 }),
    (value) => assert.match(JSON.stringify(value), /timeout|deadline/i),
  );
  await step(
    "missing_engine_isolation",
    async () => {
      const selected = structuredClone(configuration);
      delete selected.abcde;
      await writeFile(testConfigurationPath, JSON.stringify(selected));
      try {
        const absent = await reject("forge_inspect_abc", { path: abcPath });
        const unaffected = await call(
          "forge_read_harmony_result",
          ref(methods),
        );
        return { absent, unaffected };
      } finally {
        await writeFile(testConfigurationPath, JSON.stringify(configuration));
      }
    },
    (value) =>
      assert.match(JSON.stringify(value.absent), /abcde|not_configured/),
  );
  await step("cancel_and_recover", async () => {
    const stop = new AbortController();
    const pending = raw("forge_inspect_abc", { path: abcPath }, stop.signal);
    const timer = setTimeout(() => stop.abort("owned G10 cancellation"), 75);
    try {
      await assert.rejects(pending);
    } finally {
      clearTimeout(timer);
    }
    const recovered = await call("forge_inspect_abc", {
      path: abcPath,
      action: "header",
      facet: "header",
    });
    assert.equal(recovered.result.value.class_count, expectedClasses);
    return { recovered, cancelled: true };
  });
  await step(
    "cli_parity",
    async () => {
      const { stdout } = await promisify(execFile)(
        process.execPath,
        [
          entry,
          "forge-inspect-abc",
          JSON.stringify({ path: abcPath, action: "header", facet: "header" }),
          "--format",
          "json",
        ],
        {
          env,
          cwd: temporary,
          windowsHide: true,
          timeout: 25000,
          maxBuffer: 1024 * 1024,
        },
      );
      return parseEvidence(JSON.parse(stdout)).normalized_result;
    },
    (value) => assert.equal(value.result.value.class_count, expectedClasses),
  );
  for (const [path, digest] of Object.entries(originals))
    assert.equal(sha(await readFile(path)), digest);
  for (const value of Object.values(report.values)) await verifyRetained(value);
  report.checks.originals_and_retained_artifacts_unchanged = true;
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
  const receipt = join(local, "evidence", `harmony-static-${Date.now()}.json`);
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
