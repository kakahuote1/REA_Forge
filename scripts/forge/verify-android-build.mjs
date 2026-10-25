/** Real static Android group. Retained checkpoints permit failed-tail-only repair. */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import {
  copyFile,
  mkdir,
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
import { FORGE_ANDROID_BUILD_OPERATIONS } from "../../dist/domain/forge/androidBuild.js";
const root = fileURLToPath(new URL("../../", import.meta.url)),
  local = join(root, ".forge-local");
const sha = (value) => createHash("sha256").update(value).digest("hex");
const resumed = process.env.REA_FORGE_ANDROID_RESUME;
const prior = resumed ? JSON.parse(await readFile(resumed, "utf8")) : undefined;
const fixtures =
  prior?.fixtures ?? (await mkdtemp(join(local, "fixtures/android-")));
const temporary = await mkdtemp(join(local, "tmp/android-provider-"));
const original = process.env.REA_FORGE_ANDROID_FIXTURE;
assert.ok(original, "explicit installed harmless fixture required");
const apk = join(fixtures, "original.apk"),
  smali = join(fixtures, "smali");
if (!prior) {
  await copyFile(original, apk);
  await mkdir(smali);
  await writeFile(
    join(smali, "Answer.smali"),
    ".class public Lforge/Answer;\n.super Ljava/lang/Object;\n.method public static answer()I\n    .registers 1\n    const/16 v0, 0x2a\n    return v0\n.end method\n.method public static caller()I\n    .registers 1\n    invoke-static {}, Lforge/Answer;->answer()I\n    move-result v0\n    return v0\n.end method\n",
  );
}
const originals =
  prior?.originals ??
  Object.fromEntries(
    await Promise.all(
      [original, apk, join(smali, "Answer.smali")].map(async (path) => [
        path,
        sha(await readFile(path)),
      ]),
    ),
  );
for (const [path, digest] of Object.entries(originals))
  assert.equal(sha(await readFile(path)), digest);
const report = {
  status: "running",
  fixtures,
  originals,
  checks: { ...prior?.checks },
  values: { ...prior?.values },
  sample_execution: false,
  network_used: false,
  gui_started: false,
};
if (prior)
  report.reused_receipt = {
    path: resumed,
    sha256: sha(await readFile(resumed)),
  };
// All reused result and project file identities are checked; no stale pass flag alone is accepted.
for (const value of Object.values(report.values)) {
  const ref = value?.result;
  if (!ref?.receipt_path) continue;
  const bytes = await readFile(ref.receipt_path);
  assert.equal(sha(bytes), ref.receipt_sha256);
  const retained = JSON.parse(bytes);
  for (const item of retained.project?.files ?? [])
    assert.equal(
      sha(await readFile(join(retained.project.root, item.relative_path))),
      item.sha256,
    );
  for (const item of retained.artifacts ?? [])
    assert.equal(sha(await readFile(item.path)), item.sha256);
}
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
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
const client = new Client({ name: "forge-android-acceptance", version: "1" });
const started = performance.now();
let diagnostics = "";
const checkpoint = async () =>
  writeFile(
    join(local, "evidence/android-current.json"),
    JSON.stringify(report, null, 2),
  );
const reference = (value) => ({
  receipt_path: value.result.receipt_path,
  receipt_sha256: value.result.receipt_sha256,
});
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
  for (const name of FORGE_ANDROID_BUILD_OPERATIONS) assert.ok(tools.has(name));
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
    const reply = await raw(name, input);
    assert.notEqual(reply.isError, true, JSON.stringify(reply));
    return parseEvidence(
      JSON.parse(reply.content.find((part) => part.type === "text").text),
    ).normalized_result;
  };
  const reject = async (name, input) => {
    const reply = await raw(name, input);
    assert.equal(reply.isError, true, JSON.stringify(reply));
    return JSON.parse(reply.content.find((part) => part.type === "text").text);
  };
  const step = async (name, action) => {
    if (report.checks[name]) return report.values[name];
    const value = await action();
    report.values[name] = value;
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
  const prepared = await step("apk_decode", () =>
    call("forge_prepare_android_project", { path: apk }),
  );
  const manifest = await step("project_text_readback", async () => {
    const value = await call("forge_read_android_result", {
      ...reference(prepared),
      relative_path: "AndroidManifest.xml",
      byte_count: 65536,
    });
    assert.ok(value.result.file.text_utf8.includes("<manifest"));
    return value;
  });
  const built = await step("apk_edit_rebuild", async () => {
    const text = manifest.result.file.text_utf8,
      old = text.match(/<application\b[^>]*>/u)?.[0];
    assert.ok(
      old && /android:label="[^"]+"/u.test(old),
      "known fixture application must have an explicit label",
    );
    const value = await call("forge_build_android_project", {
      ...reference(prepared),
      changes: [
        {
          relative_path: "AndroidManifest.xml",
          expected_sha256: manifest.result.file.identity.sha256,
          old_text: old,
          new_text: old.replace(
            /android:label="[^"]+"/u,
            'android:label="Forge Android Acceptance"',
          ),
        },
      ],
    });
    assert.equal(value.result.changes.length, 1);
    return value;
  });
  const signed = await step("apk_test_sign_and_crypto_verify", async () => {
    const value = await call("forge_sign_apk", {
      path: built.result.artifacts[0].path,
    });
    assert.equal(value.result.verification.verified, true);
    assert.equal(value.result.signing_identity.test_only, true);
    assert.ok(value.result.verification.certificate_sha256.length);
    return value;
  });
  const signedApk = signed.result.artifacts[0].path;
  await step("explicit_crypto_and_native_declarations", async () => {
    const verified = await call("forge_verify_apk", { path: signedApk });
    assert.equal(verified.result.verification.status, "verified");
    assert.deepEqual(
      verified.result.verification.certificate_sha256,
      signed.result.verification.certificate_sha256,
    );
    const declarations = await call("inspect_apk_signature", {
      path: signedApk,
    });
    assert.ok(
      JSON.stringify(declarations)
        .replaceAll(":", "")
        .toLowerCase()
        .includes(signed.result.verification.certificate_sha256[0]),
    );
    return verified;
  });
  await step("signed_apk_redecode", async () => {
    const decoded = await call("forge_prepare_android_project", {
      path: signedApk,
    });
    const value = await call("forge_read_android_result", {
      ...reference(decoded),
      relative_path: "AndroidManifest.xml",
      byte_count: 65536,
    });
    assert.ok(value.result.file.text_utf8.includes("Forge Android Acceptance"));
    return decoded;
  });
  await step("native_resource_reader", async () => {
    const value = await call("decode_android_resources", {
      path: signedApk,
      decode_timeout_ms: 45000,
    });
    assert.ok(JSON.stringify(value).includes("Forge Android Acceptance"));
    return value;
  });
  const assembled = await step("smali_assemble_known_answer", async () => {
    const value = await call("forge_assemble_dex", { source_directory: smali });
    assert.equal(value.result.dex.class_count, 1);
    assert.equal(value.result.dex.sha1_signature_matches, true);
    assert.equal(value.result.dex.adler32_matches, true);
    return value;
  });
  const disassembled = await step("dex_disassemble_known_answer", async () => {
    const value = await call("forge_disassemble_dex", {
      path: assembled.result.artifacts[0].path,
    });
    const file = await call("forge_read_android_result", {
      ...reference(value),
      relative_path: "forge/Answer.smali",
      byte_count: 65536,
    });
    assert.ok(file.result.file.text_utf8.includes("0x2a"));
    return { ...value, observed_file: file.result.file };
  });
  const changedDex = await step("smali_edit_reassemble", () =>
    call("forge_assemble_dex", {
      ...reference(disassembled),
      changes: [
        {
          relative_path: "forge/Answer.smali",
          expected_sha256: disassembled.observed_file.identity.sha256,
          old_text: "0x2a",
          new_text: "0x2b",
        },
      ],
    }),
  );
  await step("changed_dex_redecode", async () => {
    const value = await call("forge_disassemble_dex", {
      path: changedDex.result.artifacts[0].path,
    });
    const file = await call("forge_read_android_result", {
      ...reference(value),
      relative_path: "forge/Answer.smali",
      byte_count: 65536,
    });
    assert.ok(file.result.file.text_utf8.includes("0x2b"));
    assert.ok(!file.result.file.text_utf8.includes("0x2a"));
    return value;
  });
  await step("native_jadx_manifest_class_method_references", async () => {
    const pkg = await call("inspect_android_package", { path: signedApk });
    assert.ok(pkg.package_name);
    const classes = await call("search_android_classes", {
      path: signedApk,
      query: "",
    });
    const selectedFile = prepared.result.rows.find(
      (row) =>
        row.relative_path.startsWith("smali/") &&
        row.relative_path.endsWith(".smali"),
    );
    assert.ok(
      selectedFile,
      "known fixture has an actual Smali application class",
    );
    const name = selectedFile.relative_path
      .slice("smali/".length, -".smali".length)
      .replaceAll("/", ".");
    assert.ok(classes.matches.includes(name));
    const info = await call("inspect_android_class", {
      path: signedApk,
      class_name: name,
    });
    const method =
      info.methods.find((item) => !item.is_constructor) ?? info.methods[0];
    assert.ok(method);
    const source = await call("inspect_android_method", {
      path: signedApk,
      class_name: name,
      method_name: method.name,
      overload_index: method.overload_index,
    });
    assert.equal(source.body_status, "available");
    assert.ok(source.source.text.length > 0);
    const references = await call("trace_android_references", {
      path: signedApk,
      class_name: name,
    });
    assert.ok(references.total >= 0);
    return { pkg, name, method, source, references };
  });
  await step("negative_identity_edit_and_signing_cases", async () => {
    await reject("forge_read_android_result", {
      ...reference(prepared),
      receipt_sha256: "0".repeat(64),
    });
    await reject("forge_build_android_project", {
      ...reference(prepared),
      changes: [
        {
          relative_path: "AndroidManifest.xml",
          expected_sha256: "0".repeat(64),
          old_text: "manifest",
          new_text: "other",
        },
      ],
    });
    await reject("forge_build_android_project", {
      ...reference(prepared),
      changes: [
        {
          relative_path: "AndroidManifest.xml",
          expected_sha256: manifest.result.file.identity.sha256,
          old_text: "__absent__",
          new_text: "changed",
        },
      ],
    });
    await reject("forge_sign_apk", {
      path: signedApk,
      profile: "unconfigured",
    });
    await reject("forge_read_android_result", {
      receipt_path: signed.result.signing_identity.receipt_path,
      receipt_sha256: signed.result.signing_identity.receipt_sha256,
    });
    const invalid = join(fixtures, "invalid.apk");
    await writeFile(invalid, "not an APK");
    await reject("forge_prepare_android_project", { path: invalid });
    const unsigned = await call("forge_verify_apk", {
      path: built.result.artifacts[0].path,
    });
    assert.notEqual(unsigned.result.verification.status, "verified");
    return { negative_cases: 7 };
  });
  await step("test_key_reuse", async () => {
    const key = signed.result.signing_identity;
    const value = await call("forge_sign_apk", {
      path: built.result.artifacts[0].path,
      key_receipt_path: key.receipt_path,
      key_receipt_sha256: key.receipt_sha256,
    });
    assert.deepEqual(
      value.result.verification.certificate_sha256,
      signed.result.verification.certificate_sha256,
    );
    return value;
  });
  await step("native_deadline_cancel_recovery", async () => {
    const failure = await reject("forge_disassemble_dex", {
      path: assembled.result.artifacts[0].path,
      timeout_ms: 1,
    });
    assert.equal(failure.error.code, "provider_timeout");
    const abort = new AbortController();
    const pending = raw(
      "forge_prepare_android_project",
      { path: apk },
      abort.signal,
    );
    setTimeout(() => abort.abort("fixture cancel"), 30);
    await assert.rejects(pending);
    const value = await call("forge_read_android_result", reference(prepared));
    assert.ok(value.result.project.file_count);
    return { recovered: true };
  });
  await step("cli_mcp_readback_parity", async () => {
    const { stdout } = await promisify(execFile)(
      process.execPath,
      [
        entrypoint,
        "forge-read-android-result",
        JSON.stringify(reference(prepared)),
        "--format",
        "json",
      ],
      {
        env: environment,
        windowsHide: true,
        timeout: 25000,
        maxBuffer: 2 * 1024 * 1024,
      },
    );
    const value = parseEvidence(JSON.parse(stdout)).normalized_result;
    assert.equal(value.result.project.sha256, prepared.result.project.sha256);
    return value;
  });
  for (const [path, digest] of Object.entries(originals))
    assert.equal(sha(await readFile(path)), digest);
  await step("jadx_owned_temporary_root_recovery", async () => {
    const value = await call("inspect_android_package", { path: signedApk });
    assert.equal(
      value.package_name,
      report.values.native_jadx_manifest_class_method_references.pkg
        .package_name,
    );
    return { package_name: value.package_name };
  });
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
  // The short Java prerequisite probe may leave its JVM performance directory
  // in the caller's test TEMP. Reclaim only an empty, known-name directory;
  // never recursively erase unknown/native leftovers to make a check pass.
  report.empty_jvm_performance_directories_reclaimed = [];
  for (const entry of await readdir(temporary, { withFileTypes: true })) {
    if (
      !entry.isDirectory() ||
      !/^hsperfdata_[A-Za-z0-9_.-]+$/u.test(entry.name)
    )
      continue;
    const directory = join(temporary, entry.name);
    if ((await readdir(directory)).length !== 0) continue;
    await rmdir(directory);
    report.empty_jvm_performance_directories_reclaimed.push(entry.name);
  }
  report.provider_temp_empty = (await readdir(temporary)).length === 0;
  if (report.provider_temp_empty) await rmdir(temporary);
  else {
    report.status = "failed";
    process.exitCode = 1;
  }
  report.elapsed_seconds = (performance.now() - started) / 1000;
  const receipt = join(local, "evidence", `android-build-${Date.now()}.json`);
  await writeFile(receipt, JSON.stringify(report, null, 2));
  console.log(
    JSON.stringify({
      status: report.status,
      receipt,
      elapsed_seconds: report.elapsed_seconds,
      checks: report.checks,
      failure: report.failure,
      provider_temp_empty: report.provider_temp_empty,
    }),
  );
}
