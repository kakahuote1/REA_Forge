/** Real complete-capability acceptance. Never executes the analyzed fixture. */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { deflateSync } from "node:zlib";
import { ZipWriter, Uint8ArrayWriter, TextReader } from "@zip.js/zip.js";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../../dist/domain/evidence.js";
import { FORGE_BINARY_EDITOR_TOOL_CONTRACTS } from "../../dist/contracts/forge/binaryEditorToolContracts.js";

const root = fileURLToPath(new URL("../../", import.meta.url));
const local = join(root, ".forge-local");
const execute = promisify(execFile);
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const wait = (milliseconds) =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));
const existsPid = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (cause) {
    if (cause.code === "ESRCH") return false;
    throw cause;
  }
};
await mkdir(join(local, "fixtures"), { recursive: true });
await mkdir(join(local, "assets/010editor"), { recursive: true });
await mkdir(join(local, "tmp"), { recursive: true });
await mkdir(join(local, "evidence"), { recursive: true });
const fixtures = await mkdtemp(join(local, "fixtures", "editor010-"));
const assets = await mkdtemp(join(local, "assets/010editor", "acceptance-"));
const temp = await mkdtemp(join(local, "tmp", "editor010-provider-"));
const sample = join(fixtures, "header.bin");
const other = join(fixtures, "other.bin");
const inplace = join(fixtures, "editable.bin");
const pe = join(fixtures, "not-executable-mz.bin");
const header = join(assets, "header.bt");
const script = join(assets, "patch.1sc");
const denied = join(assets, "denied.1sc");
const busy = join(assets, "busy.1sc");
const bytes = Buffer.from("123456782a000300414243442d2d2d414243440a", "hex");
await Promise.all([
  writeFile(sample, bytes),
  writeFile(other, Buffer.concat([bytes, Buffer.from([0])])),
  writeFile(inplace, bytes),
  writeFile(pe, Buffer.concat([Buffer.from("MZ"), Buffer.alloc(62)])),
  writeFile(
    header,
    "LittleEndian();\nuint32 magic;\nuint16 version;\nuint16 flags;\n",
  ),
  writeFile(script, "WriteUByte(8, 0x5A);\nFileSave();\nExit(0);\n"),
  writeFile(denied, 'FileOpen("C:\\Windows\\not-permitted.bin");\n'),
  writeFile(busy, "while (1) { }\n"),
]);
const zip = new ZipWriter(new Uint8ArrayWriter());
await zip.add("forge.txt", new TextReader("010 real template acceptance\n"));
await writeFile(join(fixtures, "input.zip"), await zip.close());
const crc32 = (buffer) => {
  let value = 0xffffffff;
  for (const byte of buffer) {
    value ^= byte;
    for (let bit = 0; bit < 8; bit++)
      value = (value >>> 1) ^ (value & 1 ? 0xedb88320 : 0);
  }
  return (value ^ 0xffffffff) >>> 0;
};
const chunk = (type, data) => {
  const name = Buffer.from(type);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([name, data])));
  return Buffer.concat([length, name, data, crc]);
};
const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(1, 0);
ihdr.writeUInt32BE(1, 4);
ihdr[8] = 8;
ihdr[9] = 6;
await writeFile(
  join(fixtures, "input.png"),
  Buffer.concat([
    Buffer.from("89504e470d0a1a0a", "hex"),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(Buffer.from([0, 255, 0, 0, 255]))),
    chunk("IEND", Buffer.alloc(0)),
  ]),
);

const report = {
  status: "running",
  checks: {},
  original_sha256: digest(bytes),
  sample_execution: false,
  gui_started: false,
  network_capture: false,
};
const started = performance.now();
const environment = Object.fromEntries(
  Object.entries({
    ...process.env,
    TEMP: temp,
    TMP: temp,
    TMPDIR: temp,
    REA_LOG_LEVEL: "error",
  }).filter(([, value]) => typeof value === "string"),
);
const entrypoint = join(root, "scripts/rea.mjs");
const client = new Client({
  name: "rea-forge-editor010-acceptance",
  version: "1",
});
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
let serverPid;
let stderr = "";
const nativePids = new Set();
const receipts = async () => {
  const work = join(local, "work/010editor");
  const directories = await readdir(work, { withFileTypes: true }).catch(
    (cause) => {
      if (cause.code === "ENOENT") return [];
      throw cause;
    },
  );
  const result = [];
  for (const directory of directories.filter((item) => item.isDirectory())) {
    const evidence = join(work, directory.name, "evidence");
    for (const filename of await readdir(evidence).catch(() => [])) {
      if (!filename.endsWith(".json")) continue;
      const value = JSON.parse(
        await readFile(join(evidence, filename), "utf8"),
      );
      if (value.kind === "010_native_started") result.push(value);
    }
  }
  return result;
};
try {
  await client.connect(transport, { timeout: 20_000 });
  serverPid = transport.pid;
  transport.stderr?.on("data", (data) => {
    stderr = (stderr + data.toString()).slice(-8192);
  });
  const catalog = (await client.listTools({}, { timeout: 20_000 })).tools;
  const definitions = new Map(catalog.map((tool) => [tool.name, tool]));
  for (const contract of FORGE_BINARY_EDITOR_TOOL_CONTRACTS) {
    assert.ok(definitions.get(contract.name)?.outputSchema);
    for (const example of contract.examples)
      assert.ok(contract.inputSchema.safeParse(example.input).success);
  }
  report.advertised_tool_count = catalog.length;
  report.checks.ten_typed_tools_and_examples = true;
  const rawCall = (name, args, signal) =>
    client.callTool(
      { name, arguments: args },
      { timeout: 65_000, toolDefinition: definitions.get(name), signal },
    );
  const call = async (name, args) => {
    const response = await rawCall(name, args);
    assert.notEqual(
      response.isError,
      true,
      `${name}: ${JSON.stringify(response)}`,
    );
    const evidence = parseEvidence(
      JSON.parse(response.content.find((item) => item.type === "text").text),
    );
    assert.equal(evidence.provider.id, "forge-010editor");
    return evidence.normalized_result;
  };
  const reject = async (name, args) => {
    const response = await rawCall(name, args);
    assert.equal(
      response.isError,
      true,
      `${name} must reject: ${JSON.stringify(response)}`,
    );
    return response;
  };
  const assetsResult = await call("forge_list_binary_assets", {
    kind: "template",
  });
  assert.ok(assetsResult.result.assets.length > 0);
  const range = await call("forge_read_binary_bytes", {
    path: sample,
    offset: 8,
    length: 4,
  });
  assert.equal(range.result.hex, "41424344");
  const search = await call("forge_search_binary_bytes", {
    path: sample,
    needle_hex: "41424344",
  });
  assert.deepEqual(search.result.offsets, [8, 15]);
  const compared = await call("forge_compare_binary_files", {
    path: sample,
    right_path: other,
  });
  assert.equal(compared.result.first_difference_offset, bytes.length);
  assert.equal(compared.result.identical, false);
  report.checks.bytes_search_native_compare = true;
  const structure = await call("forge_inspect_binary_structure", {
    path: sample,
    template_path: header,
    field_name: "version",
  });
  assert.ok(
    structure.result.template_rows.some(
      (row) => row.includes("version") && row.includes("42"),
    ),
    JSON.stringify(structure),
  );
  for (const [file, template] of [
    ["input.zip", "ZIP.bt"],
    ["input.png", "PNG.bt"],
  ]) {
    const result = await call("forge_inspect_binary_structure", {
      path: join(fixtures, file),
      template_path: join(local, "assets/010editor", template),
    });
    assert.ok(result.result.total_rows > 2);
    assert.equal(result.result.native.returncode, 0);
  }
  const page = await call("forge_read_binary_template_rows", {
    csv_path: structure.result.csv_path,
    csv_sha256: structure.result.csv_sha256,
    field_name: "flags",
  });
  assert.ok(page.result.rows.some((row) => row.includes("flags")));
  await reject("forge_read_binary_template_rows", {
    csv_path: structure.result.csv_path,
    csv_sha256: "0".repeat(64),
  });
  report.checks.real_header_zip_png_templates_and_retained_paging = true;
  const edited = await call("forge_edit_binary_copy", {
    path: sample,
    offset: 8,
    delete_length: 4,
    insert_hex: "",
  });
  assert.deepEqual(
    await readFile(edited.result.output.path),
    Buffer.concat([bytes.subarray(0, 8), bytes.subarray(12)]),
  );
  await reject("forge_edit_binary_copy", {
    path: sample,
    offset: 0,
    delete_length: 0,
    insert_hex: "00",
    output_name: "../../escape.bin",
  });
  await reject("forge_edit_binary_copy", {
    path: pe,
    offset: 0,
    delete_length: 1,
    insert_hex: "00",
  });
  const scripted = await call("forge_run_binary_script", {
    path: sample,
    script_path: script,
  });
  const scriptBytes = await readFile(scripted.result.after.path);
  assert.equal(scriptBytes[8], 0x5a);
  await reject("forge_run_binary_script", {
    path: sample,
    script_path: denied,
  });
  report.checks.derived_edit_script_and_boundary_rejections = true;
  const inPlace = await call("forge_edit_binary_in_place", {
    path: inplace,
    offset: 8,
    delete_length: 1,
    insert_hex: "5a",
    expected_sha256: digest(bytes),
  });
  assert.equal((await readFile(inplace))[8], 0x5a);
  assert.equal(
    digest(await readFile(inPlace.result.backup.path)),
    digest(bytes),
  );
  await reject("forge_edit_binary_in_place", {
    path: inplace,
    offset: 8,
    delete_length: 1,
    insert_hex: "00",
    expected_sha256: digest(bytes),
  });
  const restored = await call("forge_restore_binary_backup", {
    path: inplace,
    backup_path: inPlace.result.backup.path,
    expected_sha256: inPlace.result.source_after.sha256,
  });
  assert.equal(restored.result.source_after.sha256, digest(bytes));
  assert.deepEqual(await readFile(inplace), bytes);
  report.checks.in_place_backup_identity_and_restore = true;
  const cli = await execute(
    process.execPath,
    [
      entrypoint,
      "forge-read-binary-bytes",
      JSON.stringify({ path: sample, offset: 8, length: 4 }),
      "--format",
      "json",
    ],
    {
      cwd: root,
      env: environment,
      windowsHide: true,
      timeout: 25_000,
      maxBuffer: 8 * 1024 * 1024,
    },
  );
  const cliResult = parseEvidence(JSON.parse(cli.stdout)).normalized_result;
  assert.equal(cliResult.result.hex, range.result.hex);
  assert.deepEqual(cliResult.target, range.target);
  report.checks.real_cli_mcp_fact_parity = true;
  await reject("forge_read_binary_bytes", {
    path: sample,
    offset: -1,
    length: 4,
  });
  await reject("forge_read_binary_bytes", {
    path: join(fixtures, "missing.bin"),
    offset: 0,
    length: 4,
  });
  assert.equal(
    (
      await call("forge_read_binary_bytes", {
        path: sample,
        offset: 8,
        length: 4,
      })
    ).result.hex,
    "41424344",
  );
  report.checks.invalid_missing_input_and_same_connection_recovery = true;

  const before = new Set((await receipts()).map((item) => item.pid));
  const controller = new AbortController();
  const cancelled = rawCall(
    "forge_run_binary_script",
    { path: sample, script_path: busy },
    controller.signal,
  ).then(
    (value) => ({ kind: "reply", value }),
    (cause) => ({ kind: "rejected", message: String(cause) }),
  );
  let cancelPid;
  const startDeadline = Date.now() + 15_000;
  while (Date.now() < startDeadline) {
    const receipt = (await receipts()).find((item) => !before.has(item.pid));
    if (receipt !== undefined) {
      cancelPid = receipt.pid;
      nativePids.add(cancelPid);
      break;
    }
    await wait(100);
  }
  controller.abort(new Error("source-owned cancellation acceptance"));
  assert.ok(cancelPid, "native start must be observed before cancellation");
  const cancelResult = await cancelled;
  assert.ok(
    cancelResult.kind === "rejected" || cancelResult.value.isError === true,
  );
  const cancelDeadline = Date.now() + 15_000;
  while (existsPid(cancelPid) && Date.now() < cancelDeadline) await wait(100);
  assert.equal(
    existsPid(cancelPid),
    false,
    "owned native process remained after cancellation",
  );
  assert.equal(
    (
      await call("forge_read_binary_bytes", {
        path: sample,
        offset: 8,
        length: 4,
      })
    ).result.hex,
    "41424344",
  );
  report.checks.real_native_cancellation_cleanup_and_recovery = true;
  assert.equal(digest(await readFile(sample)), digest(bytes));
  assert.equal(
    digest(await readFile(other)),
    digest(Buffer.concat([bytes, Buffer.from([0])])),
  );
  report.checks.original_inputs_unchanged = true;
  for (const receipt of await receipts()) nativePids.add(receipt.pid);
  report.status = "passed";
} catch (cause) {
  report.status = "failed";
  report.error = cause instanceof Error ? cause.stack : String(cause);
  process.exitCode = 1;
} finally {
  try {
    await client.close();
    await transport.close();
    assert.ok(serverPid == null || !existsPid(serverPid));
    for (const pid of nativePids)
      assert.equal(existsPid(pid), false, `owned native PID ${pid} remains`);
    const pending = (await readdir(join(local, "tmp"))).filter((name) =>
      name.startsWith("forge-010editor-request-"),
    );
    assert.deepEqual(
      pending,
      [],
      "request directories remain after server close",
    );
    report.checks.server_native_processes_and_request_roots_closed = true;
    // Only these three exact, source-owned mkdtemp roots are temporary fixtures.
    await Promise.all([
      rm(fixtures, { recursive: true }),
      rm(assets, { recursive: true }),
      rm(temp, { recursive: true }),
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
    join(
      local,
      "evidence",
      `editor010-${Date.now()}-${randomUUID().slice(0, 8)}.json`,
    ),
    JSON.stringify(report, null, 2) + "\n",
  );
  console.log(JSON.stringify(report, null, 2));
}
