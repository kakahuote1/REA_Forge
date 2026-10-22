/** Concentrated dnSpy capability acceptance: real CLI and stdio MCP, no target execution. */
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
  access,
} from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { setTimeout as wait } from "node:timers/promises";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../../dist/domain/evidence.js";
import { FORGE_DOTNET_TOOL_CONTRACTS } from "../../dist/contracts/forge/dotnetToolContracts.js";

const root = fileURLToPath(new URL("../../", import.meta.url));
const local = join(root, ".forge-local");
await mkdir(join(local, "fixtures"), { recursive: true });
await mkdir(join(local, "evidence"), { recursive: true });
const fixtures = await mkdtemp(join(local, "fixtures/dotnet-"));
const temporary = await mkdtemp(join(local, "tmp/dotnet-provider-"));
const source = join(fixtures, "Fixture.cs");
const invalid = join(fixtures, "Invalid.cs");
const malformed = join(fixtures, "Broken.dll");
const heavy = join(fixtures, "Heavy.cs");
const sentinel = join(fixtures, "MUST_NOT_EXIST.txt");
await writeFile(
  source,
  `using System;
using System.IO;
[ForgeMarker("original")]
public class ForgeFixture {
  static ForgeFixture() { File.WriteAllText(@"${sentinel.replaceAll('"', '""')}", "TARGET_EXECUTED"); throw new Exception("MUST_NOT_EXECUTE"); }
  public int Value = 7;
  public int Property {get;set;}
  public event Action Changed;
  public string Greeting() { return "REA_FORGE_DOTNET_FIXTURE"; }
  public int Add(int a, int b) { return a + b; }
  public void Notify() { Changed?.Invoke(); }
  public static void Main() {}
}
public sealed class ForgeMarkerAttribute : Attribute {
  public ForgeMarkerAttribute(string label) { Label = label; }
  public string Label;
}
`,
);
await writeFile(invalid, "public class Broken { syntax ??? }\n");
await writeFile(malformed, Buffer.from("4d5a00000000", "hex"));
await writeFile(
  heavy,
  "class Heavy { public static void Main() {}\n" +
    Array.from(
      { length: 16000 },
      (_, i) => `public int M${i}(int a) { return a + ${i}; }`,
    ).join("\n") +
    "\n}\n",
);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const report = {
  status: "running",
  checks: {},
  edits: [],
  decompilers: [],
  sample_execution: false,
  gui_started: false,
};
const env = Object.fromEntries(
  Object.entries({
    ...process.env,
    TEMP: temporary,
    TMP: temporary,
    TMPDIR: temporary,
    REA_LOG_LEVEL: "error",
  }).filter(([, value]) => typeof value === "string"),
);
const entrypoint = join(root, "scripts/rea.mjs");
const client = new Client({
  name: "rea-forge-dotnet-acceptance",
  version: "1",
});
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env,
  stderr: "pipe",
});
const execute = promisify(execFile);
const native = [];
const workspaces = new Set();
const started = performance.now();
const originalSource = hash(await readFile(source));
let serverPid;
let stderr = "";
const absent = (pid) => {
  try {
    process.kill(pid, 0);
    return false;
  } catch (error) {
    if (error.code === "ESRCH") return true;
    throw error;
  }
};
try {
  await client.connect(transport, { timeout: 20000 });
  serverPid = transport.pid;
  transport.stderr?.on("data", (data) => {
    stderr = (stderr + data.toString()).slice(-8192);
  });
  const catalog = (await client.listTools({}, { timeout: 20000 })).tools;
  const tools = new Map(catalog.map((tool) => [tool.name, tool]));
  report.advertised_tool_count = catalog.length;
  for (const contract of FORGE_DOTNET_TOOL_CONTRACTS) {
    assert.ok(tools.get(contract.name)?.outputSchema);
    for (const example of contract.examples)
      assert.ok(contract.inputSchema.safeParse(example.input).success);
  }
  const raw = (name, args, signal) =>
    client.callTool(
      { name, arguments: args },
      {
        timeout: 60000,
        toolDefinition: tools.get(name),
        ...(signal ? { signal } : {}),
      },
    );
  const call = async (name, args) => {
    const reply = await raw(name, args);
    assert.notEqual(reply.isError, true, `${name}: ${JSON.stringify(reply)}`);
    const evidence = parseEvidence(
      JSON.parse(reply.content.find((block) => block.type === "text").text),
    );
    const value = evidence.normalized_result;
    assert.equal(value.operation, name);
    assert.equal(value.sample_execution, false);
    for (const item of value.native) {
      assert.equal(item.owned_wait_completed, true);
      assert.equal(item.exit_code, 0);
      native.push(item);
    }
    workspaces.add(value.workspace);
    return value;
  };
  const reject = async (name, args) =>
    assert.equal((await raw(name, args)).isError, true, `${name} must reject`);
  const compiled = await call("forge_compile_dotnet", {
    source_path: source,
    output_name: "Fixture.dll",
    embedded_resource_name: "forge.txt",
    embedded_resource_content_base64:
      Buffer.from("original resource").toString("base64"),
  });
  assert.equal(compiled.result.compiled, true);
  const input = compiled.result.output.path;
  const originalAssembly = hash(await readFile(input));
  const inspected = await call("forge_inspect_dotnet", { path: input });
  const type = inspected.result.types.find(
    (item) => item.name === "ForgeFixture",
  );
  const marker = inspected.result.types.find(
    (item) => item.name === "ForgeMarkerAttribute",
  );
  assert.ok(type && marker);
  const method = (name) => type.methods.find((item) => item.name === name);
  const page = await call("forge_inspect_dotnet", {
    path: input,
    limit: 1,
    details: false,
  });
  assert.equal(page.result.truncated, true);
  assert.equal(page.result.types.length, 1);
  assert.equal(page.result.next_offset, 1);
  const next = await call("forge_inspect_dotnet", {
    path: input,
    limit: 1,
    offset: 1,
  });
  assert.notEqual(page.result.types[0].token, next.result.types[0].token);
  const metadata = await call("forge_inspect_dotnet", {
    path: input,
    view: "metadata",
  });
  assert.equal(metadata.result.type_count, inspected.result.total_types);
  const resources = await call("forge_inspect_dotnet", {
    path: input,
    view: "resources",
  });
  assert.equal(resources.result.resources[0].name, "forge.txt");
  const originalResource = await call("forge_read_dotnet_resource", {
    path: input,
    resource_name: "forge.txt",
  });
  assert.equal(
    Buffer.from(originalResource.result.content_base64, "base64").toString(),
    "original resource",
  );
  report.checks.compilation_metadata_types_pagination_resource = true;
  const capabilities = await call("forge_inspect_dotnet", {
    path: input,
    view: "capabilities",
  });
  report.available_languages = capabilities.result.decompiler_languages;
  for (const language of ["C#", "Visual Basic"]) {
    assert.ok(
      report.available_languages.includes(language),
      `${language} required`,
    );
    const result = await call("forge_decompile_dotnet", {
      path: input,
      type_token: type.token,
      language,
    });
    assert.ok(result.result.source.includes("REA_FORGE_DOTNET_FIXTURE"));
    report.decompilers.push(language);
  }
  if (report.available_languages.includes("IL")) {
    const il = await call("forge_decompile_dotnet", {
      path: input,
      type_token: type.token,
      language: "IL",
    });
    assert.ok(il.result.source.length > 20);
    report.decompilers.push("IL");
  }
  const edit = async (action, params) => {
    const changed = await call("forge_edit_dotnet", {
      path: input,
      action,
      ...params,
      output_name: `${action}.dll`,
    });
    assert.notEqual(
      changed.result.output.sha256,
      originalAssembly,
      `${action} must change actual bytes`,
    );
    assert.equal(
      hash(await readFile(changed.result.output.path)),
      changed.result.output.sha256,
    );
    assert.ok(changed.result.readback.types.length > 0);
    report.edits.push(action);
    return changed.result;
  };
  const selected = { type_token: type.token };
  const changedType = (result) =>
    result.readback.types.find((item) => item.token === type.token);
  assert.ok(
    (
      await edit("rename_type", { ...selected, new_name: "RenamedFixture" })
    ).readback.types.some((item) => item.name === "RenamedFixture"),
  );
  for (const [action, list, key, oldName] of [
    ["rename_method", "methods", "method_token", "Greeting"],
    ["rename_field", "fields", "field_token", "Value"],
    ["rename_property", "properties", "property_token", "Property"],
    ["rename_event", "events", "event_token", "Changed"],
  ]) {
    const member = type[list].find((item) => item.name === oldName);
    const result = await edit(action, {
      ...selected,
      [key]: member.token,
      new_name: "ForgeRenamed",
    });
    assert.ok(
      changedType(result)[list].some((item) => item.name === "ForgeRenamed"),
    );
  }
  const signature = await edit("set_method_signature", {
    ...selected,
    method_token: method("Add").token,
    return_type: "int64",
    parameter_types: ["int64", "int64"],
  });
  assert.equal(
    changedType(signature).methods.find((item) => item.name === "Add")
      .return_type,
    "System.Int64",
  );
  const field = type.fields.find((item) => item.name === "Value");
  const fieldResult = await edit("set_field_type", {
    ...selected,
    field_token: field.token,
    field_type: { kind: "szarray", element: "string" },
  });
  assert.equal(
    changedType(fieldResult).fields.find((item) => item.name === "Value").type,
    "System.String[]",
  );
  const property = type.properties.find((item) => item.name === "Property");
  const propertyResult = await edit("set_property_type", {
    ...selected,
    property_token: property.token,
    property_type: "string",
  });
  assert.equal(
    changedType(propertyResult).properties.find(
      (item) => item.name === "Property",
    ).type,
    "System.String",
  );
  const constructor = marker.methods.find((item) => item.name === ".ctor");
  const attribute = await edit("replace_custom_attributes", {
    ...selected,
    target_kind: "type",
    attributes: [
      {
        constructor_token: constructor.token,
        arguments: ["changed attribute"],
      },
    ],
  });
  assert.equal(
    changedType(attribute).custom_attributes[0].arguments[0].value,
    "changed attribute",
  );
  const resource = await edit("replace_embedded_resource", {
    resource_name: "forge.txt",
    content_base64: Buffer.from("changed resource").toString("base64"),
  });
  const reread = await call("forge_read_dotnet_resource", {
    path: resource.output.path,
    resource_name: "forge.txt",
  });
  assert.equal(
    Buffer.from(reread.result.content_base64, "base64").toString(),
    "changed resource",
  );
  const identity = await edit("set_assembly_identity", {
    assembly_name: "ForgeDerived",
    assembly_version: "2.3.4.5",
  });
  assert.ok(
    identity.metadata.assembly.includes("ForgeDerived, Version=2.3.4.5"),
  );
  const greeting = method("Greeting");
  const stringIndex = greeting.instruction_details.find(
    (item) => item.opcode === "ldstr",
  ).index;
  const nop = await edit("patch_instruction_to_nop", {
    ...selected,
    method_token: greeting.token,
    instruction_index: stringIndex,
  });
  assert.equal(nop.before, "ldstr");
  assert.equal(
    changedType(nop).methods.find((item) => item.name === "Greeting")
      .instruction_details[stringIndex].opcode,
    "nop",
  );
  const body = await edit("replace_method_body", {
    ...selected,
    method_token: method("Add").token,
    instructions: [
      { opcode: "ldc.i4", value: 42 },
      { opcode: "stloc", local_index: 0 },
      { opcode: "br", target: 3 },
      { opcode: "ldloc", local_index: 0 },
      { opcode: "ret" },
    ],
    locals: ["int32"],
    max_stack: 1,
  });
  const saved = changedType(body).methods.find((item) => item.name === "Add");
  assert.deepEqual(saved.instructions, [
    "ldc.i4",
    "stloc",
    "br",
    "ldloc",
    "ret",
  ]);
  assert.equal(saved.instruction_details[0].operand, 42);
  assert.equal(saved.instruction_details[2].branch_target_index, 3);
  assert.deepEqual(saved.local_types, ["System.Int32"]);
  report.checks.all_thirteen_edit_actions_changed_and_readback_verified = true;
  const caught = await call("forge_edit_dotnet", {
    path: input,
    action: "replace_method_body",
    ...selected,
    method_token: method("Add").token,
    output_name: "Caught.dll",
    instructions: [
      { opcode: "ldnull" },
      { opcode: "throw" },
      { opcode: "pop" },
      { opcode: "ldc.i4", value: 73 },
      { opcode: "stloc", local_index: 0 },
      { opcode: "leave", target: 7 },
      { opcode: "nop" },
      { opcode: "ldloc", local_index: 0 },
      { opcode: "ret" },
    ],
    locals: ["int32"],
    exception_handlers: [
      {
        kind: "catch",
        try_start: 0,
        try_end: 2,
        handler_start: 2,
        handler_end: 6,
        catch_type: { kind: "existing_type", full_name: "System.Exception" },
      },
    ],
  });
  const caughtBody = changedType(caught.result).methods.find(
    (item) => item.name === "Add",
  );
  assert.equal(caughtBody.exception_handlers[0].kind, "Catch");
  assert.equal(caughtBody.exception_handlers[0].catch_type, "System.Exception");
  const final = await call("forge_edit_dotnet", {
    path: input,
    action: "replace_method_body",
    ...selected,
    method_token: method("Notify").token,
    output_name: "Finally.dll",
    instructions: [
      { opcode: "nop" },
      { opcode: "leave", target: 4 },
      { opcode: "nop" },
      { opcode: "endfinally" },
      { opcode: "ret" },
    ],
    exception_handlers: [
      {
        kind: "finally",
        try_start: 0,
        try_end: 2,
        handler_start: 2,
        handler_end: 4,
      },
    ],
  });
  const finalBody = changedType(final.result).methods.find(
    (item) => item.name === "Notify",
  );
  assert.equal(finalBody.exception_handlers[0].kind, "Finally");
  assert.equal(finalBody.instructions[3], "endfinally");
  const console = await call("forge_compile_dotnet", {
    source_path: source,
    output_name: "Console.exe",
    output_kind: "console",
  });
  assert.equal(console.result.compiled, true);
  for (const [target_kind, member_token] of [
    ["method", method("Greeting").token],
    ["field", field.token],
    ["property", property.token],
    ["event", type.events[0].token],
  ]) {
    const decorated = await call("forge_edit_dotnet", {
      path: input,
      action: "replace_custom_attributes",
      ...selected,
      target_kind,
      member_token,
      output_name: `Attribute-${target_kind}.dll`,
      attributes: [
        { constructor_token: constructor.token, arguments: [target_kind] },
      ],
    });
    const list = {
      method: "methods",
      field: "fields",
      property: "properties",
      event: "events",
    }[target_kind];
    assert.equal(
      changedType(decorated.result)[list].find(
        (item) => item.token === member_token,
      ).custom_attributes[0].arguments[0].value,
      target_kind,
    );
  }
  report.checks.catch_finally_console_and_all_attribute_target_kinds = true;
  // Invalid requests fail without terminating the server or claiming a derived output.
  await reject("forge_compile_dotnet", {
    source_path: invalid,
    output_name: "Broken.dll",
  });
  await reject("forge_inspect_dotnet", { path: malformed });
  await reject("forge_edit_dotnet", {
    ...selected,
    path: input,
    action: "rename_method",
    method_token: 1,
    new_name: "Missing",
    output_name: "Missing.dll",
  });
  await reject("forge_edit_dotnet", {
    ...selected,
    path: input,
    action: "rename_type",
    new_name: "../escape",
    output_name: "Bad.dll",
  });
  await reject("forge_edit_dotnet", {
    ...selected,
    path: input,
    action: "rename_type",
    new_name: "Good",
    output_name: "../Bad.dll",
  });
  await reject("forge_edit_dotnet", {
    ...selected,
    path: input,
    action: "replace_method_body",
    output_name: "BadBranch.dll",
    method_token: method("Add").token,
    instructions: [{ opcode: "br", target: 99 }, { opcode: "ret" }],
  });
  await reject("forge_inspect_dotnet", { path: join(root, "package.json") });
  await reject("forge_read_dotnet_resource", {
    path: input,
    resource_name: "missing",
  });
  await reject("forge_decompile_dotnet", {
    path: input,
    type_token: 1,
    language: "C#",
  });
  await call("forge_inspect_dotnet", { path: input });
  report.checks.invalid_source_file_token_name_path_branch_resource_and_recovery = true;
  const cli = await execute(
    process.execPath,
    [
      entrypoint,
      "forge-inspect-dotnet",
      JSON.stringify({ path: input }),
      "--format",
      "json",
    ],
    {
      cwd: root,
      env,
      windowsHide: true,
      timeout: 40000,
      maxBuffer: 8 * 1024 * 1024,
    },
  );
  const cliValue = parseEvidence(JSON.parse(cli.stdout)).normalized_result;
  assert.deepEqual(cliValue.result, inspected.result);
  assert.deepEqual(cliValue.target, inspected.target);
  report.checks.real_cli_mcp_fact_parity = true;
  // Observe a new owned native engine log before cancellation; no historical PID lookup.
  const workRoot = join(local, "work/dotnet");
  const before = new Set(await readdir(workRoot));
  const controller = new AbortController();
  const pending = raw(
    "forge_compile_dotnet",
    { source_path: heavy, output_name: "Heavy.dll" },
    controller.signal,
  ).then(
    (value) => ({ value }),
    (error) => ({ error }),
  );
  let observed = false;
  const stopAt = Date.now() + 15000;
  while (!observed && Date.now() < stopAt) {
    for (const name of await readdir(workRoot))
      if (!before.has(name)) {
        const folder = join(workRoot, name);
        workspaces.add(folder);
        const owner = (await readdir(join(folder, "logs"))).find((file) =>
          file.endsWith(".owner.json"),
        );
        if (owner) {
          const launch = JSON.parse(
            await readFile(join(folder, "logs", owner), "utf8"),
          );
          assert.equal(launch.phase, "native_started");
          report.cancelled_native_launch = launch;
          observed = true;
        }
      }
    if (!observed) await wait(20);
  }
  controller.abort(new Error("owned dnSpy cancellation acceptance"));
  assert.ok(observed, "must observe a native launch before cancellation");
  const cancelled = await pending;
  assert.ok(cancelled.error || cancelled.value.isError);
  assert.notEqual((await raw("close_binary", {})).isError, true);
  assert.deepEqual(
    (await readdir(join(local, "tmp"))).filter((name) =>
      name.startsWith("forge-dotnet-request-"),
    ),
    [],
  );
  await call("forge_inspect_dotnet", { path: input });
  report.checks.real_native_cancellation_settlement_and_recovery = true;
  assert.equal(hash(await readFile(source)), originalSource);
  assert.equal(hash(await readFile(input)), originalAssembly);
  await assert.rejects(access(sentinel), (error) => error.code === "ENOENT");
  report.checks.originals_unchanged_and_fixture_static_initializer_not_executed = true;
  report.status = "passed";
} catch (error) {
  report.status = "failed";
  report.error = error instanceof Error ? error.stack : String(error);
  process.exitCode = 1;
} finally {
  try {
    await client.close();
    await transport.close();
    assert.ok(serverPid == null || absent(serverPid));
    assert.deepEqual(
      (await readdir(join(local, "tmp"))).filter((name) =>
        name.startsWith("forge-dotnet-request-"),
      ),
      [],
    );
    report.checks.server_and_request_roots_closed = true;
    await rm(fixtures, { recursive: true });
    await rm(temporary, { recursive: true });
    report.checks.temporary_fixtures_removed = true;
  } catch (error) {
    report.status = "failed";
    report.cleanup_error = String(error);
    process.exitCode = 1;
  }
  report.elapsed_seconds = Number(
    ((performance.now() - started) / 1000).toFixed(3),
  );
  report.native_calls = native;
  report.workspaces = [...workspaces];
  if (stderr) report.stderr_tail = stderr;
  const receipt = join(local, "evidence", `dotnet-${Date.now()}.json`);
  await writeFile(receipt, JSON.stringify(report, null, 2) + "\n");
  console.log(
    JSON.stringify(
      {
        ...report,
        native_calls: native.length,
        workspaces: workspaces.size,
        receipt,
      },
      null,
      2,
    ),
  );
}
