/** Concentrated real offline CyberChef workflows; no browser or target code. */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, createHmac, createCipheriv } from "node:crypto";
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
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../../dist/domain/evidence.js";
import { CYBERCHEF_RECIPE_OPERATIONS } from "../../dist/domain/forge/cyberChef.js";

const root = fileURLToPath(new URL("../../", import.meta.url));
const local = join(root, ".forge-local");
for (const name of ["tmp", "fixtures", "evidence"])
  await mkdir(join(local, name), { recursive: true });
const fixtures = await mkdtemp(join(local, "fixtures", "cyberchef-"));
const temp = await mkdtemp(join(local, "tmp", "cyberchef-provider-"));
const sample = join(fixtures, "plain.txt");
const json = join(fixtures, "input.json");
const large = join(fixtures, "preview.txt");
const vector = join(fixtures, "vector.txt");
const plain = Buffer.from("REA Forge 中文\n");
await Promise.all([
  writeFile(sample, plain),
  writeFile(json, '{"x":1,"array":[true,false]}'),
  writeFile(large, "X".repeat(5000)),
  writeFile(vector, "123456789"),
]);
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const report = {
  status: "running",
  checks: {},
  operations_exercised: [],
  sample_execution: false,
  gui_started: false,
  network_capture: false,
  network_used: false,
};
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
  name: "rea-forge-cyberchef-acceptance",
  version: "1",
});
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
const execute = promisify(execFile);
let pid;
let stderr = "";
const started = performance.now();
try {
  await client.connect(transport, { timeout: 20_000 });
  pid = transport.pid;
  transport.stderr?.on("data", (data) => {
    stderr = (stderr + data.toString()).slice(-8192);
  });
  const tools = new Map(
    (await client.listTools({}, { timeout: 20_000 })).tools.map((tool) => [
      tool.name,
      tool,
    ]),
  );
  report.advertised_tool_count = tools.size;
  const raw = (name, args) =>
    client.callTool(
      { name, arguments: args },
      { timeout: 55_000, toolDefinition: tools.get(name) },
    );
  const call = async (name, args) => {
    assert.ok(tools.get(name)?.outputSchema);
    const response = await raw(name, args);
    assert.notEqual(
      response.isError,
      true,
      `${name}: ${JSON.stringify(response)}`,
    );
    const value = parseEvidence(
      JSON.parse(response.content.find((block) => block.type === "text").text),
    ).normalized_result;
    assert.equal(value.engine.owned_wait_completed, true);
    assert.equal(value.network_used, false);
    return value;
  };
  const reject = async (name, args) => {
    const response = await raw(name, args);
    assert.equal(response.isError, true, `${name} must reject`);
  };
  const listed = await call("forge_list_cyberchef_operations", {});
  const operations = new Map(
    listed.result.operations.map((operation) => [operation.name, operation]),
  );
  assert.deepEqual(
    [...operations.keys()].sort(),
    [...CYBERCHEF_RECIPE_OPERATIONS].sort(),
  );
  const defaults = (name) =>
    structuredClone(
      operations.get(name).arguments.map((argument) => argument.default),
    );
  const recipe = (names) => names.map((op) => ({ op }));
  const run = async (path, steps) => {
    const result = await call("forge_run_cyberchef_recipe", {
      path,
      recipe: steps,
    });
    const bytes = await readFile(result.result.output_path);
    assert.equal(sha(bytes), result.result.output_sha256);
    assert.equal(bytes.length, result.result.output_bytes);
    for (const step of steps) report.operations_exercised.push(step.op);
    return { result: result.result, bytes };
  };
  for (const pair of [
    ["To Base64", "From Base64"],
    ["To Hex", "From Hex"],
    ["URL Encode", "URL Decode"],
    ["Encode text", "Decode text"],
    ["Gzip", "Gunzip"],
    ["Zlib Deflate", "Zlib Inflate"],
  ]) {
    const value = await run(sample, recipe(pair));
    assert.deepEqual(value.bytes, plain, pair.join(" -> "));
  }
  report.checks.six_encoding_compression_roundtrips = true;
  const shaArgs = defaults("SHA2");
  const shaSizeIndex = operations
    .get("SHA2")
    .arguments.findIndex((argument) =>
      argument.options?.some((value) => String(value) === "256"),
    );
  assert.ok(shaSizeIndex >= 0);
  shaArgs[shaSizeIndex] = operations
    .get("SHA2")
    .arguments[shaSizeIndex].options.find((value) => String(value) === "256");
  const hashed = await run(sample, [{ op: "SHA2", args: shaArgs }]);
  assert.equal(hashed.bytes.toString().trim().toLowerCase(), sha(plain));
  const hmacArgs = defaults("HMAC");
  hmacArgs[0] = { string: "known-test-key", option: "UTF8" };
  const algorithmIndex = operations
    .get("HMAC")
    .arguments.findIndex((argument) => argument.options?.includes("SHA256"));
  assert.ok(algorithmIndex >= 0);
  hmacArgs[algorithmIndex] = "SHA256";
  const hmac = await run(sample, [{ op: "HMAC", args: hmacArgs }]);
  assert.equal(
    hmac.bytes.toString().trim().toLowerCase(),
    createHmac("sha256", "known-test-key").update(plain).digest("hex"),
  );
  const crcArgs = defaults("CRC Checksum");
  crcArgs[0] = "CRC-32/ISO-HDLC";
  const crc = await run(vector, [{ op: "CRC Checksum", args: crcArgs }]);
  assert.equal(
    crc.bytes.toString().trim().toLowerCase().replace(/^0x/u, ""),
    "cbf43926",
  );
  const xorArgs = defaults("XOR");
  xorArgs[0] = { string: "01", option: "Hex" };
  const xor = await run(sample, [{ op: "XOR", args: xorArgs }]);
  assert.deepEqual(
    xor.bytes,
    plain.map((byte) => byte ^ 1),
  );
  report.checks.hash_hmac_crc_xor_independent_vectors = true;
  const key = { string: "000102030405060708090a0b0c0d0e0f", option: "Hex" };
  const iv = { string: "00000000000000000000000000000000", option: "Hex" };
  const encrypt = defaults("AES Encrypt"),
    decrypt = defaults("AES Decrypt");
  encrypt[0] = key;
  encrypt[1] = iv;
  encrypt[2] = "CBC";
  encrypt[3] = "Hex";
  decrypt[0] = key;
  decrypt[1] = iv;
  decrypt[3] = "CBC";
  decrypt[4] = "Hex";
  decrypt[5] = "Hex";
  const encrypted = await run(sample, [
    { op: "To Hex" },
    { op: "AES Encrypt", args: encrypt },
  ]);
  const cipher = createCipheriv(
    "aes-128-cbc",
    Buffer.from(key.string, "hex"),
    Buffer.alloc(16),
  );
  const expectedCipher = Buffer.concat([cipher.update(plain), cipher.final()]);
  assert.equal(
    encrypted.bytes.toString().trim().toLowerCase(),
    expectedCipher.toString("hex"),
  );
  const decrypted = await run(encrypted.result.output_path, [
    { op: "AES Decrypt", args: decrypt },
    { op: "From Hex" },
  ]);
  assert.deepEqual(decrypted.bytes, plain);
  const formatted = await run(json, recipe(["JSON Beautify", "JSON Minify"]));
  assert.deepEqual(JSON.parse(formatted.bytes.toString()), {
    x: 1,
    array: [true, false],
  });
  report.checks.known_parameter_aes_independent_cipher_and_json = true;
  const validated = await call("forge_validate_cyberchef_recipe", {
    recipe: recipe(["To Base64", "From Base64"]),
  });
  assert.equal(validated.result.recipe.length, 2);
  assert.equal(validated.result.recipe[0].op, "To Base64");
  const replayed = await call("forge_replay_cyberchef_recipe", {
    path: sample,
    receipt_path: hashed.result.receipt_path,
    receipt_sha256: hashed.result.receipt_sha256,
  });
  assert.equal(replayed.result.output_sha256, hashed.result.output_sha256);
  await reject("forge_replay_cyberchef_recipe", {
    path: sample,
    receipt_path: hashed.result.receipt_path,
    receipt_sha256: "0".repeat(64),
  });
  const encoded = await run(sample, recipe(["To Base64"]));
  const candidates = await call("forge_suggest_cyberchef_steps", {
    path: encoded.result.output_path,
  });
  assert.ok(
    candidates.result.candidates.some(
      (item) =>
        item.label === "From Base64" && item.confidence === "candidate_only",
    ),
  );
  const preview = await run(large, recipe(["To Base64"]));
  assert.equal(preview.result.preview_truncated, true);
  assert.equal(
    Buffer.from(preview.result.preview_base64, "base64").length,
    4096,
  );
  report.checks.standard_recipe_validation_replay_candidates_and_preview = true;
  await reject("forge_run_cyberchef_recipe", {
    path: sample,
    recipe: [{ op: "HTTP request" }],
  });
  await reject("forge_validate_cyberchef_recipe", {
    recipe: [{ op: "AES Encrypt" }],
  });
  await reject("forge_validate_cyberchef_recipe", {
    recipe: [{ op: "To Base64", args: ["bad"] }],
  });
  await call("forge_list_cyberchef_operations", {});
  report.checks.invalid_external_operation_key_args_and_recovery = true;
  const cli = await execute(
    process.execPath,
    [
      entrypoint,
      "forge-validate-cyberchef-recipe",
      JSON.stringify({ recipe: recipe(["To Base64", "From Base64"]) }),
      "--format",
      "json",
    ],
    {
      cwd: root,
      env: environment,
      windowsHide: true,
      timeout: 35_000,
      maxBuffer: 8 * 1024 * 1024,
    },
  );
  const cliResult = parseEvidence(JSON.parse(cli.stdout)).normalized_result;
  assert.deepEqual(cliResult.result, validated.result);
  report.checks.real_cli_mcp_recipe_parity = true;
  assert.deepEqual(await readFile(sample), plain);
  assert.deepEqual(
    [...new Set(report.operations_exercised)].sort(),
    [...CYBERCHEF_RECIPE_OPERATIONS].sort(),
  );
  report.operations_exercised = [...new Set(report.operations_exercised)];
  report.checks.all_twenty_operations_and_original_unchanged = true;
  report.status = "passed";
} catch (cause) {
  report.status = "failed";
  report.error = cause instanceof Error ? cause.stack : String(cause);
  process.exitCode = 1;
} finally {
  try {
    await client.close();
    await transport.close();
    if (pid != null) {
      try {
        process.kill(pid, 0);
        throw new Error("owned MCP server still present");
      } catch (cause) {
        if (cause.code !== "ESRCH") throw cause;
      }
    }
    assert.deepEqual(
      (await readdir(join(local, "tmp"))).filter((name) =>
        name.startsWith("forge-cyberchef-request-"),
      ),
      [],
    );
    await Promise.all([
      rm(fixtures, { recursive: true }),
      rm(temp, { recursive: true }),
    ]);
    report.checks.owned_server_request_roots_and_fixtures_closed = true;
  } catch (cause) {
    report.status = "failed";
    report.cleanup_error = String(cause);
    process.exitCode = 1;
  }
  report.elapsed_seconds = Number(
    ((performance.now() - started) / 1000).toFixed(3),
  );
  if (stderr) report.stderr_tail = stderr;
  await writeFile(
    join(local, "evidence", `cyberchef-${Date.now()}.json`),
    JSON.stringify(report, null, 2) + "\n",
  );
  console.log(JSON.stringify(report, null, 2));
}
