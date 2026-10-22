/** Real native deadline boundary, separate from the completed functional group. */
import assert from "node:assert/strict";
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
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../../dist/domain/evidence.js";
const root = fileURLToPath(new URL("../../", import.meta.url));
const local = join(root, ".forge-local");
await mkdir(join(local, "fixtures"), { recursive: true });
await mkdir(join(local, "assets/010editor"), { recursive: true });
const fixtures = await mkdtemp(join(local, "fixtures", "deadline-"));
const assets = await mkdtemp(join(local, "assets/010editor", "deadline-"));
const input = join(fixtures, "one-byte.bin"),
  script = join(assets, "deadline.1sc");
await writeFile(input, Buffer.from([0]));
await writeFile(script, "while (1) { }\n");
const client = new Client({ name: "forge-native-deadline", version: "1" });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [join(root, "scripts/rea.mjs"), "mcp"],
  stderr: "pipe",
});
const report = {
  status: "running",
  checks: {},
  gui_started: false,
  target_execution: false,
};
const started = performance.now();
try {
  await client.connect(transport, { timeout: 15_000 });
  const tools = new Map(
    (await client.listTools({}, { timeout: 15_000 })).tools.map((tool) => [
      tool.name,
      tool,
    ]),
  );
  const expiry = performance.now();
  const response = await client.callTool(
    {
      name: "forge_run_binary_script",
      arguments: { path: input, script_path: script },
    },
    { timeout: 50_000, toolDefinition: tools.get("forge_run_binary_script") },
  );
  report.native_deadline_elapsed_seconds = Number(
    ((performance.now() - expiry) / 1000).toFixed(3),
  );
  assert.equal(response.isError, true);
  assert.match(JSON.stringify(response), /exceeded the fixed timeout/u);
  assert.ok(
    report.native_deadline_elapsed_seconds >= 34 &&
      report.native_deadline_elapsed_seconds < 49,
  );
  report.checks.real_35_second_native_expiry = true;
  const recovered = await client.callTool(
    {
      name: "forge_read_binary_bytes",
      arguments: { path: input, offset: 0, length: 1 },
    },
    { timeout: 15_000, toolDefinition: tools.get("forge_read_binary_bytes") },
  );
  assert.notEqual(recovered.isError, true);
  assert.equal(
    parseEvidence(
      JSON.parse(recovered.content.find((block) => block.type === "text").text),
    ).normalized_result.result.hex,
    "00",
  );
  assert.deepEqual(await readFile(input), Buffer.from([0]));
  report.checks.same_connection_recovery_and_original_unchanged = true;
  report.status = "passed";
} catch (cause) {
  report.status = "failed";
  report.error = String(cause);
  process.exitCode = 1;
} finally {
  try {
    await client.close();
    await transport.close();
    assert.deepEqual(
      (await readdir(join(local, "tmp"))).filter((name) =>
        name.startsWith("forge-010editor-request-"),
      ),
      [],
    );
    await Promise.all([
      rm(fixtures, { recursive: true }),
      rm(assets, { recursive: true }),
    ]);
    report.checks.owned_requests_and_fixtures_closed = true;
  } catch (cause) {
    report.status = "failed";
    report.cleanup_error = String(cause);
    process.exitCode = 1;
  }
  report.elapsed_seconds = Number(
    ((performance.now() - started) / 1000).toFixed(3),
  );
  await writeFile(
    join(local, "evidence", `editor010-deadline-${Date.now()}.json`),
    JSON.stringify(report, null, 2) + "\n",
  );
  console.log(JSON.stringify(report, null, 2));
}
