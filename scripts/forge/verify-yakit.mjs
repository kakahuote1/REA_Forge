/** Official local Yak MCP against owned HTTP/TLS fixtures, never public targets. */
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import http from "node:http";
import https from "node:https";
import {
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
import { FORGE_YAKIT_OPERATIONS } from "../../dist/domain/forge/yakit.js";

const root = fileURLToPath(new URL("../../", import.meta.url)),
  local = join(root, ".forge-local");
const sha = (value) => createHash("sha256").update(value).digest("hex");
const resume = process.env.REA_FORGE_YAKIT_RESUME;
const prior = resume ? JSON.parse(await readFile(resume, "utf8")) : undefined;
const fixtures =
  prior?.fixtures ?? (await mkdtemp(join(local, "fixtures/yakit-")));
const temporary = await mkdtemp(join(local, "tmp/yakit-"));
const profile =
  prior?.profile ??
  "acceptance_" + randomUUID().replaceAll("-", "").slice(0, 24);
const marker = profile + "_request";
const configuration = JSON.parse(
  await readFile(process.env.REA_FORGE_STATIC_CONFIG, "utf8"),
);
const configPath = join(fixtures, "acceptance-tools.json");
await writeFile(configPath, JSON.stringify(configuration));
const report = {
  status: "running",
  scope:
    "G18 official Yakit request/private HTTPFlow subset; DudeSuite remains unresolved",
  fixtures,
  profile,
  checks: { ...prior?.checks },
  values: { ...prior?.values },
  cpu_time: "unmeasured",
  peak_process_family_memory: "unmeasured",
  target_execution: false,
  gui_started: false,
  system_proxy_or_trust_changes_requested: false,
};
report.configuration_sha256 = sha(
  JSON.stringify([configuration.yakit, configuration.yakit_results]),
);
if (prior) {
  assert.equal(prior.configuration_sha256, report.configuration_sha256);
  report.reused_receipt = { path: resume, sha256: sha(await readFile(resume)) };
}
report.source_hashes = {};
for (const path of [
  "bridge/forge/yakit/worker.py",
  "bridge/forge/yakit/protocol.py",
  "bridge/forge/yakit/driver.mjs",
  "dist/domain/forge/yakit.js",
  "dist/forge/yakit/YakitAdapter.js",
])
  report.source_hashes[path] = sha(await readFile(join(root, path)));
async function verifyRetained(value) {
  if (!value || typeof value !== "object") return;
  if (value.result?.receipt_path) {
    assert.equal(
      sha(await readFile(value.result.receipt_path)),
      value.result.receipt_sha256,
    );
    const receipt = JSON.parse(
      await readFile(value.result.receipt_path, "utf8"),
    );
    for (const item of [receipt.full_result, ...receipt.artifacts])
      assert.equal(sha(await readFile(item.path)), item.sha256);
  } else for (const item of Object.values(value)) await verifyRetained(item);
}
for (const value of Object.values(report.values)) await verifyRetained(value);
for (const pin of [configuration.yakit.engine, configuration.yakit.node])
  assert.equal(sha(await readFile(pin.path)), pin.sha256);
const key = join(fixtures, "localhost.key"),
  certificate = join(fixtures, "localhost.crt");
if (!prior) {
  const openssl = configuration.hap_signing.openssl;
  assert.equal(sha(await readFile(openssl.path)), openssl.sha256);
  await promisify(execFile)(
    openssl.path,
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      key,
      "-out",
      certificate,
      "-days",
      "2",
      "-subj",
      "/CN=127.0.0.1",
      "-addext",
      "subjectAltName=IP:127.0.0.1",
    ],
    {
      cwd: fixtures,
      windowsHide: true,
      timeout: 20000,
      maxBuffer: 1024 * 1024,
    },
  );
}
const hits = [],
  pendingResponses = new Set();
let hangObserved;
const handler = (request, response) => {
  let body = "";
  request.setEncoding("utf8");
  request.on("data", (chunk) => {
    body += chunk;
    if (body.length > 256 * 1024) request.destroy();
  });
  request.on("end", () => {
    hits.push({ path: request.url, body, method: request.method });
    if (request.url.startsWith("/hang")) {
      pendingResponses.add(response);
      response.once("close", () => pendingResponses.delete(response));
      hangObserved?.();
      return;
    }
    if (request.url.startsWith("/redirect?")) {
      response.writeHead(302, { Location: "/redirected" });
      response.end("redirect fixture");
      return;
    }
    response.setHeader("Content-Type", "application/json; charset=utf-8");
    response.end(
      JSON.stringify({
        marker,
        path: request.url,
        method: request.method,
        body,
      }),
    );
  });
};
const plain = http.createServer(handler),
  tls = https.createServer(
    { key: await readFile(key), cert: await readFile(certificate) },
    handler,
  );
await new Promise((resolve) => plain.listen(0, "127.0.0.1", resolve));
await new Promise((resolve) => tls.listen(0, "127.0.0.1", resolve));
const httpRoot = `http://127.0.0.1:${plain.address().port}`,
  httpsRoot = `https://127.0.0.1:${tls.address().port}`;
const env = Object.fromEntries(
  Object.entries({
    ...process.env,
    REA_FORGE_STATIC_CONFIG: configPath,
    TEMP: temporary,
    TMP: temporary,
    REA_LOG_LEVEL: "error",
  }).filter(([, value]) => typeof value === "string"),
);
const entry = join(root, "scripts/rea.mjs"),
  transport = new StdioClientTransport({
    command: process.execPath,
    args: [entry, "mcp"],
    env,
    stderr: "pipe",
  });
const client = new Client({ name: "forge-yakit-acceptance", version: "1" });
const started = performance.now();
const ref = (value) => ({
  receipt_path: value.result.receipt_path,
  receipt_sha256: value.result.receipt_sha256,
});
const checkpoint = () =>
  writeFile(
    join(local, "evidence/yakit-current.json"),
    JSON.stringify(report, null, 2),
  );
try {
  await client.connect(transport, { timeout: 20000 });
  report.server_pid = transport.pid;
  const tools = new Map(
    (await client.listTools({}, { timeout: 20000 })).tools.map((tool) => [
      tool.name,
      tool,
    ]),
  );
  for (const name of FORGE_YAKIT_OPERATIONS) assert.ok(tools.has(name));
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
  const call = async (name, input) => {
    const value = await raw(name, input);
    assert.notEqual(value.isError, true, JSON.stringify(value));
    return parseEvidence(
      JSON.parse(value.content.find((part) => part.type === "text").text),
    ).normalized_result;
  };
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
  await step("target_free_readiness", async () => {
    const value = await raw("binary_session", {});
    assert.notEqual(value.isError, true);
    const status = JSON.parse(
      value.content.find((part) => part.type === "text").text,
    );
    for (const name of FORGE_YAKIT_OPERATIONS)
      assert.equal(
        status.result.tool_availability.groups.find((group) =>
          group.names.includes(name),
        )?.available,
        true,
      );
    assert.equal(status.result.open, false);
    return { ready: true };
  });
  const request = await step(
    "single_http_literal_utf8",
    async () => {
      const before = hits.length;
      const result = await call("forge_yakit_request", {
        profile,
        url: httpRoot + "/echo?marker=" + marker,
        method: "POST",
        body: "中文 {{int(1-3)}}",
        facet: "data",
      });
      return { result, observed: hits.slice(before) };
    },
    (value) => {
      assert.equal(value.observed.length, 1);
      assert.equal(value.observed[0].body, "中文 {{int(1-3)}}");
      assert.ok(value.result.result.rows[0].response.includes(marker));
      assert.equal(value.result.result.rows.length, 1);
    },
  );
  await step(
    "single_https_without_trust_store_change",
    () =>
      call("forge_yakit_request", {
        profile,
        url: httpsRoot + "/tls?marker=" + marker,
        facet: "data",
      }),
    (value) => assert.ok(value.result.rows[0].response.includes(marker)),
  );
  await step(
    "redirect_not_followed",
    async () => {
      const before = hits.length;
      const result = await call("forge_yakit_request", {
        profile,
        url: httpRoot + "/redirect?marker=" + marker,
        facet: "data",
      });
      return { result, observed: hits.slice(before) };
    },
    (value) => {
      assert.equal(value.observed.length, 1);
      assert.match(value.result.result.rows[0].response, /302/u);
      assert.ok(
        !value.observed.some((item) => item.path.startsWith("/redirected")),
      );
    },
  );
  await step(
    "official_httpflow_history",
    () =>
      call("forge_yakit_flows", {
        profile,
        keyword: marker,
        count: 20,
        facet: "data",
      }),
    (value) => {
      assert.ok(value.result.rows.length >= 3);
      assert.ok(JSON.stringify(value.result.rows).includes(marker));
    },
  );
  await step(
    "request_timeout_is_not_false_success",
    () =>
      call("forge_yakit_request", {
        profile,
        url: httpRoot + "/hang?marker=" + marker,
        request_timeout_seconds: 1,
      }),
    (value) => assert.equal(value.result.value.complete, false),
  );
  await step("retained_response_and_exact_artifact_bytes", async () => {
    const read = await call("forge_read_yakit_result", {
      ...ref(request.result),
      facet: "data",
      artifact_index: 0,
      byte_count: 64,
    });
    assert.ok(read.result.rows[0].response.includes(marker));
    assert.deepEqual(
      Buffer.from(read.result.artifact_read.base64, "base64"),
      (await readFile(request.result.result.full_result.path)).subarray(0, 64),
    );
    return { read };
  });
  await step("unselected_authority_and_receipt_refusal", async () => ({
    script: await reject("forge_yakit_request", {
      profile,
      url: httpRoot,
      script: "not-admitted",
    }),
    proxy: await reject("forge_yakit_request", {
      profile,
      url: httpRoot,
      proxy: "http://other:8080",
    }),
    header: await reject("forge_yakit_request", {
      profile,
      url: httpRoot,
      headers: [{ name: "Host", value: "other" }],
    }),
    profile: await reject("forge_yakit_flows", { profile: "../human" }),
    receipt: await reject("forge_read_yakit_result", {
      ...ref(request.result),
      receipt_sha256: "0".repeat(64),
    }),
  }));
  await step(
    "real_native_deadline",
    () => reject("forge_yakit_flows", { profile, timeout_ms: 1 }),
    (value) => assert.match(JSON.stringify(value), /timeout|deadline/iu),
  );
  await step("active_request_cancel_and_profile_recovery", async () => {
    const stop = new AbortController();
    let observed;
    const atServer = new Promise((resolve) => {
      hangObserved = () => {
        observed = true;
        resolve();
      };
    });
    const pending = raw(
      "forge_yakit_request",
      {
        profile,
        url: httpRoot + "/hang?cancel=" + marker,
        request_timeout_seconds: 15,
      },
      stop.signal,
    );
    const settled = pending.catch(() => undefined);
    const timer = setTimeout(
      () => stop.abort("acceptance admission deadline"),
      12000,
    );
    try {
      await Promise.race([atServer, settled]);
      assert.equal(observed, true);
      stop.abort("cancel source-owned active request");
      await assert.rejects(pending);
    } finally {
      clearTimeout(timer);
      hangObserved = undefined;
      stop.abort();
      await settled;
    }
    const restored = await call("forge_yakit_flows", {
      profile,
      keyword: marker,
    });
    return { observed_at_fixture: true, restored };
  });
  await step("missing_engine_isolation", async () => {
    const selected = structuredClone(configuration);
    delete selected.yakit;
    await writeFile(configPath, JSON.stringify(selected));
    try {
      return {
        failure: await reject("forge_yakit_flows", { profile }),
        read: await call("forge_read_yakit_result", ref(request.result)),
      };
    } finally {
      await writeFile(configPath, JSON.stringify(configuration));
    }
  });
  await step("cli_parity_from_another_working_directory", async () => {
    const { stdout } = await promisify(execFile)(
      process.execPath,
      [
        entry,
        "forge-read-yakit-result",
        JSON.stringify({ ...ref(request.result), facet: "data" }),
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
    assert.equal(
      value.result.rows[0].response,
      request.result.result.rows[0].response,
    );
    return { equal: true };
  });
  for (const value of Object.values(report.values)) await verifyRetained(value);
  for (const pin of [configuration.yakit.engine, configuration.yakit.node])
    assert.equal(sha(await readFile(pin.path)), pin.sha256);
  report.checks.originals_and_retained_artifacts = true;
  report.status = "passed";
} catch (cause) {
  report.status = "failed";
  report.failure = String(cause);
  process.exitCode = 1;
} finally {
  for (const response of pendingResponses) response.destroy();
  const cleanupErrors = [];
  try {
    await client.close();
    report.transport_closed = true;
  } catch (cause) {
    cleanupErrors.push("transport: " + String(cause));
  }
  try {
    plain.closeAllConnections();
    tls.closeAllConnections();
    await Promise.all([
      new Promise((resolve) => plain.close(resolve)),
      new Promise((resolve) => tls.close(resolve)),
    ]);
    report.fixture_servers_closed = true;
  } catch (cause) {
    cleanupErrors.push("fixture servers: " + String(cause));
  }
  try {
    report.temporary_empty = (await readdir(temporary)).length === 0;
    if (report.temporary_empty) await rmdir(temporary);
    else cleanupErrors.push("temporary directory is not empty");
  } catch (cause) {
    cleanupErrors.push("temporary directory: " + String(cause));
  }
  if (cleanupErrors.length) {
    report.cleanup_errors = cleanupErrors;
    report.status = "failed";
    process.exitCode = 1;
  }
  report.elapsed_seconds = (performance.now() - started) / 1000;
  const receipt = join(local, "evidence", `yakit-${Date.now()}.json`);
  await writeFile(receipt, JSON.stringify(report, null, 2));
  console.log(
    JSON.stringify({
      status: report.status,
      receipt,
      checks: report.checks,
      elapsed_seconds: report.elapsed_seconds,
      failure: report.failure,
    }),
  );
}
