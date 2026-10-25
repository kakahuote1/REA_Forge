/** One complete G16 group: local deterministic/public fixtures, CLI and real MCP. */
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
} from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { ZipWriter, Uint8ArrayWriter, Uint8ArrayReader } from "@zip.js/zip.js";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../../dist/domain/evidence.js";
import { FORGE_TRAFFIC_OPERATIONS } from "../../dist/domain/forge/offlineTraffic.js";
import { offlineHttpFixture } from "./traffic-fixture.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url)),
  local = join(root, ".forge-local");
for (const name of ["fixtures", "tmp", "evidence"])
  await mkdir(join(local, name), { recursive: true });
const fixtures = await mkdtemp(join(local, "fixtures/offline-traffic-"));
const temporary = await mkdtemp(join(local, "tmp/traffic-provider-"));
const fixtureSource = process.env.REA_FORGE_TLS_FIXTURE_ROOT;
assert.ok(
  fixtureSource,
  "Select the already installed public TLS fixture root explicitly; this verifier does not download it",
);
const sha = (value) => createHash("sha256").update(value).digest("hex");
const paths = {};
const originals = new Map();
const save = async (name, bytes) => {
  const path = join(fixtures, name);
  await writeFile(path, bytes);
  originals.set(path, sha(bytes));
  return path;
};
paths.pcap = await save("plain.pcap", offlineHttpFixture());
paths.broken = await save("broken.pcap", Buffer.from("broken"));
for (const name of [
  "tls12-no-secrets.pcapng",
  "public-fixture.keys",
  "tls13-rfc8446.pcap",
  "tls13-rfc8446.keys",
  "tls13-public-fixture-wrong.keys",
]) {
  const source = join(fixtureSource, name),
    path = join(fixtures, name);
  const hash = sha(await readFile(source));
  await copyFile(source, path);
  assert.equal(sha(await readFile(path)), hash);
  originals.set(source, hash);
  originals.set(path, hash);
  paths[name] = path;
}
const openapi = {
  openapi: "3.0.3",
  info: { title: "Fixture", version: "1" },
  paths: {
    "/items": { get: { operationId: "listItems", responses: { 200: {} } } },
    "/items/{id}": {
      delete: { operationId: "deleteItem", responses: { 204: {} } },
    },
  },
  servers: [
    {
      url: "https://example.test",
      variables: { region: { default: "PRIVATE_FIXTURE_VARIABLE" } },
    },
  ],
};
paths.api = await save("openapi.json", JSON.stringify(openapi));
paths.api2 = await save(
  "openapi-new.json",
  JSON.stringify({
    ...openapi,
    paths: {
      ...openapi.paths,
      "/health": { get: { operationId: "health", responses: { 200: {} } } },
    },
  }),
);
paths.swagger = await save(
  "swagger.json",
  JSON.stringify({
    swagger: "2.0",
    info: { title: "Legacy", version: "1" },
    paths: {
      "/legacy": {
        post: {
          operationId: "legacy",
          parameters: [
            { in: "body", name: "body", schema: { type: "object" } },
          ],
          responses: { 200: {} },
        },
      },
    },
  }),
);
paths.postman = await save(
  "postman.json",
  JSON.stringify({
    info: {
      name: "Collection",
      schema:
        "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
    },
    variable: [{ key: "token", value: "PRIVATE_FIXTURE_VARIABLE" }],
    item: [
      {
        name: "Folder",
        item: [
          {
            name: "First",
            request: {
              method: "GET",
              url: {
                path: ["items"],
                raw: "https://example.test/items?private=hidden",
              },
            },
          },
          {
            name: "Second",
            request: { method: "GET", url: { path: ["items"] } },
          },
        ],
      },
    ],
  }),
);
paths.env = await save(
  "environment.json",
  JSON.stringify({
    name: "Environment",
    values: [
      { key: "token", value: "PRIVATE_FIXTURE_VARIABLE", enabled: true },
    ],
  }),
);
paths.duplicate = await save(
  "duplicate.json",
  '{"openapi":"3.0.3","openapi":"3.1.0","paths":{}}',
);
paths.badKey = await save("invalid.keys", "not valid key material");
paths.har = await save(
  "fixture.har",
  JSON.stringify({
    log: {
      version: "1.2",
      creator: { name: "Fixture", version: "1" },
      entries: [
        {
          startedDateTime: "2026-01-01T00:00:00Z",
          time: 1,
          request: {
            method: "GET",
            url: "http://example.test/fixture",
            httpVersion: "HTTP/1.1",
            headers: [],
            queryString: [],
            cookies: [],
            headersSize: -1,
            bodySize: 0,
          },
          response: {
            status: 200,
            statusText: "OK",
            httpVersion: "HTTP/1.1",
            headers: [],
            cookies: [],
            content: {
              size: 5,
              mimeType: "text/plain",
              text: Buffer.from("hello").toString("base64"),
              encoding: "base64",
            },
            redirectURL: "",
            headersSize: -1,
            bodySize: 5,
          },
          cache: {},
          timings: { send: 0, wait: 1, receive: 0 },
        },
      ],
    },
  }),
);
const zip = new ZipWriter(new Uint8ArrayWriter(), { useWebWorkers: false });
for (const [name, bytes] of [
  [
    "raw/1_c.txt",
    Buffer.from(
      "GET http://example.test/fixture HTTP/1.1\r\nHost: example.test\r\n\r\n",
    ),
  ],
  [
    "raw/1_s.txt",
    Buffer.from(
      "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello",
    ),
  ],
  [
    "raw/1_m.xml",
    Buffer.from(
      '<Session SID="1"><SessionTimers ClientConnected="2026-01-01T00:00:00Z"/></Session>',
    ),
  ],
])
  await zip.add(name, new Uint8ArrayReader(bytes));
paths.saz = await save("fixture.saz", Buffer.from(await zip.close()));
const environment = Object.fromEntries(
  Object.entries({
    ...process.env,
    TEMP: temporary,
    TMP: temporary,
    TMPDIR: temporary,
    REA_LOG_LEVEL: "error",
  }).filter(([, value]) => typeof value === "string"),
);
const client = new Client({
  name: "forge-offline-traffic-acceptance",
  version: "1",
});
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [join(root, "scripts/rea.mjs"), "mcp"],
  env: environment,
  stderr: "pipe",
});
const report = {
  status: "running",
  checks: {},
  results: [],
  native_engines: {},
  fixture_hashes: Object.fromEntries(originals),
  sample_execution: false,
  gui_started: false,
  live_capture: false,
  network_used: false,
};
const resumePath = process.env.REA_FORGE_TRAFFIC_RESUME;
const prior = resumePath
  ? JSON.parse(await readFile(resumePath, "utf8"))
  : undefined;
if (prior) {
  assert.equal(prior.checks.api_all_formats_filters_comparison_export, true);
  assert.equal(prior.provider_temp_empty, true);
  for (const [path, hash] of Object.entries(prior.fixture_hashes))
    assert.equal(sha(await readFile(path)), hash);
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
  report.native_engines = prior.native_engines;
}
const started = performance.now();
let diagnostics = "";
try {
  await client.connect(transport, { timeout: 20000 });
  report.server_pid = transport.pid;
  transport.stderr?.on("data", (chunk) => {
    if (diagnostics.length < 65536) diagnostics += chunk.toString();
  });
  const tools = new Map(
    (await client.listTools({}, { timeout: 20000 })).tools.map((tool) => [
      tool.name,
      tool,
    ]),
  );
  for (const name of FORGE_TRAFFIC_OPERATIONS) assert.ok(tools.has(name));
  report.tool_count = tools.size;
  const raw = (name, input, signal) =>
    client.callTool(
      { name, arguments: input },
      {
        timeout: 55000,
        toolDefinition: tools.get(name),
        ...(signal === undefined ? {} : { signal }),
      },
    );
  const call = async (name, input) => {
    const response = await raw(name, input);
    assert.notEqual(response.isError, true, JSON.stringify(response));
    const result = parseEvidence(
      JSON.parse(response.content.find((part) => part.type === "text").text),
    ).normalized_result;
    if (result.result?.receipt_path)
      report.results.push({
        name,
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
  const fields = ["frame.number", "http.request.method", "http.response.code"];
  let tree, api;
  if (prior) {
    for (const name of [
      "forge_inspect_packet_tree",
      "forge_inspect_api_asset",
    ]) {
      const reference = prior.results.find((item) => item.name === name);
      assert.ok(reference);
      const retained = await call("forge_read_traffic_result", {
        receipt_path: reference.receipt_path,
        receipt_sha256: reference.receipt_sha256,
      });
      if (name === "forge_inspect_packet_tree") tree = retained;
      else api = retained;
    }
  } else {
    const native = await call("inspect_pcap_client", {});
    report.native_engines = native.client;
    const summary = await call("inspect_pcap_capture", { path: paths.pcap });
    assert.equal(summary.packet_count, 5);
    report.checks.native_pcap_summary = true;
    tree = await call("forge_inspect_packet_tree", {
      path: paths.pcap,
      limit: 2,
    });
    assert.equal(tree.result.total, 5);
    assert.equal(tree.result.has_more, true);
    assert.equal(tree.result.rows[0]._source.layers.frame["frame.number"], "1");
    const page = await call("forge_read_traffic_result", {
      receipt_path: tree.result.receipt_path,
      receipt_sha256: tree.result.receipt_sha256,
      offset: 2,
      limit: 3,
    });
    assert.equal(page.result.rows.length, 3);
    assert.equal(page.result.rows[2]._source.layers.frame["frame.number"], "5");
    report.checks.tree_and_retained_paging = true;
    const extracted = await call("forge_extract_packet_fields", {
      path: paths.pcap,
      fields,
      display_filter: "http",
    });
    assert.deepEqual(
      extracted.result.rows.map((row) => [row[fields[1]], row[fields[2]]]),
      [
        ["GET", ""],
        ["", "200"],
      ],
    );
    report.checks.exact_fields_and_filter = true;
    const statistics = await call("forge_pcap_statistics", {
      path: paths.pcap,
      statistic: "conv,tcp",
    });
    assert.ok(statistics.result.text.includes("192.0.2.10"));
    report.checks.statistics = true;
    const followed = await call("forge_follow_packet_stream", {
      path: paths.pcap,
      protocol: "tcp",
      stream_index: 0,
    });
    assert.equal(followed.result.rows.length, 2);
    const streamBytes = [];
    for (const row of followed.result.rows) {
      const artifact_index =
        followed.result.artifacts.findIndex(
          (file) =>
            file.sha256 === row.payload.sha256 &&
            file.path === row.payload.path,
        ) + 1;
      const chunk = await call("forge_read_traffic_result", {
        receipt_path: followed.result.receipt_path,
        receipt_sha256: followed.result.receipt_sha256,
        artifact_index,
        byte_count: 65536,
      });
      const bytes = Buffer.from(chunk.result.bytes.base64, "base64");
      assert.equal(sha(bytes), row.payload.sha256);
      streamBytes.push(bytes);
    }
    assert.ok(Buffer.concat(streamBytes).includes(Buffer.from("hello")));
    report.checks.exact_stream_payload_bytes = true;
    const objects = await call("forge_export_packet_objects", {
      path: paths.pcap,
      protocol: "http",
    });
    assert.equal(objects.result.rows.length, 1);
    assert.equal(objects.result.rows[0].file.sha256, sha(Buffer.from("hello")));
    assert.equal(
      sha(await readFile(objects.result.rows[0].file.path)),
      sha(Buffer.from("hello")),
    );
    report.checks.object_export_and_disk_readback = true;
    const tlsFields = [
      "frame.number",
      "http.request.method",
      "http.request.uri",
      "http.response.code",
    ];
    const tls = (path, keylog_path) =>
      call("forge_extract_packet_fields", {
        path,
        fields: tlsFields,
        display_filter: "http",
        ...(keylog_path === undefined ? {} : { keylog_path }),
      });
    assert.equal((await tls(paths["tls12-no-secrets.pcapng"])).result.total, 0);
    const decoded12 = await tls(
      paths["tls12-no-secrets.pcapng"],
      paths["public-fixture.keys"],
    );
    assert.deepEqual(
      decoded12.result.rows
        .map((row) => row["http.request.method"])
        .filter(Boolean),
      ["HEAD", "HEAD"],
    );
    assert.equal((await tls(paths["tls12-no-secrets.pcapng"])).result.total, 0);
    report.checks.tls12_explicit_keys_and_no_persistence = true;
    assert.equal(
      (
        await tls(
          paths["tls13-rfc8446.pcap"],
          paths["tls13-public-fixture-wrong.keys"],
        )
      ).result.total,
      0,
    );
    const decoded13 = await tls(
      paths["tls13-rfc8446.pcap"],
      paths["tls13-rfc8446.keys"],
    );
    assert.deepEqual(
      decoded13.result.rows
        .filter((row) => row["http.request.method"])
        .map((row) => row["http.request.uri"]),
      ["/first", "/early", "/second"],
    );
    assert.equal((await tls(paths["tls13-rfc8446.pcap"])).result.total, 0);
    report.checks.tls13_early_data_wrong_keys_and_isolation = true;
    const secretText = await readFile(paths["tls13-rfc8446.keys"], "ascii");
    for (const line of secretText.split(/\r?\n/u)) {
      const parts = line.trim().split(/\s+/u);
      if (parts.length === 3 && !line.trim().startsWith("#"))
        assert.equal(
          JSON.stringify(decoded13).includes(parts[2]),
          false,
          "key material leaked into tool result",
        );
    }
    report.checks.no_returned_key_material = true;
    for (const [path, format] of [
      [paths.har, "har"],
      [paths.saz, "saz"],
    ]) {
      const capture = await call("inspect_web_network_capture", {
        capture_path: path,
        format,
      });
      assert.equal(capture.records.length, 1);
      assert.ok(
        capture.records[0].binary_fields.some(
          (field) => field.sha256 === sha(Buffer.from("hello")),
        ),
        JSON.stringify(capture.records[0].binary_fields),
      );
    }
    report.checks.native_har_saz_exact_body = true;
    api = await call("forge_inspect_api_asset", { path: paths.api });
    assert.equal(api.result.endpoint_count, 2);
    const filtered = await call("forge_inspect_api_asset", {
      path: paths.api,
      method: "GET",
      query: "items",
    });
    assert.equal(filtered.result.total, 1);
    const swagger = await call("forge_inspect_api_asset", {
      path: paths.swagger,
    });
    assert.equal(swagger.result.rows[0].has_request_body, true);
    const collection = await call("forge_inspect_api_asset", {
      path: paths.postman,
    });
    assert.equal(collection.result.total, 2);
    const variables = await call("forge_inspect_api_asset", {
      path: paths.env,
      view: "variables",
    });
    assert.equal(
      variables.result.rows[0].value_sha256,
      sha(Buffer.from("PRIVATE_FIXTURE_VARIABLE")),
    );
    assert.equal(
      JSON.stringify(variables).includes("PRIVATE_FIXTURE_VARIABLE"),
      false,
    );
    const diff = await call("forge_compare_api_assets", {
      path: paths.api,
      right_path: paths.api2,
    });
    assert.deepEqual(
      diff.result.rows.map((row) => [row.change, row.identity]),
      [["added", "GET /health"]],
    );
    const exported = await call("forge_export_api_asset", {
      path: paths.api,
      method: "GET",
    });
    const exportedFile = exported.result.artifacts[0];
    const exportedBytes = await readFile(exportedFile.path);
    assert.equal(sha(exportedBytes), exportedFile.sha256);
    assert.equal(JSON.parse(exportedBytes).endpoints.length, 1);
    report.checks.api_all_formats_filters_comparison_export = true;
  }
  await reject("forge_inspect_api_asset", { path: paths.duplicate });
  await reject("forge_inspect_packet_tree", { path: paths.broken });
  await reject("forge_extract_packet_fields", {
    path: paths.pcap,
    fields,
    keylog_path: paths.badKey,
  });
  await reject("forge_read_traffic_result", {
    receipt_path: tree.result.receipt_path,
    receipt_sha256: "0".repeat(64),
  });
  report.checks.negative_inputs = true;
  const timeout = await reject("forge_inspect_packet_tree", {
    path: paths.pcap,
    timeout_ms: 1,
  });
  assert.equal(timeout.error.code, "provider_timeout");
  assert.equal(timeout.error.details.timeout_ms, 1);
  report.checks.actual_native_deadline = true;
  const controller = new AbortController();
  const pending = raw(
    "forge_inspect_packet_tree",
    { path: paths.pcap },
    controller.signal,
  );
  const timer = setTimeout(
    () => controller.abort(new Error("owned G16 request cancellation")),
    150,
  );
  await assert.rejects(pending);
  clearTimeout(timer);
  const recovered = await call("forge_extract_packet_fields", {
    path: paths.pcap,
    fields: ["frame.number"],
    packet_limit: 1,
  });
  assert.equal(recovered.result.rows[0]["frame.number"], "1");
  report.checks.request_cancellation_and_same_family_recovery = true;
  const whole = await call("forge_extract_packet_fields", {
    path: paths.pcap,
    fields: ["frame.number"],
    packet_limit: 0,
  });
  assert.equal(whole.result.total, 5);
  assert.equal(whole.result.coverage, "complete-source-scan");
  report.checks.explicit_whole_file_scan = true;
  // Shared-helper refactor: reuse passed G08 result and exercise only its changed boundary.
  const capaReceipt = process.env.REA_FORGE_TEST_CAPA_RECEIPT;
  assert.ok(capaReceipt);
  const capa = await call("forge_read_enrichment_result", {
    receipt_path: capaReceipt,
    receipt_sha256: sha(await readFile(capaReceipt)),
  });
  assert.ok(capa.result.rows.some((row) => /xor/iu.test(row.name)));
  const capaRecord = JSON.parse(await readFile(capaReceipt, "utf8"));
  const capaTimeout = await reject("forge_analyze_capabilities", {
    path: capaRecord.target.path,
    timeout_ms: 1,
  });
  assert.equal(capaTimeout.error.code, "provider_timeout");
  report.checks.changed_common_helper_g08_readback_deadline = true;
  const cli = await promisify(execFile)(
    process.execPath,
    [
      join(root, "scripts/rea.mjs"),
      "forge-inspect-api-asset",
      JSON.stringify({ path: paths.api }),
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
  assert.deepEqual(
    parseEvidence(JSON.parse(cli.stdout)).normalized_result.result.rows,
    api.result.rows,
  );
  report.checks.cli_mcp_parity = true;
  for (const [path, hash] of originals)
    assert.equal(sha(await readFile(path)), hash);
  report.fixture_hashes = Object.fromEntries(originals);
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
    report.cleanup_failure = "provider temporary root is not empty";
  }
  report.elapsed_seconds = (performance.now() - started) / 1000;
  const receipt = join(local, "evidence", `offline-traffic-${Date.now()}.json`);
  await writeFile(receipt, JSON.stringify(report, null, 2));
  console.log(
    JSON.stringify({
      status: report.status,
      receipt,
      elapsed_seconds: report.elapsed_seconds,
      checks: report.checks,
      provider_temp_empty: report.provider_temp_empty,
    }),
  );
  if (report.status !== "passed") process.exitCode = 1;
}
