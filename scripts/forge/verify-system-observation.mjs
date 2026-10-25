/** One real G17 group against this verifier's own trusted process only. */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile, spawn } from "node:child_process";
import { once } from "node:events";
import { promisify } from "node:util";
import { mkdtemp, readFile, readdir, rmdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../../dist/domain/evidence.js";
import { FORGE_SYSTEM_OPERATIONS } from "../../dist/domain/forge/systemObservation.js";

const root = fileURLToPath(new URL("../../", import.meta.url)),
  local = join(root, ".forge-local");
const sha = (data) => createHash("sha256").update(data).digest("hex");
const priorPath = process.env.REA_FORGE_SYSTEM_RESUME;
const prior = priorPath
  ? JSON.parse(await readFile(priorPath, "utf8"))
  : undefined;
const fixtures =
  prior?.fixtures ??
  (await mkdtemp(join(local, "fixtures/system-observation-")));
const temporary = await mkdtemp(join(local, "tmp/system-provider-"));
const configuration = JSON.parse(
  await readFile(process.env.REA_FORGE_STATIC_CONFIG, "utf8"),
);
const configPath = join(fixtures, "acceptance-tools.json");
await writeFile(configPath, JSON.stringify(configuration));
const report = {
  status: "running",
  scope:
    "G17 phlib read-only observations and fixed no-dump HH/PE-sieve; only source-owned verifier process scanned",
  fixtures,
  checks: { ...prior?.checks },
  values: { ...prior?.values },
  process_target_execution: "trusted test harness only; no sample launch",
  network_io: false,
  gui_started: false,
  cpu_time: "unmeasured",
  peak_process_family_memory: "unmeasured",
};
if (prior)
  report.reused_receipt = {
    path: priorPath,
    sha256: sha(await readFile(priorPath)),
  };
report.engine_configuration_sha256 = sha(
  JSON.stringify([
    configuration.system_informer,
    configuration.hollows_hunter,
    configuration.system_results,
  ]),
);
if (prior)
  assert.equal(
    prior.engine_configuration_sha256,
    report.engine_configuration_sha256,
  );
async function verifyRetained(value) {
  const reference = value?.result;
  if (!reference?.receipt_path) {
    if (value && typeof value === "object")
      for (const nested of Object.values(value)) await verifyRetained(nested);
    return;
  }
  assert.equal(
    sha(await readFile(reference.receipt_path)),
    reference.receipt_sha256,
  );
  assert.equal(
    sha(await readFile(reference.snapshot.path)),
    reference.snapshot.sha256,
  );
  const full = JSON.parse(await readFile(reference.snapshot.path, "utf8"));
  for (const file of full.artifacts)
    assert.equal(sha(await readFile(file.path)), file.sha256);
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
const entry = join(root, "scripts/rea.mjs"),
  started = performance.now();
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entry, "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({
  name: "forge-system-observation-acceptance",
  version: "1",
});
let diagnostics = "";
const reference = (value) => ({
  receipt_path: value.result.receipt_path,
  receipt_sha256: value.result.receipt_sha256,
});
const checkpoint = () =>
  writeFile(
    join(local, "evidence/system-observation-current.json"),
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
  for (const name of FORGE_SYSTEM_OPERATIONS) assert.ok(tools.has(name));
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
  // A new verifier invocation has a new creation identity. Never revive prior live targets.
  const current = await call("forge_inspect_system", {
    kind: "processes",
    pid: process.pid,
  });
  const target = current.result.metadata.target_process;
  assert.equal(target.pid, process.pid);
  assert.equal(typeof target.created_100ns, "string");
  assert.ok(BigInt(target.created_100ns) > 9007199254740991n);
  assert.equal(
    current.result.rows[0].value.created_100ns,
    target.created_100ns,
  );
  report.current_target = target;
  report.source_hashes = {};
  for (const path of [
    "bridge/forge/common/process_identity.py",
    "bridge/forge/system/observations.py",
    "bridge/forge/system/worker.py",
    "dist/domain/forge/systemObservation.js",
    "dist/forge/system/SystemObservationAdapter.js",
  ])
    report.source_hashes[path] = sha(await readFile(join(root, path)));
  report.checks.exact_query_handle_and_creation_identity = true;
  await checkpoint();
  for (const kind of [
    "threads",
    "thread_metadata",
    "modules",
    "handles",
    "regions",
    "details",
    "connections",
  ]) {
    await step(
      `observe_${kind}`,
      () =>
        call("forge_observe_process", {
          pid: target.pid,
          created_100ns: target.created_100ns,
          kind,
        }),
      (value) => {
        assert.equal(
          value.result.metadata.target_process.created_100ns,
          prior?.values?.[`observe_${kind}`]?.result?.metadata.target_process
            .created_100ns ?? target.created_100ns,
        );
        assert.equal(value.result.metadata.identity_checked_before_after, true);
        if (kind !== "connections") assert.ok(value.result.total > 0);
        if (kind === "thread_metadata")
          assert.ok(
            value.result.rows.every(
              (row) => typeof row.value.created_100ns === "string",
            ),
          );
        if (kind === "connections")
          assert.match(value.result.metadata.producer.backend, /IPHelper/);
      },
    );
  }
  for (const kind of ["services", "drivers", "kernel_modules"]) {
    await step(
      `system_${kind}`,
      () => call("forge_inspect_system", { kind }),
      (value) => {
        assert.equal(value.result.metadata.kind, kind);
        assert.equal(value.result.metadata.target_process, null);
        assert.ok(value.result.total > 0);
      },
    );
  }
  await step(
    "global_process_inventory",
    () =>
      call("forge_inspect_system", {
        kind: "processes",
        query: String(target.pid),
        limit: 100,
      }),
    (value) => {
      const observed = prior?.values?.global_process_inventory
        ? prior.current_target
        : target;
      assert.equal(value.result.metadata.target_process, null);
      assert.ok(
        value.result.rows.some(
          (row) =>
            row.value.pid === observed.pid &&
            row.value.created_100ns === observed.created_100ns,
        ),
      );
    },
  );
  const scan = await step(
    "hollows_one_owned_pid",
    () =>
      call("forge_scan_process", {
        pid: target.pid,
        created_100ns: target.created_100ns,
      }),
    (value) => {
      assert.equal(value.result.metadata.summary.scanned_count, 1);
      assert.equal(value.result.metadata.no_dump_filter, 2);
      assert.equal(value.result.metadata.identity_checked_before_after, true);
      assert.ok(
        value.result.metadata.artifacts.every((file) =>
          /\.(?:json|txt|log|out|stderr)$/i.test(file.path),
        ),
      );
    },
  );
  const threads = report.values.observe_thread_metadata;
  await step(
    "retained_paging",
    () => call("forge_read_system_result", { ...reference(threads), limit: 1 }),
    (value) => {
      assert.equal(value.result.historical_readback, true);
      assert.equal(value.result.rows.length, 1);
      assert.equal(
        value.result.rows[0].value.created_100ns,
        threads.result.rows[0].value.created_100ns,
      );
    },
  );
  await step(
    "self_snapshot_difference",
    () =>
      call("forge_compare_process_snapshots", {
        before: reference(threads),
        after: reference(threads),
      }),
    (value) => assert.equal(value.result.total, 0),
  );
  await step("actual_region_change", async () => {
    const args = {
      pid: target.pid,
      created_100ns: target.created_100ns,
      kind: "regions",
    };
    const before = await call("forge_observe_process", args);
    const allocation = Buffer.alloc(32 * 1024 * 1024, 0x5a);
    const after = await call("forge_observe_process", args);
    const difference = await call("forge_compare_process_snapshots", {
      before: reference(before),
      after: reference(after),
    });
    assert.equal(allocation[allocation.length - 1], 0x5a);
    assert.ok(
      difference.result.total > 0,
      "a real owned allocation must change observed region metadata",
    );
    return { before, after, difference, allocated_bytes: allocation.length };
  });
  await step("exited_owned_target_refused", async () => {
    const child = spawn(
      process.execPath,
      ["--input-type=module", "-e", "setTimeout(() => {}, 20000)"],
      { windowsHide: true, stdio: "ignore" },
    );
    let identity;
    try {
      await once(child, "spawn");
      const observed = await call("forge_inspect_system", { pid: child.pid });
      identity = observed.result.metadata.target_process;
    } finally {
      const exited = once(child, "exit");
      child.kill(); // ChildProcess retains this owned process handle; no borrowed PID signalling.
      await exited;
    }
    return await reject("forge_observe_process", {
      pid: identity.pid,
      created_100ns: identity.created_100ns,
      kind: "modules",
    });
  });
  await step("cross_kind_and_bad_receipt_refused", async () => ({
    mismatch: await reject("forge_compare_process_snapshots", {
      before: reference(threads),
      after: reference(scan),
    }),
    hash: await reject("forge_read_system_result", {
      ...reference(threads),
      receipt_sha256: "0".repeat(64),
    }),
  }));
  await step(
    "stale_process_identity_refused",
    () =>
      reject("forge_observe_process", {
        pid: target.pid,
        created_100ns: String(BigInt(target.created_100ns) + 1n),
        kind: "modules",
      }),
    (value) => assert.match(JSON.stringify(value), /identity|creation/i),
  );
  await step(
    "actual_si_deadline",
    () =>
      reject("forge_observe_process", {
        pid: target.pid,
        created_100ns: target.created_100ns,
        kind: "modules",
        timeout_ms: 1,
      }),
    (value) => assert.match(JSON.stringify(value), /timeout|deadline/i),
  );
  await step(
    "actual_scanner_deadline",
    () =>
      reject("forge_scan_process", {
        pid: target.pid,
        created_100ns: target.created_100ns,
        timeout_ms: 1,
      }),
    (value) => assert.match(JSON.stringify(value), /timeout|deadline/i),
  );
  await step("cancel_and_recover", async () => {
    const stop = new AbortController();
    const pending = raw(
      "forge_scan_process",
      { pid: target.pid, created_100ns: target.created_100ns },
      stop.signal,
    );
    const timer = setTimeout(() => stop.abort("source-owned test cancel"), 75);
    try {
      await assert.rejects(pending);
    } finally {
      clearTimeout(timer);
    }
    const result = await call("forge_inspect_system", { pid: target.pid });
    assert.equal(
      result.result.metadata.target_process.created_100ns,
      target.created_100ns,
    );
    return { recovered: true };
  });
  await step("missing_scanner_isolation", async () => {
    const selected = structuredClone(configuration);
    delete selected.hollows_hunter;
    await writeFile(configPath, JSON.stringify(selected));
    try {
      const failure = await reject("forge_scan_process", {
        pid: target.pid,
        created_100ns: target.created_100ns,
      });
      const kept = await call("forge_read_system_result", reference(threads));
      assert.equal(kept.result.metadata.kind, "thread_metadata");
      return { failure, readback_available: true };
    } finally {
      await writeFile(configPath, JSON.stringify(configuration));
    }
  });
  await step(
    "cli_historical_parity",
    async () => {
      const { stdout } = await promisify(execFile)(
        process.execPath,
        [
          entry,
          "forge-read-system-result",
          JSON.stringify(reference(threads)),
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
      return parseEvidence(JSON.parse(stdout)).normalized_result;
    },
    (value) => assert.deepEqual(value.result.rows, threads.result.rows),
  );
  for (const value of Object.values(report.values)) await verifyRetained(value);
  const final = await call("forge_inspect_system", { pid: process.pid });
  assert.equal(
    final.result.metadata.target_process.created_100ns,
    target.created_100ns,
  );
  report.checks.borrowed_target_preserved = true;
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
  const receipt = join(
    local,
    "evidence",
    `system-observation-${Date.now()}.json`,
  );
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
