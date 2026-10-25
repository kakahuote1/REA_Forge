import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { expect, it } from "vitest";
import { z } from "zod";
import { EvidenceMcpServerCore } from "./EvidenceMcpServerCore.js";
import { DeferredEvidenceMcpServer } from "./DeferredEvidenceMcpServer.js";
import { ToolResultDelivery } from "./ToolResultDelivery.js";
import { TOOL_CONTRACTS } from "../contracts/toolContracts.js";
import { hostExecutionRefusal } from "../application/ExecutionDomainAdmission.js";
import type { RecordedMcpCatalog } from "../recordedMcpCatalog.js";
import { parseMcpToolError } from "../../tests/fixtures/mcpToolError.js";

it("refuses every hazardous canonical operation before its handler and still permits cleanup and static reads", async () => {
  const server = new EvidenceMcpServerCore(
    { name: "host-admission", version: "1" },
    {},
    undefined,
    new ToolResultDelivery(1024 * 1024),
  );
  const blocked = TOOL_CONTRACTS.filter(
    ({ name }) => hostExecutionRefusal(name) !== undefined,
  );
  expect(blocked.length).toBeGreaterThan(15);
  let targetCalls = 0;
  let cleanupCalls = 0;
  let reads = 0;
  for (const contract of blocked)
    server.registerTool(
      contract.name,
      { inputSchema: contract.inputSchema },
      () => {
        targetCalls++;
        return { content: [] };
      },
    );
  server.registerTool("close_gdb_session", {}, () => {
    cleanupCalls++;
    return { content: [] };
  });
  server.registerTool(
    "inspect_python_pyc",
    { inputSchema: z.object({}) },
    () => {
      reads++;
      return { content: [] };
    },
  );
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "host-admission-test", version: "1" });
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    for (const contract of blocked) {
      const input = contract.examples[0]?.input;
      if (input === undefined)
        throw new Error(`Missing acceptance input: ${contract.name}`);
      const result = await client.callTool({
        name: contract.name,
        arguments: input,
      });
      expect(result.isError, contract.name).toBe(true);
      expect(parseMcpToolError(result).error, contract.name).toMatchObject({
        code: "capability_unavailable",
        details: { provider_id: "forge-host-static" },
      });
    }
    expect(targetCalls).toBe(0);
    expect(
      (await client.callTool({ name: "close_gdb_session" })).isError,
    ).not.toBe(true);
    expect(
      (await client.callTool({ name: "inspect_python_pyc", arguments: {} }))
        .isError,
    ).not.toBe(true);
    expect(cleanupCalls).toBe(1);
    expect(reads).toBe(1);
  } finally {
    await client.close();
    await server.close();
  }
});

it("keeps the same refusal after lazy materialization and on repeated calls", async () => {
  const schema = z.strictObject({});
  const catalog: RecordedMcpCatalog = {
    version: 1,
    info: { name: "deferred-host", version: "1" },
    capabilities: {},
    instructions: "Fixture",
    identity: {
      counts: { cli_commands: 0, mcp_tools: 1, mcp_prompts: 0 },
      digests: {
        tools_sha256: "fixture",
        prompts_sha256: "fixture",
        combined_sha256: "fixture",
      },
    },
    tools: [
      {
        name: "cutter_command",
        inputSchema: {
          type: "object",
          properties: {},
          additionalProperties: false,
        },
      },
    ],
    prompts: [],
  };
  let loads = 0;
  let calls = 0;
  let closed = 0;
  const server = new DeferredEvidenceMcpServer(
    catalog,
    new ToolResultDelivery(1024 * 1024),
    async (target) => {
      loads++;
      target.ownRuntimeCleanup(async () => {
        closed++;
        await target.closePartialRuntime();
      });
      target.materialize(() =>
        target.registerTool("cutter_command", { inputSchema: schema }, () => {
          calls++;
          return { content: [] };
        }),
      );
    },
  );
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "deferred-host-test", version: "1" });
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    for (let attempt = 0; attempt < 2; attempt++) {
      const result = await client.callTool({
        name: "cutter_command",
        arguments: {},
      });
      expect(result.isError).toBe(true);
      expect(JSON.stringify(result)).toContain("forge-host-static");
    }
    expect(loads).toBe(1);
    expect(calls).toBe(0);
  } finally {
    await client.close();
    await server.close();
  }
  expect(closed).toBe(1);
});
