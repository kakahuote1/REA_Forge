/** A fixed client of official Yak MCP, not an MCP proxy or a generic tool router. */
import { readFile, writeFile } from "node:fs/promises";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

const specification = JSON.parse(await readFile(process.argv[2], "utf8"));
if (!["http_fuzzer", "query_http_flow"].includes(specification.tool)) throw new Error("unknown fixed Yak operation");
const client = new Client({ name: "REA-Forge-Yakit", version: "1" });
const env = Object.fromEntries(Object.entries({ SystemRoot: process.env.SystemRoot, PATH: process.env.PATH, USERPROFILE: specification.home, YAKIT_HOME: specification.home, TEMP: specification.temporary, TMP: specification.temporary, NO_PROXY: "*", no_proxy: "*" }).filter(([, value]) => typeof value === "string"));
const transport = new StdioClientTransport({ command: specification.engine, args: ["mcp", "--transport", "stdio", "-t", "httpflow,http_fuzzer"], env, stderr: "pipe" });
let diagnostics = "", result;
try {
  transport.stderr?.on("data", chunk => { diagnostics = (diagnostics + chunk.toString()).slice(-16384); });
  await client.connect(transport, { timeout: 10000 });
  const catalog = await client.listTools({}, { timeout: 10000 });
  const tool = catalog.tools.find(item => item.name === specification.tool);
  if (!tool) throw new Error("required official Yak operation is absent");
  for (const name of Object.keys(specification.arguments))
    if (!Object.hasOwn(tool.inputSchema.properties ?? {}, name)) throw new Error("official Yak schema does not advertise fixed argument: " + name);
  const upstream = await client.callTool({ name: specification.tool, arguments: specification.arguments }, { timeout: 20000 });
  if (upstream.isError) throw new Error("official Yak operation returned an error; no request is retried");
  if (JSON.stringify(upstream).length > 4 * 1024 * 1024) throw new Error("official Yak result exceeds4MiB");
  const values = upstream.content.map(item => {
    if (item.type !== "text") throw new Error("unexpected official Yak content kind");
    try { return JSON.parse(item.text); } catch { throw new Error("official Yak returned non-JSON result text; completed request outcome remains unknown"); }
  });
  const data = values.flatMap(value => Array.isArray(value) ? value : [value]);
  if (data.length > 100) throw new Error("official Yak result exceeds selected row bound");
  if (specification.tool === "http_fuzzer" && (data.length !== 1 || typeof data[0]?.request !== "string" || typeof data[0]?.response !== "string")) throw new Error("official Yak did not report exactly one request/response; no retry is performed");
  result = { ok: true, server: client.getServerVersion(), tool: specification.tool, data, upstream };
} catch (cause) { result = { ok: false, error: String(cause), diagnostics }; process.exitCode = 1; }
finally {
  try { await client.close(); result.transport_closed = true; }
  catch (cause) { result = { ok: false, error: "Yak transport cleanup failed: " + String(cause), diagnostics }; process.exitCode = 1; }
}
await writeFile(specification.output, JSON.stringify(result));
