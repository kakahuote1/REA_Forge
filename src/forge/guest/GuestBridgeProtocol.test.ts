import { createServer, type Server, type RequestListener } from "node:http";
import { afterEach, expect, it, vi } from "vitest";
import { requestGuestJson } from "./GuestBridgeProtocol.js";

const servers: Server[] = [];
afterEach(async () => {
  vi.useRealTimers();
  await Promise.all(
    servers.splice(0).map(async (server) => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }),
  );
});
const serve = async (handler: RequestListener) => {
  const server = createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string")
    throw new Error("No fixture port");
  return { server, url: new URL(`http://127.0.0.1:${address.port}/health`) };
};

it("uses one explicit authenticated request and waits for complete JSON", async () => {
  const fixture = await serve((request, response) => {
    expect(request.headers["x-codex-bridge-token"]).toBe("test-secret");
    expect(request.url).toBe("/health");
    expect(request.method).toBe("GET");
    response.end('{"ok":true}');
  });
  expect(await requestGuestJson(fixture.url, "test-secret")).toEqual({
    ok: true,
  });
});

it.each([302, 401, 500])(
  "does not follow redirects or echo refusal bodies (%s)",
  async (status) => {
    let requests = 0;
    const fixture = await serve((_request, response) => {
      requests += 1;
      response.writeHead(status, { location: "/unselected" });
      response.end("sensitive remote text");
    });
    await expect(requestGuestJson(fixture.url, "test-secret")).rejects.toThrow(
      "request was refused",
    );
    expect(requests).toBe(1);
  },
);

it("bounds raw response bytes before JSON parsing", async () => {
  const fixture = await serve((_request, response) =>
    response.end("x".repeat(65537)),
  );
  await expect(requestGuestJson(fixture.url, "test-secret")).rejects.toThrow(
    "64 KiB",
  );
});

it("cancels its own incomplete request without shutting down the borrowed bridge", async () => {
  let markStarted!: () => void;
  const started = new Promise<void>((resolve) => {
    markStarted = resolve;
  });
  const fixture = await serve((_request, response) => {
    response.writeHead(200);
    response.write("{");
    markStarted();
  });
  const controller = new AbortController();
  const pending = requestGuestJson(
    fixture.url,
    "test-secret",
    controller.signal,
  );
  const rejected = expect(pending).rejects.toMatchObject({
    _tag: "AnalysisCancelledError",
  });
  await started;
  controller.abort("caller stopped");
  await rejected;
  expect(fixture.server.listening).toBe(true);
});

it("uses an absolute deadline even when response bytes keep arriving", async () => {
  let markStarted!: () => void;
  const started = new Promise<void>((resolve) => {
    markStarted = resolve;
  });
  const fixture = await serve((_request, response) => {
    response.writeHead(200);
    response.write("{");
    markStarted();
  });
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  const pending = requestGuestJson(fixture.url, "test-secret");
  const rejected = expect(pending).rejects.toThrow("absolute deadline");
  await started;
  await vi.advanceTimersByTimeAsync(5001);
  await rejected;
  expect(fixture.server.listening).toBe(true);
});
