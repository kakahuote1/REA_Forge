import { request as httpRequest } from "node:http";
import { AnalysisCancelledError } from "../../domain/analysisErrorCore.js";

/** Internal protocol transport, not a public remote-shell capability. */
export const requestGuestJson = (
  url: URL,
  token: string,
  signal?: AbortSignal,
  payload?: Readonly<Record<string, unknown>>,
  limits?: { readonly timeoutMs: number; readonly responseBytes: number },
): Promise<unknown> =>
  new Promise((resolve, reject) => {
    const body =
      payload === undefined ? undefined : Buffer.from(JSON.stringify(payload));
    if (body !== undefined && body.length > 64 * 1024) {
      reject(new Error("Guest metadata request exceeds its payload bound"));
      return;
    }
    let result: unknown;
    let failure: Error | undefined;
    let complete = false;
    const request = httpRequest(url, {
      method: body === undefined ? "GET" : "POST",
      agent: false,
      headers: {
        "x-codex-bridge-token": token,
        ...(body === undefined
          ? {}
          : {
              "content-type": "application/json",
              "content-length": body.length,
            }),
      },
    });
    const stop = (error: Error) => {
      failure ??= error;
      request.destroy(error);
    };
    const abort = () =>
      stop(
        new AnalysisCancelledError("inspect_guest_runtime", {
          cause: signal?.reason,
        }),
      );
    // Existing /run owns its selected child deadline and bounded cleanup.
    // A socket timeout alone is not evidence of remote child settlement.
    const timer = setTimeout(
      () =>
        stop(
          new Error("Guest metadata request exceeded its absolute deadline"),
        ),
      limits?.timeoutMs ?? (body === undefined ? 5000 : 25000),
    );
    signal?.addEventListener("abort", abort, { once: true });
    request.on("response", (response) => {
      const chunks: Buffer[] = [];
      let bytes = 0;
      response.on("data", (chunk: Buffer) => {
        bytes += chunk.length;
        if (bytes > (limits?.responseBytes ?? 64 * 1024)) {
          stop(new Error(limits === undefined ? "Guest metadata response exceeds 64 KiB" : "Guest response exceeds its explicit byte budget"));
          response.destroy();
        } else chunks.push(chunk);
      });
      response.on("error", () => {
        failure ??= new Error("Guest metadata response did not complete");
      });
      response.on("end", () => {
        if (failure !== undefined) return;
        if (response.statusCode !== 200) {
          failure = new Error(
            "Authenticated guest metadata request was refused",
          );
          return;
        }
        try {
          result = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          complete = true;
        } catch {
          failure = new Error("Guest metadata response is not JSON");
        }
      });
    });
    request.on("error", () => {
      failure ??= new Error("Authenticated guest bridge is unavailable");
    });
    request.once("close", () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      if (failure !== undefined || !complete)
        reject(
          failure ?? new Error("Guest metadata response did not complete"),
        );
      else resolve(result);
    });
    if (signal?.aborted) abort();
    else request.end(body);
  });
