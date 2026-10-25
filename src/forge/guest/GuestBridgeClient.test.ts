import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import {
  GuestBridgeClient,
  guestBridgeConfigurationSchema,
} from "./GuestBridgeClient.js";
import { requestGuestJson } from "./GuestBridgeProtocol.js";
import { GUEST_METADATA_PROBE } from "./guestMetadataProbe.js";

vi.mock("./GuestBridgeProtocol.js", () => ({ requestGuestJson: vi.fn() }));
const owned: string[] = [];
afterEach(async () => {
  vi.resetAllMocks();
  await Promise.all(
    owned.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});
const configuration = {
  id: "test-win10",
  vmx_path: "C:/test/selected.vmx",
  base_url: "http://192.168.2.130:8765/",
  token_file: "C:/test/secret",
  expected_computer_name: "test-guest",
};
const health = { ok: true, version: "2.0.0", computerName: "test-guest" };
const metadata = {
  computerName: "test-guest",
  bridgeProcessId: 73,
  bridgeProcessStartTicks: "638000000000000001",
};
const run = {
  ok: true,
  exitCode: 0,
  timedOut: false,
  stdout: JSON.stringify(metadata),
  stderr: "",
};
const client = async () => {
  const root = await mkdtemp(join(tmpdir(), "forge-guest-client-"));
  owned.push(root);
  const token_file = join(root, "token");
  await writeFile(token_file, "test-auth-material");
  return new GuestBridgeClient({ ...configuration, token_file });
};

it.each([
  "https://192.168.2.130:8765/",
  "http://example.com:8765/",
  "http://192.168.2.130:8765/?redirect=1",
  "http://user:pass@192.168.2.130:8765/",
])("rejects discovery, redirects and ambient URLs: %s", (base_url) => {
  expect(
    guestBridgeConfigurationSchema.safeParse({ ...configuration, base_url })
      .success,
  ).toBe(false);
});

it("enriches old health using only the reviewed constant probe and keeps exact ticks", async () => {
  const selected = await client();
  vi.mocked(requestGuestJson)
    .mockResolvedValueOnce(health)
    .mockResolvedValueOnce(run);
  const result = await selected.inspect();
  expect(result).toMatchObject(metadata);
  expect(result.bridgeInstanceId).toMatch(/^[a-f0-9]{32}$/u);
  expect(vi.mocked(requestGuestJson).mock.calls[1]?.[3]).toEqual({
    shell: "powershell",
    command: GUEST_METADATA_PROBE,
    timeoutMs: 5000,
    maxOutputBytes: 8192,
  });
  await selected.close();
});

it.each([
  [{ ...health, computerName: "wrong-guest" }, "machine identity"],
  [{ ...health, version: "unknown" }, "protocol version"],
] as const)(
  "refuses unmatched guests or protocols before running a probe",
  async (value, message) => {
    const selected = await client();
    vi.mocked(requestGuestJson).mockResolvedValueOnce(value);
    await expect(selected.inspect()).rejects.toThrow(message);
    expect(requestGuestJson).toHaveBeenCalledTimes(1);
    await selected.close();
  },
);

it.each([
  {
    ...run,
    ok: false,
    stdout: "private remote data",
    stderr: "test-auth-material",
  },
  { ...run, stdout: "invalid private data" },
  {
    ...run,
    stdout: JSON.stringify({ ...metadata, computerName: "changed-guest" }),
  },
])(
  "refuses failed or malformed metadata without reflecting remote output",
  async (value) => {
    const selected = await client();
    vi.mocked(requestGuestJson)
      .mockResolvedValueOnce(health)
      .mockResolvedValueOnce(value);
    const failure = await selected.inspect().catch((cause: unknown) => cause);
    expect(failure).toBeInstanceOf(Error);
    expect(String(failure)).not.toMatch(/private|test-auth-material/u);
    await selected.close();
  },
);

it("close during health drains its socket but does not admit a new metadata child", async () => {
  const selected = await client();
  let finish!: (value: unknown) => void;
  let markStarted!: () => void;
  const started = new Promise<void>((resolve) => {
    markStarted = resolve;
  });
  vi.mocked(requestGuestJson).mockImplementationOnce(() => {
    markStarted();
    return new Promise((resolve) => {
      finish = resolve;
    });
  });
  const pending = selected.inspect();
  await started;
  const closed = selected.close();
  finish(health);
  await expect(pending).rejects.toThrow("owner is closed");
  await closed;
  expect(requestGuestJson).toHaveBeenCalledTimes(1);
});
