import { access } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { cliTest } from "../../support/cli/cliFixture.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

cliTest(
  "the public CLI refuses raw host execution aliases before reading targets or starting an engine",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-host-boundary-");
    const marker = join(root, "must-not-exist");
    const cases = [
      ["execute-rizin-command", join(root, "absent-target.exe"), "i"],
      ["debug-with-gdb", "show version", "--inferior-tty", marker],
      [
        "instrument-with-frida",
        "spawn",
        marker,
        "--script",
        "send('fixture')",
        "--duration-ms",
        "0",
      ],
      ["start-adb-app", "--help"],
    ];
    for (const arguments_ of cases.slice(0, 3)) {
      const result = await cli.run({
        arguments: [...arguments_, "--json"],
        cwd: root,
        environment: {
          REA_LOG_LEVEL: "silent",
          REA_EXECUTION_DOMAIN: "guest",
          REA_FORGE_GUEST_APPROVED: "true",
        },
        timeoutMs: 15_000,
      });
      expect(result.exitCode).toBe(1);
      expect(result.json).toMatchObject({
        code: "capability_unavailable",
        details: { provider_id: "forge-host-static" },
      });
    }
    await expect(access(marker)).rejects.toMatchObject({ code: "ENOENT" });
    const help = await cli.run({
      arguments: cases[3]!,
      cwd: root,
      timeoutMs: 15_000,
    });
    expect(help.exitCode).toBe(0);
  },
);
