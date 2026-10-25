import { describe, expect, it } from "vitest";
import { isAbsolute } from "node:path";
import {
  bindForgeLocalSkill,
  FORGE_LOCAL_ENTRYPOINT,
  forgeLocalCommand,
} from "./ForgeLocalLaunch.js";
import { systemSetupHost } from "./SetupHost.js";
import { createDoctorHostFixture } from "./Doctor.fixture.js";

describe("Forge local distribution", () => {
  it("keeps the public local launcher even under a package runner", async () => {
    expect(isAbsolute(FORGE_LOCAL_ENTRYPOINT)).toBe(true);
    expect(FORGE_LOCAL_ENTRYPOINT.replaceAll("\\", "/")).toMatch(
      /\/scripts\/rea\.mjs$/u,
    );
    expect(forgeLocalCommand(["mcp"])).toEqual([
      process.execPath,
      FORGE_LOCAL_ENTRYPOINT,
      "mcp",
    ]);
    for (const platform of ["win32", "linux", "darwin"] as const)
      for (const runner of [undefined, "npx", "bunx"] as const) {
        const host = systemSetupHost(createDoctorHostFixture({ platform }), {
          npm_command: runner === undefined ? "run" : "exec",
          npm_config_user_agent: runner === "bunx" ? "bun/1.4" : "npm/11",
        });
        try {
          expect(host.registrationCommand).toEqual(forgeLocalCommand(["mcp"]));
        } finally {
          await host.close?.();
        }
      }
  });

  it("binds only launcher placeholders, leaving portable text unchanged", () => {
    const portable = "instructions\n";
    expect(bindForgeLocalSkill(portable)).toBe(portable);
    const bound = bindForgeLocalSkill(
      "{{REA_FORGE_ARGV_PREFIX}}\n{{REA_FORGE_POWERSHELL_PREFIX}}\n{{REA_FORGE_POSIX_PREFIX}}",
    );
    expect(bound).not.toContain("{{REA_FORGE_");
    expect(JSON.parse(bound.split("\n")[0]!)).toEqual(forgeLocalCommand());
    expect(bound).not.toContain("npx");
    expect(bound).toContain("& '");
  });
});
