import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import {
  FORGE_LOCAL_ENTRYPOINT,
  bindForgeLocalSkill,
} from "../../../src/application/ForgeLocalLaunch.js";
import {
  MANAGED_SKILL_FILES,
  canonicalSkillNeedsInstall,
  installCanonicalSkill,
  skillDestinations,
} from "../../../src/application/SetupSkill.js";
import { readClientRegistrationStatuses } from "../../../src/application/ClientRegistrationStatus.js";
import { PRODUCT_IDENTITY } from "../../../src/identity.js";

it("installs every generated reference, binds the launcher, and detects binding drift", async () => {
  const home = await createTestTempDirectory("rea-forge-local-skill-");
  const [destination] = skillDestinations(home, []);
  if (!destination) throw new Error("Missing test skill destination");
  expect(await installCanonicalSkill(home, [])).toEqual({
    ok: true,
    value: "installed",
  });
  const packaged = new URL(
    "../../../skills/reverse-engineer-anything/",
    import.meta.url,
  );
  const generatedFiles = (
    await readdir(packaged, { recursive: true, withFileTypes: true })
  )
    .filter((entry) => entry.isFile())
    .map((entry) =>
      relative(
        fileURLToPath(packaged),
        join(entry.parentPath, entry.name),
      ).replaceAll("\\", "/"),
    );
  expect(generatedFiles.sort()).toEqual([...MANAGED_SKILL_FILES].sort());
  for (const path of MANAGED_SKILL_FILES) {
    const template = await readFile(new URL(path, packaged), "utf8");
    const installed = await readFile(join(destination.path, path), "utf8");
    expect(installed).toBe(bindForgeLocalSkill(template));
    expect(installed).not.toMatch(/\b(?:npx\s+(?:-y\s+)?|bunx\s+)rea-agents/u);
  }
  expect(await canonicalSkillNeedsInstall(home, [])).toBe(false);
  expect(await installCanonicalSkill(home, [])).toEqual({
    ok: true,
    value: "unchanged",
  });
  const binding = join(destination.path, "references/forge-local.md");
  const original = await readFile(binding, "utf8");
  expect(original).toContain(FORGE_LOCAL_ENTRYPOINT.replaceAll("\\", "\\\\"));
  await writeFile(binding, `${original}\nchanged launcher\n`);
  expect(await canonicalSkillNeedsInstall(home, [])).toBe(true);
  expect(await installCanonicalSkill(home, [])).toEqual({
    ok: true,
    value: "installed",
  });
  expect(await readFile(binding, "utf8")).toBe(original);
  expect(await readFile(`${binding}.rea.backup`, "utf8")).toContain(
    "changed launcher",
  );
});

it("requires a local registration in Forge doctor, even if an upstream npm version matches", async () => {
  const home = await createTestTempDirectory("rea-forge-registration-");
  const configuration = join(home, "claude.json");
  const environment = {
    CLAUDE_CONFIG_DIR: join(home, "claude"),
    HOME: home,
    USERPROFILE: home,
  };
  await mkdir(environment.CLAUDE_CONFIG_DIR);
  const configPath = join(environment.CLAUDE_CONFIG_DIR, ".claude.json");
  await writeFile(configuration, "unrelated config\n");
  await writeFile(
    configPath,
    JSON.stringify({
      mcpServers: {
        rea: {
          command: "npx",
          args: ["-y", PRODUCT_IDENTITY.registrationPackageSpecifier, "mcp"],
        },
      },
    }),
  );
  const inspect = () =>
    readClientRegistrationStatuses(home, FORGE_LOCAL_ENTRYPOINT, {
      environment,
      requireLocalEntrypoint: true,
    });
  expect(await inspect()).toContainEqual(
    expect.objectContaining({ client: "claude_code", state: "stale" }),
  );
  await writeFile(
    configPath,
    JSON.stringify({
      mcpServers: {
        rea: {
          command: process.execPath,
          args: [FORGE_LOCAL_ENTRYPOINT, "mcp"],
        },
      },
    }),
  );
  expect(await inspect()).toContainEqual(
    expect.objectContaining({ client: "claude_code", state: "aligned" }),
  );
  expect(await readFile(configuration, "utf8")).toBe("unrelated config\n");
});
