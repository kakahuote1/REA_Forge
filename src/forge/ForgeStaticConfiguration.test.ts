import { afterEach, describe, expect, it } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import {
  inspectForgeStaticConfiguration,
  readForgeStaticConfiguration,
} from "./ForgeStaticConfiguration.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";

const roots: string[] = [];
const owners: ArtifactResourceScope[] = [];
afterEach(async () => {
  await Promise.all(owners.splice(0).map((owner) => owner.close()));
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});
const owner = () => {
  const resources = new ArtifactResourceScope();
  owners.push(resources);
  return resources;
};
const fixture = async () => {
  const parent = join(process.cwd(), ".forge-local/tmp");
  await mkdir(parent, { recursive: true });
  const root = await mkdtemp(join(parent, "native-config-"));
  roots.push(root);
  const data = join(root, "data");
  const inputs = join(root, "inputs");
  await Promise.all([mkdir(data), mkdir(inputs)]);
  const python = join(root, "python-not-executed.exe");
  const editor = join(root, "editor-not-executed.exe");
  await Promise.all([
    writeFile(python, "must not run"),
    writeFile(editor, "must not run"),
  ]);
  const document = {
    python_executable: python,
    editor010: {
      executable: editor,
      executable_sha256: "a".repeat(64),
      input_roots: [inputs],
      asset_roots: [inputs],
    },
  };
  const configurationPath = join(root, "explicit-operator.json");
  await writeFile(configurationPath, JSON.stringify(document));
  return {
    root,
    data,
    inputs,
    python,
    editor,
    document,
    configurationPath,
    environment: {
      REA_FORGE_STATIC_CONFIG: configurationPath,
      REA_FORGE_DATA_ROOT: data,
    },
  };
};

describe("explicit Forge static configuration", () => {
  it("has no implicit checkout or ambient configuration fallback", async () => {
    expect(
      await inspectForgeStaticConfiguration("editor010", {}, owner()),
    ).toMatchObject({
      status: "unavailable",
      code: "not_configured",
    });
  });
  it("accepts explicit paths outside package resource locations without launching engines", async () => {
    const input = await fixture();
    const resources = owner();
    const config = await readForgeStaticConfiguration(
      input.environment,
      resources,
    );
    expect(config.python).toBe(input.python);
    expect(config.dataRoot).toBe(input.data);
    expect(config.document).toEqual(input.document);
    expect(
      await inspectForgeStaticConfiguration(
        "editor010",
        input.environment,
        resources,
      ),
    ).toMatchObject({
      status: "available",
      diagnostics: {
        readiness_scope: "configuration-and-file-presence",
        engine_execution: "not_attempted",
      },
    });
  });
  it("keeps missing peer engines independent", async () => {
    const input = await fixture();
    const resources = owner();
    expect(
      await inspectForgeStaticConfiguration(
        "dotnet",
        input.environment,
        resources,
      ),
    ).toMatchObject({ status: "unavailable", code: "not_configured" });
    expect(
      await inspectForgeStaticConfiguration(
        "editor010",
        input.environment,
        resources,
      ),
    ).toMatchObject({ status: "available" });
  });
  it("preserves an explicit BOM and observes changed configuration on the next request", async () => {
    const input = await fixture();
    const resources = owner();
    await writeFile(
      input.configurationPath,
      "\uFEFF" + JSON.stringify(input.document),
    );
    expect(
      (await readForgeStaticConfiguration(input.environment, resources)).python,
    ).toBe(input.python);
    await writeFile(
      input.configurationPath,
      JSON.stringify({ python_executable: input.python }),
    );
    expect(
      await inspectForgeStaticConfiguration(
        "editor010",
        input.environment,
        resources,
      ),
    ).toMatchObject({ status: "unavailable", code: "not_configured" });
  });
  it.each(["REA_FORGE_STATIC_CONFIG", "REA_FORGE_DATA_ROOT"] as const)(
    "refuses relative %s",
    async (setting) => {
      const input = await fixture();
      expect(
        await inspectForgeStaticConfiguration(
          "editor010",
          {
            ...input.environment,
            [setting]: "relative/path",
          },
          owner(),
        ),
      ).toMatchObject({ status: "unavailable", code: "runtime_unavailable" });
    },
  );
  it.each([
    "{",
    "[]",
    '{"python_executable":null}',
    '{"python_executable":"relative"}',
  ])("refuses malformed bootstrap %s", async (content) => {
    const input = await fixture();
    await writeFile(input.configurationPath, content);
    expect(
      await inspectForgeStaticConfiguration(
        "editor010",
        input.environment,
        owner(),
      ),
    ).toMatchObject({ status: "unavailable", code: "runtime_unavailable" });
  });
  it("refuses non-UTF8 and oversized files before configuration interpretation", async () => {
    const input = await fixture();
    const resources = owner();
    await writeFile(input.configurationPath, Buffer.from([0xff, 0xfe, 0x00]));
    expect(
      await inspectForgeStaticConfiguration(
        "editor010",
        input.environment,
        resources,
      ),
    ).toMatchObject({ status: "unavailable" });
    await writeFile(input.configurationPath, " ".repeat(65537));
    expect(
      await inspectForgeStaticConfiguration(
        "editor010",
        input.environment,
        resources,
      ),
    ).toMatchObject({ status: "unavailable" });
  });
  it("requires actual configured paths but never infers a license or executable compatibility", async () => {
    const input = await fixture();
    await rm(input.editor);
    expect(
      await inspectForgeStaticConfiguration(
        "editor010",
        input.environment,
        owner(),
      ),
    ).toMatchObject({ status: "unavailable", code: "runtime_unavailable" });
  });
  it("propagates cancellation instead of reporting a missing engine", async () => {
    const input = await fixture();
    const controller = new AbortController();
    controller.abort(new Error("operator stopped readiness"));
    await expect(
      inspectForgeStaticConfiguration(
        "editor010",
        input.environment,
        owner(),
        controller.signal,
      ),
    ).rejects.toBeInstanceOf(AnalysisCancelledError);
  });
});

describe("independent native engine readiness", () => {
  it("keeps Android projects and DEX ready without a signer", async () => {
    const input = await fixture();
    const input_roots = [input.inputs];
    const pin = { path: input.editor, sha256: "a".repeat(64) };
    await writeFile(
      input.configurationPath,
      JSON.stringify({
        ...input.document,
        apk_workspace: {
          input_roots,
          version: "fixture",
          java: pin,
          apktool: pin,
        },
        smali: {
          input_roots,
          version: "fixture",
          java: pin,
          smali: pin,
          baksmali: pin,
        },
        android_results: { input_roots },
      }),
    );
    for (const family of ["apk_workspace", "smali", "android_results"] as const)
      expect(
        await inspectForgeStaticConfiguration(
          family,
          input.environment,
          owner(),
        ),
      ).toMatchObject({ status: "available" });
    expect(
      await inspectForgeStaticConfiguration(
        "apk_signing",
        input.environment,
        owner(),
      ),
    ).toMatchObject({ status: "unavailable", code: "not_configured" });
  });
  it("keeps bytecode inspection and readback present without models", async () => {
    const input = await fixture();
    const input_roots = [input.inputs];
    await writeFile(
      input.configurationPath,
      JSON.stringify({
        ...input.document,
        xdis: {
          input_roots,
          python: { path: input.python, sha256: "a".repeat(64) },
          xdis: { path: input.inputs, sha256: "a".repeat(64) },
        },
        python_results: { input_roots },
      }),
    );
    for (const family of ["xdis", "python_results"] as const)
      expect(
        await inspectForgeStaticConfiguration(
          family,
          input.environment,
          owner(),
        ),
      ).toMatchObject({ status: "available" });
    expect(
      await inspectForgeStaticConfiguration(
        "pylingual",
        input.environment,
        owner(),
      ),
    ).toMatchObject({ status: "unavailable", code: "not_configured" });
  });
  it("isolates enrichment engine presence and admits retained readback without an engine", async () => {
    const input = await fixture();
    const input_roots = input.document.editor010.input_roots;
    const pin = { path: input.editor, sha256: "a".repeat(64) };
    await writeFile(
      input.configurationPath,
      JSON.stringify({
        ...input.document,
        capa: { input_roots, version: "fixture", executable: pin },
        floss: {
          input_roots,
          version: "fixture",
          executable: { ...pin, path: join(input.root, "missing-floss.exe") },
        },
        api_hashes: { input_roots, version: "fixture", database: pin },
        enrichment: { input_roots },
      }),
    );
    for (const family of ["capa", "api_hashes", "enrichment"] as const)
      expect(
        await inspectForgeStaticConfiguration(
          family,
          input.environment,
          owner(),
        ),
      ).toMatchObject({ status: "available" });
    expect(
      await inspectForgeStaticConfiguration(
        "floss",
        input.environment,
        owner(),
      ),
    ).toMatchObject({ status: "unavailable" });
  });
  it("keeps API documents and retained traffic ready when pinned TShark is missing", async () => {
    const input = await fixture();
    const input_roots = [input.inputs];
    await writeFile(
      input.configurationPath,
      JSON.stringify({
        ...input.document,
        pcap: {
          input_roots,
          version: "fixture",
          tshark: {
            path: join(input.root, "missing-tshark.exe"),
            sha256: "a".repeat(64),
          },
        },
        api_documents: { input_roots },
        traffic: { input_roots },
      }),
    );
    expect(
      await inspectForgeStaticConfiguration("pcap", input.environment, owner()),
    ).toMatchObject({ status: "unavailable" });
    for (const family of ["api_documents", "traffic"] as const)
      expect(
        await inspectForgeStaticConfiguration(
          family,
          input.environment,
          owner(),
        ),
      ).toMatchObject({ status: "available" });
  });
});
