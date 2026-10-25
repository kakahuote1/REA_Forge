import { expect, it } from "vitest";
import { PythonBytecodeAdapter } from "./PythonBytecodeAdapter.js";
it("keeps non-model helpers on the existing static budget", async () => {
  const adapter = new PythonBytecodeAdapter("xdis", {});
  expect(adapter.budget).toEqual({
    deadlineMs: 55000,
    memoryLimitBytes: 1024 * 1024 * 1024,
  });
  await adapter.close();
});
it("binds the model budget at composition, not in caller arguments", async () => {
  const adapter = new PythonBytecodeAdapter("pylingual", {});
  expect(adapter.budget).toEqual({
    deadlineMs: 135000,
    memoryLimitBytes: 6 * 1024 * 1024 * 1024,
  });
  await adapter.close();
});
