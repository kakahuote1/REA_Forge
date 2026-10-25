import { expect, it } from "vitest";
import { explicitSetupRegistrationEnvironment } from "./SetupRegistrationEnvironment.js";

it("preserves explicit Forge selectors without persisting ambient configuration", () => {
  expect(
    explicitSetupRegistrationEnvironment({
      REA_FORGE_STATIC_CONFIG: "/operator/tools.json",
      REA_FORGE_DATA_ROOT: "/operator/data",
      UNRELATED_RUNTIME_VALUE: "not for registration",
    }),
  ).toEqual({
    REA_FORGE_STATIC_CONFIG: "/operator/tools.json",
    REA_FORGE_DATA_ROOT: "/operator/data",
  });
});
