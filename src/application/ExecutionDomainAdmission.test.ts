import { expect, it } from "vitest";
import { hostExecutionRefusal } from "./ExecutionDomainAdmission.js";
import { buildCapabilityInventory } from "./CapabilityInventory.js";

it("refuses host target execution and device changes without conflating trusted analyzers", () => {
  for (const operation of [
    "start_gdb_session",
    "gdb_console",
    "start_rizin_debug_session",
    "rizin_debug_command",
    "execute_rizin_command",
    "cutter_command",
    "start_frida_session",
    "load_frida_script",
    "resume_frida_session",
    "instrument_with_frida",
    "capture_browser_scenario",
    "capture_electron_scenario",
    "capture_process_scenario",
    "observe_native_calls",
    "install_adb_package",
    "push_adb_file",
    "start_adb_app",
  ])
    expect(hostExecutionRefusal(operation)).toMatchObject({
      providerId: "forge-host-static",
      operation,
    });
  for (const operation of [
    "forge_decompile_java",
    "forge_compile_dotnet",
    "forge_inspect_binary_structure",
    "forge_run_binary_script",
    "forge_edit_binary_copy",
    "inspect_python_pyc",
    "inspect_packet_capture",
    "list_adb_devices",
    "list_frida_processes",
    "close_gdb_session",
    "close_rizin_debug_session",
    "close_frida_session",
    "unload_frida_script",
  ])
    expect(hostExecutionRefusal(operation)).toBeUndefined();
});

it("reports the enforced execution domain separately from missing engines and target state", () => {
  const inventory = buildCapabilityInventory(
    { open: false, capabilities: [] },
    {
      hostStaticExecution: true,
      processCaptureEnabled: true,
    },
  );
  expect(
    inventory.find(({ name }) => name === "start_gdb_session"),
  ).toMatchObject({ available: false, reason: "execution_domain_required" });
  expect(
    inventory.find(({ name }) => name === "start_frida_session"),
  ).toMatchObject({ available: false, reason: "execution_domain_required" });
  expect(
    inventory.find(({ name }) => name === "forge_decompile_java"),
  ).toMatchObject({ available: false, reason: "provider_missing" });
  expect(
    inventory.find(({ name }) => name === "inspect_python_pyc"),
  ).toMatchObject({ available: true });
});
