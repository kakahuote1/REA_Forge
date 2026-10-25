import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";
import {
  type ForgeSystemOperation,
  systemObservationInputs,
  systemObservationReportSchema,
} from "../../domain/forge/systemObservation.js";
const descriptions = {
  forge_inspect_system:
    "Inspect read-only System Informer phlib process/service/driver-service/kernel-module tables. Optional PID only for a single process identity; global tables do not claim atomicity or rootkit absence. No driver, privilege adjustment, GUI, target launch or process control. FILETIME values are exact decimal strings; complete applies only to the observed API table.",
  forge_observe_process:
    "Observe an explicit PID plus exact created_100ns from forge_inspect_system: process/thread metadata, modules, handles, virtual-memory regions, optional command line or connection tables. A query-only process handle is held and checked before/after; stale, exited or unreadable identities fail. No memory content, thread suspension, object names or stack unwind. IP Helper connections are table reads, not traffic capture or network requests. Command lines may contain caller-selected sensitive data.",
  forge_scan_process:
    "Run pinned Hollows Hunter/embedded PE-sieve only against one PID and exact created_100ns, with fixed no-dump filter and1–45-second deadline. Hold a query-only identity handle; verify target remains alive before/after. Suspicious output is candidate evidence; negatives do not prove benignness or rootkit absence. No all-process scan, ETW, custom arguments, target launch, memory dump, service or driver.",
  forge_compare_process_snapshots:
    "Compare two digest-bound retained system snapshots of the same collection and process creation identity. Reject incomplete/truncated or duplicate-identity rows. Report exact added/removed/changed observations; transient thread/handle/address reuse cannot be excluded. No live query or control is implied by historical comparison.",
  forge_read_system_result:
    "Authenticate a retained system receipt and snapshot, then page/filter historical rows with source indices and explicit complete/has_more. Full snapshot path/digest remains available for export. No live process state is inferred from a retained result; no scanner or System Informer GUI is started.",
} as const;
const contract = <Name extends ForgeSystemOperation>(name: Name) =>
  ({
    name,
    ...toolContractMetadata(name),
    kind: "forge-static-provider" as const,
    description: descriptions[name],
    inputSchema: systemObservationInputs[name],
    outputSchema: evidenceResultOf(systemObservationReportSchema),
    examples: [
      {
        title: "Select an explicit observation identity or retained receipt",
        input:
          name === "forge_inspect_system"
            ? { kind: "processes" }
            : name === "forge_compare_process_snapshots"
              ? {
                  before: {
                    receipt_path: "/work/before.json",
                    receipt_sha256: "a".repeat(64),
                  },
                  after: {
                    receipt_path: "/work/after.json",
                    receipt_sha256: "b".repeat(64),
                  },
                }
              : name === "forge_read_system_result"
                ? {
                    receipt_path: "/work/receipt.json",
                    receipt_sha256: "a".repeat(64),
                  }
                : {
                    pid: 1234,
                    created_100ns: "134000000000000001",
                    ...(name === "forge_observe_process"
                      ? { kind: "modules" }
                      : {}),
                  },
      },
    ],
  }) as const satisfies ToolContract;
export const FORGE_SYSTEM_TOOL_CONTRACTS = [
  contract("forge_inspect_system"),
  contract("forge_observe_process"),
  contract("forge_scan_process"),
  contract("forge_compare_process_snapshots"),
  contract("forge_read_system_result"),
] as const;
