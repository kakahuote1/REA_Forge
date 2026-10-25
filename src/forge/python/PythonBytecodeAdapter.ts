import { OwnedStaticHelper } from "../OwnedStaticHelper.js";
import {
  pythonBytecodeReportSchema,
  type ForgePythonOperation,
  type PythonBytecodeFamily,
  type PythonBytecodeReport,
} from "../../domain/forge/pythonBytecode.js";
export class PythonBytecodeAdapter extends OwnedStaticHelper<
  ForgePythonOperation,
  PythonBytecodeReport
> {
  constructor(
    family: PythonBytecodeFamily,
    environment: Readonly<NodeJS.ProcessEnv> = process.env,
  ) {
    super(
      `forge-${family}`,
      "bridge/forge/python_reverse/worker.py",
      pythonBytecodeReportSchema,
      family,
      environment,
      family === "pylingual"
        ? { deadlineMs: 135000, memoryLimitBytes: 6 * 1024 * 1024 * 1024 }
        : undefined,
    );
  }
}
