import { PythonBytecodeService } from "../application/forge/PythonBytecodeService.js";
import { PythonBytecodeAdapter } from "../forge/python/PythonBytecodeAdapter.js";
export const createForgePythonBytecodeService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
) =>
  new PythonBytecodeService({
    xdis: new PythonBytecodeAdapter("xdis", environment),
    python_legacy: new PythonBytecodeAdapter("python_legacy", environment),
    pylingual: new PythonBytecodeAdapter("pylingual", environment),
    python_results: new PythonBytecodeAdapter("python_results", environment),
  });
