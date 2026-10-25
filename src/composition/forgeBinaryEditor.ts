import { BinaryEditorService } from "../application/forge/BinaryEditorService.js";
import { Editor010Adapter } from "../forge/editor010/Editor010Adapter.js";

/** Construction is side-effect free; explicit calls alone read operator config or launch helpers. */
export const createForgeBinaryEditorService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): BinaryEditorService =>
  new BinaryEditorService(new Editor010Adapter(environment));
