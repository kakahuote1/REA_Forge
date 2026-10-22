import { OwnedStaticHelper } from "../OwnedStaticHelper.js";
import {
  binaryEditorReportSchema,
  type BinaryEditorReport,
  type ForgeBinaryEditorOperation,
} from "../../domain/forge/binaryEditor.js";

/** Fixed typed entry, not an arbitrary helper or command selection endpoint. */
export class Editor010Adapter extends OwnedStaticHelper<
  ForgeBinaryEditorOperation,
  BinaryEditorReport
> {
  constructor() {
    super(
      "forge-010editor",
      "bridge/forge/editor010/worker.py",
      binaryEditorReportSchema,
    );
  }
}
