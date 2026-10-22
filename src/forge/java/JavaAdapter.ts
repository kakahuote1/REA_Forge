import { OwnedStaticHelper } from "../OwnedStaticHelper.js";
import {
  javaReportSchema,
  type JavaReport,
  type ForgeJavaOperation,
} from "../../domain/forge/javaAnalysis.js";
export class JavaAdapter extends OwnedStaticHelper<
  ForgeJavaOperation,
  JavaReport
> {
  constructor() {
    super("forge-java", "bridge/forge/java/worker.py", javaReportSchema);
  }
}
