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
  constructor(environment: Readonly<NodeJS.ProcessEnv> = process.env) {
    super(
      "forge-java",
      "bridge/forge/java/worker.py",
      javaReportSchema,
      "java",
      environment,
    );
  }
}
