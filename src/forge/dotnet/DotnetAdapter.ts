import { OwnedStaticHelper } from "../OwnedStaticHelper.js";
import {
  dotnetReportSchema,
  type DotnetReport,
  type ForgeDotnetOperation,
} from "../../domain/forge/dotnetAnalysis.js";
export class DotnetAdapter extends OwnedStaticHelper<
  ForgeDotnetOperation,
  DotnetReport
> {
  constructor(environment: Readonly<NodeJS.ProcessEnv> = process.env) {
    super(
      "forge-dotnet",
      "bridge/forge/dotnet/worker.py",
      dotnetReportSchema,
      "dotnet",
      environment,
    );
  }
}
