import { OwnedStaticHelper } from "../OwnedStaticHelper.js";
import {
  idaStaticReportSchema,
  type ForgeIdaOperation,
  type IdaStaticFamily,
  type IdaStaticReport,
} from "../../domain/forge/idaStatic.js";
export class IdaStaticAdapter extends OwnedStaticHelper<
  ForgeIdaOperation,
  IdaStaticReport
> {
  constructor(
    family: IdaStaticFamily,
    environment: Readonly<NodeJS.ProcessEnv> = process.env,
  ) {
    super(
      `forge-${family}`,
      "bridge/forge/ida/worker.py",
      idaStaticReportSchema,
      family,
      environment,
    );
  }
}
