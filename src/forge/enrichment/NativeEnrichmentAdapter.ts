import { OwnedStaticHelper } from "../OwnedStaticHelper.js";
import {
  enrichmentReportSchema,
  type EnrichmentReport,
  type ForgeEnrichmentOperation,
  type EnrichmentFamily,
} from "../../domain/forge/nativeEnrichment.js";
export class NativeEnrichmentAdapter extends OwnedStaticHelper<
  ForgeEnrichmentOperation,
  EnrichmentReport
> {
  constructor(
    family: EnrichmentFamily,
    environment: Readonly<NodeJS.ProcessEnv> = process.env,
  ) {
    super(
      `forge-${family}`,
      "bridge/forge/enrichment/worker.py",
      enrichmentReportSchema,
      family,
      environment,
    );
  }
}
