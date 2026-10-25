import { NativeEnrichmentService } from "../application/forge/NativeEnrichmentService.js";
import { NativeEnrichmentAdapter } from "../forge/enrichment/NativeEnrichmentAdapter.js";
export const createForgeNativeEnrichmentService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
) =>
  new NativeEnrichmentService({
    capa: new NativeEnrichmentAdapter("capa", environment),
    floss: new NativeEnrichmentAdapter("floss", environment),
    api_hashes: new NativeEnrichmentAdapter("api_hashes", environment),
    enrichment: new NativeEnrichmentAdapter("enrichment", environment),
  });
