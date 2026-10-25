import { IdaStaticService } from "../application/forge/IdaStaticService.js";
import { IdaStaticAdapter } from "../forge/ida/IdaStaticAdapter.js";
export const createForgeIdaStaticService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): IdaStaticService =>
  new IdaStaticService({
    ida_host: new IdaStaticAdapter("ida_host", environment),
    ida_assembly: new IdaStaticAdapter("ida_assembly", environment),
    ida_exchange: new IdaStaticAdapter("ida_exchange", environment),
    ida_results: new IdaStaticAdapter("ida_results", environment),
  });
