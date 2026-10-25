import { OfflineTrafficService } from "../application/forge/OfflineTrafficService.js";
import { OfflineTrafficAdapter } from "../forge/traffic/OfflineTrafficAdapter.js";
export const createForgeOfflineTrafficService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
) =>
  new OfflineTrafficService({
    pcap: new OfflineTrafficAdapter("pcap", environment),
    api_documents: new OfflineTrafficAdapter("api_documents", environment),
    traffic: new OfflineTrafficAdapter("traffic", environment),
  });
