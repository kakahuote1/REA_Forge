/** Facts observed on the existing authenticated guest channel, not caller assertions. */
export interface GuestRuntimeObservation {
  readonly ok: true;
  readonly version: string;
  readonly computerName: string;
  readonly bridgeInstanceId?: string;
  readonly bridgeProcessId?: number;
  readonly bridgeProcessStartTicks?: string;
}

export interface GuestHealthPort {
  inspect(signal?: AbortSignal): Promise<GuestRuntimeObservation>;
  close(): Promise<void>;
}
