/** Transport-observed identities. Display names and deterministic VBox UUIDs alone are not authority. */
export interface LdPlayerInstanceObservation {
  readonly index: number;
  readonly name: string;
  /** Fingerprint of physical file/directory creation identities and selected disk anchors. */
  readonly physicalGeneration: string;
  readonly machineUuid: string;
  readonly androidStarted: boolean;
  readonly runtime: {
    readonly playerPid: number | null;
    readonly playerStartTicks: string | null;
    readonly vmPid: number | null;
    readonly vmStartTicks: string | null;
  };
}

export interface LdPlayerObservationPort {
  list(signal?: AbortSignal): Promise<readonly LdPlayerInstanceObservation[]>;
  inspect(
    index: number,
    signal?: AbortSignal,
  ): Promise<LdPlayerInstanceObservation>;
  close(): Promise<void>;
}
