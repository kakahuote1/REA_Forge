import type { GuestCaseBinding } from "./GuestRuntimeBinding.js";

export interface GuestStagedFile {
  readonly transferId: string;
  readonly path: string;
  readonly bytes: number;
  readonly sha256: string;
}

/** A case-owned staging boundary, not a generic remote filesystem or shell. */
export interface GuestCaseFilesPort {
  allocate(binding: GuestCaseBinding, signal?: AbortSignal): Promise<string>;
  stage(
    binding: GuestCaseBinding,
    bytes: Uint8Array,
    signal?: AbortSignal,
  ): Promise<GuestStagedFile>;
  read(
    binding: GuestCaseBinding,
    file: GuestStagedFile,
    signal?: AbortSignal,
  ): Promise<Uint8Array>;
  release(binding: GuestCaseBinding, signal?: AbortSignal): Promise<void>;
  close(): Promise<void>;
}
