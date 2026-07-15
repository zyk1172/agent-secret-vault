import type { SensitiveFinding } from "./detectors";

export interface ScanFindingState extends SensitiveFinding {
  filePath: string;
  contentHash: string;
  reference?: string;
  plaintextForCurrentProcessOnly?: string;
  sourceExcerptForCurrentProcessOnly?: string;
}

type PersistableScanFindingState = Omit<
  ScanFindingState,
  "plaintextForCurrentProcessOnly" | "sourceExcerptForCurrentProcessOnly"
>;

function omitPlaintext(finding: ScanFindingState): PersistableScanFindingState {
  const {
    plaintextForCurrentProcessOnly: _plaintextForCurrentProcessOnly,
    sourceExcerptForCurrentProcessOnly: _sourceExcerptForCurrentProcessOnly,
    ...persistable
  } = finding;
  return persistable;
}

export function serializeScanState(findings: ScanFindingState[]): string {
  return JSON.stringify(findings.map(omitPlaintext));
}
