/**
 * A coarse progress signal emitted as a scan runs, so a UI can show what is happening. Optional
 * everywhere: the CLI passes nothing and the engine behaves exactly as before. `done` never
 * decreases and reaches `total` at the end.
 */
export type ScanProgress = (e: { step: string; done: number; total: number }) => void;
