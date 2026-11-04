/**
 * Which "nothing to fix" screen to show (AC39): no files at all, no lock file (packages were not
 * checked), or a clean result. null when there is something to fix or review.
 */
export function emptyKind(r: { findings: { confidence: string }[]; stats: { files: number }; locks: unknown[] }): "nothing" | "nolock" | "clean" | null {
  if (r.findings.some((f) => f.confidence !== "info")) return null;
  if (r.stats.files === 0) return "nothing";
  return r.locks.length === 0 ? "nolock" : "clean";
}
