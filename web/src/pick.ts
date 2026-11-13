const RANK: Record<string, number> = { critical: 0, high: 1, medium: 2 };

export const isProvisional = (f: { notes?: string[] }): boolean => !!f.notes?.includes("severity_provisional");

/**
 * Quick select: findings at the given severities, most severe first, capped at `max` (the fix-prompt batch limit).
 * A partial pick (critical, critical+high) skips provisional severities: they may drop once the priority is checked.
 */
export function pickBySeverity(findings: { id: string; severity: string; notes?: string[] }[], sevs: readonly string[], max: number): { ids: string[]; total: number } {
  const every = Object.keys(RANK).every((s) => sevs.includes(s));
  const hit = findings.filter((f) => sevs.includes(f.severity) && (every || !isProvisional(f))).sort((a, b) => (RANK[a.severity] ?? 9) - (RANK[b.severity] ?? 9));
  return { ids: hit.slice(0, max).map((f) => f.id), total: hit.length };
}
