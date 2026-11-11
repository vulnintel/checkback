const RANK: Record<string, number> = { critical: 0, high: 1, medium: 2 };

/** Quick select: findings at the given severities, most severe first, capped at `max` (the fix-prompt batch limit). */
export function pickBySeverity(findings: { id: string; severity: string }[], sevs: readonly string[], max: number): { ids: string[]; total: number } {
  const hit = findings.filter((f) => sevs.includes(f.severity)).sort((a, b) => (RANK[a.severity] ?? 9) - (RANK[b.severity] ?? 9));
  return { ids: hit.slice(0, max).map((f) => f.id), total: hit.length };
}
