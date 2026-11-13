// GUI API handlers. Thin wrappers over the engine: scan, recheck, prompts, ignores, SBOM, key mode,
// watch/track and the template store. Person-only actions (consent, ignore, watch, track) exist
// here and nowhere in MCP. Responses never contain raw secret values: findings carry the masked
// GUI form only (§10-3), and value hashes are dropped.

import { realpath } from "node:fs/promises";
import { basename, join } from "node:path";
import { apiKeyOf, CONSENT_VERSION, hasConsent, projectKey, readConfig, readJson, updateConfig, writeJson, type LocalConfig } from "../appdata.js";
import { BUILTIN_NAMES, findingDescription, KIND_TEXT } from "../builtins/text.js";
import { registerCves, registeredCves, subscribePackages, trackRows, watchCandidates } from "../commands.js";
import { readInventory } from "../deps/inventory.js";
import { buildSbom, inSbom, purlOf } from "../deps/sbom.js";
import { addIgnore, listIgnores, removeIgnore } from "../ignores.js";
import { ViBudget } from "../net/budget.js";
import { defaultHttp, VERSION, type Fetch } from "../net/http.js";
import { checkKey } from "../net/vulnintel.js";
import { DATA_TABLE, DISCLAIMER, osLang, scanNotices } from "../notice.js";
import { aiCheckPromptForProject, fixPromptText, MAX_BATCH, needsRevoke, PromptError } from "../prompts.js";
import { clearSnapshot, readLastScan, recordFixRequest } from "../recheck.js";
import { scan, type ScanPhase } from "../scan.js";
import {
  aiExternal, aiHash, deleteAiCheck, deleteTemplate, duplicateTemplate, exportTemplate, importTemplate, listTemplates,
  loadTemplateById, readMeta, renameTemplate, saveAiCheck, setRuleEnabled, StoreError,
} from "../template-store.js";
import { TemplateError } from "../template.js";
import { LANGS, type Finding, type Lang, type LocalizedText, type Rule, type ScanResult, type Severity, type Template } from "../types.js";

export interface GuiContext {
  /** Scan target: the folder checkback was started in. Fixed for the server's life (§3). */
  cwd: string;
  appDir: string;
  fetch?: Fetch;
}

export interface ApiError extends Error {
  status: number;
  code: string;
  detail?: unknown;
}

export type Route = (body: Record<string, unknown>) => Promise<unknown>;

const fail = (status: number, code: string, detail?: unknown): ApiError => Object.assign(new Error(code), { status, code, detail });
const SEVERITIES: Severity[] = ["critical", "high", "medium"];
const web = (lang: Lang, path: string): string => `https://www.vulnintelapp.com/${lang}${path}`;
const pick = (t: LocalizedText | undefined, lang: Lang): string | undefined => t?.[lang] ?? t?.en ?? t?.ko;
const str = (v: unknown, max = 500): string => (typeof v === "string" ? v.slice(0, max) : "");
const ids = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && /^[a-f0-9]{1,64}$/.test(x)) : []);

function ruleName(rule: Rule | undefined, f: { rule_id: string; kind?: string }, lang: Lang): string {
  const t = (rule && "name" in rule ? rule.name : undefined) ?? KIND_TEXT[`${f.rule_id}/${f.kind}`]?.title ?? BUILTIN_NAMES[f.rule_id];
  return pick(t, lang) ?? f.rule_id;
}

function describe(rule: Rule | undefined, f: Finding, lang: Lang): string {
  return pick(rule && "description" in rule ? rule.description : undefined, lang) ?? findingDescription(f, lang) ?? "";
}

/** The GUI finding: engine fields minus the keyed value hash, plus localized rule texts. */
function guiFinding(f: Finding, tpl: Template, imported: boolean, lang: Lang): Record<string, unknown> {
  const { value_hash: _h, ...rest } = f;
  const rule = tpl.rules.find((r) => r.id === f.rule_id);
  const description = describe(rule, f, lang);
  const name = ruleName(rule, f, lang);
  return {
    ...rest,
    title: name, // the engine title is this same text in the scan's language; follow the current one
    name,
    summary: description.split(/(?<=[.!?])\s|(?<=[。！？])/)[0] ?? description, // Chinese puts no space after 。
    description,
    external_text: imported && !!rule && rule.type !== "builtin",
    revoke: needsRevoke(f),
  };
}

export function createRoutes(ctx: GuiContext): { routes: Record<string, Route>; stop: () => void } {
  const { cwd, appDir } = ctx;
  let declined = false; // first-run notice declined in this session → local rules only
  let last: { result: ScanResult; tpl: Template } | null = null;
  let job: { running: boolean; phase: ScanPhase; files: number; started: number; error?: string; ctrl: AbortController } | null = null;

  const cfg = (): Promise<LocalConfig> => readConfig(appDir);
  const langOf = (c: LocalConfig): Lang => c.lang ?? osLang();
  const keyCtx = async (): Promise<{ key: string; c: LocalConfig }> => {
    const c = await cfg();
    if (!hasConsent(c)) throw fail(400, "no_consent");
    const key = apiKeyOf(c);
    if (!key) throw fail(400, "no_key");
    return { key, c };
  };
  // §7-8: "revoked at the issuer?" ticks for resolved secret items — a local note only, never a verdict input.
  const revokedFile = async (): Promise<string> => join(appDir, "revoked", `${projectKey(await realpath(cwd))}.json`);
  const tplOf = async (id: unknown): Promise<Template> => {
    try {
      return await loadTemplateById(typeof id === "string" ? id : undefined, appDir);
    } catch (e) {
      throw storeFail(e);
    }
  };

  const routes: Record<string, Route> = {
    async "GET /api/ping"() {
      return {};
    },

    async "GET /api/state"() {
      const c = await cfg();
      const lang = langOf(c);
      return {
        version: VERSION,
        folder: basename(cwd),
        folder_path: cwd,
        lang,
        theme: c.theme ?? "system",
        consent: hasConsent(c),
        declined,
        key: process.env.VULNINTEL_API_KEY ? "env" : c.api_key ? "config" : "none",
        external: { osv: c.external?.osv !== false, registry: c.external?.registry !== false, vulnintel: c.external?.vulnintel !== false },
        data_table: DATA_TABLE[lang],
        disclaimer: DISCLAIMER[lang],
        links: {
          key: web(lang, "/settings/api-keys?src=checkback"),
          subscriptions: web(lang, "/settings/notifications"),
          remediations: web(lang, "/settings/remediations"),
        },
        templates: await listTemplates(appDir),
        has_result: !!last,
      };
    },

    // ---- first-run notice and settings (S6)
    async "POST /api/consent"(b) {
      if (b.accept === true) await updateConfig(appDir, { consent: { at: new Date().toISOString(), version: CONSENT_VERSION } });
      else declined = true;
      return {};
    },
    async "POST /api/settings"(b) {
      const patch: Partial<LocalConfig> = {};
      if (LANGS.includes(b.lang as Lang)) patch.lang = b.lang as Lang;
      if (b.theme === "light" || b.theme === "dark") patch.theme = b.theme;
      else if (b.theme === "system") patch.theme = undefined; // dropped from the file: follow the OS again
      if (typeof b.external === "object" && b.external !== null) {
        const e = b.external as Record<string, unknown>;
        const c = await cfg();
        patch.external = { ...c.external };
        for (const k of ["osv", "registry", "vulnintel"] as const) if (typeof e[k] === "boolean") patch.external[k] = e[k] as boolean;
      }
      await updateConfig(appDir, patch);
      return {};
    },
    async "POST /api/key"(b) {
      const key = b.key === null ? null : str(b.key, 300).trim();
      if (key !== null && !/^[\x21-\x7e]{8,200}$/.test(key)) throw fail(400, "bad_key_format");
      const c = await updateConfig(appDir, { api_key: key ?? undefined });
      if (!key) return { status: "none" };
      if (!hasConsent(c)) return { status: "unchecked" }; // no external request before first-run consent (AC34)
      return { status: await checkKey(defaultHttp(ctx.fetch), new ViBudget(appDir, { keyMode: true }), apiKeyOf(c)!) };
    },
    async "POST /api/revoked"(b) {
      const [id] = ids([b.id]);
      if (!id) throw fail(400, "bad_id");
      const file = await revokedFile();
      const set = new Set(await readJson<string[]>(file, []));
      if (b.done === true) set.add(id);
      else set.delete(id);
      await writeJson(file, [...set]);
      return {};
    },
    async "POST /api/baseline/clear"() {
      await clearSnapshot(cwd, appDir);
      return {};
    },

    // ---- scan (S1 → S2 → S3)
    async "POST /api/scan"(b) {
      if (job?.running) throw fail(409, "scan_running");
      const tpl = await tplOf(b.template);
      const c = await cfg();
      const ctrl = new AbortController();
      const j = { running: true, phase: "files" as ScanPhase, files: 0, started: Date.now(), ctrl } as NonNullable<typeof job>;
      job = j;
      scan(cwd, tpl, {
        appDir, lang: langOf(c), signal: ctrl.signal, refreshVulnIntel: b.refresh === true,
        ...(ctx.fetch && { fetch: ctx.fetch }),
        onPhase: (p, n) => {
          j.phase = p;
          j.files = n;
        },
      })
        .then((result) => {
          last = { result, tpl };
        })
        .catch((e: Error) => {
          j.error = ctrl.signal.aborted ? "stopped" : "scan_failed";
          if (!ctrl.signal.aborted) process.stderr.write(`checkback gui: scan failed: ${e.message}\n`);
        })
        .finally(() => {
          j.running = false;
        });
      return {};
    },
    async "GET /api/scan"() {
      if (!job) return { running: false };
      return { running: job.running, phase: job.phase, files: job.files, elapsed_ms: Date.now() - job.started, ...(job.error && { error: job.error }) };
    },
    async "POST /api/scan/stop"() {
      job?.ctrl.abort();
      return {};
    },
    async "GET /api/result"() {
      if (!last) throw fail(404, "no_result");
      const { result: r, tpl } = last;
      const lang = langOf(await cfg());
      const imported = tpl.id !== "default" && (await readMeta(appDir, tpl.id)).imported;
      const inv = await readInventory(cwd);
      const hit = new Set(r.findings.map((f) => f.rule_id));
      const name = (id: string): string => ruleName(tpl.rules.find((x) => x.id === id), { rule_id: id }, lang);
      const cmp = r.compare;
      const revoked = cmp?.resolved.some((x) => x.confirm_revocation) ? new Set(await readJson<string[]>(await revokedFile(), [])) : new Set<string>();
      return {
        scan_at: r.scan_at,
        template: { id: tpl.id, name: tpl.name, imported },
        findings: r.findings.map((f) => guiFinding(f, tpl, imported, lang)),
        passed: r.checked.filter((c) => c.ran && !c.reason && !hit.has(c.rule_id)).map((c) => ({ rule_id: c.rule_id, name: name(c.rule_id) })),
        not_run: r.checked.filter((c) => !c.ran || c.reason).map((c) => ({ rule_id: c.rule_id, name: name(c.rule_id), reason: c.reason ?? "disabled" })),
        stats: r.stats,
        notices: scanNotices(r, lang),
        locks: inv.lockfiles.map((l) => ({ path: l.path, packages: l.packages.length })),
        manifests: inv.manifests.length,
        ai_checks: tpl.rules.filter((x) => x.type === "ai_check" && x.enabled).length,
        // ids, rule ids, titles and locations only — the stored baseline holds no values (§10-3)
        ...(cmp && {
          compare: {
            ...cmp,
            requested: cmp.requested ?? [],
            resolved: cmp.resolved.map((x) => {
              const rule = tpl.rules.find((y) => y.id === x.rule_id);
              return {
                ...x,
                title: rule ? ruleName(rule, x, lang) : x.title, // same text as the card title; stored title is in the scan's language
                ...(x.confirm_revocation && { revoked: revoked.has(x.id) }),
              };
            }),
          },
        }),
      };
    },

    // ---- prompts (S8, S9). Preview never records; [Copy] records the fix-request snapshot (§7-8).
    async "POST /api/fix-prompt"(b) {
      const want = ids(b.ids);
      if (want.length === 0) throw fail(400, "no_selection");
      if (want.length > MAX_BATCH) throw fail(400, "too_many", { max: MAX_BATCH });
      const stored = await readLastScan(cwd, appDir);
      const byId = new Map((stored?.findings ?? []).map((f) => [f.id, f]));
      const picked = want.map((i) => byId.get(i));
      if (picked.some((f) => !f)) throw fail(400, "unknown_finding");
      const lang = langOf(await cfg());
      const tpl = await tplOf(stored!.template_id).catch(() => tplOf("default"));
      try {
        const p = fixPromptText(picked as NonNullable<(typeof picked)[number]>[], tpl, lang);
        const human = (picked as Finding[]).filter(needsRevoke).map((f) => `${f.title} — ${f.location ? `${f.location.file}${f.location.line ? `:${f.location.line}` : ""}` : ""}`);
        return { text: p.text, external: p.external, human };
      } catch (e) {
        if (e instanceof PromptError) throw fail(400, "prompt_error");
        throw e;
      }
    },
    async "POST /api/fix-request"(b) {
      const want = ids(b.ids);
      if (want.length === 0 || want.length > MAX_BATCH) throw fail(400, "too_many", { max: MAX_BATCH });
      try {
        await recordFixRequest(cwd, want, appDir);
      } catch {
        throw fail(400, "unknown_finding");
      }
      return {};
    },
    async "POST /api/ai-check"(b) {
      const tpl = await tplOf(b.template);
      const lang = langOf(await cfg());
      const ext = await aiExternal(appDir, tpl);
      const p = await aiCheckPromptForProject(cwd, tpl, lang, appDir, ext);
      const items = tpl.rules.flatMap((r) =>
        r.type === "ai_check" && r.enabled ? [{ id: r.id, name: pick(r.name, lang) ?? r.id, check: pick(r.check, lang) ?? "", files: r.files, external: ext(r) }] : [],
      );
      return { text: p?.text ?? null, external: p?.external ?? false, items };
    },

    // ---- ignore list (person-only, §5)
    async "POST /api/ignore"(b) {
      const [id] = ids([b.id]);
      const reason = str(b.reason).trim();
      if (!id || !reason) throw fail(400, "reason_required");
      await addIgnore(cwd, id, reason, appDir);
      if (last) {
        const r = last.result;
        const gone = r.findings.find((f) => f.id === id);
        r.findings = r.findings.filter((f) => f.id !== id);
        // §7-8: an ignored item counts in no recheck state — keep the summary in step with the cards
        if (gone?.recheck && r.compare) r.compare.counts[gone.recheck]--;
      }
      return {};
    },
    async "POST /api/unignore"(b) {
      const [id] = ids([b.id]);
      if (!id) throw fail(400, "bad_id");
      await removeIgnore(cwd, id, appDir);
      return {};
    },
    async "GET /api/ignores"() {
      return { items: await listIgnores(cwd, appDir) };
    },

    // ---- SBOM (S7): generated locally, returned as text for a client-side download.
    async "GET /api/sbom"() {
      const inv = await readInventory(cwd);
      const json = buildSbom(inv);
      return {
        json,
        components: (JSON.parse(json) as { components?: unknown[] }).components?.length ?? 0,
        // per lock: the components that lock contributes (same rule as buildSbom)
        locks: inv.lockfiles.map((l) => ({ path: l.path, kind: l.kind, packages: new Set(l.packages.filter(inSbom).map(purlOf)).size })),
      };
    },

    // ---- key mode: watch (S3a) and remediation tracker
    async "GET /api/watch"() {
      await keyCtx();
      const { cands, defaults } = await watchCandidates(cwd, appDir);
      return { candidates: cands, defaults, max: 50 };
    },
    async "POST /api/watch"(b) {
      const { key } = await keyCtx();
      const want = new Set(Array.isArray(b.keys) ? b.keys.filter((x): x is string => typeof x === "string") : []);
      // Only names from our own candidate list can be sent (no free-form names, no private packages).
      const picked = (await watchCandidates(cwd, appDir)).cands.filter((c) => want.has(c.key));
      if (picked.length === 0) throw fail(400, "no_selection");
      return subscribePackages(cwd, appDir, key, picked, ctx.fetch);
    },
    async "GET /api/track"() {
      const { key } = await keyCtx();
      const rows = await trackRows(cwd, appDir);
      if (rows.length === 0) return { rows: [] };
      const reg = await registeredCves(appDir, key, rows.map((r) => r.cve), ctx.fetch);
      if (!reg.ok) throw fail(502, "tracker_unavailable", reg.kind);
      return { rows: rows.map((r) => ({ cve: r.cve, registered: reg.set.has(r.cve) })) };
    },
    async "POST /api/track"(b) {
      const { key } = await keyCtx();
      const want = new Set(Array.isArray(b.cves) ? b.cves.filter((x): x is string => typeof x === "string") : []);
      const rows = (await trackRows(cwd, appDir)).filter((r) => want.has(r.cve));
      const reg = await registeredCves(appDir, key, rows.map((r) => r.cve), ctx.fetch);
      if (!reg.ok) throw fail(502, "tracker_unavailable", reg.kind);
      const r = await registerCves(appDir, key, rows.filter((x) => !reg.set.has(x.cve)), ctx.fetch);
      return { registered: r.ok + rows.filter((x) => reg.set.has(x.cve)).length, ...(r.error && { error: r.error.kind }) };
    },

    // ---- templates (S5)
    async "GET /api/templates"() {
      const lang = langOf(await cfg());
      const out = [];
      for (const t of await listTemplates(appDir)) {
        const tpl = await loadTemplateById(t.id, appDir);
        const meta = await readMeta(appDir, t.id);
        const mine = new Set(meta.mine);
        const bundled = new Set(meta.bundled);
        out.push({
          ...t,
          rules: tpl.rules.map((r) => ({
            id: r.id,
            type: r.type,
            name: r.type === "ai_check" ? (pick(r.name, lang) ?? r.id) : ruleName(r, { rule_id: r.id }, lang),
            severity: "severity" in r ? (r.severity ?? null) : null,
            enabled: r.enabled,
            ...(r.type === "ai_check" && { check: pick(r.check, lang) ?? "", files: r.files, mine: !t.readOnly && mine.has(aiHash(r)), bundled: t.readOnly || bundled.has(aiHash(r)) }),
          })),
        });
      }
      return { templates: out, max_ai_checks: 30 };
    },
    async "POST /api/templates/duplicate"(b) {
      const lang = langOf(await cfg());
      return { id: (await store(() => duplicateTemplate(appDir, str(b.from, 64), lang))).id };
    },
    async "POST /api/templates/toggle"(b) {
      await store(() => setRuleEnabled(appDir, str(b.id, 64), str(b.rule, 64), b.enabled === true));
      return {};
    },
    async "POST /api/templates/rename"(b) {
      await store(() => renameTemplate(appDir, str(b.id, 64), str(b.name, 200).trim()));
      return {};
    },
    async "POST /api/templates/delete"(b) {
      await store(() => deleteTemplate(appDir, str(b.id, 64)));
      return {};
    },
    async "POST /api/templates/import"(b) {
      const content = typeof b.content === "string" ? b.content : "";
      const r = await store(() => importTemplate(appDir, content));
      return { id: r.tpl.id, renamed: r.renamed };
    },
    async "POST /api/templates/export"(b) {
      const id = str(b.id, 64);
      return { filename: `${id}.yaml`, content: await store(() => exportTemplate(appDir, id)) };
    },
    async "POST /api/templates/ai-check"(b) {
      const lang = langOf(await cfg());
      const severity = SEVERITIES.includes(b.severity as Severity) ? (b.severity as Severity) : "medium";
      const files = str(b.files, 2500).split(/\s+/).filter(Boolean);
      const rule = typeof b.rule === "string" ? b.rule : undefined;
      await store(() => saveAiCheck(appDir, str(b.id, 64), { check: str(b.check, 2000), severity, files }, lang, rule));
      return {};
    },
    async "POST /api/templates/ai-check/delete"(b) {
      await store(() => deleteAiCheck(appDir, str(b.id, 64), str(b.rule, 64)));
      return {};
    },
  };

  return { routes, stop: () => job?.ctrl.abort() };
}

function storeFail(e: unknown): ApiError {
  if (e instanceof TemplateError) return fail(400, "template_invalid", e.issues);
  if (e instanceof StoreError) return fail(e.code === "not_found" ? 404 : 400, e.code, e.issues);
  return e as ApiError;
}

async function store<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    throw storeFail(e);
  }
}
