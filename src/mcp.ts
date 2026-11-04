// Stage 8 MCP server over stdio (newline-delimited JSON-RPC 2.0). Target = the server's working
// folder, fixed. Tools: scan, explain, export_sbom, fix_prompts, ai_check_prompt — nothing that
// ignores, consents, watches, runs an AI or stores AI judgments (§4, N2). Responses never carry
// secret values, masked values or file contents (§10-3).

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";
import type { Readable, Writable } from "node:stream";
import { apiKeyOf, defaultAppDir, hasConsent, readConfig } from "./appdata.js";
import { KIND_TEXT } from "./builtins/text.js";
import { buildSbom } from "./deps/sbom.js";
import { readInventory } from "./deps/inventory.js";
import { VERSION, type Fetch } from "./net/http.js";
import { CONSENT_HOWTO, DATA_TABLE, DISCLAIMER, KEY_NOTICE, osLang, PARTIAL_NOTICE, viNotice } from "./notice.js";
import { aiCheckPromptForProject, fixPromptsForIds, MAX_BATCH } from "./prompts.js";
import { readLastScan, type Compare } from "./recheck.js";
import { scan } from "./scan.js";
import { loadDefaultTemplate, loadTemplate } from "./template.js";
import type { CheckedRule, Finding, Lang, Template } from "./types.js";

const PROTOCOLS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
/** MCP clients time out long tool calls: external lookups get this budget, the rest continues next scan. */
export const MCP_SCAN_DEADLINE_MS = 20_000;

/** Finding fields an MCP response may carry — an allowlist, so masked_match/value_hash can never leak. */
const MCP_FIELDS = [
  "id", "rule_id", "kind", "severity", "confidence", "title", "location", "secret_kind", "source", "notes", "related",
  "ecosystem", "package", "version", "fixed_version", "vuln_ids", "kev", "vpi_level", "epss", "cvss", "lockfile",
  "recheck", "recheck_note", "carried",
] as const;
export type McpFinding = Pick<Finding, (typeof MCP_FIELDS)[number]>;

export function mcpFinding(f: Finding): McpFinding {
  const out: Record<string, unknown> = {};
  for (const k of MCP_FIELDS) if (f[k] !== undefined) out[k] = f[k];
  return out as McpFinding;
}

export interface McpScan {
  findings: McpFinding[];
  checked: CheckedRule[];
  compare?: Compare;
  notice?: string;
}

export interface McpOptions {
  cwd: string;
  appDir?: string;
  fetch?: Fetch;
  now?: () => number;
  /** Override MCP_SCAN_DEADLINE_MS (tests). */
  deadlineMs?: number;
}

const TOOLS = [
  {
    name: "scan",
    description:
      "Run checkback's deterministic security checks on this project (secrets, .env/key files, CORS, debug settings, Supabase/Firebase rules, vulnerable/malicious/missing packages). Re-running after fixes compares with the last fix request.",
    inputSchema: { type: "object", properties: { template: { type: "string", description: "Template id (default: the bundled default template)" } }, additionalProperties: false },
  },
  {
    name: "explain",
    description: "Explain one finding from the latest scan: why it matters, where it is, and how to fix it.",
    inputSchema: { type: "object", properties: { finding_id: { type: "string" } }, required: ["finding_id"], additionalProperties: false },
  },
  {
    name: "export_sbom",
    description: "Return a CycloneDX JSON SBOM of the project's locked dependencies (generated locally).",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "fix_prompts",
    description: `Fix instructions for up to ${MAX_BATCH} findings from the latest scan (by id). Records the fix request so the next scan reports what is still left.`,
    inputSchema: {
      type: "object",
      properties: { finding_ids: { type: "array", items: { type: "string" }, minItems: 1, maxItems: MAX_BATCH } },
      required: ["finding_ids"],
      additionalProperties: false,
    },
  },
  {
    name: "ai_check_prompt",
    description: "Read-only review checklist for the AI (authorization, IDOR, injection, …) from the template's ai_check items. Results are AI judgments, separate from scan findings.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
];

class ToolError extends Error {}

async function templateById(id: string | undefined, appDir: string): Promise<Template> {
  if (!id || id === "default") return loadDefaultTemplate();
  if (!/^[a-z0-9-]{1,64}$/.test(id)) throw new ToolError("invalid template id");
  try {
    return await loadTemplate(await readFile(join(appDir, "templates", `${id}.yaml`)));
  } catch (e) {
    throw new ToolError(`template ${id} could not be loaded: ${(e as Error).message.split("\n")[0]}`);
  }
}

export function createMcpHandler(o: McpOptions): (msg: unknown) => Promise<unknown | null> {
  const appDir = o.appDir ?? defaultAppDir();
  const lang = async (): Promise<Lang> => (await readConfig(appDir)).lang ?? osLang();

  const tools: Record<string, (args: Record<string, unknown>) => Promise<string>> = {
    async scan(args) {
      const cfg = await readConfig(appDir);
      const l = cfg.lang ?? osLang();
      const tpl = await templateById(typeof args.template === "string" ? args.template : undefined, appDir);
      const r = await scan(o.cwd, tpl, {
        appDir, lang: l, deadlineMs: o.deadlineMs ?? MCP_SCAN_DEADLINE_MS, ...(o.fetch && { fetch: o.fetch }), ...(o.now && { now: o.now }),
      });
      const partial = r.checked.some((c) => c.reason === "timeout_partial") || r.findings.some((f) => f.notes?.includes("priority_pending"));
      const vi = viNotice(r.vulnintel, l);
      const notice = [
        ...(hasConsent(cfg) ? [] : [DATA_TABLE[l], CONSENT_HOWTO[l]]),
        ...(vi ? [vi] : []),
        ...(partial ? [PARTIAL_NOTICE[l]] : []),
        ...(apiKeyOf(cfg) ? [] : [KEY_NOTICE[l]]),
        DISCLAIMER[l],
      ].join("\n\n");
      const out: McpScan = { findings: r.findings.map(mcpFinding), checked: r.checked, ...(r.compare && { compare: r.compare }), notice };
      return JSON.stringify(out);
    },
    async explain(args) {
      const id = String(args.finding_id ?? "");
      const last = await readLastScan(o.cwd, appDir);
      const f = last?.findings.find((x) => x.id === id);
      if (!last || !f) throw new ToolError("unknown finding id — run scan first");
      const l = await lang();
      const tpl = await templateById(last.template_id, appDir).catch(() => loadDefaultTemplate());
      const rule = tpl.rules.find((r) => r.id === f.rule_id);
      const kt = KIND_TEXT[`${f.rule_id}/${f.kind}`];
      const pick = (t?: { ko?: string; en?: string }): string | undefined => t?.[l] ?? t?.en ?? t?.ko;
      return JSON.stringify({
        finding: mcpFinding(f as Finding),
        description: pick(rule && "description" in rule ? rule.description : undefined) ?? pick(kt?.description) ?? "",
        fix: pick(rule && "fix_prompt" in rule ? rule.fix_prompt : undefined)?.replace(/\{[a-z_]+\}/g, "…") ?? pick(kt?.fix)?.replace(/\{[a-z_]+\}/g, "…") ?? "",
      });
    },
    async export_sbom() {
      return buildSbom(await readInventory(o.cwd));
    },
    async fix_prompts(args) {
      const ids = args.finding_ids;
      if (!Array.isArray(ids) || ids.length === 0 || !ids.every((x) => typeof x === "string")) throw new ToolError("finding_ids must be a non-empty list of ids");
      if (ids.length > MAX_BATCH) throw new ToolError(`at most ${MAX_BATCH} findings per request`);
      const last = await readLastScan(o.cwd, appDir);
      const tpl = await templateById(last?.template_id, appDir).catch(() => loadDefaultTemplate());
      try {
        return (await fixPromptsForIds(o.cwd, ids as string[], tpl, await lang(), appDir)).text;
      } catch (e) {
        throw new ToolError((e as Error).message);
      }
    },
    async ai_check_prompt() {
      const last = await readLastScan(o.cwd, appDir);
      const tpl = await templateById(last?.template_id, appDir).catch(() => loadDefaultTemplate());
      const l = await lang();
      const p = await aiCheckPromptForProject(o.cwd, tpl, l, appDir);
      return p?.text ?? (l === "ko" ? "켜진 AI 점검 항목이 없습니다. `npx checkback` 화면의 템플릿에서 AI 점검 항목을 켜세요." : "No AI check items are enabled. Turn them on in the template screen of `npx checkback`.");
    },
  };

  return async (raw) => {
    const msg = raw as { jsonrpc?: string; id?: string | number | null; method?: string; params?: Record<string, unknown> };
    const isRequest = msg && typeof msg === "object" && "id" in msg && msg.id !== undefined;
    const reply = (result: unknown): unknown => ({ jsonrpc: "2.0", id: msg.id, result });
    const fail = (code: number, message: string): unknown => ({ jsonrpc: "2.0", id: msg?.id ?? null, error: { code, message } });
    if (!msg || typeof msg !== "object" || msg.jsonrpc !== "2.0" || typeof msg.method !== "string") return fail(-32600, "invalid request");
    if (!isRequest) return null; // notifications (initialized, cancelled, …)
    switch (msg.method) {
      case "initialize": {
        const asked = String(msg.params?.protocolVersion ?? "");
        return reply({
          protocolVersion: PROTOCOLS.includes(asked) ? asked : PROTOCOLS[0],
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: "checkback", version: VERSION },
        });
      }
      case "ping":
        return reply({});
      case "tools/list":
        return reply({ tools: TOOLS });
      case "tools/call": {
        const name = String(msg.params?.name ?? "");
        const fn = tools[name];
        if (!fn) return fail(-32602, `unknown tool: ${name}`);
        try {
          const text = await fn((msg.params?.arguments ?? {}) as Record<string, unknown>);
          return reply({ content: [{ type: "text", text }] });
        } catch (e) {
          return reply({ content: [{ type: "text", text: e instanceof ToolError ? e.message : "internal error" }], isError: true });
        }
      }
      default:
        return fail(-32601, `method not found: ${msg.method}`);
    }
  };
}

/** Serve on stdio until stdin closes. Diagnostics go to stderr only (stdout is the protocol). */
export function runStdioServer(o: McpOptions, input: Readable = process.stdin, output: Writable = process.stdout): Promise<void> {
  const handle = createMcpHandler(o);
  const rl = createInterface({ input, crlfDelay: Infinity });
  const pending: Promise<void>[] = [];
  rl.on("line", (line) => {
    if (!line.trim()) return;
    pending.push(
      (async () => {
        let parsed: unknown;
        try {
          parsed = JSON.parse(line);
        } catch {
          output.write(`${JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } })}\n`);
          return;
        }
        const batch = Array.isArray(parsed);
        const res = (await Promise.all((batch ? (parsed as unknown[]) : [parsed]).map(handle))).filter((x: unknown) => x !== null);
        if (res.length) output.write(`${JSON.stringify(batch ? res : res[0])}\n`);
      })(),
    );
  });
  return new Promise((resolve) => rl.on("close", () => void Promise.all(pending).then(() => resolve())));
}
