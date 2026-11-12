// Local web GUI server (§10-1). 127.0.0.1 only, OS-assigned port, a per-run token handed to the
// page in the URL fragment, an HttpOnly session cookie named after the port, and both the cookie
// and the X-Checkback-Token header on every API call. Host/Origin are checked on every request;
// no CORS headers are ever sent. There is no API that takes a path: the target is the CWD.

import { randomBytes, timingSafeEqual } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { createRoutes, type ApiError, type GuiContext } from "./routes.js";

export const TOKEN_HEADER = "x-checkback-token";
const MAX_BODY = 2 * 1024 * 1024; // template import is 1 MB of YAML inside JSON
const IDLE_MS = 30 * 60_000;

const ROOT = new URL("../../", import.meta.url); // package root from src/gui and dist/gui alike
const SECURITY_HEADERS = {
  "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
};
const TYPES: Record<string, string> = { html: "text/html; charset=utf-8", css: "text/css; charset=utf-8", js: "text/javascript; charset=utf-8", svg: "image/svg+xml", woff2: "font/woff2" };

export interface GuiOptions extends Omit<GuiContext, "appDir"> {
  appDir?: string;
  /** Exit after this long without API calls (all tabs closed). Default 30 min. */
  idleMs?: number;
  onIdle?: () => void;
}

export interface GuiServer {
  url: string;
  port: number;
  server: Server;
  /** Route keys ("METHOD /path"), for the AC5 route-list test. */
  routes: string[];
  close: () => Promise<void>;
}

/** Static files: a fixed map built at start-up from known folders, never from the request path. */
async function staticFiles(): Promise<Map<string, { type: string; body: Buffer }>> {
  const files = new Map<string, { type: string; body: Buffer }>();
  const add = async (urlPath: string, file: URL): Promise<void> => {
    const ext = file.pathname.split(".").pop()!;
    const body = await readFile(file).catch(() => null);
    if (body && TYPES[ext]) files.set(urlPath, { type: TYPES[ext]!, body });
  };
  await add("/", new URL("web/index.html", ROOT));
  await add("/app.css", new URL("web/app.css", ROOT));
  await add("/favicon.svg", new URL("web/favicon.svg", ROOT));
  // The UI typeface ships in the package: the page loads nothing from the network.
  await add("/fonts/PretendardVariable.woff2", new URL("web/fonts/PretendardVariable.woff2", ROOT));
  const js = new URL("dist/web/", ROOT);
  const walk = async (dir: URL, prefix: string): Promise<void> => {
    for (const e of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
      if (e.isDirectory() && /^[a-z0-9-]+$/.test(e.name)) await walk(new URL(`${e.name}/`, dir), `${prefix}${e.name}/`);
      else if (/^[a-z0-9-]+\.js$/.test(e.name)) await add(`/${prefix}${e.name}`, new URL(e.name, dir));
    }
  };
  await walk(js, "");
  return files;
}

const same = (a: string | undefined, b: string): boolean => {
  if (typeof a !== "string") return false;
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

function cookieOf(req: IncomingMessage, name: string): string | undefined {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return undefined;
}

function readBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(Object.assign(new Error("too large"), { status: 413 }));
        req.destroy();
      } else chunks.push(c);
    });
    req.on("end", () => {
      if (!chunks.length) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        reject(Object.assign(new Error("bad json"), { status: 400 }));
      }
    });
    req.on("error", reject);
  });
}

export async function startGui(o: GuiOptions): Promise<GuiServer> {
  const { defaultAppDir } = await import("../appdata.js");
  const ctx: GuiContext = { ...o, appDir: o.appDir ?? defaultAppDir() };
  const token = randomBytes(32).toString("hex");
  const sessions = new Set<string>();
  const files = await staticFiles();
  const { routes, stop } = createRoutes(ctx);
  let port = 0;
  let lastSeen = Date.now();

  const send = (res: ServerResponse, status: number, body?: unknown, headers: Record<string, string> = {}): void => {
    res.writeHead(status, { ...SECURITY_HEADERS, "Cache-Control": "no-store", ...(body !== undefined && { "Content-Type": "application/json; charset=utf-8" }), ...headers });
    res.end(body === undefined ? undefined : JSON.stringify(body));
  };

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const host = req.headers.host ?? "";
    if (host !== `127.0.0.1:${port}` && host !== `localhost:${port}`) return send(res, 403, { error: "forbidden_host" });
    const self = `http://${host}`;
    const origin = req.headers.origin;
    if (origin !== undefined && origin !== self) return send(res, 403, { error: "forbidden_origin" });
    const path = (req.url ?? "/").split("?")[0]!;
    const method = req.method ?? "GET";

    if (!path.startsWith("/api/")) {
      const f = method === "GET" || method === "HEAD" ? files.get(path) : undefined;
      if (!f) return send(res, 404, { error: "not_found" });
      res.writeHead(200, { ...SECURITY_HEADERS, "Content-Type": f.type, "Cache-Control": "no-cache" });
      res.end(method === "HEAD" ? undefined : f.body);
      return;
    }

    // State-changing calls must carry our exact Origin (browsers always send it on POST).
    if (method !== "GET" && origin !== self) return send(res, 403, { error: "forbidden_origin" });
    if (method === "POST" && !/^application\/json\b/i.test(req.headers["content-type"] ?? "")) return send(res, 415, { error: "json_only" });
    const cookieName = `checkback_s_${port}`;
    const hasSession = (): boolean => {
      const c = cookieOf(req, cookieName);
      return !!c && [...sessions].some((s) => same(c, s));
    };

    if (path === "/api/session" && method === "POST") {
      if (!same(req.headers[TOKEN_HEADER] as string | undefined, token)) return send(res, 401, { error: "unauthorized" });
      const sid = randomBytes(32).toString("hex");
      sessions.add(sid);
      lastSeen = Date.now();
      return send(res, 204, undefined, { "Set-Cookie": `${cookieName}=${sid}; HttpOnly; SameSite=Strict; Path=/` });
    }
    if (path === "/api/token" && method === "GET") {
      // Reload: the cookie is the proof; Fetch Metadata (when sent) must say same-origin.
      const site = req.headers["sec-fetch-site"];
      if (!hasSession() || (site !== undefined && site !== "same-origin")) return send(res, 401, { error: "unauthorized" });
      return send(res, 200, { token });
    }
    if (!hasSession() || !same(req.headers[TOKEN_HEADER] as string | undefined, token)) return send(res, 401, { error: "unauthorized" });
    lastSeen = Date.now();

    const route = routes[`${method} ${path}`];
    if (!route) return send(res, 404, { error: "not_found" });
    let body: unknown = {};
    try {
      if (method === "POST") body = await readBody(req);
    } catch (e) {
      return send(res, (e as { status?: number }).status ?? 400, { error: "bad_request" });
    }
    try {
      const out = await route(typeof body === "object" && body !== null && !Array.isArray(body) ? (body as Record<string, unknown>) : {});
      return send(res, 200, out ?? {});
    } catch (e) {
      const err = e as ApiError;
      // Known errors carry a code for the screen; anything else stays generic (no stack to the page).
      if (err.status) return send(res, err.status, { error: err.code, ...(err.detail !== undefined && { detail: err.detail }) });
      process.stderr.write(`checkback gui: ${(e as Error).message}\n`);
      return send(res, 500, { error: "internal" });
    }
  };

  const server = createServer((req, res) => {
    handle(req, res).catch(() => {
      if (!res.headersSent) send(res, 500, { error: "internal" });
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve()); // loopback only, no option for other interfaces
  });
  port = (server.address() as AddressInfo).port;

  const idleMs = o.idleMs ?? IDLE_MS;
  const timer = setInterval(() => {
    if (Date.now() - lastSeen > idleMs) o.onIdle?.();
  }, Math.min(60_000, idleMs));
  timer.unref();

  return {
    url: `http://127.0.0.1:${port}/#t=${token}`,
    port,
    server,
    routes: Object.keys(routes),
    close: () => {
      clearInterval(timer);
      stop();
      const done = new Promise<void>((resolve) => server.close(() => resolve()));
      server.closeAllConnections();
      return done;
    },
  };
}
