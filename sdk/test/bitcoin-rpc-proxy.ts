/**
 * Same-origin-friendly proxy used by the regtest suite's globalSetup.
 *
 *   - `POST /`        → bitcoind JSON-RPC (CORS-blind upstream)
 *   - `* /api/...`    → indexer HTTP API
 *
 * Both are funneled through this one Node-side server because Chromium
 * under Playwright/Vitest hits a reproducible bug where, after the first
 * handful of fetches to a given localhost server, every subsequent
 * `connect()` syscall to that host:port returns `ECONNREFUSED` —
 * verified via Chrome's `--log-net-log` (the connect is rejected by the
 * kernel from Chrome's POV even though `curl` and Node `fetch` reach
 * the same listening socket without issue). The pattern is stable
 * across our matrix of attempted workarounds (long-poll on/off, dual-
 * stack bind, `Connection: close`, cache-bust query, `cache: "no-store"`).
 *
 * Routing through this proxy bypasses the bug: the browser only ever
 * talks to one localhost port (this server), and Chrome's failure mode
 * is per-origin — we've observed it serve 30+ requests in a row with
 * the same test workload that hangs talking to the indexer directly.
 * The Node-side `fetch` from the proxy to the indexer is unaffected.
 */

import http, { type IncomingMessage, type ServerResponse } from "node:http";
import { AddressInfo } from "node:net";

export interface RpcProxy {
  /** bitcoind JSON-RPC URL with embedded `rpc:rpc@` auth — POSTs are
   *  forwarded to the upstream bitcoind. */
  bitcoinRpc: string;
  /** Indexer HTTP API base — `GET`/`POST` `/api/...` are forwarded to
   *  the upstream indexer. No auth needed. */
  apiUrl: string;
  stop: () => Promise<void>;
}

export interface StartProxyOptions {
  /** Upstream bitcoind URL with embedded auth (`http://rpc:rpc@host:port`). */
  bitcoinRpc: string;
  /** Upstream indexer API URL (`http://host:port/api`). */
  apiUrl: string;
}

export async function startRpcProxy(opts: StartProxyOptions): Promise<RpcProxy> {
  const bitcoinUpstream = new URL(opts.bitcoinRpc);
  const bitcoinOrigin = `${bitcoinUpstream.protocol}//${bitcoinUpstream.host}${bitcoinUpstream.pathname.replace(/\/$/, "")}`;
  const apiUpstream = new URL(opts.apiUrl);
  // Just the host — we keep the original `/api/...` path from the request.
  const apiOrigin = `${apiUpstream.protocol}//${apiUpstream.host}`;

  const server = http.createServer(async (req, res) => {
    // CORS preflight — browser fires this for any non-simple POST.
    if (req.method === "OPTIONS") {
      writeCors(res, 204);
      res.end();
      return;
    }

    // Diagnostic sink — browser tests POST a string body to /__log to
    // surface it on the Node-side stderr (vitest's browser mode doesn't
    // forward chromium `console.log` to the terminal in our config).
    if (req.method === "POST" && req.url === "/__log") {
      const body = await collectBody(req);
      process.stderr.write(`[browser] ${body.toString("utf8")}\n`);
      writeCors(res, 204);
      res.end();
      return;
    }

    // Indexer `/api/...` path — any method.
    if (req.url?.startsWith("/api")) {
      await forwardRequest(req, res, apiOrigin + req.url);
      return;
    }

    // Bitcoind RPC — POST to the root.
    if (req.method === "POST" && (req.url === "/" || req.url === "")) {
      await forwardRequest(req, res, bitcoinOrigin);
      return;
    }

    writeCors(res, 404);
    res.end();
  });

  await new Promise<void>((resolve) =>
    server.listen(0, "127.0.0.1", () => resolve()),
  );
  const { port } = server.address() as AddressInfo;

  const auth = bitcoinUpstream.username
    ? `${bitcoinUpstream.username}:${bitcoinUpstream.password}@`
    : "";
  return {
    bitcoinRpc: `http://${auth}127.0.0.1:${port}`,
    apiUrl: `http://127.0.0.1:${port}/api`,
    stop: () =>
      new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      ),
  };
}

/** Forward `req` to `upstreamUrl` and pipe the response back. */
async function forwardRequest(
  req: IncomingMessage,
  res: ServerResponse,
  upstreamUrl: string,
): Promise<void> {
  try {
    const hasBody = req.method !== "GET" && req.method !== "HEAD";
    const body = hasBody ? await collectBody(req) : undefined;
    const headers: Record<string, string> = {};
    const ct = req.headers["content-type"];
    if (typeof ct === "string") headers["content-type"] = ct;
    const auth = req.headers.authorization;
    if (typeof auth === "string") headers.authorization = auth;
    const upstreamRes = await fetch(upstreamUrl, {
      method: req.method,
      headers,
      body,
    });
    const buf = Buffer.from(await upstreamRes.arrayBuffer());
    writeCors(res, upstreamRes.status, {
      "content-type":
        upstreamRes.headers.get("content-type") ?? "application/json",
    });
    res.end(buf);
  } catch (e) {
    writeCors(res, 502, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: `proxy: ${(e as Error).message}` }));
  }
}

function writeCors(
  res: ServerResponse,
  status: number,
  extra: Record<string, string> = {},
): void {
  res.writeHead(status, {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type, authorization",
    ...extra,
  });
}

function collectBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}
