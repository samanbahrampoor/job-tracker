// worker.mjs
//
// Drop-in Cloudflare Worker that:
// 1) Performs GitHub OAuth (start + callback) and sets a signed session cookie (HS256 JWT)
// 2) Exposes JSON APIs for per-user job "applied" state stored in D1
//    - GET  /api/me
//    - GET  /api/applications
//    - PUT  /api/applications/:job_id   body: { applied: true|false }
// 3) Handles CORS for your GitHub Pages origin
//
// REQUIRED BINDINGS (wrangler.toml):
// ------------------------------------------------------
// account_id = "<your account id>"
// name = "<your worker name>"
// main = "worker.mjs"
//
// [[d1_databases]]
// binding = "DB"
// database_name = "job-tracker"
// database_id = "<UUID from `wrangler d1 create job-tracker`>"
//
// [vars]
// // The origin that is allowed to call your APIs (GitHub Pages):
// PAGES_ORIGIN = "https://samanbahrampoor.github.io"
// // Where to send the user after login:
// APP_REDIRECT = "https://samanbahrampoor.github.io/job-tracker/jobs.html"
// // Your deployed callback URL. Example: "https://<your-worker-subdomain>.workers.dev/auth/github/callback"
// OAUTH_REDIRECT_URI = "https://<your-worker-domain>/auth/github/callback"
// OAUTH_PROVIDER = "github"
//
// SECRETS (set with `wrangler secret put ...`):
// ------------------------------------------------------
// GITHUB_CLIENT_ID
// GITHUB_CLIENT_SECRET
// JWT_SECRET
//
// D1 SCHEMA (run via migration before deploying this file):
// ------------------------------------------------------
// CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT);
// CREATE TABLE IF NOT EXISTS applications (
//   user_id TEXT NOT NULL,
//   job_id  TEXT NOT NULL,
//   applied INTEGER NOT NULL,
//   updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
//   PRIMARY KEY (user_id, job_id),
//   FOREIGN KEY (user_id) REFERENCES users(id)
// );
//
// ------------------------------------------------------

/** @typedef {import('@cloudflare/workers-types').D1Database} D1Database */

/** Utility: base64url helpers for JWT */
const b64u = {
  enc(bytes) {
    let s = btoa(String.fromCharCode(...new Uint8Array(bytes)));
    return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  },
  decToBytes(b64url) {
    const s = b64url.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64url.length + 3) % 4);
    const bin = atob(s);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  },
  encJSON(obj) {
    return b64u.enc(new TextEncoder().encode(JSON.stringify(obj)));
  },
  decJSON(b64url) {
    return JSON.parse(new TextDecoder().decode(b64u.decToBytes(b64url)));
  }
};

/** Create HS256 JWT */
async function jwtSignHS256(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const encHeader = b64u.encJSON(header);
  const encPayload = b64u.encJSON(payload);
  const toSign = `${encHeader}.${encPayload}`;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(toSign));
  const encSig = b64u.enc(new Uint8Array(sig));
  return `${toSign}.${encSig}`;
}

/** Verify HS256 JWT; returns payload or null */
async function jwtVerifyHS256(token, secret) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [encHeader, encPayload, encSig] = parts;
  let header;
  try {
    header = b64u.decJSON(encHeader);
    if (header.alg !== "HS256" || header.typ !== "JWT") return null;
  } catch {
    return null;
  }
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const ok = await crypto.subtle.verify(
    "HMAC",
    key,
    b64u.decToBytes(encSig),
    new TextEncoder().encode(`${encHeader}.${encPayload}`)
  );
  if (!ok) return null;
  try {
    const payload = b64u.decJSON(encPayload);
    // Optional: basic exp check if present
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

/** Cookie helpers */
function getCookie(req, name) {
  const cookie = req.headers.get("cookie") || "";
  const m = cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return m ? decodeURIComponent(m[1]) : null;
}
function setCookieHeader(name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (opts.Path) parts.push(`Path=${opts.Path}`);
  if (opts.HttpOnly) parts.push(`HttpOnly`);
  if (opts.Secure) parts.push(`Secure`);
  if (opts.SameSite) parts.push(`SameSite=${opts.SameSite}`);
  if (typeof opts["Max-Age"] === "number") parts.push(`Max-Age=${opts["Max-Age"]}`);
  if (opts.Domain) parts.push(`Domain=${opts.Domain}`);
  return parts.join("; ");
}

/** CORS helpers */
function withCORS(res, origin) {
  const h = new Headers(res.headers);
  h.set("Access-Control-Allow-Origin", origin);
  h.set("Access-Control-Allow-Credentials", "true");
  h.set("Vary", "Origin");
  return new Response(res.body, { status: res.status, headers: h });
}
function preflight(origin, methods = "GET,PUT,OPTIONS") {
  return withCORS(
    new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Headers": "content-type",
        "Access-Control-Allow-Methods": methods
      }
    }),
    origin
  );
}
function json(status, data, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...extra }
  });
}

/** Require user session from cookie */
async function requireUser(req, env) {
  const token = getCookie(req, "session");
  if (!token) return null;
  const payload = await jwtVerifyHS256(token, env.JWT_SECRET);
  if (!payload || !payload.sub) return null;
  return { id: String(payload.sub), email: payload.email || null };
}

/** GitHub OAuth helper: exchange code for token */
async function githubExchangeCodeForToken(code, env) {
  const body = new URLSearchParams({
    client_id: env.GITHUB_CLIENT_ID,
    client_secret: env.GITHUB_CLIENT_SECRET,
    code,
    redirect_uri: env.OAUTH_REDIRECT_URI
  });
  const r = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { Accept: "application/json" },
    body
  });
  if (!r.ok) throw new Error(`GitHub token exchange failed: ${r.status}`);
  const j = await r.json();
  if (!j.access_token) throw new Error("No access_token in exchange response");
  return j.access_token;
}

/** GitHub API: get user profile */
async function githubGetUser(accessToken) {
  const r = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "job-tracker-worker"
    }
  });
  if (!r.ok) throw new Error(`GitHub /user failed: ${r.status}`);
  return r.json();
}

/** Build GitHub authorize URL */
function githubAuthorizeURL(env, state) {
  const u = new URL("https://github.com/login/oauth/authorize");
  u.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  u.searchParams.set("redirect_uri", env.OAUTH_REDIRECT_URI);
  u.searchParams.set("scope", "read:user user:email");
  u.searchParams.set("state", state);
  return u.toString();
}

/** CSRF state (lightweight): HMAC of timestamp */
async function buildState(env) {
  const ts = Math.floor(Date.now() / 1000).toString();
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.JWT_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(ts));
  return `${ts}.${b64u.enc(new Uint8Array(sig))}`;
}
async function verifyState(env, state) {
  if (!state) return false;
  const [ts, encSig] = state.split(".");
  if (!ts || !encSig) return false;
  // Optional: check freshness (e.g., 10 minutes)
  const age = Math.floor(Date.now() / 1000) - parseInt(ts, 10);
  if (isNaN(age) || age > 600) return false;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.JWT_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  const ok = await crypto.subtle.verify(
    "HMAC",
    key,
    b64u.decToBytes(encSig),
    new TextEncoder().encode(ts)
  );
  return ok;
}

/** Ensure user row exists in D1 */
async function ensureUser(env, user) {
  await env.DB.prepare(
    "INSERT OR IGNORE INTO users (id, email) VALUES (?, ?)"
  ).bind(user.id, user.email).run();
}

/** Main Worker */
export default {
  /**
   * @param {Request} req
   * @param {{ DB: D1Database, JWT_SECRET: string, GITHUB_CLIENT_ID: string, GITHUB_CLIENT_SECRET: string, PAGES_ORIGIN: string, APP_REDIRECT: string, OAUTH_REDIRECT_URI: string }} env
   * @param {ExecutionContext} ctx
   */
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const method = req.method;

    // Quick sanity for required vars
    const PAGES_ORIGIN = env.PAGES_ORIGIN || "https://samanbahrampoor.github.io";

    // OPTIONS preflight
    if (method === "OPTIONS") {
      return preflight(PAGES_ORIGIN, "GET,PUT,POST,OPTIONS");
    }

    // CSRF: only allow calls from configured origin for mutating endpoints
    const origin = req.headers.get("Origin");
    if (origin && origin !== PAGES_ORIGIN && url.pathname.startsWith("/api/")) {
      return withCORS(json(403, { error: "Forbidden origin" }), PAGES_ORIGIN);
    }

    // ----- Auth routes (GitHub) -----

    // Start OAuth: redirects user to GitHub
    if (url.pathname === "/auth/github/start" && method === "GET") {
      const state = await buildState(env);
      // set a small, short-lived cookie with the state (defense-in-depth)
      const headers = new Headers();
      headers.append(
        "Set-Cookie",
        setCookieHeader("oauth_state", state, {
          Path: "/",
          HttpOnly: true,
          Secure: true,
          SameSite: "Lax",
          "Max-Age": 600
        })
      );
      headers.set("Location", githubAuthorizeURL(env, state));
      return new Response(null, { status: 302, headers });
    }

    // OAuth callback: exchanges code -> token; fetches profile; sets session cookie; redirects to app
    if (url.pathname === "/auth/github/callback" && method === "GET") {
      try {
        const code = url.searchParams.get("code");
        const state = url.searchParams.get("state");
        const stateCookie = getCookie(req, "oauth_state");

        if (!code) return json(400, { error: "missing code" });
        if (!state || state !== stateCookie || !(await verifyState(env, state))) {
          return json(400, { error: "invalid state" });
        }

        const accessToken = await githubExchangeCodeForToken(code, env);
        const profile = await githubGetUser(accessToken);

        const userId = String(profile.id);
        // GitHub may return null email if private; ignore if not present
        const email = (profile.email && String(profile.email)) || null;

        // Issue a signed session (JWT)
        const now = Math.floor(Date.now() / 1000);
        const payload = {
          sub: userId,
          email,
          iat: now,
          exp: now + 60 * 60 * 24 * 30 // 30 days
        };
        const sessionToken = await jwtSignHS256(payload, env.JWT_SECRET);

        // Ensure user row exists
        await ensureUser(env, { id: userId, email });

        const headers = new Headers();
        headers.append(
          "Set-Cookie",
          setCookieHeader("session", sessionToken, {
            Path: "/",
            HttpOnly: true,
            Secure: true,
            SameSite: "Lax",
            "Max-Age": 60 * 60 * 24 * 30
          })
        );
        // Clear oauth_state cookie
        headers.append(
          "Set-Cookie",
          setCookieHeader("oauth_state", "", {
            Path: "/",
            HttpOnly: true,
            Secure: true,
            SameSite: "Lax",
            "Max-Age": 0
          })
        );
        headers.set("Location", env.APP_REDIRECT || PAGES_ORIGIN);
        return new Response(null, { status: 302, headers });
      } catch (e) {
        return json(500, { error: "oauth_callback_failed", detail: String(e) });
      }
    }

    // ----- Session inspection -----
    if (url.pathname === "/api/me" && method === "GET") {
      const user = await requireUser(req, env);
      const res = user ? json(200, { user }) : json(401, { error: "unauthorized" });
      return withCORS(res, PAGES_ORIGIN);
    }

    // ----- Applications API -----

    // GET: list of { job_id, applied } for the logged-in user
    if (url.pathname === "/api/applications" && method === "GET") {
      const user = await requireUser(req, env);
      if (!user) return withCORS(json(401, { error: "unauthorized" }), PAGES_ORIGIN);

      await ensureUser(env, user);

      const { results } = await env.DB
        .prepare("SELECT job_id, applied FROM applications WHERE user_id = ?")
        .bind(user.id)
        .all();

      return withCORS(json(200, { items: results || [] }), PAGES_ORIGIN);
    }

    // PUT: upsert a single job toggle
    // URL: /api/applications/:job_id
    if (url.pathname.startsWith("/api/applications/") && method === "PUT") {
      const user = await requireUser(req, env);
      if (!user) return withCORS(json(401, { error: "unauthorized" }), PAGES_ORIGIN);

      const jobId = decodeURIComponent(url.pathname.split("/").pop() || "");
      if (!jobId) return withCORS(json(400, { error: "missing job_id" }), PAGES_ORIGIN);

      let body = {};
      try {
        body = await req.json();
      } catch {}
      const applied = !!body.applied;

      await env.DB.prepare(
        `INSERT INTO applications (user_id, job_id, applied, updated_at)
         VALUES (?, ?, ?, unixepoch())
         ON CONFLICT(user_id, job_id)
         DO UPDATE SET applied = excluded.applied, updated_at = unixepoch()`
      )
        .bind(user.id, jobId, applied ? 1 : 0)
        .run();

      return withCORS(json(200, { ok: true, job_id: jobId, applied }), PAGES_ORIGIN);
    }

    // Fallback: simple index
    if (url.pathname === "/" && method === "GET") {
      const msg = {
        ok: true,
        routes: [
          "GET  /auth/github/start",
          "GET  /auth/github/callback",
          "GET  /api/me",
          "GET  /api/applications",
          "PUT  /api/applications/:job_id"
        ]
      };
      return new Response(JSON.stringify(msg, null, 2), {
        headers: { "content-type": "application/json" }
      });
    }

    // Not found
    return new Response("not found", { status: 404 });
  }
};
export class AppSync {
  constructor(state, env) { this.state = state; this.env = env; this.sockets = new Set(); }
  async fetch(req) {
    const { 0: client, 1: server } = new WebSocketPair();
    this.state.acceptWebSocket(server);
    return new Response(null, { status: 101, webSocket: client });
  }
  webSocketMessage(ws, msg) { /* ignore or handle pings */ }
  webSocketClose(ws) { this.sockets.delete(ws); }
  webSocketOpen(ws) { this.sockets.add(ws); }
  broadcast(obj) { for (const ws of this.sockets) ws.send(JSON.stringify(obj)); }
}