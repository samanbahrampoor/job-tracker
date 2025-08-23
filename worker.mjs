// worker.mjs
//
// Cloudflare Worker for Job Tracker
// - GitHub OAuth (start + callback) and signed session cookie (HS256 JWT)
// - CORS for GitHub Pages
// - D1-backed API for per-user "applied" job status
// - Alias route /oauth/login?redirect=... for compatibility
//
// REQUIRED ENV & BINDINGS (wrangler.toml)
//
// name = "job-tracker-oauth"
// main = "worker.mjs"
// compatibility_date = "2024-11-01"
// account_id = "<your account id>"
//
// [vars]
// PAGES_ORIGIN = "https://samanbahrampoor.github.io"
// APP_REDIRECT  = "https://samanbahrampoor.github.io/job-tracker/jobs.html"
// OAUTH_REDIRECT_URI = "https://job-tracker-oauth.<your-subdomain>.workers.dev/auth/github/callback"
//
// [[d1_databases]]
// binding = "DB"
// database_name = "job-tracker"
// database_id = "<UUID from `wrangler d1 create job-tracker`>"
//
// If you keep Durable Objects, also have in wrangler.toml:
// [durable_objects]
// bindings = [{ name = "APP_SYNC", class_name = "AppSync" }]
// [[migrations]]
// tag = "v1"                # or v2, v3… (unique per change)
// new_sqlite_classes = ["AppSync"]
//
// Secrets (set with `wrangler secret put ...`):
// - GITHUB_CLIENT_ID
// - GITHUB_CLIENT_SECRET
// - JWT_SECRET
//
// D1 schema (apply via migrations before deploy):
// CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT);
// CREATE TABLE IF NOT EXISTS applications (
//   user_id TEXT NOT NULL,
//   job_id  TEXT NOT NULL,
//   applied INTEGER NOT NULL,
//   updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
//   PRIMARY KEY (user_id, job_id),
//   FOREIGN KEY (user_id) REFERENCES users(id)
// );

////////////////////////////////////////////////////////////////////////////////
// Small utils
////////////////////////////////////////////////////////////////////////////////

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

async function jwtSignHS256(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const h = b64u.encJSON(header);
  const p = b64u.encJSON(payload);
  const data = `${h}.${p}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return `${data}.${b64u.enc(new Uint8Array(sig))}`;
}

async function jwtVerifyHS256(token, secret) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  let header;
  try {
    header = b64u.decJSON(h);
    if (header.alg !== "HS256" || header.typ !== "JWT") return null;
  } catch { return null; }

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
    b64u.decToBytes(s),
    new TextEncoder().encode(`${h}.${p}`)
  );
  if (!ok) return null;

  let payload;
  try { payload = b64u.decJSON(p); } catch { return null; }
  if (payload.exp && Date.now() / 1000 > payload.exp) return null;
  return payload;
}

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

function json(status, data, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...extra }
  });
}

function withCORS(res, origin) {
  const h = new Headers(res.headers);
  h.set("Access-Control-Allow-Origin", origin);
  h.set("Access-Control-Allow-Credentials", "true");
  h.set("Vary", "Origin");
  return new Response(res.body, { status: res.status, headers: h });
}

function preflight(origin, methods = "GET,PUT,POST,OPTIONS") {
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

async function requireUser(req, env) {
  const token = getCookie(req, "session");
  if (!token) return null;
  const payload = await jwtVerifyHS256(token, env.JWT_SECRET);
  if (!payload || !payload.sub) return null;
  return { id: String(payload.sub), email: payload.email || null };
}

async function ensureUser(env, user) {
  await env.DB.prepare(
    "INSERT OR IGNORE INTO users (id, email) VALUES (?, ?)"
  ).bind(user.id, user.email).run();
}

////////////////////////////////////////////////////////////////////////////////
// GitHub OAuth helpers
////////////////////////////////////////////////////////////////////////////////

function githubAuthorizeURL(env, state) {
  const u = new URL("https://github.com/login/oauth/authorize");
  u.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  u.searchParams.set("redirect_uri", env.OAUTH_REDIRECT_URI);
  u.searchParams.set("scope", "read:user user:email");
  u.searchParams.set("state", state);
  return u.toString();
}

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

// lightweight CSRF state based on HMAC(secret, timestamp)
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
  const age = Math.floor(Date.now() / 1000) - parseInt(ts, 10);
  if (isNaN(age) || age > 600) return false;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.JWT_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
  return await crypto.subtle.verify(
    "HMAC",
    key,
    b64u.decToBytes(encSig),
    new TextEncoder().encode(ts)
  );
}

////////////////////////////////////////////////////////////////////////////////
// Worker
////////////////////////////////////////////////////////////////////////////////

export default {
  /**
   * @param {Request} req
   * @param {{ DB:any, JWT_SECRET:string, GITHUB_CLIENT_ID:string, GITHUB_CLIENT_SECRET:string, PAGES_ORIGIN:string, APP_REDIRECT:string, OAUTH_REDIRECT_URI:string }} env
   * @param {ExecutionContext} ctx
   */
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const method = req.method;
    const ORIGIN = env.PAGES_ORIGIN || "https://samanbahrampoor.github.io";

    // Preflight
    if (method === "OPTIONS") return preflight(ORIGIN);

    // Enforce allowed Origin for /api/* routes
    const origin = req.headers.get("Origin");
    if (origin && origin !== ORIGIN && url.pathname.startsWith("/api/")) {
      return withCORS(json(403, { error: "Forbidden origin" }), ORIGIN);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Auth routes
    ////////////////////////////////////////////////////////////////////////////

    // (Alias) Support old /oauth/login?redirect=...
    if (url.pathname === "/oauth/login" && method === "GET") {
      const desired = url.searchParams.get("redirect");
      const headers = new Headers();
      if (desired) {
        headers.append("Set-Cookie", setCookieHeader("post_login_redirect", desired, {
          Path: "/",
          HttpOnly: true,
          Secure: true,
          SameSite: "Lax", // same-site during redirects
          "Max-Age": 600
        }));
      }
      const state = await buildState(env);
      headers.append("Set-Cookie", setCookieHeader("oauth_state", state, {
        Path: "/",
        HttpOnly: true,
        Secure: true,
        SameSite: "Lax",
        "Max-Age": 600
      }));
      headers.set("Location", githubAuthorizeURL(env, state));
      return new Response(null, { status: 302, headers });
    }

    // Start OAuth
    if (url.pathname === "/auth/github/start" && method === "GET") {
      const state = await buildState(env);
      const headers = new Headers();
      headers.append("Set-Cookie", setCookieHeader("oauth_state", state, {
        Path: "/",
        HttpOnly: true,
        Secure: true,
        SameSite: "Lax",
        "Max-Age": 600
      }));
      headers.set("Location", githubAuthorizeURL(env, state));
      return new Response(null, { status: 302, headers });
    }

    // OAuth callback
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
        const email = profile.email ? String(profile.email) : null;

        // Issue session JWT (30d)
        const now = Math.floor(Date.now() / 1000);
        const payload = { sub: userId, email, iat: now, exp: now + 60 * 60 * 24 * 30 };
        const sessionToken = await jwtSignHS256(payload, env.JWT_SECRET);

        // Ensure user exists
        await ensureUser(env, { id: userId, email });

        const headers = new Headers();

        // IMPORTANT for cross-site fetch from github.io → workers.dev:
        headers.append("Set-Cookie", setCookieHeader("session", sessionToken, {
          Path: "/",
          HttpOnly: true,
          Secure: true,
          SameSite: "None",
          "Max-Age": 60 * 60 * 24 * 30
        }));

        // Clear oauth_state
        headers.append("Set-Cookie", setCookieHeader("oauth_state", "", {
          Path: "/",
          HttpOnly: true,
          Secure: true,
          SameSite: "Lax",
          "Max-Age": 0
        }));

        // Optional post-login redirect override
        const desired = getCookie(req, "post_login_redirect");
        headers.append("Set-Cookie", setCookieHeader("post_login_redirect", "", {
          Path: "/",
          HttpOnly: true,
          Secure: true,
          SameSite: "Lax",
          "Max-Age": 0
        }));

        const safeDesired =
          desired && /^https:\/\/samanbahrampoor\.github\.io\/job-tracker\//.test(desired)
            ? desired
            : (env.APP_REDIRECT || ORIGIN);

        headers.set("Location", safeDesired);
        return new Response(null, { status: 302, headers });
      } catch (e) {
        return json(500, { error: "oauth_callback_failed", detail: String(e) });
      }
    }

    ////////////////////////////////////////////////////////////////////////////
    // API routes
    ////////////////////////////////////////////////////////////////////////////

    if (url.pathname === "/api/me" && method === "GET") {
      const user = await requireUser(req, env);
      const res = user ? json(200, { user }) : json(401, { error: "unauthorized" });
      return withCORS(res, ORIGIN);
    }

    if (url.pathname === "/api/applications" && method === "GET") {
      const user = await requireUser(req, env);
      if (!user) return withCORS(json(401, { error: "unauthorized" }), ORIGIN);

      await ensureUser(env, user);
      const { results } = await env.DB
        .prepare("SELECT job_id, applied FROM applications WHERE user_id = ?")
        .bind(user.id)
        .all();

      return withCORS(json(200, { items: results || [] }), ORIGIN);
    }

    if (url.pathname.startsWith("/api/applications/") && method === "PUT") {
      const user = await requireUser(req, env);
      if (!user) return withCORS(json(401, { error: "unauthorized" }), ORIGIN);

      const jobId = decodeURIComponent(url.pathname.split("/").pop() || "");
      if (!jobId) return withCORS(json(400, { error: "missing job_id" }), ORIGIN);

      let body = {};
      try { body = await req.json(); } catch {}
      const applied = !!body.applied;

      await env.DB.prepare(
        `INSERT INTO applications (user_id, job_id, applied, updated_at)
         VALUES (?, ?, ?, unixepoch())
         ON CONFLICT(user_id, job_id)
         DO UPDATE SET applied = excluded.applied, updated_at = unixepoch()`
      ).bind(user.id, jobId, applied ? 1 : 0).run();

      return withCORS(json(200, { ok: true, job_id: jobId, applied }), ORIGIN);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Default route
    ////////////////////////////////////////////////////////////////////////////

    if (url.pathname === "/" && method === "GET") {
      const msg = {
        ok: true,
        routes: [
          "GET  /oauth/login?redirect=<url>   (alias)",
          "GET  /auth/github/start",
          "GET  /auth/github/callback",
          "GET  /api/me",
          "GET  /api/applications",
          "PUT  /api/applications/:job_id"
        ],
        origin: ORIGIN
      };
      return new Response(JSON.stringify(msg, null, 2), {
        headers: { "content-type": "application/json" }
      });
    }

    return new Response("not found", { status: 404 });
  }
};

////////////////////////////////////////////////////////////////////////////////
// Minimal Durable Object export to satisfy binding
////////////////////////////////////////////////////////////////////////////////
export class AppSync {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }
  async fetch(req) {
    // No behavior yet; DO is present only to satisfy binding.
    return new Response("OK");
  }
}
