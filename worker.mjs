// worker.mjs — alias-safe router + OAuth + KV status with CORS + Bearer token fallback

const SESSION_COOKIE = "sid";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days
const GH_AUTH_URL = "https://github.com/login/oauth/authorize";
const GH_TOKEN_URL = "https://github.com/login/oauth/access_token";
const GH_USER_API = "https://api.github.com/user";

// ---- route alias + path helpers ----
const ROUTE_ALIASES = new Map([
  ["/oauth/login", "/auth/start"],
  ["/login", "/auth/start"],
  ["/oauth/callback", "/auth/callback"],
  ["/callback", "/auth/callback"],
  ["/github/callback", "/auth/callback"],
  ["/oauth/logout", "/auth/logout"],
  ["/logout", "/auth/logout"],
]);

function normalizePath(p) {
  if (!p) return "/";
  return (p.length > 1 && p.endsWith("/")) ? p.slice(0, -1) : p;
}

function fixRedirect(redirect, allowedOrigin) {
  const fallback = (allowedOrigin || "https://samanbahrampoor.github.io") + "/job-tracker/jobs.html";
  try {
    const u = new URL(redirect);
    if (u.pathname.endsWith("/jobs.htm")) u.pathname += "l";
    return u.toString();
  } catch {
    return fallback;
  }
}

// Allow multiple origins via comma-separated env.ALLOWED_ORIGIN
function pickAllowedOrigin(request, env) {
  const reqOrigin = request.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGIN || "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);
  return allowed.includes(reqOrigin) ? reqOrigin : allowed[0] || "*";
}

function preflight(request, env) {
  const o = pickAllowedOrigin(request, env);
  return new Response(null, {
    headers: {
      "Access-Control-Allow-Origin": o,
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Allow-Methods": "GET,PUT,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Vary": "Origin",
    },
  });
}

function withCORS(res, request, env) {
  const o = pickAllowedOrigin(request, env);
  const headers = new Headers(res.headers);
  headers.set("Access-Control-Allow-Origin", o);
  headers.set("Access-Control-Allow-Credentials", "true");
  headers.append("Vary", "Origin");
  return new Response(res.body, { ...res, headers });
}

function getBearerSid(request) {
  const auth = request.headers.get("Authorization") || "";
  if (auth.startsWith("Bearer ")) return auth.slice(7).trim();
  return null;
}

function appendSidToRedirect(redirect, sid) {
  try {
    const u = new URL(redirect);
    const sp = new URLSearchParams(u.hash?.slice(1) || "");
    sp.set("sid", sid);
    u.hash = sp.toString();
    return u.toString();
  } catch {
    return redirect;
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = (env.ALLOWED_ORIGIN || "https://samanbahrampoor.github.io").split(",")[0];

    const path = normalizePath(url.pathname);
    const aliased = ROUTE_ALIASES.get(path) || path;

    if (aliased === "/favicon.ico") return new Response(null, { status: 204 });

    if (request.method === "OPTIONS" && aliased.startsWith("/api/")) {
      return preflight(request, env);
    }

    if (aliased === "/") {
      return Response.redirect(`${origin}/job-tracker/jobs.html`, 302);
    }

    // ---- Auth routes ----
    if (aliased === "/auth/start") {
      const r = url.searchParams.get("redirect");
      if (r) url.searchParams.set("redirect", fixRedirect(r, origin));
      return authStart(new Request(url.toString(), request), env);
    }
    if (aliased === "/auth/callback") return authCallback(request, env);
    if (aliased === "/auth/logout")   return authLogout(request, env, origin);

    // ---- APIs ----
    if (aliased === "/api/status") {
      const user = await getUserFromSession(request, env);
      if (!user) {
        return withCORS(new Response(JSON.stringify({ error: "unauthorized" }), {
          status: 401, headers: { "Content-Type": "application/json" }
        }), request, env);
      }
      const key = `user:${user.login}:applied`;
      if (request.method === "GET") {
        const data = await env.JOBS_KV.get(key);
        return withCORS(new Response(data ?? "{}", { headers: { "Content-Type": "application/json" } }), request, env);
      }
      if (request.method === "PUT") {
        let body = {};
        try { body = await request.json(); } catch {}
        await env.JOBS_KV.put(key, JSON.stringify(body));
        return withCORS(new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" } }), request, env);
      }
      return withCORS(new Response("Method not allowed", { status: 405 }), request, env);
    }

    if (aliased === "/api/whoami") {
      const user = await getUserFromSession(request, env);
      return withCORS(new Response(JSON.stringify({ user: user ? { login: user.login, id: user.id } : null }), {
        headers: { "Content-Type": "application/json" }
      }), request, env);
    }

    return new Response("Not found", { status: 404 });
  }
};

// ---------- OAuth handlers ----------
async function authStart(request, env) {
  const url = new URL(request.url);
  const redirect = url.searchParams.get("redirect") || (env.ALLOWED_ORIGIN || "") + "/job-tracker/jobs.html";
  const state = crypto.randomUUID();
  await env.JOBS_KV.put(`oauth:state:${state}`, redirect, { expirationTtl: 600 });

  const clientId = env.GITHUB_CLIENT_ID || await getSecret(env, "GITHUB_CLIENT_ID");
  const authorizeUrl = new URL(GH_AUTH_URL);
  authorizeUrl.searchParams.set("client_id", clientId);
  authorizeUrl.searchParams.set("scope", "read:user");
  authorizeUrl.searchParams.set("state", state);
  return Response.redirect(authorizeUrl.toString(), 302);
}

async function authCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) return new Response("Missing code/state", { status: 400 });

  const redirect = await env.JOBS_KV.get(`oauth:state:${state}`);
  if (!redirect) return new Response("Invalid state", { status: 400 });
  await env.JOBS_KV.delete(`oauth:state:${state}`);

  const clientId = env.GITHUB_CLIENT_ID || await getSecret(env, "GITHUB_CLIENT_ID");
  const clientSecret = await getSecret(env, "GITHUB_CLIENT_SECRET");

  const tokenRes = await fetch(GH_TOKEN_URL, {
    method: "POST",
    headers: { "Accept": "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code })
  });
  if (!tokenRes.ok) return new Response("Token exchange failed", { status: 500 });
  const tokenJson = await tokenRes.json();
  const accessToken = tokenJson.access_token;
  if (!accessToken) return new Response("No access token", { status: 500 });

  const userRes = await fetch(GH_USER_API, {
    headers: { "Accept": "application/json", "Authorization": `Bearer ${accessToken}`, "User-Agent": "job-tracker-worker" }
  });
  if (!userRes.ok) return new Response("User fetch failed", { status: 500 });
  const ghUser = await userRes.json();

  if (env.ALLOWED_LOGIN && env.ALLOWED_LOGIN !== ghUser.login) {
    return new Response("Forbidden", { status: 403 });
  }

  const sid = crypto.randomUUID();
  const session = { login: ghUser.login, id: ghUser.id };
  await env.JOBS_KV.put(`sess:${sid}`, JSON.stringify(session), { expirationTtl: SESSION_TTL_SECONDS });

  const redirectWithSid = appendSidToRedirect(redirect, sid);
  const headers = new Headers();
  headers.append("Set-Cookie", cookieSet(SESSION_COOKIE, sid, {
    httpOnly: true, secure: true, sameSite: "None", path: "/", maxAge: SESSION_TTL_SECONDS
  }));
  headers.append("Location", redirectWithSid);
  return new Response(null, { status: 302, headers });
}

async function authLogout(request, env, origin) {
  const url = new URL(request.url);
  const redirect = url.searchParams.get("redirect") || (origin + "/job-tracker/jobs.html");
  const sid = cookieGet(request.headers.get("Cookie") || "", SESSION_COOKIE);
  if (sid) await env.JOBS_KV.delete(`sess:${sid}`);

  const headers = new Headers();
  headers.append("Set-Cookie", cookieSet(SESSION_COOKIE, "", {
    httpOnly: true, secure: true, sameSite: "None", path: "/", maxAge: 0
  }));
  headers.append("Location", redirect);
  return new Response(null, { status: 302, headers });
}

// ---------- Session + utils ----------
async function getUserFromSession(request, env) {
  // Bearer takes priority (works even with 3rd-party cookies blocked)
  const bearerSid = getBearerSid(request);
  if (bearerSid) {
    const json = await env.JOBS_KV.get(`sess:${bearerSid}`);
    if (json) { try { return JSON.parse(json); } catch {} }
  }

  // Fallback to cookie
  const cookie = request.headers.get("Cookie") || "";
  const sid = cookieGet(cookie, SESSION_COOKIE);
  if (sid) {
    const json = await env.JOBS_KV.get(`sess:${sid}`);
    if (json) { try { return JSON.parse(json); } catch {} }
  }
  return null;
}

function cookieGet(cookieHeader, name) {
  const m = cookieHeader.match(new RegExp("(^|; )" + name.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&") + "=([^;]*)"));
  return m ? decodeURIComponent(m[2]) : null;
}
function cookieSet(name, value, opts = {}) {
  const p = [];
  p.push(`${name}=${encodeURIComponent(value)}`);
  if (opts.path) p.push(`Path=${opts.path}`);
  if (opts.maxAge !== undefined) p.push(`Max-Age=${opts.maxAge}`);
  if (opts.sameSite) p.push(`SameSite=${opts.sameSite}`);
  if (opts.secure) p.push("Secure");
  if (opts.httpOnly) p.push("HttpOnly");
  return p.join("; ");
}

async function getSecret(env, key) {
  const v = env[key];
  if (!v) throw new Error(`Missing secret/env: ${key}`);
  return v;
}
