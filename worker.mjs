// worker.mjs (v2 with diagnostics and multi-origin support)
const ALLOWED_ORIGINS = [
  "https://samanbahrampoor.github.io",
  // Add dev origins if needed:
  // "http://localhost:5500",
  // "http://127.0.0.1:5500",
];

function pickOrigin(origin) {
  if (!origin) return ALLOWED_ORIGINS[0];
  return ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
}

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin",
  };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = pickOrigin(request.headers.get("Origin"));
    const headers = corsHeaders(origin);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers });
    }

    // Only allow requests from known origins (except direct curl which has no Origin)
    const reqOrigin = request.headers.get("Origin");
    if (reqOrigin && !ALLOWED_ORIGINS.includes(reqOrigin)) {
      return new Response("Forbidden origin", { status: 403, headers });
    }

    // Public ping (no auth)
    if (url.pathname === "/api/ping") {
      return json({ ok: true, time: Date.now() }, 200, headers);
    }

    // Whoami route to help debugging auth
    if (url.pathname === "/api/whoami") {
      const userId = await getUserIdFromRequest(request, env);
      return json({ userId: userId || null }, 200, headers);
    }

    // below requires auth
    const userId = await getUserIdFromRequest(request, env);
    if (!userId) {
      return json({ error: "unauthorized" }, 401, headers);
    }

    if (url.pathname === "/api/state" && request.method === "GET") {
      const key = `user:${userId}`;
      const doc = await env.JOB_STATE.get(key, "json");
      return json(doc || { applied: {} }, 200, headers);
    }

    if (url.pathname === "/api/state" && request.method === "POST") {
      let body;
      try { body = await request.json(); } catch {}
      const jobId = body?.jobId;
      const applied = body?.applied;
      if (!jobId || typeof applied !== "boolean") {
        return json({ error: "bad_request" }, 400, headers);
      }
      const key = `user:${userId}`;
      const doc = (await env.JOB_STATE.get(key, "json")) || { applied: {} };
      doc.applied[jobId] = { applied, updatedAt: Date.now() };
      await env.JOB_STATE.put(key, JSON.stringify(doc));
      return json({ ok: true }, 200, headers);
    }

    return new Response("Not found", { status: 404, headers });
  },
};

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

// Replace with your own session/JWT verification.
// This version reads a cookie named "session" and expects a KV record at session:<id> = { userId }
async function getUserIdFromRequest(request, env) {
  const cookies = Object.fromEntries(
    (request.headers.get("Cookie") || "")
      .split(";")
      .map(v => v.trim())
      .filter(Boolean)
      .map(kv => {
        const i = kv.indexOf("=");
        return [decodeURIComponent(kv.slice(0, i)), decodeURIComponent(kv.slice(i+1))];
      }),
  );

  // direct username cookie also supported
  const ghUser = cookies["gh_user"] || cookies["github_user"] || cookies["user"] || cookies["uid"];
  if (ghUser) return ghUser;

  // session cookie
  const sessionId = cookies["session"];
  if (sessionId) {
    const sess = await env.JOB_STATE.get(`session:${sessionId}`, "json");
    if (sess?.userId) return sess.userId;
  }
  return null;
}
