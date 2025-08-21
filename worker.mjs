// worker.mjs
// Minimal API to persist per-user "applied" status in Cloudflare KV.
// Endpoints:
//   GET  /api/state           -> { applied: { [jobId]: { applied: boolean, updatedAt: number } } }
//   POST /api/state           -> body { jobId, applied } -> { ok: true }
// Notes:
// - Replace getUserIdFromRequest() with your existing auth/session logic if needed.
// - Set ORIGIN to your GitHub Pages origin.
// - Ensure KV binding 'JOB_STATE' exists in wrangler.toml.

const ORIGIN = "https://samanbahrampoor.github.io"

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin"
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url)
    const origin = request.headers.get("Origin") || ORIGIN
    const headers = corsHeaders(origin)

    // Preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers })
    }

    // Only allow our site
    if (origin !== ORIGIN && origin !== null) {
      return new Response("Forbidden", { status: 403, headers })
    }

    // Require login (adapt this to your existing auth/session)
    const userId = await getUserIdFromRequest(request, env)
    if (!userId) {
      return json({ error: "unauthorized" }, 401, headers)
    }

    if (url.pathname === "/api/state" && request.method === "GET") {
      const key = `user:${userId}`
      const doc = await env.JOB_STATE.get(key, "json")
      return json(doc || { applied: {} }, 200, headers)
    }

    if (url.pathname === "/api/state" && request.method === "POST") {
      let body
      try { body = await request.json() } catch {}
      const jobId = body?.jobId
      const applied = body?.applied
      if (!jobId || typeof applied !== "boolean") {
        return json({ error: "bad_request" }, 400, headers)
      }
      const key = `user:${userId}`
      const doc = (await env.JOB_STATE.get(key, "json")) || { applied: {} }
      doc.applied[jobId] = { applied, updatedAt: Date.now() }
      await env.JOB_STATE.put(key, JSON.stringify(doc))
      return json({ ok: true }, 200, headers)
    }

    return new Response("Not found", { status: 404, headers })
  },
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  })
}

// --- Auth helper ---
// This tries a few common patterns to find a user id.
// Replace with your actual logic (e.g., verify a JWT or read your session from KV).
async function getUserIdFromRequest(request, env) {
  const cookies = Object.fromEntries(
    (request.headers.get("Cookie") || "")
      .split(";")
      .map(v => v.trim())
      .filter(Boolean)
      .map(kv => {
        const i = kv.indexOf("=")
        return [decodeURIComponent(kv.slice(0, i)), decodeURIComponent(kv.slice(i+1))]
      }),
  )

  // Prefer an explicit GitHub username/id if you set it
  const ghUser = cookies["gh_user"] || cookies["github_user"] || cookies["user"] || cookies["uid"]
  if (ghUser) return ghUser

  // If you have a session cookie, try to resolve it from KV
  const sessionId = cookies["session"]
  if (sessionId) {
    const sess = await env.JOB_STATE.get(`session:${sessionId}`, "json")
    if (sess?.userId) return sess.userId
  }

  // TODO: Add JWT verification here if your flow sets a token instead of a session.
  return null
}
