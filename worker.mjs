// worker.mjs
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const cors = {
      "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN,
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
    };

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors });
    }

    const auth = request.headers.get("Authorization");
    let login = null;
    if (auth && auth.startsWith("Bearer ")) {
      try {
        const token = auth.slice(7);
        const data = JSON.parse(atob(token.split(".")[1]));
        login = data.login;
      } catch (e) {}
    }

    // GET applied state
    if (url.pathname === "/api/applied" && request.method === "GET") {
      if (!login) return new Response("Unauthorized", { status: 401, headers: cors });
      const stored = await env.JOBS_KV.get("applied:" + login, { type: "json" }) || [];
      return new Response(JSON.stringify(stored), { headers: { "content-type": "application/json", ...cors } });
    }

    // POST applied state
    if (url.pathname === "/api/applied" && request.method === "POST") {
      if (!login) return new Response("Unauthorized", { status: 401, headers: cors });
      const body = await request.json();
      let applied = (await env.JOBS_KV.get("applied:" + login, { type: "json" })) || [];
      if (body.applied) {
        if (!applied.includes(body.key)) applied.push(body.key);
      } else {
        applied = applied.filter(k => k !== body.key);
      }
      await env.JOBS_KV.put("applied:" + login, JSON.stringify(applied));
      return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json", ...cors } });
    }

    // Default
    return new Response("worker running");
  }
}
