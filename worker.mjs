
// worker.mjs
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const cors = { "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN, "Access-Control-Allow-Headers": "Authorization, Content-Type" };

    // Handle applied GET
    if (url.pathname === "/api/applied" && request.method === "GET") {
      return new Response(JSON.stringify([]), { headers: { "content-type": "application/json", ...cors } });
    }

    // Handle applied POST
    if (url.pathname === "/api/applied" && request.method === "POST") {
      return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json", ...cors } });
    }

    return new Response("worker running");
  }
}
