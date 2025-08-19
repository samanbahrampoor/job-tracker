// worker.mjs



export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cors = {
      "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN || "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
    };
	
	const APP_URL = (env.ALLOWED_ORIGIN || "") + "/job-tracker/jobs.html";

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors });
    }

    // ---------- LOGIN ----------
    if (url.pathname === "/oauth/login") {
      const redirect = url.searchParams.get("redirect") || APP_URL;
      const auth = new URL("https://github.com/login/oauth/authorize");
      auth.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
      auth.searchParams.set("scope", "read:user");
      auth.searchParams.set("redirect_uri", (env.PUBLIC_URL || url.origin) + "/oauth/callback");
      auth.searchParams.set("state", crypto.randomUUID() + "|" + encodeURIComponent(redirect));
      return new Response(null, { status: 302, headers: { Location: auth.toString(), ...cors } });
    }

    // ---------- CALLBACK ----------
    if (url.pathname === "/oauth/callback") {
      const code = url.searchParams.get("code");
      if (!code) return new Response("missing code", { status: 400, headers: cors });

      const gh = await fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({
          client_id: env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: (env.PUBLIC_URL || url.origin) + "/oauth/callback",
        }),
      });
      const data = await gh.json();
      if (!data.access_token) {
        return new Response("OAuth error: " + JSON.stringify(data), { status: 400, headers: cors });
      }

      const ghUser = await fetch("https://api.github.com/user", {
        headers: { Authorization: "Bearer " + data.access_token, "User-Agent": "job-tracker" },
      }).then(r => r.json());

      if (env.ALLOWED_LOGIN && ghUser.login !== env.ALLOWED_LOGIN) {
        return new Response("unauthorized", { status: 403, headers: cors });
      }

      const tok = await signJWT({ login: ghUser.login }, env.SESSION_SECRET);

      const stateParam = url.searchParams.get("state") || "";
      // const redirect = decodeURIComponent((stateParam.split("|")[1] || APP_URL));
	  const redirect = decodeURIComponent((stateParam.split("|")[1] || "")) || (env.ALLOWED_ORIGIN + "/job-tracker/jobs.html");
      const loc = redirect + (redirect.includes("#") ? "&" : "#") + "token=" + encodeURIComponent(tok);
      return new Response(null, { status: 302, headers: { Location: loc, ...cors } });
    }

    // ---------- SESSION ----------
    if (url.pathname === "/api/session") {
      const u = await verifyJWT(request.headers.get("Authorization"), env.SESSION_SECRET);
      return new Response(JSON.stringify(u || { authenticated: false }), {
        headers: { "Content-Type": "application/json", ...cors },
      });
    }

    // ---------- JOBS ----------
    if (url.pathname === "/api/jobs") {
      const u = await verifyJWT(request.headers.get("Authorization"), env.SESSION_SECRET);
      if (!u) return new Response(JSON.stringify({ error: "not_authenticated" }), { status: 401, headers: cors });
      const jobs = await env.JOBS_KV.get("jobs.json", "json") || [];
      return new Response(JSON.stringify(jobs), { headers: { "Content-Type": "application/json", ...cors } });
    }

    return new Response("OK", { headers: cors });
  },
};
