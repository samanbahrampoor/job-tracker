// Cloudflare Worker — GitHub OAuth → token-in-URL (no cookies), KV-backed /api/jobs
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // ---- CORS ----
    const cors = {
      "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN || "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      "Access-Control-Allow-Credentials": "false",
    };
    if (request.method === "OPTIONS") return new Response(null, { headers: cors });

    // ---- Helpers ----
    const APP_URL = (env.ALLOWED_ORIGIN || "") + "/job-tracker/jobs.html";

    function b64urlEncode(u8) {
      let s = "";
      for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
      return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/,"");
    }
    function b64urlDecodeToU8(s) {
      s = s.replace(/-/g, "+").replace(/_/g, "/");
      const pad = s.length % 4 === 2 ? "==" : s.length % 4 === 3 ? "=" : "";
      const bin = atob(s + pad);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
    async function hmacHex(msgStr) {
      const keyRaw = new TextEncoder().encode(env.SESSION_SECRET || "");
      const key = await crypto.subtle.importKey("raw", keyRaw, { name: "HMAC", hash: "SHA-256" }, false, ["sign","verify"]);
      const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msgStr));
      return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2,"0")).join("");
    }
    async function signToken(payloadObj) {
      const json = JSON.stringify(payloadObj);
      const b64 = b64urlEncode(new TextEncoder().encode(json));
      const sig = await hmacHex(json);
      return `${b64}.${sig}`;
    }
    async function verifyTokenFromAuth(hdr) {
      try {
        if (!hdr || !hdr.startsWith("Bearer ")) return null;
        const tok = hdr.slice(7).trim();
        const [b64, sig] = tok.split(".");
        if (!b64 || !sig) return null;
        const json = new TextDecoder().decode(b64urlDecodeToU8(b64));
        const expect = await hmacHex(json);
        if (expect !== sig) return null;
        const obj = JSON.parse(json);
        if (!obj.login) return null;
        if (obj.exp && Date.now() > obj.exp) return null;
        return { login: obj.login, id: obj.id };
      } catch { return null; }
    }

    // ---- Routes ----

    // 1) Start OAuth
    if (url.pathname === "/oauth/login") {
      const redirect = url.searchParams.get("redirect") || APP_URL;
      const state = crypto.randomUUID() + "|" + encodeURIComponent(redirect);
      const auth = new URL("https://github.com/login/oauth/authorize");
      auth.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
      auth.searchParams.set("scope", "read:user");
      auth.searchParams.set("redirect_uri", (env.PUBLIC_URL || url.origin) + "/oauth/callback");
      auth.searchParams.set("state", state);
      return new Response(null, { status: 302, headers: { Location: auth.toString(), ...cors } });
    }

    // 2) OAuth callback → exchange + token → redirect to app with #token
    if (url.pathname === "/oauth/callback") {
      const code = url.searchParams.get("code") || "";
      const stateParam = url.searchParams.get("state") || "";
      if (!code || !stateParam.includes("|")) {
        return new Response(JSON.stringify({ error: "state_mismatch" }), { status: 400, headers: { "content-type":"application/json", ...cors } });
      }
      const redirect = decodeURIComponent(stateParam.split("|")[1] || "") || APP_URL;

      // Exchange the code
      const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: { "content-type":"application/json", "accept":"application/json" },
        body: JSON.stringify({
          client_id: env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: (env.PUBLIC_URL || url.origin) + "/oauth/callback",
        })
      });
      const ct = tokenRes.headers.get("content-type") || "";
      const tj = ct.includes("application/json") ? await tokenRes.json()
                  : Object.fromEntries(new URLSearchParams(await tokenRes.text()));
      if (!tj.access_token) {
        return new Response(JSON.stringify({ error: "no_token", detail: tj }), { status: 400, headers: { "content-type":"application/json", ...cors } });
      }

      // Fetch GitHub user
      const userRes = await fetch("https://api.github.com/user", {
        headers: { "authorization": `Bearer ${tj.access_token}`, "user-agent": "cf-worker-jobs-app" }
      });
      if (!userRes.ok) {
        return new Response(JSON.stringify({ error: "user_fetch_failed", status: userRes.status }), { status: 502, headers: { "content-type":"application/json", ...cors } });
      }
      const user = await userRes.json();
      if (!user?.login) {
        return new Response(JSON.stringify({ error: "no_user" }), { status: 400, headers: { "content-type":"application/json", ...cors } });
      }
      if (env.ALLOWED_LOGIN && user.login.toLowerCase() !== env.ALLOWED_LOGIN.toLowerCase()) {
        return new Response(JSON.stringify({ error: "not_allowed", login: user.login }), { status: 403, headers: { "content-type":"application/json", ...cors } });
      }

      // Issue 7-day token and bounce to app
      const tok = await signToken({ login: user.login, id: user.id, exp: Date.now() + 7*24*60*60*1000 });
      const loc = redirect + (redirect.includes("#") ? "&" : "#") + "token=" + encodeURIComponent(tok);
      return new Response(null, { status: 302, headers: { Location: loc, ...cors } });
    }

    // 3) Session (for SPA)
    if (url.pathname === "/api/session") {
      const user = await verifyTokenFromAuth(request.headers.get("Authorization"));
      return new Response(JSON.stringify({ authenticated: !!user, user }), { headers: { "content-type":"application/json", ...cors } });
    }

    // 4) Jobs (protected)
    /*if (url.pathname === "/api/jobs") {
      const user = await verifyTokenFromAuth(request.headers.get("Authorization"));
      if (!user) return new Response(JSON.stringify({ error: "not_authenticated" }), { status: 401, headers: { "content-type":"application/json", ...cors } });
      const jobs = await env.JOBS_KV.get("jobs.json", "json");
      return new Response(JSON.stringify(jobs || []), { headers: { "content-type":"application/json", ...cors } });
    }*/
	

    //return new Response("OK", { headers: cors });
	// inside: if (url.pathname === "/api/jobs") { ... }
	const raw = await env.JOBS_KV.get("jobs.json", "json") || [];
	// Normalize to the shape the UI expects
	const jobs = raw.map(r => ({
	  company: r.company ?? r.Company ?? "",
	  title:   r.title   ?? r.Title   ?? "",
	  city:    r.city    ?? r.City    ?? "",
	  country: r.country ?? r.Country ?? "",
	  job_id:  r.job_id  ?? r.JobID   ?? r.id ?? "",
	  url:     r.url     ?? r.Link    ?? r.URL ?? "",
	  key:     r.key     ?? `${(r.company ?? r.Company ?? "")}|${(r.job_id ?? r.JobID ?? r.id ?? "")}`
	}));
	return new Response(JSON.stringify(jobs), {
	  headers: { "content-type": "application/json", ...cors }
	});

	
  }
}
