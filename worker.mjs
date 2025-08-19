export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const origin = req.headers.get("Origin") || "";
    const cors = {
      "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN, // || origin || "*",
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    };
    if (req.method === "OPTIONS") return new Response(null, { headers: cors });
    const send = (obj, status=200)=> new Response(JSON.stringify(obj), {status, headers:{ "content-type":"application/json", ...cors }});
    const cookies = Object.fromEntries((req.headers.get("Cookie")||"").split(";").map(v=>v.trim().split("=").map(decodeURIComponent)).filter(x=>x[0]));
    async function hmac(msg){
      const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.SESSION_SECRET), {name:"HMAC", hash:"SHA-256"}, false, ["sign","verify"]);
      const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
      return Array.from(new Uint8Array(sig)).map(b=>b.toString(16).padStart(2,"0")).join("");
    }
    async function verify(payload,sig){ return (await hmac(payload))===sig; }
    function setCookie(h, name, value, opts={}){
      const parts = [`${name}=${value}`];
      if (opts.Path) parts.push(`Path=${opts.Path}`);
      if (opts.HttpOnly) parts.push("HttpOnly");
      if (opts.Secure) parts.push("Secure");
      if (opts.SameSite) parts.push(`SameSite=${opts.SameSite}`);
      if (opts.MaxAge) parts.push(`Max-Age=${opts.MaxAge}`);
      h.append("Set-Cookie", parts.join("; "));
    }
    if (url.pathname === "/oauth/login") {
      const state = crypto.randomUUID();
      const redirect = url.searchParams.get("redirect") || (env.ALLOWED_ORIGIN || "");
      const auth = new URL("https://github.com/login/oauth/authorize");
      auth.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
      auth.searchParams.set("scope","read:user");
      auth.searchParams.set("redirect_uri", (env.PUBLIC_URL || url.origin) + "/oauth/callback");
      auth.searchParams.set("state", state);
      const h = new Headers({ "Location": auth.toString(), ...cors });
      setCookie(h, "oauth_state", state, {Path:"/", HttpOnly:true, Secure:true, SameSite:"None", MaxAge:300});
      setCookie(h, "post_login_redirect", encodeURIComponent(redirect), {Path:"/", HttpOnly:true, Secure:true, SameSite:"Lax", MaxAge:600});
      return new Response(null, { status:302, headers:h });
    }
    if (url.pathname === "/oauth/callback") {
      const state = url.searchParams.get("state") || ""; const code = url.searchParams.get("code") || "";
      if (!state || !code || cookies.oauth_state !== state) return send({error:"state_mismatch"}, 400);
      const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
        method:"POST", headers:{ "content-type":"application/json", "accept":"application/json" },
        body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, code, redirect_uri:(env.PUBLIC_URL || url.origin)+"/oauth/callback", state })
      });
      const tj = await tokenRes.json(); if (!tj.access_token) return send({error:"no_token"}, 400);
      const userRes = await fetch("https://api.github.com/user", { headers:{ "authorization":`Bearer ${tj.access_token}`, "user-agent":"cf-worker-jobs-app" } });
      const user = await userRes.json(); if (!user || !user.login) return send({error:"no_user"}, 400);
      if (env.ALLOWED_LOGIN && user.login.toLowerCase() !== env.ALLOWED_LOGIN.toLowerCase()) return send({error:"not_allowed"}, 403);
      const payload = JSON.stringify({ login:user.login, id:user.id });
      const sig = await hmac(payload);
      const val = btoa(unescape(encodeURIComponent(payload))) + "." + sig;
      const h = new Headers({ "Location": decodeURIComponent(cookies.post_login_redirect || (env.ALLOWED_ORIGIN || "/")), ...cors });
      setCookie(h, "session", val, {Path:"/", HttpOnly:true, Secure:true, SameSite:"Lax", MaxAge:60*60*24*7});
      setCookie(h, "oauth_state","", {Path:"/", HttpOnly:true, Secure:true, SameSite:"Lax", MaxAge:0});
      setCookie(h, "post_login_redirect","", {Path:"/", HttpOnly:true, Secure:true, SameSite:"Lax", MaxAge:0});
      return new Response(null, { status:302, headers:h });
    }
    if (url.pathname === "/api/logout" && req.method === "POST") {
      const h = new Headers(cors); setCookie(h, "session","", {Path:"/", HttpOnly:true, Secure:true, SameSite:"None", MaxAge:0}); return new Response(null, {status:204, headers:h});
    }
    if (url.pathname === "/api/session") {
      let user=null;
      try{
        const val=cookies.session||""; const [b64,sig]=(val||".").split("."); const payload=decodeURIComponent(escape(atob(b64||"")));
        if (await verify(payload, sig||"")) user = { login: JSON.parse(payload).login };
      }catch(_){}
      return send({authenticated: !!user, user});
    }
    if (url.pathname === "/api/jobs") {
      const sess = await (await this.fetch(new Request(url.origin + "/api/session", { headers:req.headers }), env, ctx)).json();
      if (!sess.authenticated || (env.ALLOWED_LOGIN && sess.user.login.toLowerCase() !== env.ALLOWED_LOGIN.toLowerCase())) return send({error:"not_authenticated"}, 401);
      const obj = await env.JOBS_KV.get("jobs.json","json"); return send(obj || []);
    }
    return new Response("OK", { headers: cors });
  }
}