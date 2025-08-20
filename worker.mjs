// worker.mjs — Full Worker with OAuth + Jobs + Applied sync

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const cors = {
      "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN,
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors });
    }

    // -------------------
    // JWT Helpers
    // -------------------
    function b64urlEncode(u8) {
      let s = "";
      for (let i = 0; i < u8.length; i += 0x8000)
        s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
      return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }
    function b64urlDecodeToU8(s) {
      s = s.replace(/-/g, "+").replace(/_/g, "/");
      const pad = s.length % 4 === 2 ? "==" : s.length % 4 === 3 ? "=" : "";
      const bin = atob(s + pad);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
    async function hmacHex(secret, data) {
      const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      );
      const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
      return b64urlEncode(new Uint8Array(sig));
    }
    async function signToken(payload, secret) {
      const header = b64urlEncode(new TextEncoder().encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
      const body = b64urlEncode(new TextEncoder().encode(JSON.stringify(payload)));
      const sig = await hmacHex(secret, header + "." + body);
      return header + "." + body + "." + sig;
    }
    async function verifyToken(token, secret, allowedLogin) {
      const [h, b, sig] = token.split(".");
      const expected = await hmacHex(secret, h + "." + b);
      if (sig !== expected) throw new Error("bad signature");
      const payload = JSON.parse(new TextDecoder().decode(b64urlDecodeToU8(b)));
      if (payload.login !== allowedLogin) throw new Error("not allowed");
      return payload;
    }

    // -------------------
    // GitHub OAuth
    // -------------------
    if (url.pathname === "/oauth/login") {
      const state = crypto.randomUUID() + "|" + encodeURIComponent(url.searchParams.get("redirect") || env.ALLOWED_ORIGIN);
      const loc = `https://github.com/login/oauth/authorize?client_id=${env.GITHUB_CLIENT_ID}&scope=read:user&redirect_uri=${env.PUBLIC_URL}/oauth/callback&state=${state}`;
      return Response.redirect(loc, 302);
    }

    if (url.pathname === "/oauth/callback") {
      const code = url.searchParams.get("code");
      const stateParam = url.searchParams.get("state") || "";
      const redirect = decodeURIComponent((stateParam.split("|")[1] || env.ALLOWED_ORIGIN));

      // Exchange code for token
      const ghRes = await fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: { Accept: "application/json" },
        body: new URLSearchParams({
          client_id: env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          code
        }),
      });
      const ghData = await ghRes.json();
      const token = ghData.access_token;

      // Get user
      const userRes = await fetch("https://api.github.com/user", {
        headers: { Authorization: "token " + token, "User-Agent": "cfworker" },
      });
      const user = await userRes.json();

      if (user.login !== env.ALLOWED_LOGIN) {
        return new Response("not allowed", { status: 403 });
      }

      const appToken = await signToken({ login: user.login, id: user.id }, env.SESSION_SECRET);
      const loc = redirect + (redirect.includes("#") ? "&" : "#") + "token=" + appToken;
      return Response.redirect(loc, 302);
    }

    // -------------------
    // API: session
    // -------------------
    if (url.pathname === "/api/session") {
      const token = request.headers.get("Authorization")?.split(" ")[1];
      if (!token) return new Response("unauthorized", { status: 401, headers: cors });
      try {
        const payload = await verifyToken(token, env.SESSION_SECRET, env.ALLOWED_LOGIN);
        return new Response(JSON.stringify({ authenticated: true, user: payload }), { headers: { "content-type": "application/json", ...cors } });
      } catch {
        return new Response("unauthorized", { status: 401, headers: cors });
      }
    }

    // -------------------
    // API: jobs
    // -------------------
    if (url.pathname === "/api/jobs") {
      const raw = await env.JOBS_KV.get("jobs.json");
      return new Response(raw || "[]", { headers: { "content-type": "application/json", ...cors } });
    }

    // -------------------
    // API: applied
    // -------------------
    async function getApplied(user) {
      const val = await env.JOBS_KV.get("applied:" + user);
      return val ? JSON.parse(val) : [];
    }
    async function setApplied(user, list) {
      await env.JOBS_KV.put("applied:" + user, JSON.stringify(list));
    }

    if (url.pathname === "/api/applied" && request.method === "GET") {
      const token = request.headers.get("Authorization")?.split(" ")[1];
      if (!token) return new Response("unauthorized", { status: 401, headers: cors });
      try {
        const { login } = await verifyToken(token, env.SESSION_SECRET, env.ALLOWED_LOGIN);
        const list = await getApplied(login);
        return new Response(JSON.stringify(list), { headers: { "content-type": "application/json", ...cors } });
      } catch {
        return new Response("unauthorized", { status: 401, headers: cors });
      }
    }

    if (url.pathname === "/api/applied" && request.method === "POST") {
      const token = request.headers.get("Authorization")?.split(" ")[1];
      if (!token) return new Response("unauthorized", { status: 401, headers: cors });
      try {
        const { login } = await verifyToken(token, env.SESSION_SECRET, env.ALLOWED_LOGIN);
        const body = await request.json();
        const list = new Set(await getApplied(login));
        if (body.applied) list.add(body.key); else list.delete(body.key);
        await setApplied(login, [...list]);
        return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json", ...cors } });
      } catch {
        return new Response("unauthorized", { status: 401, headers: cors });
      }
    }

    return new Response("worker running", { headers: cors });
  }
};
