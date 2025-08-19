// Cloudflare Worker: Token-based OAuth (no external imports, no cookies)
export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const origin = req.headers.get("Origin") || "";
    const cors = {
      "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN, // || origin || "*",
      "Access-Control-Allow-Credentials": "false",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    };
    if (req.method === "OPTIONS") return new Response(null, { headers: cors });

    const send = (obj, status=200) => new Response(JSON.stringify(obj), { status, headers: { "content-type":"application/json", ...cors } });

    // --- helpers ---
    function b64url_encode(u8) {
      let str = "";
      const chunk = 0x8000;
      for (let i = 0; i < u8.length; i += chunk) {
        str += String.fromCharCode.apply(null, u8.subarray(i, i + chunk));
      }
      return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/,"");
    }
    function b64url_decode_to_u8(s) {
      s = s.replace(/-/g, "+").replace(/_/g, "/");
      const pad = s.length % 4 === 2 ? "==" : s.length % 4 === 3 ? "=" : "";
      const bin = atob(s + pad);
      const arr = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
      return arr;
    }
    async function hmac_hex(msgStr) {
      const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(env.SESSION_SECRET || ""),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign", "verify"]
      );
      const sigBuf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msgStr));
      const u8 = new Uint8Array(sigBuf);
      return Array.from(u8).map(b => b.toString(16).padStart(2, "0")).join("");
    }
    function getBearer(req) {
      const h = req.headers.get("Authorization") || "";
      if (!h.startsWith("Bearer ")) return null;
      return h.slice(7).trim();
    }
    async function signToken(payloadObj) {
      const json = JSON.stringify(payloadObj);
      const payloadB64 = b64url_encode(new TextEncoder().encode(json));
      const sig = await hmac_hex(json);
      return payloadB64 + "." + sig;
    }
    async function verifyToken(tok) {
      try {
        const [b64, sig] = tok.split(".");
        if (!b64 || !sig) return null;
        const json = new TextDecoder().decode(b64url_decode_to_u8(b64));
        const expect = await hmac_hex(json);
        if (expect !== sig) return null;
        const obj = JSON.parse(json);
        if (!obj.login) return null;
        if (obj.exp && Date.now() > obj.exp) return null;
        return { login: obj.login };
      } catch (e) {
        return null;
      }
    }

    // --- routes ---
    if (url.pathname === "/oauth/login") {
      const state = crypto.randomUUID();
      const redirect = url.searchParams.get("redirect") || (env.ALLOWED_ORIGIN || "");
      const auth = new URL("https://github.com/login/oauth/authorize");
      auth.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
      auth.searchParams.set("scope", "read:user");
      auth.searchParams.set("redirect_uri", (env.PUBLIC_URL || url.origin) + "/oauth/callback");
      // pack state + redirect to avoid server storage
      auth.searchParams.set("state", state + "|" + encodeURIComponent(redirect));
      return new Response(null, { status: 302, headers: { "Location": auth.toString(), ...cors } });
    }

    if (url.pathname === "/oauth/callback") {
      const code = url.searchParams.get("code") || "";
      const stateParam = url.searchParams.get("state") || "";
      const pipeIdx = stateParam.indexOf("|");
      if (!code || pipeIdx < 0) return send({ error: "state_mismatch" }, 400);
      const state = stateParam.slice(0, pipeIdx);
      const redirectEnc = stateParam.slice(pipeIdx + 1);
      const redirect = decodeURIComponent(redirectEnc || "");

      // token exchange
      const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: { "content-type": "application/json", "accept": "application/json" },
        body: JSON.stringify({
          client_id: env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: (env.PUBLIC_URL || url.origin) + "/oauth/callback",
          state
        })
      });
      const ct = tokenRes.headers.get("content-type") || "";
      let tj;
      try { tj = ct.includes("application/json") ? await tokenRes.json() : Object.fromEntries(new URLSearchParams(await tokenRes.text())); }
      catch { return send({ error: "token_parse_failed", status: tokenRes.status }, 502); }
      if (!tj.access_token) return send({ error: "no_token", status: tokenRes.status, detail: tj }, 400);

      const userRes = await fetch("https://api.github.com/user", {
        headers: { "authorization": `Bearer ${tj.access_token}`, "user-agent": "cf-worker-jobs-app" }
      });
      if (!userRes.ok) return send({ error: "user_fetch_failed", status: userRes.status }, 502);
      const user = await userRes.json();
      if (!user?.login) return send({ error: "no_user" }, 400);
      if (env.ALLOWED_LOGIN && user.login.toLowerCase() !== (env.ALLOWED_LOGIN || "").toLowerCase()) {
        return send({ error: "not_allowed", login: user.login }, 403);
      }

      // issue 7-day token
      const tok = await signToken({ login: user.login, id: user.id, exp: Date.now() + 7*24*60*60*1000 });
      const to = redirect || (env.ALLOWED_ORIGIN || "/");
      const loc = to + (to.includes("#") ? "&" : "#") + "token=" + encodeURIComponent(tok);
      return new Response(null, { status: 302, headers: { "Location": loc, ...cors } });
    }

    if (url.pathname === "/api/session") {
      const tok = getBearer(req);
      const user = tok ? await verifyToken(tok) : null;
      return send({ authenticated: !!user, user });
    }

    if (url.pathname === "/api/jobs") {
      const tok = getBearer(req);
      const user = tok ? await verifyToken(tok) : null;
      if (!user || (env.ALLOWED_LOGIN && user.login.toLowerCase() !== (env.ALLOWED_LOGIN || "").toLowerCase())) {
        return send({ error: "not_authenticated" }, 401);
      }
      const obj = await env.JOBS_KV.get("jobs.json", "json");
      return send(obj || []);
    }

    return new Response("OK", { headers: cors });
  }
}
