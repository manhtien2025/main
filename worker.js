// Secure web proxy — Cloudflare Worker
// Auth: X-Proxy-Secret header must equal env.PROXY_SECRET
// Target: env.UPSTREAM (default) or X-Target header, host must be in env.ALLOWED_HOSTS (comma-separated)
// Not an open proxy: only allowlisted hosts.

export default {
  async fetch(request, env) {
    // --- auth ---
    if (!env.PROXY_SECRET) {
      return new Response("PROXY_SECRET not configured", { status: 500 });
    }
    const secret = request.headers.get("X-Proxy-Secret");
    if (secret !== env.PROXY_SECRET) {
      return new Response("Unauthorized", { status: 401 });
    }

    // --- resolve upstream ---
    let target = env.UPSTREAM || "";
    const override = request.headers.get("X-Target");
    if (override) {
      let host;
      try { host = new URL(override).hostname; }
      catch (e) { return new Response("Bad X-Target URL", { status: 400 }); }
      const allowed = (env.ALLOWED_HOSTS || "").split(",").map(s => s.trim()).filter(Boolean);
      if (!allowed.includes(host)) {
        return new Response("Host not allowed: " + host, { status: 403 });
      }
      target = override;
    }
    if (!target) {
      return new Response("No upstream configured (set UPSTREAM env or X-Target header)", { status: 500 });
    }

    let base;
    try { base = new URL(target); }
    catch (e) { return new Response("Bad upstream URL", { status: 500 }); }

    const u = new URL(request.url);
    // Build upstream URL: base origin + base path + original path + query
    const basepath = base.pathname.replace(/\/$/, "");
    const upstream = new URL(base.origin + basepath + u.pathname + u.search);

    // --- proxy request ---
    const headers = new Headers(request.headers);
    headers.delete("X-Proxy-Secret");
    headers.delete("X-Target");
    // Host is set automatically by fetch based on URL

    let res;
    try {
      res = await fetch(new Request(upstream.toString(), {
        method: request.method,
        headers: headers,
        body: request.body,
        redirect: "manual",
      }));
    } catch (e) {
      return new Response("Upstream error: " + e.message, { status: 502 });
    }

    // --- rewrite response headers ---
    const outHeaders = new Headers(res.headers);
    outHeaders.delete("content-security-policy");
    outHeaders.delete("content-security-policy-report-only");
    outHeaders.delete("x-frame-options");
    outHeaders.delete("strict-transport-security");

    // Rewrite Set-Cookie: drop Domain, force Path=/, SameSite=None; Secure
    const cookies = (typeof res.headers.getSetCookie === "function") ? res.headers.getSetCookie() : [];
    if (cookies.length) {
      outHeaders.delete("set-cookie");
      for (const c of cookies) {
        let nc = c.replace(/;\s*Domain=[^;]*/gi, "");
        if (!/;\s*Path=/i.test(nc)) nc += "; Path=/";
        if (!/;\s*SameSite=/i.test(nc)) nc += "; SameSite=None";
        if (!/;\s*Secure/i.test(nc)) nc += "; Secure";
        outHeaders.append("set-cookie", nc);
      }
    }

    // WebSocket upgrade passthrough
    if (request.headers.get("Upgrade") && request.headers.get("Upgrade").toLowerCase() === "websocket") {
      return res;
    }

    return new Response(res.body, {
      status: res.status,
      statusText: res.statusText,
      headers: outHeaders,
    });
  }
};
