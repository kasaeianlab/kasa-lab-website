import { json, cookieValue, hmacHex, sessionCookie, requireSameOrigin } from "../../../_lib/admin-auth.js";

export async function onRequestPost({ request, env }) {
  if (!requireSameOrigin(request)) return json({ success: false, message: "Invalid request origin." }, 403);
  if (env.DB && env.ADMIN_AUTH_SECRET) {
    const token = cookieValue(request, "__Host-kasa_admin");
    if (/^[a-f0-9]{64}$/.test(token)) {
      const hash = await hmacHex(env.ADMIN_AUTH_SECRET, `session:${token}`);
      await env.DB.prepare("DELETE FROM admin_sessions WHERE session_hash = ?").bind(hash).run();
    }
  }
  return json({ success: true, message: "You have been signed out." }, 200, { "Set-Cookie": sessionCookie("", 0) });
}
