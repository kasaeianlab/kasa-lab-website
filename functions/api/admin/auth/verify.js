import { ADMIN_EMAIL, json, randomHex, hmacHex, consumeRateLimit, sessionCookie, SESSION_SECONDS, requireSameOrigin } from "../../../_lib/admin-auth.js";

export async function onRequestPost({ request, env }) {
  if (!requireSameOrigin(request)) return json({ success: false, message: "Invalid request origin." }, 403);
  if (!env.DB || !env.ADMIN_AUTH_SECRET) return json({ success: false, message: "Authentication service is not configured." }, 503);
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const ipKey = await hmacHex(env.ADMIN_AUTH_SECRET, `verify-ip:${ip}`);
  const limit = await consumeRateLimit(env, `verify:${ipKey}`, 10, 15 * 60);
  if (!limit.allowed) return json({ success: false, message: "Too many attempts. Please try again later." }, 429, { "Retry-After": String(limit.retryAfter) });
  let body;
  try { body = await request.json(); } catch { return json({ success: false, message: "Invalid request." }, 400); }
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const code = typeof body.code === "string" ? body.code.trim() : "";
  if (email !== ADMIN_EMAIL || !/^\d{6}$/.test(code)) return json({ success: false, message: "The code is invalid or has expired." }, 400);

  const now = Math.floor(Date.now() / 1000);
  const record = await env.DB.prepare(`SELECT id, code_hash, attempts FROM admin_login_codes WHERE email = ? AND consumed_at IS NULL AND expires_at > ? ORDER BY created_at DESC LIMIT 1`)
    .bind(ADMIN_EMAIL, now).first();
  if (!record || record.attempts >= 5) return json({ success: false, message: "The code is invalid or has expired." }, 400);
  const submittedHash = await hmacHex(env.ADMIN_AUTH_SECRET, `otp:${record.id}:${code}`);
  if (submittedHash !== record.code_hash) {
    await env.DB.prepare("UPDATE admin_login_codes SET attempts = attempts + 1 WHERE id = ? AND consumed_at IS NULL")
      .bind(record.id).run();
    return json({ success: false, message: "The code is invalid or has expired." }, 400);
  }
  const consumed = await env.DB.prepare("UPDATE admin_login_codes SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL AND expires_at > ? AND attempts < 5")
    .bind(now, record.id, now).run();
  if (!consumed.meta || consumed.meta.changes !== 1) return json({ success: false, message: "The code is invalid or has expired." }, 400);

  const token = randomHex(32);
  const sessionHash = await hmacHex(env.ADMIN_AUTH_SECRET, `session:${token}`);
  await env.DB.prepare("INSERT INTO admin_sessions (session_hash, email, expires_at, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?)")
    .bind(sessionHash, ADMIN_EMAIL, now + SESSION_SECONDS, now, now).run();
  return json({ success: true, email: ADMIN_EMAIL }, 200, { "Set-Cookie": sessionCookie(token) });
}
