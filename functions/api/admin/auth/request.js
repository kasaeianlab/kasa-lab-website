import { ADMIN_EMAIL, json, randomHex, hmacHex, consumeRateLimit, sendOtpEmail, requireSameOrigin } from "../../../_lib/admin-auth.js";

export async function onRequestPost({ request, env }) {
  if (!requireSameOrigin(request)) return json({ success: false, message: "Invalid request origin." }, 403);
  if (!env.DB || !env.ADMIN_AUTH_SECRET || !env.RESEND_API_KEY || !env.RESEND_FROM_EMAIL) {
    return json({ success: false, message: "Authentication service is not configured." }, 503);
  }
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const ipKey = await hmacHex(env.ADMIN_AUTH_SECRET, `request-ip:${ip}`);
  const ipLimit = await consumeRateLimit(env, `request:${ipKey}`, 5, 15 * 60);
  if (!ipLimit.allowed) {
    return json({ success: false, message: "Too many sign-in requests. Please try again later." }, 429, { "Retry-After": String(ipLimit.retryAfter) });
  }
  let body;
  try { body = await request.json(); } catch { return json({ success: false, message: "Invalid request." }, 400); }
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  if (email !== ADMIN_EMAIL) return json({ success: true, message: "If this address is authorized, a sign-in code will be sent." });
  const emailKey = await hmacHex(env.ADMIN_AUTH_SECRET, `request-email:${ADMIN_EMAIL}`);
  const emailLimit = await consumeRateLimit(env, `request:${emailKey}`, 3, 15 * 60);
  if (!emailLimit.allowed) {
    return json({ success: false, message: "Too many sign-in requests. Please try again later." }, 429, { "Retry-After": String(emailLimit.retryAfter) });
  }

  const now = Math.floor(Date.now() / 1000);
  const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, "0");
  const id = randomHex(16);
  const codeHash = await hmacHex(env.ADMIN_AUTH_SECRET, `otp:${id}:${code}`);
  await env.DB.prepare("UPDATE admin_login_codes SET consumed_at = ? WHERE email = ? AND consumed_at IS NULL")
    .bind(now, ADMIN_EMAIL).run();
  await env.DB.prepare(`INSERT INTO admin_login_codes (id, email, code_hash, expires_at, attempts, consumed_at, created_at) VALUES (?, ?, ?, ?, 0, NULL, ?)`)
    .bind(id, ADMIN_EMAIL, codeHash, now + 300, now).run();
  const sent = await sendOtpEmail(env, code);
  if (!sent) {
    await env.DB.prepare("UPDATE admin_login_codes SET consumed_at = ? WHERE id = ?").bind(now, id).run();
    return json({ success: false, message: "Could not send the sign-in email. Please try again later." }, 502);
  }
  return json({ success: true, message: "A sign-in code has been sent to the authorized email address." });
}
