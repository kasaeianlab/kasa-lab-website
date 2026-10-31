export const ADMIN_EMAIL = "kasaeian.lab@gmail.com";
export const SESSION_SECONDS = 8 * 60 * 60;

export function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      "Pragma": "no-cache",
      "X-Content-Type-Options": "nosniff",
      ...extraHeaders
    }
  });
}

export function randomHex(length = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

export async function hmacHex(secret, value) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return Array.from(new Uint8Array(signature), b => b.toString(16).padStart(2, "0")).join("");
}

export function cookieValue(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  for (const part of cookie.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    if (part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return "";
}

export function sessionCookie(token, maxAge = SESSION_SECONDS) {
  return `__Host-kasa_admin=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

export async function requireAdmin(request, env) {
  if (!env.DB || !env.ADMIN_AUTH_SECRET) return { ok: false, unavailable: true };
  const token = cookieValue(request, "__Host-kasa_admin");
  if (!/^[a-f0-9]{64}$/.test(token)) return { ok: false };
  const sessionHash = await hmacHex(env.ADMIN_AUTH_SECRET, `session:${token}`);
  const now = Math.floor(Date.now() / 1000);
  const session = await env.DB.prepare(
    "SELECT email, expires_at FROM admin_sessions WHERE session_hash = ? AND expires_at > ?"
  ).bind(sessionHash, now).first();
  if (!session || session.email !== ADMIN_EMAIL) return { ok: false };
  await env.DB.prepare("UPDATE admin_sessions SET last_seen_at = ? WHERE session_hash = ?")
    .bind(now, sessionHash).run();
  return { ok: true, email: session.email };
}

export async function consumeRateLimit(env, key, limit, windowSeconds) {
  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare(`
    INSERT INTO admin_auth_rate_limits (rate_key, request_count, window_started_at)
    VALUES (?, 1, ?)
    ON CONFLICT(rate_key) DO UPDATE SET
      request_count = CASE WHEN admin_auth_rate_limits.window_started_at <= ? THEN 1 ELSE admin_auth_rate_limits.request_count + 1 END,
      window_started_at = CASE WHEN admin_auth_rate_limits.window_started_at <= ? THEN excluded.window_started_at ELSE admin_auth_rate_limits.window_started_at END
    RETURNING request_count, window_started_at
  `).bind(key, now, now - windowSeconds, now - windowSeconds).first();
  return { allowed: !!row && row.request_count <= limit, retryAfter: row ? Math.max(1, row.window_started_at + windowSeconds - now) : windowSeconds };
}

export async function sendOtpEmail(env, code) {
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: env.RESEND_FROM_EMAIL || "KASA Lab Projects <projects@kasalab.org>",
      to: [ADMIN_EMAIL],
      subject: "Your KASA Lab admin sign-in code",
      text: `Your KASA Lab admin sign-in code is: ${code}\n\nThis code expires in 5 minutes. If you did not request it, you can ignore this email.`,
      html: `<p>Your KASA Lab admin sign-in code is:</p><p style="font-size:30px;font-weight:700;letter-spacing:6px">${code}</p><p>This code expires in 5 minutes. If you did not request it, you can ignore this email.</p>`
    })
  });
  return response.ok;
}
