import { json, requireAdmin } from "../../../_lib/admin-auth.js";

export async function onRequestGet({ request, env }) {
  const auth = await requireAdmin(request, env);
  if (auth.unavailable) return json({ success: false, authenticated: false, message: "Authentication service is unavailable." }, 503);
  if (!auth.ok) return json({ success: true, authenticated: false }, 401);
  return json({ success: true, authenticated: true, email: auth.email });
}
