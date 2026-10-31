import { json, requireAdmin } from "../../_lib/admin-auth.js";

export async function onRequestGet({ request, env }) {
  const auth = await requireAdmin(request, env);
  if (auth.unavailable) return json({ success: false, message: "Authentication service is unavailable." }, 503);
  if (!auth.ok) return json({ success: false, message: "Unauthorized." }, 401);
  if (!env.DB) return json({ success: false, message: "Database is unavailable." }, 503);

  try {
    const result = await env.DB.prepare(`
      SELECT id, name, email, organization, organization_type, country,
             service_type, project_title, status, created_at, updated_at,
             notification_status
      FROM projects
      ORDER BY created_at DESC
      LIMIT 500
    `).all();
    return json({ success: true, projects: result.results || [] });
  } catch (error) {
    return json({ success: false, message: "Could not load projects. Check the projects table schema." }, 500);
  }
}
