import { json, requireAdmin, requireSameOrigin } from "../../../_lib/admin-auth.js";

const ALLOWED_STATUSES = new Set(["Submitted", "Under Review", "Accepted", "Rejected", "Completed"]);

export async function onRequestGet({ request, env, params }) {
  const auth = await requireAdmin(request, env);
  if (auth.unavailable) return json({ success: false, message: "Authentication service is unavailable." }, 503);
  if (!auth.ok) return json({ success: false, message: "Unauthorized." }, 401);

  const id = String(params?.id || "");
  if (!id || id.length > 100) return json({ success: false, message: "Invalid project ID." }, 400);

  try {
    const project = await env.DB.prepare(`
      SELECT id, name, email, organization, organization_type, country,
             service_type, project_title, description, expected_deliverables,
             timeline, budget_range, status, created_at, updated_at,
             notification_status, public_note, public_note_updated_at, internal_note
      FROM projects WHERE id = ?
    `).bind(id).first();
    if (!project) return json({ success: false, message: "Project not found." }, 404);
    return json({ success: true, project });
  } catch {
    return json({ success: false, message: "Could not load project details. Check that notes columns exist." }, 500);
  }
}

export async function onRequestPatch({ request, env, params }) {
  if (!requireSameOrigin(request)) return json({ success: false, message: "Invalid request origin." }, 403);
  const auth = await requireAdmin(request, env);
  if (auth.unavailable) return json({ success: false, message: "Authentication service is unavailable." }, 503);
  if (!auth.ok) return json({ success: false, message: "Unauthorized." }, 401);

  const id = String(params?.id || "");
  if (!id || id.length > 100) return json({ success: false, message: "Invalid project ID." }, 400);

  let body;
  try { body = await request.json(); } catch { return json({ success: false, message: "Invalid JSON body." }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return json({ success: false, message: "Invalid update." }, 400);

  const fields = [];
  const values = [];
  if (Object.prototype.hasOwnProperty.call(body, "status")) {
    if (typeof body.status !== "string" || !ALLOWED_STATUSES.has(body.status)) return json({ success: false, message: "Invalid project status." }, 400);
    fields.push("status = ?"); values.push(body.status);
  }
  if (Object.prototype.hasOwnProperty.call(body, "publicNote")) {
    if (typeof body.publicNote !== "string" || body.publicNote.length > 3000) return json({ success: false, message: "Public note must be text up to 3,000 characters." }, 400);
    fields.push("public_note = ?", "public_note_updated_at = ?");
    values.push(body.publicNote.trim(), body.publicNote.trim() ? new Date().toISOString() : null);
  }
  if (Object.prototype.hasOwnProperty.call(body, "internalNote")) {
    if (typeof body.internalNote !== "string" || body.internalNote.length > 5000) return json({ success: false, message: "Internal note must be text up to 5,000 characters." }, 400);
    fields.push("internal_note = ?"); values.push(body.internalNote.trim());
  }
  if (!fields.length) return json({ success: false, message: "No valid fields were provided." }, 400);

  fields.push("updated_at = ?"); values.push(new Date().toISOString()); values.push(id);
  try {
    const result = await env.DB.prepare(`UPDATE projects SET ${fields.join(", ")} WHERE id = ?`).bind(...values).run();
    if (!result.meta?.changes) return json({ success: false, message: "Project not found." }, 404);
    return json({ success: true, message: "Project updated." });
  } catch {
    return json({ success: false, message: "Could not save changes. Check that notes columns exist." }, 500);
  }
}
