
const RATE_LIMIT = 3;
const RATE_WINDOW_SECONDS = 60 * 60;

const ALLOWED_SERVICES = new Set([
  "engineering-simulation",
  "thermal-engineering",
  "cfd-multiphysics",
  "research-development",
  "scientific-data-analysis",
  "technical-consulting",
  "other"
]);

const ALLOWED_ORGANIZATION_TYPES = new Set([
  "company",
  "university",
  "research-institution",
  "individual",
  "other"
]);

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

function cleanText(value, maxLength = 5000) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLength);
}

function randomToken(byteLength = 24) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);

  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function validEmail(email) {
  return (
    email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  );
}

async function checkRateLimit(env, ipHash, now) {
  const windowStart = now - RATE_WINDOW_SECONDS;

  await env.DB.prepare(`
    INSERT INTO submission_rate_limits
      (ip_hash, window_started_at, request_count)
    VALUES (?, ?, 1)
    ON CONFLICT(ip_hash) DO UPDATE SET
      window_started_at = CASE
        WHEN submission_rate_limits.window_started_at <= ?
        THEN excluded.window_started_at
        ELSE submission_rate_limits.window_started_at
      END,
      request_count = CASE
        WHEN submission_rate_limits.window_started_at <= ?
        THEN 1
        ELSE submission_rate_limits.request_count + 1
      END
  `)
    .bind(ipHash, now, windowStart, windowStart)
    .run();

  const row = await env.DB.prepare(`
    SELECT request_count, window_started_at
    FROM submission_rate_limits
    WHERE ip_hash = ?
  `)
    .bind(ipHash)
    .first();

  return Boolean(
    row &&
    row.request_count <= RATE_LIMIT &&
    now - row.window_started_at < RATE_WINDOW_SECONDS
  );
}

async function sendNotification(env, project, trackingCode) {
  if (
    !env.RESEND_API_KEY ||
    !env.RESEND_FROM_EMAIL ||
    !env.ADMIN_EMAIL
  ) {
    return false;
  }

  const message = [
    "A new project request has been submitted to KASA Lab.",
    "",
    `Project ID: ${project.id}`,
    `Tracking code: ${trackingCode}`,
    `Name: ${project.name}`,
    `Email: ${project.email}`,
    `Organization: ${project.organization || "Not provided"}`,
    `Organization type: ${project.organization_type}`,
    `Country: ${project.country || "Not provided"}`,
    `Service: ${project.service_type}`,
    `Project title: ${project.project_title}`,
    `Timeline: ${project.timeline || "Not provided"}`,
    "",
    "Description:",
    project.description,
    "",
    "Expected deliverables:",
    project.expected_deliverables || "Not provided",
    "",
    "No files were uploaded. File uploads are temporarily unavailable."
  ].join("\n");

  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: env.RESEND_FROM_EMAIL,
        to: [env.ADMIN_EMAIL],
        reply_to: project.email,
        subject: `New KASA Lab project request: ${project.project_title}`,
        text: message
      })
    });

    return response.ok;
  } catch {
    return false;
  }
}

export async function onRequestPost({ request, env }) {
  if (
    !env.DB ||
    !env.TRACKING_HASH_SECRET ||
    !env.RATE_LIMIT_SALT
  ) {
    return jsonResponse({
      success: false,
      message: "The project submission service is not fully configured."
    }, 503);
  }

  const contentType = request.headers.get("Content-Type") || "";

  if (!contentType.toLowerCase().startsWith("multipart/form-data")) {
    return jsonResponse({
      success: false,
      message: "Please submit the form using the supported form."
    }, 415);
  }

  // File uploads are temporarily disabled.
  // Reject oversized requests before parsing the form.
  const contentLength = Number(request.headers.get("Content-Length") || 0);

  if (contentLength > 128 * 1024) {
    return jsonResponse({
      success: false,
      message: "The request is too large. Please submit without attachments."
    }, 413);
  }

  let form;

  try {
    form = await request.formData();
  } catch {
    return jsonResponse({
      success: false,
      message: "The submitted form could not be read."
    }, 400);
  }

  // Honeypot: ordinary visitors should leave this field empty.
  if (cleanText(form.get("website"), 200)) {
    return jsonResponse({
      success: true,
      message: "Submission received."
    });
  }

  const name = cleanText(form.get("name"), 150);
  const email = cleanText(form.get("email"), 254).toLowerCase();
  const organization = cleanText(form.get("organization"), 200);
  const organizationType = cleanText(form.get("organization_type"), 50);
  const country = cleanText(form.get("country"), 100);
  const serviceType = cleanText(form.get("service_type"), 80);
  const projectTitle = cleanText(form.get("project_title"), 200);
  const description = cleanText(form.get("description"), 10000);
  const expectedDeliverables = cleanText(
    form.get("expected_deliverables"),
    4000
  );
  const timeline = cleanText(form.get("timeline"), 150);

  if (
    !name ||
    !validEmail(email) ||
    !organizationType ||
    !ALLOWED_ORGANIZATION_TYPES.has(organizationType) ||
    !ALLOWED_SERVICES.has(serviceType) ||
    !projectTitle ||
    !description
  ) {
    return jsonResponse({
      success: false,
      message: "Please complete all required fields with valid information."
    }, 400);
  }

  // Do not accept attachments until private file storage is configured.
  const submittedFiles = form.getAll("files").filter(
    (item) => item instanceof File && item.size > 0
  );

  if (submittedFiles.length > 0) {
    return jsonResponse({
      success: false,
      message: "File uploads are temporarily unavailable. Please remove attachments and submit your request again."
    }, 400);
  }

  const now = Math.floor(Date.now() / 1000);
  const ipAddress = request.headers.get("CF-Connecting-IP") || "unknown";
  const ipHash = await sha256Hex(
    `${env.RATE_LIMIT_SALT}:${ipAddress}`
  );

  let allowed;

  try {
    allowed = await checkRateLimit(env, ipHash, now);
  } catch {
    return jsonResponse({
      success: false,
      message: "The submission service is temporarily unavailable."
    }, 503);
  }

  if (!allowed) {
    return jsonResponse({
      success: false,
      message: "Too many submissions. Please try again later."
    }, 429);
  }

  const projectId = crypto.randomUUID();
  const trackingCode = `KASA-${randomToken(24)}`;
  const trackingHash = await sha256Hex(
    `${env.TRACKING_HASH_SECRET}:${trackingCode}`
  );
  const timestamp = new Date().toISOString();

  const project = {
    id: projectId,
    name,
    email,
    organization,
    organization_type: organizationType,
    country,
    service_type: serviceType,
    project_title: projectTitle,
    description,
    expected_deliverables,
    timeline
  };

  try {
    await env.DB.prepare(`
      INSERT INTO projects (
        id,
        tracking_hash,
        name,
        email,
        organization,
        organization_type,
        country,
        service_type,
        project_title,
        description,
        expected_deliverables,
        timeline,
        budget_range,
        status,
        created_at,
        updated_at,
        notification_status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      project.id,
      trackingHash,
      project.name,
      project.email,
      project.organization || null,
      project.organization_type,
      project.country || null,
      project.service_type,
      project.project_title,
      project.description,
      project.expected_deliverables || null,
      project.timeline || null,
      null,
      "Submitted",
      timestamp,
      timestamp,
      "pending"
    ).run();
  } catch {
    return jsonResponse({
      success: false,
      message: "We could not save your request. Please try again later."
    }, 500);
  }

  const emailSent = await sendNotification(env, project, trackingCode);

  try {
    await env.DB.prepare(`
      UPDATE projects
      SET notification_status = ?, updated_at = ?
      WHERE id = ?
    `).bind(
      emailSent ? "sent" : "failed",
      new Date().toISOString(),
      projectId
    ).run();
  } catch {
    // The request remains saved even if updating this status fails.
  }

  return jsonResponse({
    success: true,
    projectId,
    trackingCode,
    emailSent,
    message: emailSent
      ? "Your request has been submitted successfully."
      : "Your request has been saved, but email notification could not be confirmed. Please keep your tracking code."
  }, 201);
}
