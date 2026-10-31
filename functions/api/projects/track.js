
const RATE_LIMIT = 5;
const RATE_WINDOW_SECONDS = 15 * 60;

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

async function sha256Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);

  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function checkRateLimit(request, env) {
  const ip = request.headers.get("CF-Connecting-IP");

  if (!ip) {
    return { allowed: false, error: true };
  }

  const ipHash = await sha256Hex(
    `${env.RATE_LIMIT_SALT}:${ip}`
  );

  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - RATE_WINDOW_SECONDS;

  try {
    const result = await env.DB.prepare(`
      INSERT INTO tracking_rate_limits (
        ip_hash,
        request_count,
        window_start
      )
      VALUES (?, 1, ?)

      ON CONFLICT(ip_hash) DO UPDATE SET
        request_count = CASE
          WHEN tracking_rate_limits.window_start <= ?
          THEN 1
          ELSE tracking_rate_limits.request_count + 1
        END,
        window_start = CASE
          WHEN tracking_rate_limits.window_start <= ?
          THEN excluded.window_start
          ELSE tracking_rate_limits.window_start
        END

      RETURNING request_count, window_start
    `)
      .bind(ipHash, now, windowStart, windowStart)
      .first();

    if (!result) {
      return { allowed: false, error: true };
    }

    return {
      allowed: result.request_count <= RATE_LIMIT,
      retryAfter: Math.max(
        1,
        result.window_start + RATE_WINDOW_SECONDS - now
      )
    };

  } catch {
    return { allowed: false, error: true };
  }
}

export async function onRequestPost({ request, env }) {
  // Check required configuration.
  if (
    !env.DB ||
    !env.TRACKING_HASH_SECRET ||
    !env.RATE_LIMIT_SALT
  ) {
    return jsonResponse({
      success: false,
      message: "The tracking service is not fully configured."
    }, 503);
  }

  // Accept JSON requests only.
  const contentType = request.headers.get("Content-Type") || "";

  if (!contentType.toLowerCase().includes("application/json")) {
    return jsonResponse({
      success: false,
      message: "Please use a valid tracking request."
    }, 415);
  }

  // Reject oversized requests.
  const contentLength = Number(
    request.headers.get("Content-Length") || 0
  );

  if (contentLength > 2048) {
    return jsonResponse({
      success: false,
      message: "Invalid request."
    }, 413);
  }

  // Apply rate limiting before processing the tracking code.
  const rateLimit = await checkRateLimit(request, env);

  if (rateLimit.error) {
    return jsonResponse({
      success: false,
      message: "The tracking service is temporarily unavailable."
    }, 503);
  }

  if (!rateLimit.allowed) {
    return new Response(
      JSON.stringify({
        success: false,
        message: "Too many tracking attempts. Please try again later."
      }),
      {
        status: 429,
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Cache-Control": "no-store",
          "Retry-After": String(rateLimit.retryAfter),
          "X-Content-Type-Options": "nosniff"
        }
      }
    );
  }

  // Read request body.
  let body;

  try {
    body = await request.json();
  } catch {
    return jsonResponse({
      success: false,
      message: "Invalid request format."
    }, 400);
  }

  // Read and validate tracking code.
  const rawTrackingCode =
    typeof body.trackingCode === "string"
      ? body.trackingCode.trim()
      : "";

  if (!/^KASA-[A-Fa-f0-9]{48}$/i.test(rawTrackingCode)) {
    return jsonResponse({
      success: false,
      message: "Please enter a valid tracking code."
    }, 400);
  }

  // Normalize only the hexadecimal part.
  const trackingCode =
    "KASA-" + rawTrackingCode.slice(5).toLowerCase();

  // Hash the tracking code.
  let trackingHash;

  try {
    trackingHash = await sha256Hex(
      `${env.TRACKING_HASH_SECRET}:${trackingCode}`
    );
  } catch {
    return jsonResponse({
      success: false,
      message: "The tracking service is temporarily unavailable."
    }, 500);
  }

  // Retrieve public project information only.
  try {
    const project = await env.DB.prepare(`
      SELECT
        project_title,
        status,
        created_at,
        updated_at,
        public_note,
        public_note_updated_at
      FROM projects
      WHERE tracking_hash = ?
      LIMIT 1
    `)
      .bind(trackingHash)
      .first();

    if (!project) {
      return jsonResponse({
        success: false,
        message: "No project was found with this tracking code."
      }, 404);
    }

    return jsonResponse({
      success: true,
      project: {
        projectTitle: project.project_title,
        status: project.status,
        submittedAt: project.created_at,
        updatedAt: project.updated_at,
        publicNote: project.public_note,
        publicNoteUpdatedAt: project.public_note_updated_at
      }
    });

  } catch {
    return jsonResponse({
      success: false,
      message: "The tracking service is temporarily unavailable."
    }, 500);
  }
}
