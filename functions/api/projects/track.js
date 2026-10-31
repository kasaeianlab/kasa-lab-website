
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

export async function onRequestPost({ request, env }) {
  // Check required configuration.
  if (!env.DB || !env.TRACKING_HASH_SECRET) {
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

  // Tracking codes contain KASA- followed by 48 hexadecimal characters.
  if (!/^KASA-[A-Fa-f0-9]{48}$/i.test(rawTrackingCode)) {
    return jsonResponse({
      success: false,
      message: "Please enter a valid tracking code."
    }, 400);
  }

  // Normalize only the hexadecimal part.
  // This preserves consistency with the original submission code.
  const trackingCode =
    "KASA-" + rawTrackingCode.slice(5).toLowerCase();

  // Hash the tracking code using the same secret and format
  // used when the project was originally submitted.
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

    // No matching project.
    if (!project) {
      return jsonResponse({
        success: false,
        message: "No project was found with this tracking code."
      }, 404);
    }

    // Return public information only.
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
