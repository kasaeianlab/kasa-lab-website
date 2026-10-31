# KASA Lab Admin Authentication deployment

This adds email one-time-password authentication for the single administrator `kasaeian.lab@gmail.com`.

## Cloudflare configuration

Keep the existing Pages D1 binding named `DB` and existing Resend settings. Confirm these Production secrets/variables exist:

- `ADMIN_AUTH_SECRET` — Secret, 64 hexadecimal characters generated locally (32 random bytes).
- `RESEND_API_KEY` — Secret.
- `RESEND_FROM_EMAIL` — verified sender, e.g. `KASA Lab Projects <projects@kasalab.org>`.

No Zero Trust subscription or payment card is needed for this implementation.

## Database

The three authentication tables were added using the Cloudflare D1 console in the previous setup step. For a fresh database, run `migrations/0002_admin_auth.sql` against the production D1 database bound as `DB`.

## Deploy

Commit and push all new files. Cloudflare Pages should deploy automatically. Then open:

- `https://kasalab.org/admin/` — request a six-digit code.
- `https://kasalab.org/admin/dashboard.html` — session-protected dashboard placeholder.

The code expires after five minutes. A successful login creates an eight-hour HttpOnly, Secure, SameSite=Strict cookie. Only the hard-coded administrator email is accepted. Login request and verification attempts are rate-limited in D1.

## API routes

- `POST /api/admin/auth/request` with JSON `{ "email": "kasaeian.lab@gmail.com" }`
- `POST /api/admin/auth/verify` with JSON `{ "email": "kasaeian.lab@gmail.com", "code": "123456" }`
- `GET /api/admin/auth/me`
- `POST /api/admin/auth/logout`

All responses are marked `Cache-Control: no-store`. The session token is never stored in plaintext in D1; only its HMAC is stored.

## Important scope note

This deployment provides authentication and a placeholder dashboard only. It does not yet implement project-list/detail/update APIs. Every future admin API must call `requireAdmin(request, env)` from `functions/_lib/admin-auth.js` before reading or changing project data. Do not expose `internal_note` through public tracking endpoints.
