'use strict';

// lib/rbac.js
//
// Minimal role-based access control helper. Two roles only: `admin` (full
// access, the only role that can write anything) and `viewer` (strictly
// read-only — cannot acknowledge/dismiss findings, run analyses, trigger
// syncs, rotate credentials, delete devices, or change any setting).
// Deliberately NOT a granular permission system (no "viewer can acknowledge
// but not delete" middle ground) — a coarse, unambiguous boundary is safer
// than a fine-grained one that's easy to get subtly wrong across dozens of
// routes.
//
// Every route resolves its own session via the already-established
// `getServerSession(authOptions)` pattern (see any existing route under
// app/api/devices/[id]/*), then calls isAdmin(session) from here. This
// file deliberately does NOT import authOptions itself or do session
// resolution — keeping it a pure, dependency-free CommonJS module avoids
// any ESM/CJS interop risk with the Next.js route files that import it.

const ADMIN_ROLE = 'admin';
const VIEWER_ROLE = 'viewer';

function isAdmin(session) {
  return !!session && !!session.user && session.user.role === ADMIN_ROLE;
}

// Standard 403 JSON body used by every write route's guard, matching the
// Response shape Next.js route handlers already return elsewhere in this
// app (NextResponse.json(...) or plain Response with a JSON body).
function forbiddenResponse() {
  return new Response(
    JSON.stringify({ error: 'Forbidden — admin role required' }),
    { status: 403, headers: { 'Content-Type': 'application/json' } }
  );
}

module.exports = { ADMIN_ROLE, VIEWER_ROLE, isAdmin, forbiddenResponse };
