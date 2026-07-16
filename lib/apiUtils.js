// lib/apiUtils.js
// Small shared helpers for app/api/** route handlers.

// Matches the 8-4-4-4-12 hex-group shape produced by gen_random_uuid() (and any
// standard UUID string). Deliberately loose on version/variant bits — this only
// exists to cheaply reject obviously-non-UUID path segments (e.g. "foo") before
// they reach a parameterized query against a UUID-typed column, where Postgres
// would otherwise throw a raw "invalid input syntax for type uuid" error.
const UUID_SHAPE_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isValidUuid(value) {
  return typeof value === 'string' && UUID_SHAPE_RE.test(value);
}

module.exports = { isValidUuid };
