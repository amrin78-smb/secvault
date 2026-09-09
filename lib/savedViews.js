// lib/savedViews.js
//
// Named filter/column/sort states for one table. See the saved_views comment
// in lib/schema.sql for why `query` is a raw URL query string.
//
// ⛔ Every function takes `pool` as a parameter (CLAUDE.md: never instantiate
// a Pool per request, never omit it from a signature that needs DB access).

'use strict';

// A view is per-table. Free text by design so a new page needs no migration,
// but it is normalised and length-capped so a typo cannot create a phantom
// scope that quietly hides someone's views forever.
function normalizeScope(scope) {
  if (typeof scope !== 'string') return null;
  const v = scope.trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9_-]{0,39}$/.test(v)) return null;
  return v;
}

function normalizeName(name) {
  if (typeof name !== 'string') return null;
  const v = name.trim().replace(/\s+/g, ' ');
  if (v === '' || v.length > 60) return null;
  return v;
}

// ⛔ The stored query string is REPLAYED into the address bar, so it is
// untrusted input that ends up shaping a page's own links. Strip the leading
// '?', reject anything with a scheme or a path separator, and cap the length:
// a saved view must be able to restore filters and nothing else.
function normalizeQuery(query) {
  if (typeof query !== 'string') return null;
  let v = query.trim();
  if (v.startsWith('?')) v = v.slice(1);
  if (v.length > 2000) return null;
  if (/[\s<>"'\\]/.test(v)) return null;
  if (v.includes('//') || v.includes(':')) return null;
  // An empty query is legal and means "the unfiltered table", which is a
  // perfectly reasonable thing to save as a default.
  return v;
}

/**
 * Views this user can see for one table: their own, plus anyone's shared ones.
 * Own views sort first so a shared view can never displace the operator's.
 */
async function listSavedViews(pool, userId, scope) {
  const s = normalizeScope(scope);
  if (!s || !userId) return [];
  const { rows } = await pool.query(
    `SELECT id, user_id, scope, name, query, shared, is_default, updated_at,
            (user_id = $1) AS owned
       FROM saved_views
      WHERE scope = $2 AND (user_id = $1 OR shared = true)
      ORDER BY (user_id = $1) DESC, is_default DESC, lower(name) ASC`,
    [userId, s]
  );
  return rows;
}

/**
 * Create or rename-in-place. Upsert on (user_id, scope, name) so saving twice
 * under one name updates rather than erroring at the operator.
 */
async function saveView(pool, userId, { scope, name, query, shared = false, isDefault = false }) {
  const s = normalizeScope(scope);
  const n = normalizeName(name);
  const q = normalizeQuery(query);
  if (!userId) throw new Error('saveView requires a user');
  if (!s) throw new Error('Invalid view scope');
  if (!n) throw new Error('A view name is required (60 characters max)');
  if (q === null) throw new Error('Invalid view query');

  // ⛔ Clearing the previous default MUST happen before the insert, in the
  // same transaction: uq_saved_views_one_default is a real DB constraint, so
  // doing it the other way round fails the insert rather than moving the
  // default. Same ordering rule as device_configs.is_baseline.
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (isDefault) {
      await client.query(
        'UPDATE saved_views SET is_default = false, updated_at = now() WHERE user_id = $1 AND scope = $2 AND is_default',
        [userId, s]
      );
    }
    const { rows } = await client.query(
      `INSERT INTO saved_views (user_id, scope, name, query, shared, is_default)
            VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (user_id, scope, name)
       DO UPDATE SET query = EXCLUDED.query,
                     shared = EXCLUDED.shared,
                     is_default = EXCLUDED.is_default,
                     updated_at = now()
         RETURNING id, user_id, scope, name, query, shared, is_default, updated_at`,
      [userId, s, n, q, Boolean(shared), Boolean(isDefault)]
    );
    await client.query('COMMIT');
    return rows[0];
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Delete one view. ⛔ Scoped to the OWNER in the SQL itself, not checked in the
 * route: a shared view is visible to everyone and must still only be
 * deletable by the person who made it, and putting that condition in the
 * WHERE clause means no future caller can forget it.
 */
async function deleteSavedView(pool, userId, id) {
  if (!userId || !id) return false;
  const { rowCount } = await pool.query(
    'DELETE FROM saved_views WHERE id = $1 AND user_id = $2',
    [id, userId]
  );
  return rowCount > 0;
}

/** The view to apply when a page is opened with no query of its own. */
async function getDefaultView(pool, userId, scope) {
  const s = normalizeScope(scope);
  if (!s || !userId) return null;
  const { rows } = await pool.query(
    'SELECT id, name, query FROM saved_views WHERE user_id = $1 AND scope = $2 AND is_default LIMIT 1',
    [userId, s]
  );
  return rows[0] || null;
}

module.exports = {
  listSavedViews,
  saveView,
  deleteSavedView,
  getDefaultView,
  normalizeScope,
  normalizeName,
  normalizeQuery,
};
