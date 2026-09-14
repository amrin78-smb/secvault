import Link from 'next/link';
import { describeConfigChange } from '../../lib/configChangeSummary';
import { pool } from '../../lib/db';
import Card from '../ui/Card';
import EmptyState from '../ui/EmptyState';
import IconChip from '../ui/IconChip';
import NotMeasured from '../ui/NotMeasured';
import { IconRefresh } from '../icons';

// Dashboard widget: fleet-wide config-change summary over the trailing
// `days` window. Standalone, read-only, server component -- not wired into
// any page yet (a later assembly pass does that).
//
// config_diffs.diff IS a structured jsonb object ({added:[...],
// removed:[...], modified:[...]} -- see lib/engines/configDiff.js's
// diffConfigs()/detectAndStoreDiff()), so an Added/Removed/Modified count
// breakdown below is real data read straight out of that column via
// jsonb_array_length(), not a fabricated split. What IS honestly absent is
// any structured "what changed" beyond that (no per-field type/severity),
// so beyond the counts this only lists change_summary strings (the same
// free-text field app/api/events/route.js's fetchConfigDiffs() and
// alerts/page.js already surface), not a synthesized categorization.
//
// `d.active = true` filter copied from the same convention as
// app/api/events/route.js's fetchConfigDiffs() / alerts/page.js. `days` is
// passed as a numeric parameter multiplied against interval '1 day' --
// never string-concatenated into the query -- per CLAUDE.md's "always
// parameterized queries" rule, with no exception for internally-supplied
// prop values.

async function getConfigChanges(dbPool, days) {
  const { rows } = await dbPool.query(
    `SELECT cd.id, cd.device_id, d.name AS device_name, cd.change_summary, cd.diff, cd.detected_at,
            -- ⛔ NO COALESCE(..., 0) HERE, deliberately. These three used to be
            -- wrapped in COALESCE(x, 0), which made "this diff row has no
            -- structured added/removed/modified payload" indistinguishable from
            -- "this change added, removed and modified exactly nothing" — a
            -- fabricated zero standing in for an absent read, the exact class
            -- this codebase treats as a Critical Rule. NULL now means the key was
            -- absent or was not an array, and the render below reports that
            -- separately instead of summing it in as zero.
            --
            -- The jsonb_typeof guard also removes a real crash: jsonb_array_length()
            -- RAISES on a non-array input, so one malformed diff row would have
            -- failed the whole dashboard query.
            CASE WHEN jsonb_typeof(cd.diff->'added') = 'array'
                 THEN jsonb_array_length(cd.diff->'added') END AS added_count,
            CASE WHEN jsonb_typeof(cd.diff->'removed') = 'array'
                 THEN jsonb_array_length(cd.diff->'removed') END AS removed_count,
            CASE WHEN jsonb_typeof(cd.diff->'modified') = 'array'
                 THEN jsonb_array_length(cd.diff->'modified') END AS modified_count
     FROM config_diffs cd
     JOIN devices d ON d.id = cd.device_id
     WHERE d.active = true
       AND cd.detected_at > now() - ($1::int * interval '1 day')
     ORDER BY cd.detected_at DESC`,
    [days]
  );
  return rows;
}

const RECENT_LIST_LIMIT = 5;

export default async function ConfigChangesWidget({ days = 7 }) {
  const rows = await getConfigChanges(pool, days);

  const totalCount = rows.length;
  // ⛔ A row whose diff carries none of the three arrays contributes NOTHING to
  // the totals and is counted separately as unstructured. Folding it in as
  // 0/0/0 would report "this change touched no lines", which is a measurement
  // we never made.
  const totals = rows.reduce(
    (acc, r) => {
      const a = r.added_count;
      const d = r.removed_count;
      const m = r.modified_count;
      if (a === null && d === null && m === null) {
        acc.unstructured += 1;
        return acc;
      }
      acc.measured += 1;
      acc.added += Number(a) || 0;
      acc.removed += Number(d) || 0;
      acc.modified += Number(m) || 0;
      return acc;
    },
    { added: 0, removed: 0, modified: 0, measured: 0, unstructured: 0 }
  );
  const recent = rows.slice(0, RECENT_LIST_LIMIT);

  return (
    <Card>
      <div className="card-header-compact">
        <div className="card-title-compact" style={{ display: 'flex', alignItems: 'center', gap: 'var(--s2)' }}>
          {/* ⛔ NOT --tint-purple. app/globals.css aliases exactly that pair as
              --evidence / --evidence-wash, and violet is reserved for the
              EVIDENCE axis and nothing else -- this chip was pixel-identical to
              an EvidenceMark, so the one mark in the product that means "here is
              how we know this" stopped being learnable at a glance the moment a
              decorative widget header wore it too. --tint-info is the app's
              neutral informational pair (DeviceStatusSummary already uses it for
              the same kind of factual, non-risk widget). Blue is barred from the
              SEVERITY RAMP, not from the palette: a config change is an event,
              not a severity, so nothing here reads as a risk level. */}
          <IconChip icon={IconRefresh} color="var(--tint-info-fg)" bg="var(--tint-info)" />
          Config Changes ({days}d)
        </div>
      </div>
      <div className="card-body-compact">
        {totalCount === 0 ? (
          <EmptyState message={`No configuration changes in the last ${days} days.`} />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
            <div style={{ display: 'flex', gap: 'var(--s3)', flexWrap: 'wrap', alignItems: 'flex-end' }}>
              <div>
                <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {totalCount}
                </div>
                {/* ⛔ --text-xs, not 10px. The type scale starts at --text-xs
                    (11.5px) and a hardcoded 10 sits BELOW its smallest step --
                    it opts itself out of every future scale change silently, the
                    same way a hardcoded hex opts out of the palette, and it does
                    so in the direction that hurts: smaller than anything the
                    scale allows. */}
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                  Change{totalCount === 1 ? '' : 's'}
                </div>
              </div>
              <div style={{ display: 'flex', gap: 'var(--s2)', alignItems: 'flex-end', fontSize: 'var(--text-xs)' }}>
                {totals.measured === 0 ? (
                  // Every row in the window lacked a structured diff — there is
                  // no added/removed/modified count to report at all. Three
                  // zeros here would be three fabricated measurements.
                  <NotMeasured reason="None of these changes stored a structured added/removed/modified diff, so the line counts are unknown." />
                ) : (
                  // ⛔ THE TEXT-SAFE TINT FOREGROUNDS, NOT THE RAW RAMP HUES.
                  // The raw hues are GRAPHICS tokens: globals.css measures
                  // --yellow at 3.64:1 on a card in light theme, which clears
                  // WCAG 1.4.11's 3:1 for a bar or a dot and FAILS 1.4.3's
                  // 4.5:1 for text. --green and --red were 4.80:1, i.e. passing
                  // by 0.3 and one palette tweak away from not. These three
                  // were text.
                  //
                  // ⛔ AND THIS IS NOT THE SEVERITY RAMP, which is why the
                  // colours stay at all. "removed" here means LINES REMOVED
                  // from a config, not danger -- red is reserved for danger in
                  // this product and a deletion is not one. What these three
                  // are is the DIFF vocabulary, which components/config/
                  // DiffViewer.js already fixes as added/removed/modified ->
                  // success/danger/warning, on the same --tint-*-fg tokens.
                  // This widget links straight into that viewer, so inventing
                  // a private hueless treatment here would mean the summary and
                  // the page it opens spoke different languages about the same
                  // three numbers. One vocabulary, in its readable form.
                  <>
                    <span style={{ color: 'var(--tint-success-fg)', fontWeight: 600 }}>{totals.added} added</span>
                    <span style={{ color: 'var(--tint-danger-fg)', fontWeight: 600 }}>{totals.removed} removed</span>
                    <span style={{ color: 'var(--tint-warn-fg)', fontWeight: 600 }}>{totals.modified} modified</span>
                  </>
                )}
              </div>
            </div>
            {totals.unstructured > 0 && totals.measured > 0 && (
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--unmeasured)' }}>
                Counts cover {totals.measured} of {totalCount} changes — {totals.unstructured} stored no structured
                diff.
              </div>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
              {recent.map((r) => (
                <Link
                  key={r.id}
                  href={`/devices/${r.device_id}/changes`}
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 'var(--s1)',
                    padding: 'var(--s2)',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--border)',
                    color: 'inherit',
                    textDecoration: 'none',
                  }}
                >
                  <span style={{ fontWeight: 500, fontSize: 'var(--text-xs)', color: 'var(--text-primary)' }}>
                    {r.device_name}
                  </span>
                  <span
                    style={{
                      fontSize: 'var(--text-xs)',
                      color: 'var(--text-secondary)',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                    title={r.change_summary || 'Config changed'}
                  >
                    {describeConfigChange(r.diff, r.change_summary) || 'Config changed'}
                  </span>
                </Link>
              ))}
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}
