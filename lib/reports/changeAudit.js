// lib/reports/changeAudit.js
//
// R8 — "Configuration Change Audit". Fleet-wide, or narrowed to one firewall.
//
// It answers one question: WHAT CHANGED ON OUR FIREWALLS, WHEN, AND DID ANYONE
// LOOK AT IT? This is the document an auditor asks for when they want evidence
// of change control rather than an assertion of it.
//
// ⛔ FOUR THINGS MAKE THIS DOCUMENT WORTH HANDING TO AN AUDITOR. Each of them is
// a way the obvious implementation would lie.
//
// 1. ⛔ IT PRINTS CHANGED KEYS, NEVER CHANGED VALUES.
//    A firewall configuration contains pre-shared keys, SNMP communities, local
//    admin password hashes and API tokens. SecVault already redacts those before
//    a config or a diff is ever stored (see .ai-codex/gotchas.md's Redaction
//    rules), and `config_diffs` rows on the live fleet do carry `<redacted>`
//    placeholders — but a PDF is emailed, forwarded and archived, and it is the
//    single worst place in this product for a secret to surface. So this report
//    does not rely on that redaction being complete. It never reads a diff
//    entry's `value`, `old` or `new` AT ALL. Only `path` — the KEY that changed
//    — reaches the page, and the assembled data object carries no diff payload
//    onward, so a future renderer cannot print one either. That is a structural
//    guarantee rather than a filter, which is the only kind worth having here:
//    a filter has to be right about every vendor's config shape forever.
//
// 2. ⛔ "NO DIFFS RECORDED" IS NOT "NOTHING CHANGED".
//    A firewall whose config collection is failing produces no diffs and reads,
//    on any naive change report, as the most stable device on the estate. It is
//    the failed-read-as-a-fact rule in its most seductive form, because silence
//    reads as calm. So a firewall is only credited with a quiet window when
//    SecVault actually ran a COMPARISON on it in that window — which needs two
//    snapshots, not one. Everything else is UNKNOWN, counted on the cover, and
//    given its own section. Live on the reference fleet this is not
//    hypothetical: one firewall's last config snapshot is 40 days old and one
//    has a single snapshot and therefore no comparison at all.
//
// 3. ⛔ THE CHANGE RECORD OUTLIVES THE SNAPSHOT IT CAME FROM.
//    `config_diffs` is append-only and carries its own stored payload, with no
//    reference to any `device_configs` row. Config retention deletes snapshots
//    after 60 days. So a change from three months ago is still a real, provable
//    change whose before/after configurations no longer exist. Rendering that as
//    an empty diff would read as "there was nothing in it"; it says
//    "snapshot no longer retained" instead.
//
// 4. ⛔ AN UNREVIEWED CHANGE IS THE FINDING, NOT THE CHANGE.
//    Firewalls are supposed to change. Change control is about whether a human
//    saw it. Acknowledgement is the evidence of review, so unacknowledged
//    changes get their own prominent section — and the document says plainly
//    that an acknowledgement proves a box was ticked, not that anyone read the
//    change. Where acknowledgements arrive in bursts, it says so, as a timing
//    observation and not as an allegation.
//
// ⛔ BASELINE DRIFT IS A DIFFERENT QUESTION AND IS NOT CONFLATED WITH THIS ONE.
// Every change here is a CONSECUTIVE-PULL comparison: this collection against
// the one before it. Drift is latest-versus-an-operator-designated-baseline. The
// two differ precisely because a consecutive-pull comparison target may itself
// already be drifted — a device that drifted once and then sat still reports
// zero changes here forever. `device_configs.is_baseline` is reported alongside,
// as coverage, never merged into the change counts.
//
// CommonJS — same reason as every engine and every other report: the App Router
// and plain-node callers both load it.

'use strict';

const PDFDocument = require('pdfkit');

const {
  NAVY, MUTED, GREEN, INK,
  // ⛔ The status ramp comes from the chassis, not from a local copy. A change
  // that is amber on screen and red in the PDF an auditor is holding is two
  // different claims about the same fact.
  STATUS_RED, ORANGE, BLUE, UNMEASURED,
  fmtStamp, installPdfSafeText,
  layoutOf,
  drawCover, sectionTitle, paragraph, labelledNote, drawTable, stampHeadersFooters,
} = require('./chassis');

const { PRODUCT_NAME } = require('../branding');

// ⛔ IMPORTED, NEVER RE-IMPLEMENTED. `classifyDiff()` is the one place that knows
// which section of a vendor's configuration tree a given path belongs to, and it
// is already applied at read time by the diffs API route, so this document and
// the app's own Diff panel name the same change the same way. Only its SECTION
// LABELS AND COUNTS are used here — never `entries[].value/old/new`, never
// `ruleChanges[].value`. See the redaction note at the top of this file.
const { classifyDiff } = require('../engines/configDiff');

// ── the printed form of an unknown ────────────────────────────────────────
// ⛔ chassis.pdfSafe() folds this to an ASCII hyphen, which is the point: what
// must never appear in one of these cells is a `0`. A dash reads as "no value";
// a zero reads as a measurement.
const NOT_MEASURED_MARK = '—';

// ── secret-shaped keyword pattern ─────────────────────────────────────────
//
// ⛔ A LOCAL COPY, ON PURPOSE, AND IT MUST BE KEPT IN STEP. This codebase's
// documented convention (.ai-codex/gotchas.md, "Universal keyword pattern") is
// that every redaction site carries its own copy rather than importing a shared
// module, and that widening one means widening all of them. The canonical copies
// live in lib/adapters/forcepoint/parser.js, lib/adapters/checkpoint/parser.js
// and lib/engines/configDiff.js's SECRET_PATH_PATTERN. This is the fourth.
//
// ⛔ IT IS NOT WHAT KEEPS SECRETS OUT OF THIS DOCUMENT. That job is done
// structurally — no diff value is ever read. This pattern does two narrower
// things: it FLAGS a changed key as credential-bearing so the reader knows a
// secret was rotated without being shown it, and it withholds operator free text
// that mentions a credential-shaped word.
const SECRET_KEYWORD_PATTERN =
  /secret|password|passwd|psk|pre[-_]?shared|private[-_]?key|phash|community|credential|token|api[-_]?key|keytab/i;

// Section/setting names that merely contain a secret-shaped substring. Mirrors
// configDiff.js's SECRET_PATH_EXCEPTIONS — Fortinet's `password_policy` is a
// real config section holding `minimum-length`/`status`, not a credential.
const SECRET_KEYWORD_EXCEPTIONS = new Set(['password_policy', 'password-policy']);

/**
 * True when the LEAF field name of a dot/bracket diff path looks secret-shaped.
 * Same "check only the immediate field name" approach as configDiff.js.
 */
function isSecretShapedKey(path) {
  const field = String(path == null ? '' : path).split(/[.[]/).pop();
  if (SECRET_KEYWORD_EXCEPTIONS.has(field.toLowerCase())) return false;
  return SECRET_KEYWORD_PATTERN.test(field);
}

/**
 * Operator free text — an acknowledgement note, an activity-log detail line —
 * withheld when it mentions a credential-shaped word.
 *
 * ⛔ FAIL-CLOSED AND DELIBERATELY OVER-BROAD. This text is typed by a human and
 * SecVault has no way to know whether "psk rotated to <value>" ends in a value.
 * Over-withholding costs a sentence of context in a document that still shows
 * the row, the actor and the timestamp; under-withholding puts a credential in a
 * file that gets emailed. The row is never dropped, and the reason is printed in
 * place of the text, so a reader can go and look it up in the app.
 */
function safeFreeText(text) {
  if (text == null || text === '') return '';
  const s = String(text);
  if (SECRET_KEYWORD_PATTERN.test(s)) {
    return '(note withheld - it mentions a credential-shaped word; read it in the app)';
  }
  return s;
}

// ── small formatters ──────────────────────────────────────────────────────

function num(n) {
  return Number(n || 0).toLocaleString('en-GB');
}

function plural(n, one, many) {
  return Number(n) === 1 ? one : many;
}

/**
 * A count cell. `known === false` means the number is not zero, it is UNKNOWN.
 * A firewall SecVault never collected from has not had zero changes; it has an
 * unanswered question, and the two must not share a glyph.
 */
function countCell(value, known) {
  return known === false ? NOT_MEASURED_MARK : num(value);
}

/** Clamp the reporting window. Never 0 days, never a fraction, never negative. */
function clampDays(v, def) {
  const n = Number(v);
  if (!Number.isFinite(n)) return def;
  return Math.max(Math.trunc(n), 1);
}

/**
 * Clamp a caller-supplied table cap. ⛔ Never 0: a cap of 0 would silently empty
 * a section, which on the page is indistinguishable from "nothing was found".
 */
function clampCap(v, def) {
  const n = Number(v);
  if (!Number.isFinite(n)) return def;
  return Math.max(Math.trunc(n), 1);
}

/**
 * "Showing N of M". ⛔ NEVER A SILENT CAP — a truncated table that does not say
 * so is a wrong answer, not a shorter one. Returns null when nothing was
 * dropped, so the caller prints nothing rather than a reassuring "showing all".
 */
function truncationNote(shown, total, noun) {
  if (shown >= total) return null;
  return `Showing ${num(shown)} of ${num(total)} ${noun}, newest first. `
    + 'The remainder are not in this document - the full list is in the app.';
}

const MAX_KEY_DISPLAY_LENGTH = 76;

// ⛔ A DIFF "PATH" IS NOT ALWAYS A PATH, AND THIS REPORT IS THE FOURTH PLACE
// THAT HAS HAD TO LEARN IT.
//
// A real config path is dot/bracket-separated identifiers and never contains
// whitespace or braces. When a vendor parser mis-segments its input, hundreds or
// thousands of characters of RAW CONFIGURATION TEXT end up inside what should
// have been one short object key. configDiff.js documents this as a live
// production fact (a `change_summary` row of 13,647 characters, two of whose
// example paths were ~6,800-character blobs) and names the three render surfaces
// that each had to be fixed independently — `change_summary`, classifyDiff()'s
// section entries, and its rule-change rows.
//
// ⛔ FOUND AGAIN HERE, ON LIVE DATA, WHILE VERIFYING THIS REPORT: one PAN-OS
// address-object diff path is ~10 KB of brace-grammar config carrying the
// estate's entire internal address book and a run of `phash <redacted>` lines.
// So "we only print KEYS, therefore we are safe" is NOT true on its own — a
// corrupted key is a config excerpt wearing a key's clothes. Two consequences,
// both applied at EXTRACTION rather than at draw time, so the assembled data
// object never carries the blob for some future consumer to print:
//
//   1. A shape violation swaps in an honest PLACEHOLDER rather than a truncated
//      fragment. A truncated fragment still reads as a real, oddly-formatted
//      key — and, on this report, it would put a slice of somebody's internal
//      topology in an auditor's PDF while looking like a field name.
//   2. It is reported as CORRUPTED, never as a credential field. Labelling it
//      "credential field" because the blob happens to contain the word `phash`
//      would be a confident false statement about a field that does not exist.
//
// Wording matches configDiff.js's own placeholder so the two documents say the
// same thing about the same row. The regex is the same one for the same reason;
// neither is exported, and this codebase's convention is a kept-in-step copy.
const PATH_SHAPE_VIOLATION = /[\s{}]/;
const UNREADABLE_KEY_MARK = '(unreadable path - see the full record in the app)';

/**
 * Sanitise a stored diff path for BOTH storage in the report data and display.
 * Returns `{path, corrupted}`.
 */
function safeKeyPath(path) {
  const s = String(path == null ? '' : path);
  if (PATH_SHAPE_VIOLATION.test(s)) return { path: UNREADABLE_KEY_MARK, corrupted: true };
  if (s.length > MAX_KEY_DISPLAY_LENGTH) {
    const head = Math.ceil((MAX_KEY_DISPLAY_LENGTH - 3) / 2);
    const tail = Math.floor((MAX_KEY_DISPLAY_LENGTH - 3) / 2);
    return { path: `${s.slice(0, head)}...${s.slice(s.length - tail)}`, corrupted: false };
  }
  return { path: s, corrupted: false };
}

/** Display-only shortening of a key path. Kept for callers that already hold a
 *  sanitised path; delegates to the same rule so the two cannot drift. */
function shortenKey(path) {
  return safeKeyPath(path).path;
}

const CHANGE_MARK = Object.freeze({ added: '+', removed: '-', modified: '~' });

// ── the diff payload, read for KEYS ONLY ──────────────────────────────────

// diffConfigs() caps a single recorded change at 500 entries and pushes one
// sentinel entry in place of the rest. A capped record is a PARTIAL record of
// that change and must say so, not quietly present itself as the whole thing.
const TRUNCATION_SENTINEL = '(truncated)';

/**
 * ⛔ THE ONE FUNCTION THAT TOUCHES A STORED DIFF PAYLOAD, AND IT READS EXACTLY
 * ONE FIELD FROM IT: `path`.
 *
 * `value`, `old` and `new` are never read, never copied, and never returned.
 * That is the whole redaction posture of this report expressed as a function
 * signature — it is not possible to print a secret from the object this returns
 * because the object does not contain one.
 *
 * Pure. Never throws: a malformed payload yields `payloadUnreadable`, which the
 * page prints, rather than an empty list that would read as "nothing changed".
 *
 * ⛔ The `path` it returns is SANITISED (see safeKeyPath) — a stored "path" can
 * itself be kilobytes of raw configuration text, so returning it verbatim would
 * reintroduce exactly the leak this function exists to prevent.
 *
 * @param {*} diff the raw `config_diffs.diff` jsonb
 * @param {number} maxKeys how many keys to carry for display
 * @returns {{added:number, removed:number, modified:number, total:number,
 *            keys:{changeType:string, path:string, corrupted:boolean, secretShaped:boolean}[],
 *            corruptedKeys:number,
 *            payloadTruncated:boolean, payloadUnreadable:boolean}}
 */
function changedKeysOf(diff, maxKeys) {
  const empty = {
    added: 0, removed: 0, modified: 0, total: 0, keys: [], corruptedKeys: 0,
    payloadTruncated: false, payloadUnreadable: true,
  };
  if (diff == null || typeof diff !== 'object' || Array.isArray(diff)) return empty;

  const lists = [
    ['added', Array.isArray(diff.added) ? diff.added : null],
    ['removed', Array.isArray(diff.removed) ? diff.removed : null],
    ['modified', Array.isArray(diff.modified) ? diff.modified : null],
  ];
  // ⛔ A payload with none of the three arrays present is UNREADABLE, not empty.
  // "We could not read this record" and "this record contains no changes" are
  // opposite claims and only one of them is a measurement.
  if (lists.every(([, arr]) => arr === null)) return empty;

  const out = {
    added: 0, removed: 0, modified: 0, total: 0, keys: [], corruptedKeys: 0,
    payloadTruncated: false, payloadUnreadable: false,
  };
  for (const [changeType, arr] of lists) {
    if (!arr) continue;
    for (const entry of arr) {
      // ⛔ `entry.path` and nothing else. Never destructure the entry, never
      // spread it, never carry it forward — a spread is how a value ends up
      // somewhere it was never meant to be.
      const path = entry && typeof entry === 'object' ? entry.path : null;
      if (path === TRUNCATION_SENTINEL) {
        out.payloadTruncated = true;
        continue;
      }
      out[changeType] += 1;
      out.total += 1;
      if (out.keys.length < maxKeys) {
        // ⛔ Sanitised HERE, not at draw time. A corrupted path is raw config
        // text, and the report data object must never carry it — see
        // safeKeyPath()'s note. A corrupted key is never called a credential
        // field: that would be a confident claim about a field that does not
        // exist.
        const safe = safeKeyPath(path);
        if (safe.corrupted) out.corruptedKeys += 1;
        out.keys.push({
          changeType,
          path: safe.path,
          corrupted: safe.corrupted,
          secretShaped: !safe.corrupted && isSecretShapedKey(safe.path),
        });
      }
    }
  }
  return out;
}

/**
 * The configuration AREAS a change touched, as section labels and counts.
 *
 * ⛔ Reuses `classifyDiff()` UNCHANGED and reads only `label` and the counts.
 * Its `entries[]` carry the same `value`/`old`/`new` this file refuses to look
 * at, so they are not read here either. Never throws — an unclassifiable
 * payload simply has no area names, which the caller renders as a dash.
 */
function changedAreasOf(diff) {
  try {
    const classified = classifyDiff(diff);
    const areas = (classified.sections || []).map((s) => ({
      label: s.label,
      count: Number(s.totalCount) || 0,
    }));
    const ruleChanges = Array.isArray(classified.ruleChanges) ? classified.ruleChanges.length : 0;
    if (ruleChanges > 0) {
      areas.unshift({ label: 'Firewall rules', count: ruleChanges });
    }
    return areas;
  } catch (_err) {
    return [];
  }
}

// ── review evidence ───────────────────────────────────────────────────────

const BULK_ACK_WINDOW_SECONDS = 120;
const BULK_ACK_MIN_GROUP = 5;

/**
 * Changes acknowledged in a burst: `minGroup` or more, by the SAME actor, each
 * within `windowSeconds` of the previous one.
 *
 * ⛔ THIS IS AN OBSERVATION ABOUT TIMING, NOT AN ALLEGATION, and the document
 * says so in those words. A bulk sweep is a legitimate way to clear a backlog of
 * changes an operator already understands. It is reported because an auditor
 * asking "did anyone look at it?" is entitled to know the difference between
 * thirty acknowledgements spread over a month and thirty in ninety seconds, and
 * because a report that presents both identically is quietly answering a
 * question it was never able to answer.
 *
 * Pure. Takes rows carrying `{acknowledgedAt, acknowledgedBy}`.
 */
function detectBulkAcknowledgements(rows, options = {}) {
  const windowSeconds = Number(options.windowSeconds) > 0
    ? Number(options.windowSeconds) : BULK_ACK_WINDOW_SECONDS;
  const minGroup = Number(options.minGroup) > 0 ? Number(options.minGroup) : BULK_ACK_MIN_GROUP;

  const byActor = new Map();
  for (const r of rows || []) {
    if (!r || !r.acknowledgedAt) continue;
    const t = r.acknowledgedAt instanceof Date ? r.acknowledgedAt : new Date(r.acknowledgedAt);
    if (Number.isNaN(t.getTime())) continue;
    const actor = r.acknowledgedBy || 'unknown';
    if (!byActor.has(actor)) byActor.set(actor, []);
    byActor.get(actor).push(t.getTime());
  }

  let inBursts = 0;
  let bursts = 0;
  let largest = 0;
  for (const times of byActor.values()) {
    times.sort((a, b) => a - b);
    let run = 1;
    for (let i = 1; i <= times.length; i += 1) {
      const contiguous = i < times.length && (times[i] - times[i - 1]) <= windowSeconds * 1000;
      if (contiguous) { run += 1; continue; }
      if (run >= minGroup) {
        bursts += 1;
        inBursts += run;
        if (run > largest) largest = run;
      }
      run = 1;
    }
  }
  return { bursts, inBursts, largest, windowSeconds, minGroup };
}

/**
 * How long changes sat before anybody looked at them.
 *
 * ⛔ An UNREVIEWED change has no latency — it is not a large number, it is an
 * open interval. It is counted separately and never folded into an average,
 * which would let a pile of never-reviewed changes improve the figure.
 * ⛔ A NEGATIVE interval (acknowledged before detected) is a clock disagreement,
 * not a measurement — counted as `clockMismatch`, same discipline as
 * vpn_sessions' negative durations.
 */
function reviewLatency(rows) {
  const hours = [];
  let unreviewed = 0;
  let clockMismatch = 0;
  for (const r of rows || []) {
    if (!r || !r.detectedAt) continue;
    if (!r.acknowledgedAt) { unreviewed += 1; continue; }
    const a = new Date(r.acknowledgedAt).getTime();
    const d = new Date(r.detectedAt).getTime();
    if (Number.isNaN(a) || Number.isNaN(d)) { clockMismatch += 1; continue; }
    const h = (a - d) / 3600000;
    if (h < 0) { clockMismatch += 1; continue; }
    hours.push(h);
  }
  hours.sort((x, y) => x - y);
  const median = hours.length === 0
    ? null
    : (hours.length % 2 === 1
      ? hours[(hours.length - 1) / 2]
      : (hours[hours.length / 2 - 1] + hours[hours.length / 2]) / 2);
  return {
    reviewed: hours.length,
    unreviewed,
    clockMismatch,
    // null, not 0, when nothing was reviewed — an absent measurement, not a
    // fast one.
    medianHours: median,
    longestHours: hours.length ? hours[hours.length - 1] : null,
    within24h: hours.filter((h) => h <= 24).length,
  };
}

function hoursText(h) {
  if (h == null) return NOT_MEASURED_MARK;
  if (h < 1) return `${Math.round(h * 60)} min`;
  if (h < 48) return `${h.toFixed(1)} h`;
  return `${(h / 24).toFixed(1)} days`;
}

// ── coverage: did we actually look? ───────────────────────────────────────

const COVERAGE = Object.freeze({
  OBSERVED: 'observed',
  NEVER_COLLECTED: 'never_collected',
  NOTHING_IN_WINDOW: 'nothing_in_window',
  FIRST_SNAPSHOT_ONLY: 'first_snapshot_only',
});

/**
 * ⛔ THE RULE THIS REPORT EXISTS TO ENFORCE, AS ONE FUNCTION.
 *
 * A firewall is credited with a quiet window only if SecVault actually ran a
 * COMPARISON on it inside that window. A comparison needs two configuration
 * snapshots: every snapshot taken in the window is compared against the one
 * before it, so the number of comparisons is the in-window snapshot count, minus
 * one when there was no snapshot at all before the window opened (nothing to
 * compare the first one against).
 *
 * Zero comparisons means UNKNOWN. It does not mean zero changes, and no caller
 * may render it as one.
 *
 * Pure — takes counts, returns a state.
 */
function coverageStateOf(d) {
  if (!d.snapshotsTotal) return COVERAGE.NEVER_COLLECTED;
  if (!d.snapshotsInWindow) return COVERAGE.NOTHING_IN_WINDOW;
  const comparisons = d.snapshotsInWindow - (d.snapshotsBeforeWindow > 0 ? 0 : 1);
  if (comparisons < 1) return COVERAGE.FIRST_SNAPSHOT_ONLY;
  return COVERAGE.OBSERVED;
}

function comparisonsInWindow(d) {
  if (!d.snapshotsInWindow) return 0;
  return Math.max(0, d.snapshotsInWindow - (d.snapshotsBeforeWindow > 0 ? 0 : 1));
}

/**
 * The sentence that must travel WITH a firewall's counts rather than in a
 * footnote. Pure and exported so the wording is pinned by a test — every one of
 * these exists to stop a number being over-read.
 */
function deviceCoverageNote(d) {
  switch (d.coverage) {
    case COVERAGE.NEVER_COLLECTED:
      return 'SecVault has never successfully collected a configuration from this firewall, so it '
        + 'cannot say whether anything changed. This is not a quiet firewall; it is an unanswered '
        + 'question.';
    case COVERAGE.NOTHING_IN_WINDOW:
      return 'No configuration was collected from this firewall during the window (the most recent '
        + `snapshot is from ${fmtStamp(d.newestSnapshotAt)}). Any change made in this period would `
        + 'not have been detected. Zero changes here means NOT OBSERVED, not none.';
    case COVERAGE.FIRST_SNAPSHOT_ONLY:
      return 'Only one configuration snapshot exists for this firewall and there is none from '
        + 'before the window, so no comparison has ever been run against it. Nothing can yet be '
        + 'said about change on this device.';
    default:
      break;
  }
  const parts = [`${num(d.comparisons)} ${plural(d.comparisons, 'comparison', 'comparisons')} run `
    + `against ${num(d.snapshotsInWindow)} collected ${plural(d.snapshotsInWindow, 'snapshot', 'snapshots')}.`];
  if (d.changes === 0) {
    parts.push('No change was detected - this is a measured result, not an absence of data.');
  }
  if (d.unacknowledged > 0) {
    parts.push(`${num(d.unacknowledged)} ${plural(d.unacknowledged, 'change has', 'changes have')} `
      + 'not been reviewed by anyone.');
  }
  if (!d.hasBaseline) {
    parts.push('No baseline configuration is designated, so drift from a known-good state cannot '
      + 'be reported for it.');
  }
  return parts.join(' ');
}

// ── the answer-first sentence ─────────────────────────────────────────────

/**
 * ⛔ AN ALL-CLEAR IS FORBIDDEN WHILE COVERAGE IS INCOMPLETE. "No changes this
 * month" over a fleet where collection failed is the failed-read-as-a-fact bug
 * written in English, and it is the exact sentence a change-control auditor
 * would quote back. The only route to an unqualified sentence is every gap being
 * genuinely zero.
 *
 * Pure — takes totals, returns a string.
 */
function headlineSentence(totals) {
  const firewalls = `${num(totals.devices)} ${plural(totals.devices, 'firewall', 'firewalls')}`;
  const window = `${num(totals.windowDays)} ${plural(totals.windowDays, 'day', 'days')}`;

  const gaps = [];
  if (totals.devicesUnobserved > 0) {
    gaps.push(
      `${num(totals.devicesUnobserved)} ${plural(totals.devicesUnobserved, 'firewall', 'firewalls')} `
      + 'had no configuration comparison run at all in this period, so SecVault cannot say whether '
      + `${plural(totals.devicesUnobserved, 'it', 'they')} changed`
    );
  }
  if (totals.devicesWithoutBaseline > 0) {
    gaps.push(
      `${num(totals.devicesWithoutBaseline)} of them ${plural(totals.devicesWithoutBaseline, 'has', 'have')} `
      + 'no designated baseline configuration, so drift from a known-good state is not reported here '
      + 'for any of them'
    );
  }

  let head;
  if (totals.changes === 0) {
    head = `Across ${firewalls} SecVault recorded no configuration changes in the last ${window}.`;
  } else {
    head = `Across ${firewalls} SecVault recorded ${num(totals.changes)} configuration `
      + `${plural(totals.changes, 'change', 'changes')} in the last ${window}, on `
      + `${num(totals.devicesWithChanges)} of them`;
    head += totals.unacknowledged > 0
      ? `, and ${num(totals.unacknowledged)} of those changes ${plural(totals.unacknowledged, 'has', 'have')} `
        + 'not been reviewed by anyone.'
      : ', every one of which has been reviewed and acknowledged.';
  }

  if (gaps.length === 0) {
    return totals.changes === 0
      // ⛔ The ONLY place this document is allowed to sound reassuring, and it
      // earns it by naming the measurement rather than the absence.
      ? `${head} Every firewall in scope was collected from and compared at least once in that `
        + 'period, so a change would have been detected.'
      : head;
  }
  return `${head} This is not a complete picture: ${gaps.join('; ')}.`;
}

// ── data assembly ─────────────────────────────────────────────────────────

const DEFAULT_WINDOW_DAYS = 30;
const DEFAULT_MAX_CHANGE_ROWS = 300;
const DEFAULT_MAX_KEYS_PER_CHANGE = 6;
const DEFAULT_MAX_ACTIVITY_ROWS = 120;

/**
 * Fetch everything the cover and the body need.
 *
 * ⛔ THE CORE READS ARE NOT BEST-EFFORT. Devices, snapshot coverage and change
 * counts either arrive or the export fails: a change-audit report with silently
 * missing changes is worse than an error the operator can see, because an empty
 * change log reads as "nothing happened here".
 *
 * ⛔ THE SIDE READS ARE BEST-EFFORT AND THEIR FAILURE IS RECORDED rather than
 * swallowed — the operator review trail and the snapshot-retention check are
 * each isolated, and a failure becomes a named row in the document. A section
 * that quietly vanishes reads as a section with nothing in it.
 *
 * @param {import('pg').Pool} pool
 * @param {object} [options]
 * @param {string} [options.deviceId]   omit for a fleet-wide report
 * @param {number} [options.days=30]    reporting window
 * @param {Date}   [options.now]
 * @param {number} [options.maxChangeRows]
 * @param {number} [options.maxKeysPerChange]
 * @param {number} [options.maxActivityRows]
 * @returns {Promise<object|null>} null ONLY when a named device does not exist.
 */
async function buildChangeAuditData(pool, options = {}) {
  const now = options.now instanceof Date ? options.now : new Date();
  const windowDays = clampDays(options.days, DEFAULT_WINDOW_DAYS);
  const since = new Date(now.getTime() - windowDays * 86400000);
  const maxChangeRows = clampCap(options.maxChangeRows, DEFAULT_MAX_CHANGE_ROWS);
  const maxKeysPerChange = clampCap(options.maxKeysPerChange, DEFAULT_MAX_KEYS_PER_CHANGE);
  const maxActivityRows = clampCap(options.maxActivityRows, DEFAULT_MAX_ACTIVITY_ROWS);
  const deviceId = options.deviceId || null;

  const sectionErrors = [];

  // ⛔ A device-scoped report deliberately does NOT filter on `active`. An
  // operator auditing a firewall they have just deactivated still needs its
  // change history, and returning null there would look like the device had
  // vanished from inventory rather than that it was switched off.
  const { rows: deviceRows } = deviceId
    ? await pool.query(
      `SELECT id, name, vendor, mgmt_method, mgmt_ip, site, active,
              last_collected_at, last_rules_collected_at
         FROM devices
        WHERE id = $1::uuid`,
      [deviceId]
    )
    : await pool.query(
      `SELECT id, name, vendor, mgmt_method, mgmt_ip, site, active,
              last_collected_at, last_rules_collected_at
         FROM devices
        WHERE active = true
        ORDER BY name`
    );

  // ⛔ null ONLY for a named device that does not exist. A fleet report over an
  // empty inventory is a legitimate, honest document that says so — returning
  // null there would present an empty estate as an error.
  if (deviceId && deviceRows.length === 0) return null;
  const ids = deviceRows.map((d) => d.id);

  // ── did we actually collect anything? ───────────────────────────────────
  // ⛔ Counted IN THE DATABASE with FILTER clauses rather than in JS. The whole
  // coverage judgement rests on telling "no snapshot in the window" from "one"
  // from "several", and node-pg hands counts back as strings — a truthiness test
  // in JS is how a '0' becomes a yes.
  const { rows: snapshotRows } = await pool.query(
    `SELECT device_id,
            count(*)::int                                          AS snapshots_total,
            count(*) FILTER (WHERE collected_at >= $2::timestamptz
                               AND collected_at <= $3::timestamptz)::int AS snapshots_in_window,
            count(*) FILTER (WHERE collected_at < $2::timestamptz)::int  AS snapshots_before_window,
            count(*) FILTER (WHERE is_baseline)::int                AS baselines,
            min(collected_at)                                      AS oldest_snapshot_at,
            max(collected_at)                                      AS newest_snapshot_at,
            max(collected_at) FILTER (WHERE is_baseline)           AS baseline_at
       FROM device_configs
      WHERE device_id = ANY($1::uuid[])
      GROUP BY device_id`,
    [ids, since, now]
  );
  const snapshotsById = new Map(snapshotRows.map((r) => [r.device_id, r]));

  // ── how many changes, and how many unreviewed ───────────────────────────
  // ⛔ AGGREGATED SEPARATELY FROM THE LISTED ROWS, deliberately. The change log
  // below is capped; these counts are not. If the two came from the same capped
  // query, a truncated list would silently deflate the headline figure — the
  // reader would count the rows, believe the number, and be wrong.
  const { rows: changeCountRows } = await pool.query(
    `SELECT device_id,
            count(*)::int                                          AS changes,
            count(*) FILTER (WHERE acknowledged_at IS NULL)::int    AS unacknowledged,
            min(detected_at)                                       AS first_change_at,
            max(detected_at)                                       AS last_change_at
       FROM config_diffs
      WHERE device_id = ANY($1::uuid[])
        AND detected_at >= $2::timestamptz
        AND detected_at <= $3::timestamptz
      GROUP BY device_id`,
    [ids, since, now]
  );
  const changeCountsById = new Map(changeCountRows.map((r) => [r.device_id, r]));

  // ── the change log itself ───────────────────────────────────────────────
  // ⛔ `diff` IS SELECTED AND IS IMMEDIATELY REDUCED TO KEYS. It never reaches
  // the returned data object — see changedKeysOf()'s contract. `change_summary`
  // is deliberately NOT selected: it is a cached string written at detection
  // time, and this document recomputes the counts from the payload so that a
  // stale or oversized cached summary cannot misstate what is in the record.
  const { rows: diffRows } = await pool.query(
    `SELECT id, device_id, diff, detected_at, acknowledged_at, acknowledged_by, acknowledged_note
       FROM config_diffs
      WHERE device_id = ANY($1::uuid[])
        AND detected_at >= $2::timestamptz
        AND detected_at <= $3::timestamptz
      ORDER BY detected_at DESC
      LIMIT $4`,
    [ids, since, now, maxChangeRows]
  );

  // ── are the snapshots this change came from still on disk? ──────────────
  // ⛔ `config_diffs` is append-only and holds its own payload; config retention
  // ages out `device_configs` after 60 days. So the CHANGE RECORD outlives the
  // configurations it was computed from, and this counts how many of the two
  // source snapshots survive. Best-effort: if the check fails the rows say the
  // retention state is unknown, never that the snapshots are gone.
  const retainedById = new Map();
  if (diffRows.length > 0) {
    try {
      const { rows: retainedRows } = await pool.query(
        `SELECT cd.id AS diff_id, count(dc.id)::int AS snapshots_retained
           FROM config_diffs cd
           LEFT JOIN device_configs dc
             ON dc.device_id = cd.device_id
            AND dc.collected_at <= cd.detected_at
          WHERE cd.id = ANY($1::uuid[])
          GROUP BY cd.id`,
        [diffRows.map((r) => r.id)]
      );
      retainedRows.forEach((r) => retainedById.set(r.diff_id, Number(r.snapshots_retained)));
    } catch (err) {
      sectionErrors.push({
        section: 'Source-snapshot retention',
        message: `Could not be checked (${err.message}). Every change below is listed with its `
          + 'retention state unknown; SecVault is NOT claiming the snapshots are still available, '
          + 'nor that they have been deleted.',
      });
    }
  }

  // ── the operator review trail ───────────────────────────────────────────
  // Best-effort: the change log and the coverage judgement do not depend on it.
  let activity = [];
  let activityTotal = 0;
  try {
    const { rows: activityRows } = await pool.query(
      `SELECT actor, action, device_id, detail, occurred_at
         FROM activity_log
        WHERE device_id = ANY($1::uuid[])
          AND occurred_at >= $2::timestamptz
          AND occurred_at <= $3::timestamptz
        ORDER BY occurred_at DESC
        LIMIT $4`,
      [ids, since, now, maxActivityRows]
    );
    activity = activityRows;
    activityTotal = activityRows.length;
  } catch (err) {
    sectionErrors.push({
      section: 'Operator review trail',
      message: `Could not be read (${err.message}). The acknowledgement status shown against each `
        + 'change is still accurate; what is missing is the wider record of who did what.',
    });
  }

  // ── per-firewall assembly ───────────────────────────────────────────────
  const devices = deviceRows.map((d) => {
    const s = snapshotsById.get(d.id) || null;
    const c = changeCountsById.get(d.id) || null;
    const dev = {
      id: d.id,
      name: d.name,
      vendor: d.vendor,
      mgmtMethod: d.mgmt_method,
      mgmtIp: d.mgmt_ip,
      site: d.site,
      active: d.active,
      lastCollectedAt: d.last_collected_at,
      lastRulesCollectedAt: d.last_rules_collected_at,
      snapshotsTotal: s ? Number(s.snapshots_total) : 0,
      snapshotsInWindow: s ? Number(s.snapshots_in_window) : 0,
      snapshotsBeforeWindow: s ? Number(s.snapshots_before_window) : 0,
      oldestSnapshotAt: s ? s.oldest_snapshot_at : null,
      newestSnapshotAt: s ? s.newest_snapshot_at : null,
      hasBaseline: s ? Number(s.baselines) > 0 : false,
      baselineAt: s ? s.baseline_at : null,
      changes: c ? Number(c.changes) : 0,
      unacknowledged: c ? Number(c.unacknowledged) : 0,
      firstChangeAt: c ? c.first_change_at : null,
      lastChangeAt: c ? c.last_change_at : null,
    };
    dev.comparisons = comparisonsInWindow(dev);
    dev.coverage = coverageStateOf(dev);
    dev.observed = dev.coverage === COVERAGE.OBSERVED;
    dev.note = deviceCoverageNote(dev);
    return dev;
  });
  const deviceById = new Map(devices.map((d) => [d.id, d]));

  // ── the change rows ─────────────────────────────────────────────────────
  const changes = diffRows.map((r) => {
    const dev = deviceById.get(r.device_id) || null;
    const keys = changedKeysOf(r.diff, maxKeysPerChange);
    const areas = changedAreasOf(r.diff);
    const retained = retainedById.has(r.id) ? retainedById.get(r.id) : null;
    return {
      id: r.id,
      deviceId: r.device_id,
      deviceName: dev ? dev.name : NOT_MEASURED_MARK,
      detectedAt: r.detected_at,
      acknowledgedAt: r.acknowledged_at || null,
      acknowledgedBy: r.acknowledged_by || null,
      // ⛔ Operator free text, through the fail-closed filter.
      acknowledgedNote: safeFreeText(r.acknowledged_note),
      added: keys.added,
      removed: keys.removed,
      modified: keys.modified,
      entries: keys.total,
      keys: keys.keys,
      keysShown: keys.keys.length,
      secretShapedKeys: keys.keys.filter((k) => k.secretShaped).length,
      corruptedKeys: keys.corruptedKeys,
      payloadTruncated: keys.payloadTruncated,
      payloadUnreadable: keys.payloadUnreadable,
      areas,
      // null = the retention check did not run. 0 = both source snapshots have
      // been aged out. 1 = only one survives. >=2 = both are still on disk.
      snapshotsRetained: retained,
    };
  });

  // ── totals ──────────────────────────────────────────────────────────────
  const unobserved = devices.filter((d) => !d.observed);
  const totals = {
    windowDays,
    devices: devices.length,
    devicesObserved: devices.length - unobserved.length,
    devicesUnobserved: unobserved.length,
    devicesNeverCollected: devices.filter((d) => d.coverage === COVERAGE.NEVER_COLLECTED).length,
    devicesStale: devices.filter((d) => d.coverage === COVERAGE.NOTHING_IN_WINDOW).length,
    devicesFirstSnapshotOnly: devices.filter((d) => d.coverage === COVERAGE.FIRST_SNAPSHOT_ONLY).length,
    devicesWithChanges: devices.filter((d) => d.changes > 0).length,
    // ⛔ "Quiet AND confirmed quiet" is a different population from "quiet".
    // Only the first is a result; the second includes every firewall nobody
    // looked at.
    devicesQuietConfirmed: devices.filter((d) => d.observed && d.changes === 0).length,
    devicesWithoutBaseline: devices.filter((d) => !d.hasBaseline).length,
    changes: devices.reduce((a, d) => a + d.changes, 0),
    unacknowledged: devices.reduce((a, d) => a + d.unacknowledged, 0),
    changesListed: changes.length,
    changesWithLostSnapshots: changes.filter((c) => c.snapshotsRetained === 0).length,
    changesPartiallyRetained: changes.filter((c) => c.snapshotsRetained === 1).length,
    changesTruncatedPayload: changes.filter((c) => c.payloadTruncated).length,
    changesUnreadablePayload: changes.filter((c) => c.payloadUnreadable).length,
    changesTouchingSecretKeys: changes.filter((c) => c.secretShapedKeys > 0).length,
    changesWithCorruptedKeys: changes.filter((c) => c.corruptedKeys > 0).length,
    snapshots: devices.reduce((a, d) => a + d.snapshotsInWindow, 0),
    comparisons: devices.reduce((a, d) => a + d.comparisons, 0),
    activityRows: activityTotal,
  };

  const unreviewed = changes.filter((c) => !c.acknowledgedAt);
  const latency = reviewLatency(changes);
  const bulk = detectBulkAcknowledgements(changes);

  return {
    scope: deviceId ? 'device' : 'fleet',
    device: deviceId ? devices[0] : null,
    generatedAt: now,
    windowStart: since,
    windowEnd: now,
    windowDays,
    devices,
    changes,
    unreviewed,
    activity: activity.map((a) => ({
      actor: a.actor || 'unknown',
      action: a.action,
      deviceId: a.device_id,
      deviceName: deviceById.has(a.device_id) ? deviceById.get(a.device_id).name : NOT_MEASURED_MARK,
      // ⛔ Operator free text, through the fail-closed filter.
      detail: safeFreeText(a.detail),
      occurredAt: a.occurred_at,
    })),
    latency,
    bulk,
    totals,
    sectionErrors,
    caps: { maxChangeRows, maxKeysPerChange, maxActivityRows },
    headline: headlineSentence(totals),
  };
}

// ── tables ────────────────────────────────────────────────────────────────

function scaleText(c) {
  const bits = [];
  if (c.added) bits.push(`${num(c.added)} added`);
  if (c.removed) bits.push(`${num(c.removed)} removed`);
  if (c.modified) bits.push(`${num(c.modified)} modified`);
  if (bits.length === 0) {
    // ⛔ Not "no changes". A stored change record with no readable entries is a
    // record SecVault could not read, which is not the same as an empty one.
    return c.payloadUnreadable ? 'RECORD UNREADABLE' : 'no entries recorded';
  }
  return bits.join(', ');
}

function areasText(c) {
  if (!c.areas || c.areas.length === 0) return NOT_MEASURED_MARK;
  return c.areas.slice(0, 4).map((a) => `${a.label} (${num(a.count)})`).join('\n')
    + (c.areas.length > 4 ? `\n+${c.areas.length - 4} more` : '');
}

/**
 * The changed KEYS cell.
 *
 * ⛔ KEYS, NOT VALUES, AND THAT IS THE WHOLE POINT OF THIS COLUMN. A reader can
 * see that `...ike.gateway.entry[4].pre-shared-key` was touched, which is what an
 * auditor needs in order to ask about it, without the document carrying the key.
 */
function keysText(c, maxKeys) {
  if (c.payloadUnreadable) {
    return 'The stored record could not be read, so the changed keys cannot be listed. '
      + 'This is not an empty change.';
  }
  if (c.keys.length === 0) return NOT_MEASURED_MARK;
  // ⛔ `k.path` is ALREADY sanitised by changedKeysOf(). It is not re-shortened
  // here, and the raw one is not available to re-fetch — that is the point of
  // sanitising at extraction rather than at draw time.
  const lines = c.keys.map((k) => {
    const mark = CHANGE_MARK[k.changeType] || '?';
    if (k.corrupted) {
      return `${mark} ${k.path}   [the stored key is corrupted config text, not a field name]`;
    }
    return `${mark} ${k.path}${k.secretShaped ? '   [credential field - value never shown]' : ''}`;
  });
  const hidden = c.entries - c.keys.length;
  if (hidden > 0) {
    lines.push(`... and ${num(hidden)} more ${plural(hidden, 'key', 'keys')} (limit ${num(maxKeys)} per change)`);
  }
  if (c.payloadTruncated) {
    lines.push('PARTIAL RECORD: this change exceeded the stored entry limit, so the record itself is incomplete.');
  }
  return lines.join('\n');
}

function reviewText(c) {
  if (!c.acknowledgedAt) return 'NOT REVIEWED';
  const who = c.acknowledgedBy && c.acknowledgedBy !== 'unknown'
    ? c.acknowledgedBy
    : 'an unidentified operator';
  return `${who}\n${fmtStamp(c.acknowledgedAt)}${c.acknowledgedNote ? `\n${c.acknowledgedNote}` : ''}`;
}

/**
 * ⛔ AN EMPTY DIFF AND A DELETED SNAPSHOT MUST NOT LOOK THE SAME. `config_diffs`
 * is append-only, so the change record is still evidence that something changed;
 * what has gone is the pair of configurations it was computed from.
 */
function retentionText(c) {
  if (c.snapshotsRetained === null) return 'not checked';
  if (c.snapshotsRetained === 0) {
    return 'Snapshot no longer retained - the change record survives, the before/after '
      + 'configurations have been aged out';
  }
  if (c.snapshotsRetained === 1) return 'Partly retained - only one of the two source snapshots survives';
  return 'Both source snapshots retained';
}

function retentionColor(c) {
  if (c.snapshotsRetained === null || c.snapshotsRetained === 0) return UNMEASURED;
  if (c.snapshotsRetained === 1) return ORANGE;
  return MUTED;
}

function buildChangeTable(rows, includeDevice, maxKeys) {
  const columns = [];
  columns.push({ key: 'when', label: 'Detected', width: 58, font: 'Helvetica-Bold' });
  if (includeDevice) columns.push({ key: 'device', label: 'Firewall', width: 50 });
  columns.push(
    { key: 'scale', label: 'Scale of change', width: 54, color: (r) => (r._unreadable ? UNMEASURED : INK) },
    { key: 'areas', label: 'Configuration area', width: 72, color: MUTED },
    { key: 'keys', label: 'Keys that changed (values are never printed)', width: 176 },
    {
      key: 'review',
      label: 'Reviewed by',
      width: 62,
      color: (r) => (r._unreviewed ? STATUS_RED : MUTED),
      font: (r) => (r._unreviewed ? 'Helvetica-Bold' : 'Helvetica'),
    },
    { key: 'retention', label: 'Source snapshots', width: 58, color: (r) => r._retColor }
  );
  return {
    columns,
    rows: rows.map((c) => ({
      when: fmtStamp(c.detectedAt),
      device: c.deviceName,
      scale: scaleText(c),
      areas: areasText(c),
      keys: keysText(c, maxKeys),
      review: reviewText(c),
      retention: retentionText(c),
      _unreviewed: !c.acknowledgedAt,
      _unreadable: c.payloadUnreadable,
      _retColor: retentionColor(c),
    })),
  };
}

function buildDeviceTable(devices) {
  return {
    columns: [
      { key: 'name', label: 'Firewall', width: 62, font: 'Helvetica-Bold' },
      { key: 'access', label: 'Vendor / access', width: 52, color: MUTED },
      { key: 'snapshots', label: 'Configs collected', width: 40, align: 'right' },
      // ⛔ Beside the snapshot count, not after the change count. It is a
      // property of the MEASUREMENT, not of the firewall's behaviour.
      {
        key: 'comparisons',
        label: 'Comparisons run',
        width: 40,
        align: 'right',
        color: (r) => (r._observed ? INK : UNMEASURED),
        font: 'Helvetica-Bold',
      },
      { key: 'changes', label: 'Changes', width: 34, align: 'right', font: 'Helvetica-Bold' },
      {
        key: 'unack',
        label: 'Not reviewed',
        width: 40,
        align: 'right',
        color: (r) => (r._unack ? STATUS_RED : MUTED),
        font: 'Helvetica-Bold',
      },
      { key: 'last', label: 'Last change', width: 58, color: MUTED },
      { key: 'baseline', label: 'Baseline set', width: 36, color: (r) => (r._baseline ? MUTED : UNMEASURED) },
      {
        key: 'note',
        label: 'What this row does and does not say',
        width: 168,
        color: (r) => (r._observed ? MUTED : UNMEASURED),
      },
    ],
    rows: devices.map((d) => ({
      name: d.name,
      access: `${d.vendor}${d.mgmtMethod ? ` / ${d.mgmtMethod}` : ''}`,
      snapshots: num(d.snapshotsInWindow),
      comparisons: num(d.comparisons),
      // ⛔ A firewall with no comparison has not had zero changes. Its change
      // and not-reviewed cells are dashes, never zeroes.
      changes: countCell(d.changes, d.observed),
      unack: countCell(d.unacknowledged, d.observed),
      last: d.lastChangeAt ? fmtStamp(d.lastChangeAt) : NOT_MEASURED_MARK,
      baseline: d.hasBaseline ? 'Yes' : 'No',
      note: d.note,
      _observed: d.observed,
      _unack: d.unacknowledged > 0 && d.observed,
      _baseline: d.hasBaseline,
    })),
  };
}

function buildUnreviewedTable(rows, includeDevice, maxKeys) {
  const columns = [];
  columns.push({ key: 'when', label: 'Detected', width: 62, font: 'Helvetica-Bold' });
  if (includeDevice) columns.push({ key: 'device', label: 'Firewall', width: 56 });
  columns.push(
    { key: 'age', label: 'Unreviewed for', width: 50, color: STATUS_RED, font: 'Helvetica-Bold' },
    { key: 'scale', label: 'Scale of change', width: 56 },
    { key: 'areas', label: 'Configuration area', width: 80, color: MUTED },
    { key: 'keys', label: 'Keys that changed (values are never printed)', width: 196 }
  );
  return {
    columns,
    rows: rows.map((c) => ({
      when: fmtStamp(c.detectedAt),
      device: c.deviceName,
      age: c.ageText || NOT_MEASURED_MARK,
      scale: scaleText(c),
      areas: areasText(c),
      keys: keysText(c, maxKeys),
    })),
  };
}

function buildCoverageTable(devices) {
  return {
    columns: [
      { key: 'name', label: 'Firewall', width: 62, font: 'Helvetica-Bold' },
      { key: 'access', label: 'Vendor / access', width: 52, color: MUTED },
      { key: 'lastConfig', label: 'Last configuration collected', width: 68, color: UNMEASURED },
      { key: 'lastRules', label: 'Last ruleset collected', width: 68, color: UNMEASURED },
      {
        key: 'reason',
        label: 'Why nothing can be said about change on this firewall',
        width: 230,
        color: UNMEASURED,
      },
    ],
    rows: devices.map((d) => ({
      name: d.name,
      access: `${d.vendor}${d.mgmtMethod ? ` / ${d.mgmtMethod}` : ''}`,
      // ⛔ A dash, never a blank — a blank cell in a spreadsheet export reads as
      // an empty string, which reads as fine.
      lastConfig: d.newestSnapshotAt ? fmtStamp(d.newestSnapshotAt) : NOT_MEASURED_MARK,
      lastRules: d.lastRulesCollectedAt ? fmtStamp(d.lastRulesCollectedAt) : NOT_MEASURED_MARK,
      reason: d.note,
    })),
  };
}

function buildActivityTable(rows, includeDevice) {
  const columns = [];
  columns.push({ key: 'when', label: 'When', width: 62 });
  columns.push({ key: 'actor', label: 'Operator', width: 44, font: 'Helvetica-Bold' });
  if (includeDevice) columns.push({ key: 'device', label: 'Firewall', width: 52 });
  columns.push(
    { key: 'action', label: 'Action', width: 66 },
    { key: 'detail', label: 'Detail', width: 210, color: MUTED }
  );
  return {
    columns,
    rows: rows.map((a) => ({
      when: fmtStamp(a.occurredAt),
      actor: a.actor,
      device: a.deviceName,
      action: a.action,
      detail: a.detail,
    })),
  };
}

// ── body ──────────────────────────────────────────────────────────────────

function renderSectionErrors(doc, layout, sectionErrors) {
  if (!sectionErrors || sectionErrors.length === 0) return;
  doc.y += 8;
  sectionTitle(doc, layout, 'Parts of this report could not be gathered');
  paragraph(
    doc, layout,
    'The following did not return data for this run. Nothing below is reported as a clean result on '
    + 'their behalf.',
    STATUS_RED
  );
  sectionErrors.forEach((e) => labelledNote(doc, layout, e.section, UNMEASURED, e.message));
}

function renderChangeLog(doc, layout, data) {
  const { totals, changes, caps } = data;
  doc.y += 10;
  sectionTitle(doc, layout, `Change log - every configuration change recorded (${num(totals.changes)})`);
  paragraph(
    doc, layout,
    'Each row is one detected difference between a firewall\'s configuration and the configuration '
    + 'collected from it immediately before. The KEYS that changed are listed; the VALUES are never '
    + 'printed, because a firewall configuration contains pre-shared keys, community strings and '
    + 'password hashes, and this document is emailed and archived.',
    INK
  );
  if (totals.changes === 0 && totals.devicesUnobserved > 0) {
    // ⛔ An empty change log is NOT an all-clear while coverage is incomplete.
    // Repeated here as well as in the headline, because this is where a reader
    // who skipped the first page will look.
    paragraph(
      doc, layout,
      `No changes were recorded - but ${num(totals.devicesUnobserved)} `
      + `${plural(totals.devicesUnobserved, 'firewall', 'firewalls')} had no comparison run at all in `
      + 'this window (see the coverage section below), so this is not a statement that the estate was '
      + 'stable.',
      UNMEASURED
    );
  }
  const shown = changes.slice(0, caps.maxChangeRows);
  const note = truncationNote(shown.length, totals.changes, 'changes');
  if (note) paragraph(doc, layout, note, MUTED);

  drawTable(doc, buildChangeTable(shown, data.scope === 'fleet', caps.maxKeysPerChange), layout, {
    continueOnPage: true,
    emptyText: totals.devicesUnobserved > 0
      ? 'No configuration change was recorded in this window. See the coverage section - this is not '
        + 'the same as nothing having changed.'
      : 'No configuration change was recorded in this window, on firewalls that were all successfully '
        + 'collected from and compared.',
  });
}

function renderPerFirewall(doc, layout, data) {
  const { devices, totals } = data;
  doc.y += 10;
  sectionTitle(doc, layout, `Changes by firewall (${num(devices.length)})`);
  paragraph(
    doc, layout,
    'A dash means the figure is UNKNOWN for that firewall, not zero. "Comparisons run" is how many '
    + 'times SecVault actually put this firewall\'s configuration next to its previous one during the '
    + 'window - a firewall with no comparisons cannot have a change count at all.',
    MUTED
  );
  drawTable(doc, buildDeviceTable(devices), layout, {
    continueOnPage: true,
    emptyText: 'No firewalls in scope.',
  });
  if (totals.devicesQuietConfirmed > 0) {
    paragraph(
      doc, layout,
      `${num(totals.devicesQuietConfirmed)} of ${num(totals.devices)} `
      + `${plural(totals.devices, 'firewall', 'firewalls')} were collected from and compared during the `
      + 'window and had no configuration change at all. That is a measured result and can be relied on. '
      + `The ${num(totals.devicesUnobserved)} in the coverage section below cannot.`,
      MUTED
    );
  }
}

function renderUnreviewed(doc, layout, data) {
  const {
    totals, unreviewed, caps, latency, bulk,
  } = data;
  doc.y += 10;
  sectionTitle(doc, layout, `Changes nobody has reviewed (${num(totals.unacknowledged)})`);

  if (totals.unacknowledged === 0) {
    paragraph(
      doc, layout,
      'Every configuration change recorded in this window has been acknowledged by an operator. '
      + 'That is what a working change-review process looks like in this product - with the caveat '
      + 'stated at the end of this document: an acknowledgement records that somebody marked the '
      + 'change as seen, not that they understood it or that it was authorised.',
      GREEN
    );
  } else {
    paragraph(
      doc, layout,
      `${num(totals.unacknowledged)} recorded ${plural(totals.unacknowledged, 'change has', 'changes have')} `
      + 'not been acknowledged by anyone. On a change-control audit THIS is the finding - the change '
      + 'itself may well have been routine and authorised, but nothing in this system records that a '
      + 'human ever looked at it.',
      STATUS_RED
    );
    const shown = unreviewed.slice(0, caps.maxChangeRows);
    const note = truncationNote(shown.length, totals.unacknowledged, 'unreviewed changes');
    if (note) paragraph(doc, layout, note, MUTED);
    drawTable(doc, buildUnreviewedTable(shown, data.scope === 'fleet', caps.maxKeysPerChange), layout, {
      continueOnPage: true,
      emptyText: 'These changes could not be listed individually for this run.',
    });
  }

  doc.y += 8;
  labelledNote(
    doc, layout,
    'How quickly changes were reviewed', INK,
    latency.reviewed === 0
      ? 'No change in this window has been reviewed, so there is no review time to report. This is an '
        + 'absent measurement, not a fast one.'
      : `Of the ${num(latency.reviewed)} reviewed ${plural(latency.reviewed, 'change', 'changes')} listed, `
        + `${num(latency.within24h)} were acknowledged within 24 hours. Median time to review `
        + `${hoursText(latency.medianHours)}; longest ${hoursText(latency.longestHours)}. `
        + `${num(latency.unreviewed)} ${plural(latency.unreviewed, 'change is', 'changes are')} still open `
        + 'and are deliberately excluded from those figures - counting an unreviewed change as a very '
        + 'slow review would let a backlog improve the average.'
        + (latency.clockMismatch > 0
          ? ` ${num(latency.clockMismatch)} ${plural(latency.clockMismatch, 'change', 'changes')} could not `
            + 'be timed because the acknowledgement is dated before the detection - a clock disagreement, '
            + 'not a measurement.'
          : '')
  );

  if (bulk.inBursts > 0) {
    labelledNote(
      doc, layout,
      'Acknowledgements that arrived in bursts', UNMEASURED,
      `${num(bulk.inBursts)} of the acknowledgements listed fell into ${num(bulk.bursts)} `
      + `${plural(bulk.bursts, 'burst', 'bursts')} of ${num(bulk.minGroup)} or more by the same operator, `
      + `each within ${num(bulk.windowSeconds)} seconds of the last; the largest run was `
      + `${num(bulk.largest)}. THIS IS AN OBSERVATION ABOUT TIMING AND NOT AN ALLEGATION - clearing a `
      + 'backlog of changes you already understand in one sitting is legitimate. It is reported because '
      + 'an auditor asking whether anyone looked at these is entitled to tell thirty acknowledgements '
      + 'spread over a month from thirty in ninety seconds, and a report that draws both the same way '
      + 'is quietly answering a question it cannot answer.'
    );
  }
}

function renderReviewTrail(doc, layout, data) {
  const { activity, totals } = data;
  doc.y += 10;
  sectionTitle(doc, layout, `Operator actions recorded against these firewalls (${num(totals.activityRows)})`);
  paragraph(
    doc, layout,
    'SecVault\'s own audit trail for the window: who acknowledged what, who ran a collection or an '
    + 'analysis. It is evidence about the REVIEWERS, separate from the evidence about the firewalls. '
    + 'A note an operator typed is withheld where it mentions a credential-shaped word - the row and '
    + 'the actor still appear, and the note can be read in the app.',
    MUTED
  );
  drawTable(doc, buildActivityTable(activity, data.scope === 'fleet'), layout, {
    continueOnPage: true,
    // ⛔ Not 'No data.' — an empty audit trail is itself a finding on a change
    // control review, and must not read as a formatting artefact.
    emptyText: 'No operator action was recorded against these firewalls in this window. On a change '
      + 'control review that is itself a finding, not a blank section.',
  });
}

function renderCoverage(doc, layout, data) {
  const { totals, devices } = data;
  const unobserved = devices.filter((d) => !d.observed);
  doc.y += 10;
  sectionTitle(
    doc, layout,
    `Firewalls SecVault could not confirm anything about (${num(totals.devicesUnobserved)})`
  );

  if (unobserved.length === 0) {
    paragraph(
      doc, layout,
      'Every firewall in scope was collected from and compared against its own previous configuration '
      + 'at least once during this window. Nothing in this report rests on a firewall that was simply '
      + 'not looked at.',
      GREEN
    );
  } else {
    paragraph(
      doc, layout,
      `${num(unobserved.length)} of ${num(totals.devices)} `
      + `${plural(totals.devices, 'firewall', 'firewalls')} had no configuration comparison run during `
      + 'this window. THEY ARE NOT QUIET FIREWALLS. A firewall whose collection is failing produces no '
      + 'change records and, on any report that does not separate these out, becomes the most stable '
      + 'device on the estate. Every one of them is named below with the reason, and none of them '
      + 'contributes a zero to any count in this document.',
      INK
    );
    drawTable(doc, buildCoverageTable(unobserved), layout, {
      continueOnPage: true,
      emptyText: 'None.',
    });
  }

  doc.y += 8;
  labelledNote(
    doc, layout,
    'Baseline configurations - a different question, deliberately not merged into the above', UNMEASURED,
    totals.devicesWithoutBaseline === totals.devices && totals.devices > 0
      ? 'No firewall in scope has an operator-designated baseline configuration, so this report makes '
        + 'no statement about drift from a known-good state. Every change above is a CONSECUTIVE-PULL '
        + 'comparison: this collection against the one before it. Those two questions genuinely differ '
        + '- a firewall that drifted once and has sat still since reports no changes here forever, '
        + 'because the thing each new collection is compared against is the already-drifted one.'
      : `${num(totals.devices - totals.devicesWithoutBaseline)} of ${num(totals.devices)} `
        + `${plural(totals.devices, 'firewall has', 'firewalls have')} a designated baseline `
        + 'configuration. Drift from a baseline is NOT what this report measures and is not included '
        + 'in any count above: every change here is a consecutive-pull comparison, whose comparison '
        + 'target may itself already be drifted. Read the two together, never as one number.'
  );
}

function renderWhatThisProves(doc, layout, data) {
  const { totals } = data;
  doc.y += 10;
  sectionTitle(doc, layout, 'What a recorded change does and does not prove');
  paragraph(
    doc, layout,
    'This document is evidence of change control, so it is worth being precise about what each part '
    + 'of it is evidence OF.',
    INK
  );
  doc.y += 4;

  const bullets = [
    ['A row in the change log', INK,
      'PROVES that this firewall\'s configuration differed from its own previous configuration, at the '
      + 'time stated, in the keys listed. SecVault read both configurations off the device over its '
      + 'own management API or CLI; nothing here is typed in by hand.'],
    ['It does NOT prove who made the change, or why', UNMEASURED,
      'SecVault reads configurations; it is not in the change path. The firewall\'s own administrative '
      + 'audit log is where authorship lives. A change appearing here with no corresponding approval '
      + 'is a question to ask, not an unauthorised change proven.'],
    ['Values are never printed, and that is not an omission', GREEN,
      'The key that changed is shown; the old and new values are not read from the database at all by '
      + 'the software that produced this page. A firewall configuration contains pre-shared keys, SNMP '
      + 'community strings, API tokens and local password hashes. A PDF is forwarded and archived, and '
      + 'no redaction rule is worth trusting in that position when the alternative is simply not '
      + 'carrying the value.'
      + (totals.changesTouchingSecretKeys > 0
        ? ` ${num(totals.changesTouchingSecretKeys)} of the changes listed touched a credential-bearing `
          + 'field; those rows say so, and still do not show it.'
        : '')],
    ['An acknowledgement proves a box was ticked', MUTED,
      'It records that a named operator marked the change as seen, at a stated time. It does not '
      + 'record that they read it, understood it, or checked it against a change request. Where '
      + 'acknowledgements arrived in bursts, this report says so, because the reader can then decide '
      + 'what weight to give them.'],
    ['NO CHANGE RECORDED IS NOT NOTHING CHANGED', UNMEASURED,
      'It only means that: no change was recorded. A firewall must have been collected from at least '
      + 'twice for a comparison to exist at all, and a firewall whose collection is failing is silent '
      + 'in exactly the same way as one that is genuinely stable. This report never merges those two: '
      + `${num(totals.devicesQuietConfirmed)} `
      + `${plural(totals.devicesQuietConfirmed, 'firewall was', 'firewalls were')} measured quiet, and `
      + `${num(totals.devicesUnobserved)} could not be measured at all.`],
    ['A change record outlives the configurations it came from', UNMEASURED,
      'Configuration snapshots are aged out on a retention schedule; the change records are not, and '
      + 'carry their own stored copy of what changed. So an older change can be entirely real while '
      + 'its before-and-after configurations no longer exist. Those rows say "snapshot no longer '
      + 'retained" rather than showing an empty comparison, because an empty comparison reads as '
      + '"there was nothing in it".'
      + (totals.changesWithLostSnapshots > 0
        ? ` ${num(totals.changesWithLostSnapshots)} of the changes listed are in that state.`
        : '')],
  ];
  bullets.forEach(([label, color, text]) => labelledNote(doc, layout, label, color, text));

  if (totals.changesTruncatedPayload > 0 || totals.changesUnreadablePayload > 0) {
    doc.y += 6;
    labelledNote(
      doc, layout,
      'Records that are themselves incomplete', UNMEASURED,
      `${num(totals.changesTruncatedPayload)} `
      + `${plural(totals.changesTruncatedPayload, 'change', 'changes')} exceeded the number of entries a `
      + 'single change record stores and were capped at write time, and '
      + `${num(totals.changesUnreadablePayload)} could not be read back at all. Those rows are marked. `
      + 'A capped record is a partial account of a real change, not a small change.'
    );
  }

  if (totals.changesWithCorruptedKeys > 0) {
    doc.y += 6;
    labelledNote(
      doc, layout,
      'Keys that could not be read as keys', UNMEASURED,
      `${num(totals.changesWithCorruptedKeys)} of the changes listed contain at least one stored key `
      + 'that is not a field name at all - the firewall\'s configuration parser mis-segmented its input '
      + 'and swept a block of raw configuration text into what should have been a single short key. '
      + 'Those entries show a placeholder rather than an excerpt: a truncated fragment would still read '
      + 'as a real, oddly-formatted field name, and on this document it would also put a slice of '
      + 'internal configuration into a file that leaves the building. The change itself is real and is '
      + 'counted; only the label for it is unavailable, and the full record can be read in the app.'
    );
  }

  doc.y += 6;
  paragraph(
    doc, layout,
    `Window: ${fmtStamp(data.windowStart)} to ${fmtStamp(data.windowEnd)} (${num(data.windowDays)} `
    + `${plural(data.windowDays, 'day', 'days')}). ${num(totals.comparisons)} configuration `
    + `${plural(totals.comparisons, 'comparison was', 'comparisons were')} run across `
    + `${num(totals.snapshots)} collected ${plural(totals.snapshots, 'snapshot', 'snapshots')}.`,
    MUTED
  );
}

function renderBody(doc, data, layout) {
  doc.addPage();

  // Answer first, in a sentence, before any table.
  sectionTitle(doc, layout, 'Summary');
  paragraph(doc, layout, data.headline, INK, 10);
  doc.y += 6;

  renderSectionErrors(doc, layout, data.sectionErrors);
  renderChangeLog(doc, layout, data);
  renderPerFirewall(doc, layout, data);
  renderUnreviewed(doc, layout, data);
  renderReviewTrail(doc, layout, data);
  renderCoverage(doc, layout, data);
  renderWhatThisProves(doc, layout, data);
}

// ── PDF ───────────────────────────────────────────────────────────────────

const TITLE = 'Configuration Change Audit';

/** Pure-ish: report data -> PDF Buffer. No DB, no network, no browser. */
function renderChangeAuditPdf(data) {
  const doc = installPdfSafeText(
    new PDFDocument({ size: 'A4', layout: 'portrait', margin: 36, bufferPages: true })
  );
  const layout = layoutOf(doc);
  const generatedAt = fmtStamp(data.generatedAt || new Date());
  const { totals, scope, device } = data;
  const subject = scope === 'device' && device
    ? `${device.name} (${device.vendor}${device.mgmtMethod ? ` / ${device.mgmtMethod}` : ''})`
    : 'Fleet-wide';

  // How long each unreviewed change has been sitting, computed once against the
  // report's own `now` so every row on the page agrees with the cover.
  const nowMs = new Date(data.generatedAt || new Date()).getTime();
  (data.unreviewed || []).forEach((c) => {
    const h = (nowMs - new Date(c.detectedAt).getTime()) / 3600000;
    c.ageText = Number.isFinite(h) && h >= 0 ? hoursText(h) : NOT_MEASURED_MARK;
  });

  drawCover(
    doc,
    {
      title: TITLE,
      subtitle: scope === 'device'
        ? `${subject} - what changed, when, and whether anyone reviewed it`
        : 'What changed on the firewall estate, when, and whether anyone reviewed it',
      company: PRODUCT_NAME,
      generatedAt,
      footerStamp: true,
      meta: [
        ['Scope', scope === 'device' ? subject : `${num(totals.devices)} firewalls`],
        scope === 'device' && device && device.site ? ['Site', device.site] : null,
        ['Reporting window', `${num(data.windowDays)} ${plural(data.windowDays, 'day', 'days')} `
          + `- ${fmtStamp(data.windowStart)} to ${fmtStamp(data.windowEnd)}`],
        ['Configurations collected', num(totals.snapshots)],
        ['Comparisons actually run', num(totals.comparisons)],
        // ⛔ On the cover, in its own row. This is the number a change report
        // that only counts diffs cannot state, and without it every other
        // figure on this page is unbounded.
        ['Firewalls with NO comparison run', num(totals.devicesUnobserved)],
        ['Firewalls measured quiet', num(totals.devicesQuietConfirmed)],
        ['Firewalls with no baseline designated', num(totals.devicesWithoutBaseline)],
        totals.changesWithLostSnapshots > 0
          ? ['Changes whose source snapshots are gone', num(totals.changesWithLostSnapshots)]
          : null,
      ].filter(Boolean),
      summary: [
        { label: 'Changes recorded', value: num(totals.changes), color: NAVY },
        {
          label: 'Not reviewed by anyone',
          value: num(totals.unacknowledged),
          color: totals.unacknowledged > 0 ? STATUS_RED : GREEN,
        },
        // ⛔ Hueless on purpose. This chip is not good news and not bad news; it
        // is the SIZE OF THE QUESTION SecVault could not answer, and colouring
        // it either way would turn a coverage figure into an assessment.
        { label: 'Firewalls not observed', value: num(totals.devicesUnobserved), color: UNMEASURED },
        { label: 'Firewalls measured quiet', value: num(totals.devicesQuietConfirmed), color: BLUE },
      ],
    },
    layout
  );

  renderBody(doc, data, layout);
  stampHeadersFooters(doc, {
    title: `${PRODUCT_NAME} ${TITLE}`,
    company: scope === 'device' && device ? device.name : `${num(totals.devices)} firewalls`,
    generatedAt,
  });

  return new Promise((resolve, reject) => {
    const chunks = [];
    doc.on('data', (c) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    doc.end();
  });
}

/**
 * @param {import('pg').Pool} pool
 * @param {object} [options] `{deviceId}` for one firewall; `{days}` for the window.
 * @returns {Promise<Buffer|null>} null only when a named device does not exist.
 */
async function generateChangeAuditPdf(pool, options = {}) {
  const data = await buildChangeAuditData(pool, options);
  if (!data) return null;
  return renderChangeAuditPdf(data);
}

module.exports = {
  TITLE,
  NOT_MEASURED_MARK,
  COVERAGE,
  DEFAULT_WINDOW_DAYS,
  SECRET_KEYWORD_PATTERN,
  isSecretShapedKey,
  safeFreeText,
  countCell,
  clampDays,
  clampCap,
  truncationNote,
  shortenKey,
  safeKeyPath,
  UNREADABLE_KEY_MARK,
  changedKeysOf,
  changedAreasOf,
  detectBulkAcknowledgements,
  reviewLatency,
  coverageStateOf,
  comparisonsInWindow,
  deviceCoverageNote,
  headlineSentence,
  buildChangeAuditData,
  renderChangeAuditPdf,
  generateChangeAuditPdf,
};
