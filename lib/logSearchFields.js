'use strict';

// THE LOG SEARCH FORM'S FIELDS, AS DATA.
//
// ⛔ ═══ WHY THIS IS A REGISTRY AND NOT JSX ═══════════════════════════════
// components/logs/LogSearchForm.js already carried this warning, in prose,
// because it had happened twice:
//
//   "A PARAM WITH NO FIELD IS DROPPED BY THE FIRST RE-SUBMIT. This form is
//    the whole query — it carries no hidden inputs — so anything the page
//    accepts but the form cannot render disappears the moment an operator
//    presses Search, silently WIDENING their search while looking like the
//    same one."
//
// A warning in a comment cannot fail a build. With the fields as data,
// tests/logSearchFields.test.js compares this list against the parameter list
// `app/(dashboard)/logs/page.js` accepts and fails when they diverge — so the
// next param added from a link elsewhere in the product cannot be silently
// un-renderable.
//
// ⛔ ═══ TIER: ESSENTIAL vs ADVANCED ══════════════════════════════════════
// All nineteen controls were on screen before any results. §8's requirement
// is "essential filters first, advanced behind progressive disclosure" — and
// the hard half is the one it states next: "do not hide active advanced
// filters without an indicator." Two mechanisms, both required:
//
//   1. The disclosure OPENS ITSELF when any advanced field has a value, the
//      same rule FilterBar follows. Rendered server-side as <details open>,
//      so it needs no JavaScript and is correct on first paint.
//   2. Every applied filter appears as a removable CHIP beside the results,
//      whichever tier it came from.
//
// Either alone is insufficient: the disclosure is invisible once an operator
// scrolls past it, and chips alone would leave them hunting for the control
// that set one.
//
// ⛔ THE TIER IS ABOUT WHAT AN INVESTIGATION REACHES FOR FIRST, not about how
// useful a field is. "Threat name" is the most interesting column in the
// table and is still advanced, because nobody starts there — they start with
// a time window and a host, and narrow.

const LOG_SEARCH_FIELDS = [
  // ── Essential ────────────────────────────────────────────────────────
  // ⛔ The window is first and is MANDATORY server-side; blank means the
  // default last hour, never "everything".
  { name: 'from', label: 'From', tier: 'essential', type: 'datetime-local' },
  { name: 'to', label: 'To', tier: 'essential', type: 'datetime-local' },
  { name: 'deviceId', label: 'Firewall', tier: 'essential', control: 'select', source: 'devices' },
  { name: 'logClass', label: 'Log type', tier: 'essential', control: 'select', source: 'logClasses' },
  { name: 'action', label: 'Action', tier: 'essential', control: 'select', source: 'actions' },
  { name: 'srcIp', label: 'Source IP', tier: 'essential', placeholder: '10.1.2.3 or 10.1.0.0/16' },
  { name: 'dstIp', label: 'Destination IP', tier: 'essential', placeholder: '8.8.8.8' },

  // ── Advanced ─────────────────────────────────────────────────────────
  { name: 'dstPort', label: 'Dest port', tier: 'advanced', placeholder: '443' },
  { name: 'srcUser', label: 'User', tier: 'advanced', placeholder: 'exact match' },
  { name: 'ruleName', label: 'Rule', tier: 'advanced', placeholder: 'exact match' },
  // ⛔ `ruleId` IS A SEPARATE COLUMN AND THE COMMON FORTIOS CASE, AND IT WAS
  // ACCEPTED EVERYWHERE EXCEPT HERE. `lib/syslog/logSearch.js` registers it,
  // both `/api/logs/search` and `/api/logs/export` accept it — and the page's
  // own whitelist and this registry both omitted it, so they AGREED WITH EACH
  // OTHER and the completeness test comparing the two could not see it.
  //
  // ⛔ THE COST WAS THE DANGEROUS DIRECTION. `DeviceTrafficTab` links the
  // busiest rule as `ruleId` whenever `rule_name` is null (the normal FortiOS
  // shape), so the drill-through dropped the only narrowing term and landed the
  // operator on EVERY session on that firewall for 24 hours, captioned as that
  // one rule's traffic, with no chip and no control to say so. Its own comment
  // records this bug being fixed once already in the other direction — passing
  // an id as `ruleName` returned NOTHING, and "an empty forensics result reads
  // as 'no such traffic', not as 'wrong field'". Returning everything is worse,
  // because nothing on screen looks wrong.
  //
  // ⛔ A REAL CONTROL RATHER THAN THE `hidden` TIER its six siblings use: a
  // vendor rule id is a value an investigator types and edits, not only one a
  // link carries. Advanced tier gives the chip and the server-side panel
  // auto-open as well, so nothing is lost by promoting it.
  { name: 'ruleId', label: 'Rule ID', tier: 'advanced', placeholder: '118' },
  { name: 'srcCountry', label: 'Source country', tier: 'advanced', placeholder: 'Poland' },
  { name: 'dstCountry', label: 'Dest country', tier: 'advanced', placeholder: 'Singapore' },
  {
    name: 'authOutcome',
    label: 'VPN login',
    tier: 'advanced',
    control: 'select',
    // ⛔ "Logins only" is IS NOT NULL, not a third outcome: most
    // log_class='vpn' rows are portal probes and keepalives, not
    // authentications.
    options: [
      { value: 'any', label: 'Logins only' },
      { value: 'success', label: 'Succeeded' },
      { value: 'failure', label: 'Failed' },
    ],
    emptyLabel: 'Any event',
  },
  { name: 'application', label: 'Application', tier: 'advanced', placeholder: 'ssl' },
  { name: 'threatName', label: 'Threat', tier: 'advanced', placeholder: 'exact match' },
  { name: 'urlHostname', label: 'Website contains', tier: 'advanced', placeholder: 'bing.com' },
  { name: 'q', label: 'Raw text contains', tier: 'advanced', placeholder: 'slower — narrow the window' },

  // ⛔ PRESENT, AND NEITHER TIER. The page accepts these and the form must
  // carry them or they are dropped on the next submit, but they are not
  // filters: `limit` is the page size (rendered beside the Search button) and
  // `page` is the position in the result set (rendered by the pager). Marking
  // them `tier: null` is what lets the completeness test below demand a field
  // for every accepted param WITHOUT demanding a chip for these two — a chip
  // reading "Page: 3 ×" would be a filter control that navigates.
  { name: 'limit', label: 'Rows per page', tier: null, control: 'select', options: [
    { value: '50', label: '50' }, { value: '100', label: '100' },
    { value: '200', label: '200' }, { value: '500', label: '500' },
  ] },
  { name: 'page', label: 'Page', tier: null, control: 'hidden' },

  // ⛔ ACCEPTED BY THE PAGE AND CARRIED HERE AS A HIDDEN INPUT. `sourceIp`,
  // `logSubtype`, `protocol`, `vendor`, `urlCategory` and `srcPort` are all
  // in the page's accepted list and had NO control, which is precisely the
  // silent-widening bug the header describes: a link from elsewhere in the
  // product sets one, the operator presses Search, and it vanishes while the
  // result set quietly grows. A hidden input is the honest minimum — the
  // value survives a re-submit — and the CHIP is what makes it visible and
  // removable.
  { name: 'vendor', label: 'Vendor', tier: 'hidden' },
  { name: 'logSubtype', label: 'Log subtype', tier: 'hidden' },
  { name: 'protocol', label: 'Protocol', tier: 'hidden' },
  { name: 'sourceIp', label: 'Sending host', tier: 'hidden' },
  { name: 'urlCategory', label: 'URL category', tier: 'hidden' },
  { name: 'srcPort', label: 'Source port', tier: 'hidden' },
];

const ESSENTIAL = LOG_SEARCH_FIELDS.filter((f) => f.tier === 'essential');
const ADVANCED = LOG_SEARCH_FIELDS.filter((f) => f.tier === 'advanced');
const HIDDEN = LOG_SEARCH_FIELDS.filter((f) => f.tier === 'hidden');

// Every name the form renders or carries. The page's accepted-parameter list
// must be a subset of this, or a param is droppable.
const ALL_FIELD_NAMES = LOG_SEARCH_FIELDS.map((f) => f.name);

// ⛔ `limit` AND `page` ARE NOT FILTERS, so they never become chips and are
// never cleared by "Clear filters" — the same NON_FILTER_PARAMS distinction
// lib/urlFilters.js draws, stated here because this form does not use it.
const NON_FILTER = new Set(['limit', 'page']);

/**
 * Should the advanced disclosure start open?
 *
 * ⛔ TRUE WHEN ANY ADVANCED **OR HIDDEN** FIELD IS APPLIED. The hidden ones
 * matter more, not less: they have no control at all, so if the disclosure
 * stayed shut there would be nothing on screen between the operator and a
 * filter narrowing their results. The chips are what actually show them, and
 * opening the panel is what stops the chips looking like they refer to
 * something that is not there.
 */
function advancedIsApplied(params) {
  const p = params || {};
  return [...ADVANCED, ...HIDDEN].some((f) => {
    const v = p[f.name];
    return v !== undefined && v !== null && String(v) !== '';
  });
}

/**
 * The applied filters, as chips.
 *
 * ⛔ A FIELD THIS REGISTRY DOES NOT KNOW STILL PRODUCES A CHIP, marked
 * `known: false`. Skipping it would hide an active filter from the one row
 * whose entire job is to list them — the same call lib/urlFilters.js makes.
 */
function logFilterChips(params) {
  const p = params || {};
  const byName = new Map(LOG_SEARCH_FIELDS.map((f) => [f.name, f]));
  const out = [];
  for (const [name, raw] of Object.entries(p)) {
    if (raw === undefined || raw === null || String(raw) === '') continue;
    if (NON_FILTER.has(name)) continue;
    const def = byName.get(name);
    const value = String(raw);
    if (!def) { out.push({ name, label: name, value, known: false }); continue; }
    let shown = value;
    if (def.options) {
      const opt = def.options.find((o) => o.value === value);
      if (opt) shown = opt.label;
    }
    out.push({ name, label: def.label, value: shown, known: true });
  }
  return out;
}

/** The query string with one filter removed, for a chip's remove link. */
function withoutLogFilter(params, name) {
  const next = new URLSearchParams();
  for (const [k, v] of Object.entries(params || {})) {
    if (k === name) continue;
    // ⛔ `page` RESETS when a filter changes, for the reason every other
    // filter bar in this product resets it: a page number from a larger
    // result set lands past the end of a smaller one and renders an empty
    // table that reads as "nothing matched".
    if (k === 'page') continue;
    if (v !== undefined && v !== null && String(v) !== '') next.set(k, String(v));
  }
  const qs = next.toString();
  return qs ? `/logs?${qs}` : '/logs';
}

module.exports = {
  LOG_SEARCH_FIELDS,
  ESSENTIAL_LOG_FIELDS: ESSENTIAL,
  ADVANCED_LOG_FIELDS: ADVANCED,
  HIDDEN_LOG_FIELDS: HIDDEN,
  ALL_FIELD_NAMES,
  advancedIsApplied,
  logFilterChips,
  withoutLogFilter,
};
