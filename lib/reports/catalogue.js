'use strict';

// lib/reports/catalogue.js — the single registry of every SecVault report.
//
// ⛔ ONE REGISTRY, READ BY EVERYTHING. The reports page, the download route and
// (from Phase C) the scheduler all resolve a report through this file. That is
// the point: a report cannot exist in the UI but not the API, or be schedulable
// but not downloadable, or be gated on one capability in one place and another
// somewhere else. Those three drifting apart is the same class of bug as the
// two PDF helper copies this directory was created to merge.
//
// ⛔ `capability` IS ENFORCED BY THE ROUTE, NOT BY THIS FILE. A registry entry
// is data; it cannot deny anything. Every consumer must call
// `can(session, entry.capability)` itself — listing a capability here and
// forgetting the check is a UI gate with no API behind it, which CLAUDE.md
// names as worse than no gate at all because it teaches the operator the
// product is broken rather than that they lack access.
//
// ⛔ A REPORT THAT NAMES PEOPLE MUST CARRY `view_identity`. Raw VPN and log data
// carry usernames, internal addresses and URLs; the RBAC section treats those
// as a documented exception to the "GETs are ungated" rule, and a PDF is not a
// loophole in that.

const { OPERATE, VIEW_IDENTITY } = require('../rbac');

/**
 * Scope tells the builder what it is being asked for, and tells the UI which
 * parameters to collect.
 *   fleet   — the whole estate, no device parameter
 *   device  — one firewall, requires deviceId
 *   entity  — one specific record (a change request), requires id
 */
const SCOPES = Object.freeze({ FLEET: 'fleet', DEVICE: 'device', ENTITY: 'entity' });

// ⛔ Phase A registers ONLY what already ships. The seven proposed reports are
// deliberately absent rather than present-and-stubbed: an entry here is a
// promise the UI will render and the route will serve, and a catalogue listing
// reports that return nothing is exactly the "looks complete, is not" failure
// this codebase keeps finding. Add an entry in the commit that adds its builder.
const REPORTS = [
  {
    id: 'executive-summary',
    icon: 'IconTrendingUp',
    contents: [
      'Fleet security score, with the three components that produced it',
      'What needs attention now, ranked across every engine',
      'Vulnerability, rule-hygiene and compliance headlines',
      'An explicit account of what could not be measured',
    ],
    name: 'Executive Security Posture',
    summary:
      'The fleet in one page: security score and what moved it, the work that needs '
      + 'attention now, and an explicit account of what could not be measured. Written '
      + 'for someone who will not read page two.',
    scope: SCOPES.FLEET,
    capability: OPERATE,
    formats: ['pdf'],
    builder: () => require('./executiveSummary').generateExecutiveSummaryPdf,
  },
  {
    id: 'rule-hygiene',
    icon: 'IconChecklist',
    contents: [
      'Findings by type — unused, shadowed, redundant, over-permissive',
      'Per-firewall breakdown with rule counts',
      'Deletion candidates, each backed by a measured zero',
      'Rules whose usage could not be measured, counted separately',
    ],
    name: 'Rule Hygiene & Policy Audit',
    summary:
      'Unused, shadowed, redundant and over-permissive rules — with every '
      + '"never used" backed by a measured zero, and rules whose usage could not be '
      + 'measured counted separately rather than listed as deletion candidates.',
    scope: SCOPES.FLEET,
    // ⛔ FLEET-SCOPED WITH AN OPTIONAL NARROWING, not a second scope.
    // This report answers the same question of one firewall or of all of them,
    // and the SCOPES enum treats fleet/device as exclusive. Registering it
    // twice would put two entries in the catalogue that differ only by a
    // parameter — two ids, two URLs, two things to keep in step — and the
    // reader would have to work out that they are the same document. So the
    // scope stays FLEET (what it does when given nothing) and the device is a
    // filter the UI may offer.
    optionalDevice: true,
    capability: OPERATE,
    formats: ['pdf'],
    builder: () => require('./ruleHygiene').generateRuleHygienePdf,
  },
  {
    id: 'vulnerability-posture',
    icon: 'IconShield',
    contents: [
      'Patch-now, scheduled and monitor bands with counts',
      'Per advisory: the priority rule that fired, not just the band',
      'KEV and CVSS context per finding',
      'Advisories that could not be matched, and firewalls never assessed',
    ],
    name: 'Vulnerability & Patch Posture',
    summary:
      'What must be patched and in what order, with the priority rule that fired '
      + 'stated per finding rather than just the band. Advisories SecVault could not '
      + 'match, and firewalls it never assessed, are listed rather than omitted.',
    scope: SCOPES.FLEET,
    optionalDevice: true,
    capability: OPERATE,
    formats: ['pdf'],
    builder: () => require('./vulnerabilityPosture').generateVulnerabilityPdf,
  },
  {
    id: 'compliance-fleet',
    icon: 'IconDocument',
    contents: [
      'Fleet score across PCI DSS, ISO 27001, CIS v8, NIST and SANS',
      'Per-firewall compliance scores',
      'Failing and warning findings appendix',
      'Checks SecVault cannot ask of a device, listed but not scored',
    ],
    name: 'Compliance Report',
    summary:
      'Fleet compliance across PCI DSS, ISO 27001, CIS v8, NIST and SANS — per-device '
      + 'scores and a findings appendix. Checks SecVault cannot ask of a device are '
      + 'excluded from the score and listed separately.',
    scope: SCOPES.FLEET,
    capability: OPERATE,
    formats: ['pdf'],
    // ⛔ A DECLARED PARAMETER, NOT FIVE MORE CATALOGUE ENTRIES. One check
    // commonly maps to several frameworks, so "PCI DSS" is a different
    // DENOMINATOR over the same fleet rather than a different report — and five
    // near-identical rail entries would say the opposite. The scoped document
    // states its own coverage so the two scores are not mistaken for a
    // disagreement (see standardCoverage() in lib/engines/complianceReport.js).
    //
    // ⛔ THE CHOICES ARE THE ALLOW-LIST. The route accepts a value only if it
    // appears here, so nothing unvalidated can reach a builder — the engine's
    // own resolveStandard() then refuses it a second time. Two independent
    // gates, because a mislabelled audit document is the one output this
    // product must never produce.
    params: [
      {
        key: 'standard',
        label: 'Standard',
        allLabel: 'All standards',
        choices: [
          { value: 'PCI_DSS', label: 'PCI DSS' },
          { value: 'ISO_27001', label: 'ISO 27001' },
          { value: 'CIS_V8', label: 'CIS v8' },
          { value: 'NIST', label: 'NIST' },
          { value: 'SANS', label: 'SANS' },
        ],
      },
    ],
    // Resolved lazily so the registry stays requireable from a client component
    // without dragging pdfkit and the whole engine graph in behind it.
    builder: () => require('../engines/complianceReport').generateReportPdf,
  },
  {
    id: 'rule-change-request',
    icon: 'IconReport',
    contents: [
      'The rules proposed for removal, with the evidence for each',
      'Who raised the request and when',
      'Verification status once a later collection has run',
      'CSV alongside the PDF, for whoever edits the firewall',
    ],
    name: 'Rule Change Request',
    summary:
      'The evidence-backed rules proposed for removal, and — once a later collection '
      + 'has run — whether they were actually removed. Rules whose usage could not be '
      + 'measured are refused from the request rather than listed with a caveat.',
    scope: SCOPES.ENTITY,
    capability: OPERATE,
    formats: ['pdf', 'csv'],
    builder: () => require('../engines/ruleChangeRequestReport').generateRequestPdf,
  },
];

const BY_ID = new Map(REPORTS.map((r) => [r.id, r]));

/** @returns {object|null} the entry, or null — never a partially-populated stub. */
function reportById(id) {
  return BY_ID.get(String(id || '')) || null;
}

/**
 * The catalogue as the UI should render it, filtered to what this session may
 * actually download.
 *
 * ⛔ FILTERING HERE IS DISCOVERY, NOT ENFORCEMENT. It stops an operator being
 * shown a report they cannot fetch; it does not stop them fetching it. The
 * route does that.
 */
function visibleReports(capabilities) {
  const caps = capabilities || {};
  return REPORTS.filter((r) => !r.capability || caps[r.capability]);
}

/**
 * The subset of an entry that may cross the server/client boundary.
 *
 * ⛔ THE `builder` IS A FUNCTION AND REACT WILL REFUSE IT. A catalogue entry is
 * not serialisable: `builder` is a lazy `() => require(...)` so the registry can
 * be read without dragging pdfkit and the whole engine graph in behind it. Hand
 * a raw entry to a client component and the page dies at render with
 * "Functions cannot be passed directly to Client Components" — which in a
 * production build is a bare digest and an empty screen, with the actual message
 * omitted "to avoid leaking sensitive details". That is exactly what happened on
 * the first deploy of /reports.
 *
 * ⛔ THIS IS AN ALLOW-LIST, NOT A DELETE. Written as "pick these fields" rather
 * than "drop builder", because the next field added to an entry might also be a
 * function — a formatter, a validator, a predicate — and a deny-list silently
 * starts passing it. The allow-list fails the other way: a new field simply does
 * not reach the UI until someone adds it here, which is visible and harmless.
 */
function clientSafe(entry) {
  if (!entry) return null;
  return {
    id: entry.id,
    name: entry.name,
    summary: entry.summary,
    icon: entry.icon || null,
    contents: Array.isArray(entry.contents) ? [...entry.contents] : [],
    params: Array.isArray(entry.params)
      ? entry.params.map((p) => ({
        key: p.key,
        label: p.label,
        allLabel: p.allLabel || null,
        choices: Array.isArray(p.choices)
          ? p.choices.map((c) => ({ value: c.value, label: c.label }))
          : [],
      }))
      : [],
    scope: entry.scope,
    optionalDevice: Boolean(entry.optionalDevice),
    formats: Array.isArray(entry.formats) ? [...entry.formats] : [],
  };
}

module.exports = { SCOPES, REPORTS, reportById, visibleReports, clientSafe, VIEW_IDENTITY };
