// lib/cvssVector.js
//
// Decodes a CVSS v3.x vector string into plain English.
//
// ── WHY ───────────────────────────────────────────────────────────────────
// The advisory detail page rendered the vector raw, with `word-break: break-all`:
//
//     CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H
//
// That is the most information-dense fact on the page and the least readable
// thing in the product. It answers exactly the questions a non-technical
// reader has — can this be hit from the internet? does the attacker need an
// account? does a user have to click something? — and answers them in a code.
// Live: 746 of 1,001 advisories carry a vector, all CVSS:3.1, uniform format.
//
// ⛔ EXTRACTS, NEVER INFERS. An unrecognised metric or value is skipped rather
// than guessed at, and a vector that parses to nothing returns an empty list so
// the caller can fall back to showing the raw string. The raw vector is kept on
// screen underneath regardless — it is the citation, and decoding is an aid to
// reading it, not a replacement for it.
//
// ⛔ This does NOT compute or re-derive a score. `advisories.cvss_score` is the
// published score and stays the single source of truth; inventing a second
// number from the vector would create two scores that could disagree.

'use strict';

// CVSS v3.x base metrics. Only the base group is decoded — temporal and
// environmental metrics are rare in this data and their meaning depends on a
// deployment context SecVault does not have.
const METRICS = {
  AV: {
    label: 'Attack vector',
    values: {
      N: { text: 'Network-reachable', risky: true },
      A: { text: 'Adjacent network', risky: false },
      L: { text: 'Local access needed', risky: false },
      P: { text: 'Physical access needed', risky: false },
    },
  },
  AC: {
    label: 'Attack complexity',
    values: {
      L: { text: 'Low complexity', risky: true },
      H: { text: 'High complexity', risky: false },
    },
  },
  PR: {
    label: 'Privileges required',
    values: {
      N: { text: 'No privileges needed', risky: true },
      L: { text: 'Low privileges needed', risky: false },
      H: { text: 'High privileges needed', risky: false },
    },
  },
  UI: {
    label: 'User interaction',
    values: {
      N: { text: 'No user interaction', risky: true },
      R: { text: 'User must act', risky: false },
    },
  },
  S: {
    label: 'Scope',
    values: {
      C: { text: 'Can affect other components', risky: true },
      U: { text: 'Contained to this component', risky: false },
    },
  },
  C: {
    label: 'Confidentiality impact',
    values: {
      H: { text: 'High confidentiality impact', risky: true },
      L: { text: 'Low confidentiality impact', risky: false },
      N: { text: 'No confidentiality impact', risky: false },
    },
  },
  I: {
    label: 'Integrity impact',
    values: {
      H: { text: 'High integrity impact', risky: true },
      L: { text: 'Low integrity impact', risky: false },
      N: { text: 'No integrity impact', risky: false },
    },
  },
  A: {
    label: 'Availability impact',
    values: {
      H: { text: 'High availability impact', risky: true },
      L: { text: 'Low availability impact', risky: false },
      N: { text: 'No availability impact', risky: false },
    },
  },
};

// Rendered in this order regardless of the order the vector lists them, so two
// advisories always read the same way.
const ORDER = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];

/**
 * @param {string|null} vector e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H"
 * @returns {{metric:string, label:string, text:string, risky:boolean}[]}
 *   Empty array when the vector is absent or nothing in it was recognised —
 *   the caller then shows the raw string alone rather than a partial decode
 *   that might read as complete.
 */
function parseCvssVector(vector) {
  if (typeof vector !== 'string' || vector.trim() === '') return [];
  const found = new Map();

  for (const part of vector.split('/')) {
    const [metric, value] = part.split(':');
    if (!metric || !value) continue;
    const m = METRICS[metric.trim().toUpperCase()];
    if (!m) continue; // includes the leading "CVSS:3.1" token, and any
    // temporal/environmental metric we deliberately do not decode
    const v = m.values[value.trim().toUpperCase()];
    if (!v) continue; // an unrecognised value is skipped, never guessed
    found.set(metric.trim().toUpperCase(), {
      metric: metric.trim().toUpperCase(),
      label: m.label,
      text: v.text,
      risky: v.risky,
    });
  }

  return ORDER.filter((k) => found.has(k)).map((k) => found.get(k));
}

module.exports = { parseCvssVector, METRICS };
