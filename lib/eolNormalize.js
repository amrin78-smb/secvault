// lib/eolNormalize.js
//
// The MATCHING CONTRACT for hardware end-of-life, shared with the central
// nocvault-eol service and with NetVault.
//
// ⛔ PORTED VERBATIM from nocvault-eol/lib/match-normalize.ts, which was itself
// ported verbatim from netvault/lib/eolEnrich.ts. Three copies, deliberately —
// each app normalises LOCALLY because the published feed carries RAW model
// strings, so a wrong brand in the feed can never block a match. The cost of
// that design is that these three files must not drift.
//
// ⛔ IF THE BEHAVIOUR CHANGES, IT CHANGES IN ALL THREE, AND NORMALIZER_VERSION
// IS BUMPED IN ALL THREE. A one-sided change does not throw and does not fail a
// build: it silently stops matching some models, and the only symptom is a
// device that used to show an EOL date quietly showing "unknown". The feed
// stamps its own `normalizer_version` so a consumer can at least DETECT the
// drift — `lib/feeds/eolFeed.js` records it and warns.
//
// Verified 2026-09-17 against the live feed (normalizer_version 4) and against
// the live fleet's real model strings: SecVault stores `FortiGate-60F` with a
// hyphen while the seed stores `FortiGate 100E` with a space, and this collapses
// both — the punctuation strip at the end is what makes that work.

'use strict';

// 4 (2026-08): the Cisco PID strip requires a digit after the prefix, so it no
// longer mangles non-Cisco models that merely start with 'air-' / 'ws-c'.
const NORMALIZER_VERSION = 4;

/**
 * Normalise a device/seed model into a flat matching key.
 *  - lowercase
 *  - strip a leading vendor prefix (also drops a vendor baked into the model)
 *  - strip curated product-line "noise" words (Catalyst, NGFW, Series…)
 *  - strip common Cisco product-ID prefixes (WS-C / AIR-AP / AIR-…)
 *  - strip region/series suffixes (-us/-ww/-row/series)
 *  - remove all punctuation and whitespace
 */
function normalizeForMatch(vendor, model) {
  let s = (model === null || model === undefined ? '' : String(model)).toLowerCase().trim();
  if (!s) return '';

  // Strip leading vendor words (also drops a redundant vendor baked into model).
  const vendorWords = [
    'hpe aruba networking', 'aruba', 'hpe', 'hp', 'cisco', 'grandstream',
    'ruckus', 'meraki', 'sonicwall', 'palo alto', 'paloalto', 'netgear',
    'tp-link', 'tplink', 'fortinet', 'juniper', 'forcepoint', 'dell',
  ];
  const v = (vendor === null || vendor === undefined ? '' : String(vendor)).toLowerCase().trim();
  if (v) vendorWords.unshift(v);
  let changed = true;
  while (changed) {
    changed = false;
    for (const w of vendorWords) {
      if (w && (s === w || s.startsWith(w + ' ') || s.startsWith(w + '-'))) {
        s = s.slice(w.length).trim().replace(/^[-\s]+/, '');
        changed = true;
        break;
      }
    }
  }

  // Product-LINE noise words. Excludes model-DEFINING lines (SonicWave, Aironet…).
  const noiseWords = ['catalyst', 'flexnetwork', 'procurve', 'powerconnect', 'ngfw', 'series', 'appliance'];
  for (const w of noiseWords) {
    s = s.replace(new RegExp('(^|[^a-z0-9])' + w + '([^a-z0-9]|$)', 'g'), '$1 $2');
  }

  // ⛔ The digit lookahead is load-bearing: it distinguishes a Cisco PID
  // (AIR-AP3802I, WS-C2960X) from an ordinary model that merely starts with the
  // same letters ('air-fiber-5XHD'), which would otherwise collapse to a key
  // that false-matches a genuine Cisco row.
  s = s.replace(/\b(?:ws-c|air-cap|air-ap|air-)(?=[a-z]{0,4}\d)/g, '');

  let suffixChanged = true;
  while (suffixChanged) {
    suffixChanged = false;
    const next = s.replace(/(?:[-_\s]?(?:us|ww|row|series))$/i, '');
    if (next !== s) { s = next.trim(); suffixChanged = true; }
  }

  return s.replace(/[^a-z0-9]/g, '');
}

/**
 * SecVault's own `devices.vendor` slug -> the vendor label the feed uses.
 *
 * ⛔ THE SLUG IS NOT THE LABEL. `paloalto` must become `Palo Alto` before it is
 * handed to normalizeForMatch, because the vendor-prefix strip compares the
 * vendor string against the START of the model — and a seed row stored as
 * "Palo Alto PA-3220" would keep its prefix if we passed the slug, producing a
 * key of `paloaltopa3220` that matches nothing.
 */
const VENDOR_LABEL = {
  paloalto: 'Palo Alto',
  fortinet: 'Fortinet',
  forcepoint: 'Forcepoint',
  cisco_asa: 'Cisco',
  checkpoint: 'Check Point',
  sangfor: 'Sangfor',
};

/** The feed's vendor label for one of this product's vendor slugs. */
function vendorLabelFor(slug) {
  return VENDOR_LABEL[slug] || null;
}

module.exports = { NORMALIZER_VERSION, normalizeForMatch, vendorLabelFor, VENDOR_LABEL };
