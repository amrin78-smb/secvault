'use strict';

// tests/configDiffCollapseRedaction.test.js
//
// Roadmap row 38 — `collapseObjectArrayIdentityCascades` persisted
// `diffValue()` output WITHOUT the redaction pass every other persisting call
// site applies.
//
// ⛔ WHY THIS IS A SECURITY TEST AND NOT A TIDINESS ONE. The function re-diffs
// two whole stored objects and splices the result into a diff that
// `collapseHistoricalArrayShiftCascades` UPDATEs back into `config_diffs` —
// a table BOTH readonly roles can read, unlike `device_credentials`. So a
// secret that was carried opaquely inside a whole-element entry can be
// PROMOTED by that re-diff into its own named top-level leaf, and before the
// fix it landed there in plaintext.
//
// ⛔ AND THE REPAIR RE-RUNS ON EVERY DEPLOY, because this pass is NOT
// ledger-gated — so the exposure is recreated rather than being a one-off.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const diffEngine = require('../lib/engines/configDiff');

// The live shape this was found for: a PAN-OS local admin, whose password hash
// sits at `mgt-config.users.entry[N].phash`. CLAUDE.md names that field by
// name as one the redactor exists to catch.
const user = (hash) => ({ '@_name': 'admin1', role: 'superuser', phash: hash });

const PLAINTEXT_OLD = 'OLD$1$abcdefgh$NOTAREALHASH';
const PLAINTEXT_NEW = 'NEW$1$ijklmnop$NOTAREALHASH';

function wholeElementSwap() {
  return {
    added: [{ path: 'mgt-config.users.entry[3]', value: user(PLAINTEXT_NEW) }],
    removed: [{ path: 'mgt-config.users.entry[3]', value: user(PLAINTEXT_OLD) }],
    modified: [],
  };
}

describe('⛔ the identity-cascade collapse redacts what it promotes', () => {
  it('⛔ a secret promoted out of a whole element never reaches the output', () => {
    const out = diffEngine.collapseObjectArrayIdentityCascades(wholeElementSwap(), 'paloalto');
    const blob = JSON.stringify(out);

    // The re-diff really did happen — otherwise this test passes vacuously on
    // a function that stopped collapsing at all.
    assert.equal(out.modified.length, 1, 'the whole-element pair must collapse to its real delta');
    assert.equal(out.modified[0].path, 'mgt-config.users.entry[3].phash');

    // And the promoted leaf is redacted on BOTH sides.
    assert.equal(out.modified[0].old, '<redacted>');
    assert.equal(out.modified[0].new, '<redacted>');
    assert.doesNotMatch(blob, /NOTAREALHASH/, 'no part of the carried secret may survive');
  });

  it('⛔ it redacts the PASS-THROUGH entries too, so a legacy row is repaired', () => {
    // A diff written before a redaction rule existed is exactly what this pass
    // re-reads. Leaving an untouched entry alone would preserve the exposure
    // on the one code path that was already rewriting the row.
    const d = wholeElementSwap();
    d.modified.push({ path: 'devices.entry[0].snmp.community', old: 'public1', new: 'public2' });
    const out = diffEngine.collapseObjectArrayIdentityCascades(d, 'paloalto');
    const passed = out.modified.find((e) => e.path.endsWith('snmp.community'));
    assert.ok(passed, 'the unrelated entry must still be carried');
    assert.equal(passed.old, '<redacted>');
    assert.equal(passed.new, '<redacted>');
  });

  it('a non-secret field is left completely alone', () => {
    // Redacting everything would be safe and useless — the diff is the product.
    const d = {
      added: [{ path: 'rules.entry[1]', value: { '@_name': 'r1', action: 'allow' } }],
      removed: [{ path: 'rules.entry[1]', value: { '@_name': 'r1', action: 'deny' } }],
      modified: [],
    };
    const out = diffEngine.collapseObjectArrayIdentityCascades(d, 'paloalto');
    assert.equal(out.modified.length, 1);
    assert.equal(out.modified[0].old, 'deny');
    assert.equal(out.modified[0].new, 'allow');
  });

  it('⛔ every persisting diffValue() path redacts — stated as one rule', () => {
    // `filterDiffForCurrentRules` performed the structurally identical
    // re-decomposition and HAS always redacted; this function was the one that
    // did not. A future third collapse pass must not repeat it.
    const src = fs.readFileSync(
      path.join(__dirname, '..', 'lib', 'engines', 'configDiff.js'), 'utf8'
    );
    const bodies = src.split(/\nfunction /).filter((b) => /\bdiffValue\(/.test(b));
    assert.ok(bodies.length >= 2, 'the scan must find the real call sites');
    for (const b of bodies) {
      const name = (b.match(/^([A-Za-z0-9_]+)/) || [])[1] || '(top level)';
      // Only the functions that RETURN or STORE a composed diff need it; the
      // recursive internals of diffValue itself do not.
      if (!/\breturn \{[\s\S]{0,400}?added:/.test(b)) continue;
      assert.match(b, /redactSecretEntries\(/,
        `${name} composes a diff from diffValue() output and must redact it`);
    }
  });
});
