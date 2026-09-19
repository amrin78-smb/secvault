'use strict';
// tests/cveVendorSquat.test.js
//
// ⛔ `advisories.cve_id` IS UNIQUE AND CARRIES EXACTLY ONE VENDOR, so whichever
// feed ingests a CVE first owns it permanently. Every upsert already refuses to
// clobber another vendor's row — and then reported nothing, so an advisory that
// was permanently LOST looked exactly like an update where nothing had changed.
//
// This pins the distinction, not the policy. Whether the identity should become
// (cve_id, vendor) is a separate decision that touches how this product counts
// vulnerabilities everywhere; what it needs first is a number, and a number
// nobody can read is not one.
//
// The stub records the SQL it was handed and answers it — no database.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// ⛔ LINE ENDINGS NORMALISED FIRST. This repo is checked out with CRLF on
// Windows, so a pattern ending in a newline silently never matches — the trap
// tests/serverHealth.js and tests/backupScripts.js both already record. It cost
// a debugging round here too: the assertion failed against source that was
// entirely correct, which is the most expensive kind of false positive.
const CRLF = new RegExp(String.fromCharCode(13) + String.fromCharCode(10), 'g');
const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8')
  .replace(CRLF, String.fromCharCode(10));

describe('⛔ the upserts can SEE who owns the row', () => {
  for (const file of ['lib/feeds/nvd.js', 'lib/feeds/paloalto.js']) {
    it(`${file} returns the owning vendor, not what it tried to write`, () => {
      const src = read(file);
      // Without this the caller cannot tell "I updated my row" from "someone
      // else's row was left alone", because both return a row.
      assert.match(src, /RETURNING \(xmax = 0\) AS inserted, advisories\.vendor AS owning_vendor/);
    });
  }

  it('lib/feeds/fortinet.js resolves the owner when its conditional update declines', () => {
    const src = read('lib/feeds/fortinet.js');
    // Fortinet's ON CONFLICT carries a WHERE, so zero rows is ambiguous: either
    // another vendor owns the cve_id, or this degraded record had no gap. Both
    // used to return 'unchanged'.
    assert.match(src, /SELECT vendor FROM advisories WHERE cve_id = \$1/);
    assert.match(src, /outcome: 'claimed'/);
  });
});

describe('⛔ a claimed CVE is counted, never folded into "unchanged"', () => {
  const fortinet = read('lib/feeds/fortinet.js');
  const nvd = read('lib/feeds/nvd.js');

  it('fortinet keeps a separate accumulator and returns it', () => {
    assert.match(fortinet, /const claimedByOtherVendor = \[\];/);
    assert.match(fortinet, /claimedByOtherVendor\.push\(\{ cve_id: rec\.cve_id, wanted: rec\.vendor, held_by: res\.heldBy \}\)/);
    assert.match(fortinet, /\n\s*claimedByOtherVendor,\n/, 'it must reach the run summary');
  });

  it('nvd counts a claim INSTEAD of an update, not as well as one', () => {
    // Counting it as an update would keep the loss invisible in the one number
    // an operator reads.
    const block = nvd.slice(nvd.indexOf('const res = await upsertAdvisory(pool, rec);'));
    assert.match(block.slice(0, 400), /if \(res\.claimedBy\)/);
    const ifIdx = block.indexOf('if (res.claimedBy)');
    const elseIdx = block.indexOf('else if (res.inserted) inserted++;');
    assert.ok(ifIdx > -1 && elseIdx > ifIdx, 'the claim branch must come first and be exclusive');
  });

  it('the claim carries WHICH vendor holds it — a bare count cannot be acted on', () => {
    assert.match(nvd, /claimedBy: row\.owning_vendor === rec\.vendor \? null : row\.owning_vendor/);
  });
});

describe('⛔ it reaches feed_sync_log, or it may as well not exist', () => {
  const index = read('lib/feeds/index.js');

  it('both discovery feeds record the count in their sync summary', () => {
    const matches = index.match(/claimed_by_other_vendor:/g) || [];
    assert.equal(matches.length, 2, 'nvd and fortinet');
    assert.match(index, /claimed_examples:/);
  });

  it('it is filed as INFORMATIONAL and cannot flip a clean run to partial', () => {
    // `status` is computed from result.errors BEFORE the summary entry is
    // appended, exactly as the per-vendor summary already is. A feed reporting
    // itself degraded because another feed owns a CVE would be a permanent
    // amber chip for correct behaviour.
    const fortinetBlock = index.slice(index.indexOf("logSyncStart(pool, 'fortinet_psirt')"));
    const statusIdx = fortinetBlock.indexOf('const status =');
    const claimedIdx = fortinetBlock.indexOf('const claimed =');
    assert.ok(statusIdx > -1 && claimedIdx > statusIdx, 'status must be decided before the summary is built');
    assert.match(fortinetBlock.slice(0, 1200), /informational, not an error/);
  });

  it('⛔ the KEV block does not reference fortinet\'s local variable', () => {
    // It did, for one edit: a find-and-replace landed on the wrong occurrence
    // and put `fortinetErrorsForLog` inside runKevSync, where it is not in
    // scope. `node --check` passes that happily — it is a ReferenceError, and
    // it would have thrown on the next live KEV sync, not in any test.
    const kev = index.slice(index.indexOf("logSyncStart(pool, 'kev')"));
    assert.ok(!/fortinetErrorsForLog/.test(kev.slice(0, 700)));
  });
});
