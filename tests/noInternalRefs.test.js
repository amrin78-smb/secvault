'use strict';
// Guards the boundary between SecVault's INTERNAL developer documentation and
// the prose a CUSTOMER reads.
//
// WHY THIS EXISTS. The evidence drawer shipped in v2.107.0 with a footer that
// read "Governed by CLAUDE.md § Priority Decision Tree". CLAUDE.md is an AI
// assistant's instruction file. Printing its name in a panel a buyer opens
// tells them how the product was built, which is neither something they asked
// for nor something that helps them trust the number above it — and it was
// sitting under the most trust-sensitive figure in the product.
//
// It was not one slip. A repo scan found the same leak in nine user-visible
// strings: two empty states, a Forcepoint error message, two compliance check
// descriptions (which are STORED IN THE DATABASE and rendered per device), and
// two release notes. The pattern is easy to repeat because the reference is
// genuinely useful while writing the code and invisible to the person writing
// it afterwards.
//
// ⛔ The rule this pins: CLAUDE.md may appear in COMMENTS as often as it likes
// — 499 times at the time of writing, and that is good, it is how the rules
// stay findable. It may never appear in a STRING LITERAL under app/,
// components/ or lib/, because those reach the screen.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const DIRS = ['app', 'components', 'lib'];

/**
 * Strip comments so only code (and therefore string literals) remains.
 *
 * ⛔ Deliberately crude, and biased toward FALSE NEGATIVES rather than false
 * positives: block comments go first (which also covers JSX `{  }` comments,
 * since their body is a block comment), then line comments, skipping `://` so
 * a URL inside a string does not truncate the rest of that line. A missed leak
 * is a bug this test failed to catch; a spurious failure would be a test
 * nobody trusts, which is worse.
 */
function stripComments(src) {
  let s = src.replace(/\/\*[\s\S]*?\*\//g, ' ');
  s = s.replace(/(^|[^:])\/\/[^\n]*/g, '$1');
  return s;
}

function walk(dir, out) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === '.next') continue;
      walk(full, out);
    } else if (entry.name.endsWith('.js')) {
      out.push(full);
    }
  }
  return out;
}

const FILES = DIRS.flatMap((d) => walk(path.join(ROOT, d), []));

describe('internal developer references never reach a user-visible string', () => {
  it('scans a meaningful number of files', () => {
    // A guard on the guard: a broken walk would make every assertion below
    // pass vacuously, which is the quietest way for a test to stop working.
    assert.ok(FILES.length > 200, 'expected to scan >200 files, got ' + FILES.length);
  });

  it('⛔ no CLAUDE.md reference survives comment-stripping', () => {
    const offenders = [];
    for (const file of FILES) {
      const code = stripComments(fs.readFileSync(file, 'utf8'));
      if (!code.includes('CLAUDE.md')) continue;
      const line = code.split('\n').findIndex((l) => l.includes('CLAUDE.md')) + 1;
      offenders.push(path.relative(ROOT, file) + ':' + line);
    }
    assert.deepEqual(
      offenders,
      [],
      'CLAUDE.md appears outside a comment — it will render to a user:\n  ' + offenders.join('\n  ')
    );
  });

  it('⛔ the evidence drawer footer names a PRODUCT, not a source file', () => {
    // `source` and `rule` are rendered verbatim in the drawer a buyer opens.
    // A path like "lib/engines/cveMatcher.js" is developer shorthand; the
    // reader wants to know which part of the PRODUCT produced the number.
    const evidence = require('../lib/evidence');
    const headline = {
      deviceCount: 16, devicesOnline: 16, devicesCveAssessed: 16,
      rulesTotal: 100, rulesEnabled: 90,
      patchNowCount: 3, devicesWithPatchNow: 3, highRiskCount: 5,
      complianceScore: 51, complianceCounts: { X: { pass: 1, fail: 1, warning: 0 } },
      securityScore: 49,
      securityComponents: [{ key: 'v', label: 'Vulnerability posture', score: 49, weight: 40 }],
    };

    const built = [
      evidence.deviceCountEvidence(headline),
      evidence.securityScoreEvidence(headline),
      evidence.patchNowEvidence(headline),
      evidence.highRiskEvidence(headline),
      evidence.rulesEvidence(headline),
      evidence.complianceScoreEvidence(headline),
      evidence.cvePostureEvidence(
        { total_cves: 5, patch_now_cves: 1, scheduled_cves: 4, monitor_cves: 0 },
        { active_devices: 16, devices_with_version: 16, devices_assessed: 16 }
      ),
      evidence.deviceComplianceEvidence({ pass: 1, fail: 1, warning: 0, na: 0 }, 'X'),
      evidence.ruleHygieneEvidence(
        { critical: 1, high: 1, medium: 0, info: 0, total: 2 },
        { total: 10, not_measured: 1, measured_zero: 4, with_hits: 5 }
      ),
    ].filter(Boolean);

    assert.ok(built.length >= 9, 'expected every builder to produce evidence');

    for (const ev of built) {
      assert.doesNotMatch(ev.source, /\.js\b/, 'source is a file path: ' + ev.source);
      assert.doesNotMatch(ev.source, /CLAUDE/i, 'source names CLAUDE.md: ' + ev.source);
      if (ev.rule) {
        assert.doesNotMatch(ev.rule, /CLAUDE/i, 'rule names CLAUDE.md: ' + ev.rule);
        assert.doesNotMatch(ev.rule, /\.js\b/, 'rule is a file path: ' + ev.rule);
        assert.match(ev.rule, /^SecVault /, 'rule should name a SecVault policy: ' + ev.rule);
      }
    }
  });

  it('the stripper does not simply blank every file', () => {
    // Without this, a stripComments() that returned '' would make the scan
    // above pass forever while checking nothing.
    const sample = stripComments(fs.readFileSync(path.join(ROOT, 'lib', 'evidence.js'), 'utf8'));
    assert.ok(sample.includes('function isRenderableEvidence'), 'stripper ate real code');
    assert.ok(!sample.includes('most-repeated rule'), 'stripper failed to remove a comment');
  });
});
