'use strict';
// tests/deviceScopeCoverage.test.js
//
// ⛔ THE REGISTER IS THE SAFETY MECHANISM, SO THE REGISTER NEEDS A TEST.
// Per-device scoping cannot be retrofitted across 104 device-reading files in
// one change, and the failure that creates is not "too little access" — it is
// an administrator restricting an account to two firewalls, watching the
// device list obey, and never learning a report still shows the other
// fourteen. A boundary somebody believes in and that is not there is worse
// than none.
//
// So: every reachable surface must be classified, a NEW surface fails the
// build until someone classifies it, and the coverage may only move toward
// 'aware'. This is the same shrinking-allow-list shape
// tests/installerNativeCalls.test.js uses, pointed at an authorisation
// boundary instead of a shell quirk.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  COVERAGE, CLASSIFICATIONS, isScopeAware, touchesDeviceData, countByClassification,
} = require('../lib/deviceScopeCoverage');

const ROOT = path.join(__dirname, '..');

function walk(dir, name, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, name, out);
    else if (e.name === name) out.push(path.relative(ROOT, p).split(path.sep).join('/'));
  }
  return out;
}

const surfaces = () => [
  ...walk(path.join(ROOT, 'app', 'api'), 'route.js'),
  ...walk(path.join(ROOT, 'app', '(dashboard)'), 'page.js'),
].sort();

// ⛔ THE BASELINE IS A FLOOR, NOT A TARGET. It is the count at the moment
// scoping shipped; the assertion is that it never FALLS. Raising it as
// surfaces are covered is the work, and lowering it is a regression that
// silently re-exposes firewalls to a scoped account.
const AWARE_FLOOR = 4;

describe('⛔ every reachable surface is classified', () => {
  it('finds the routes and pages at all', () => {
    // A walk that silently found nothing would make every assertion below
    // vacuously true — the guard-that-cannot-fire pattern, aimed at the one
    // test standing between a scoped user and the rest of the fleet.
    const found = surfaces();
    assert.ok(found.length > 80, `expected the app tree, found ${found.length} files`);
    assert.ok(found.includes('app/api/devices/route.js'));
    assert.ok(found.includes('app/(dashboard)/devices/page.js'));
  });

  it('⛔ a surface on no list fails the build', () => {
    // The whole point: adding a route must be a deliberate decision about
    // whether a scoped account may reach it, never a default.
    const missing = surfaces().filter((f) => !Object.prototype.hasOwnProperty.call(COVERAGE, f));
    assert.deepEqual(missing, [],
      'these routes/pages are not in lib/deviceScopeCoverage.js. Classify each as '
      + "'aware' (it narrows by the session's device scope), 'blocked' (it reads device "
      + "data and does not scope it, so scoped accounts are refused) or 'no-device-data':\n  "
      + missing.join('\n  '));
  });

  it('and a register entry that no longer exists is removed', () => {
    // A stale entry is the same defect as a stale allow-list: it makes
    // coverage look broader than it is.
    const live = new Set(surfaces());
    const ghosts = Object.keys(COVERAGE).filter((f) => !live.has(f));
    assert.deepEqual(ghosts, [], `no longer exist — drop them:\n  ${ghosts.join('\n  ')}`);
  });

  it('every classification is one of the three known values', () => {
    const bad = Object.entries(COVERAGE).filter(([, v]) => !CLASSIFICATIONS.includes(v));
    assert.deepEqual(bad, [], 'unrecognised classification');
  });
});

describe('⛔ coverage may only move toward enforcement', () => {
  it('the aware count never falls below the shipped floor', () => {
    const { aware } = countByClassification();
    assert.ok(aware >= AWARE_FLOOR,
      `device scoping covered ${aware} surfaces, down from ${AWARE_FLOOR}. Demoting a surface `
      + 're-exposes firewalls to accounts that were restricted from them. If this is '
      + 'deliberate, the floor moves in the same commit and the reason goes in the message.');
  });

  it('the four surfaces scoping shipped with are still aware', () => {
    // Named rather than counted: four OTHER surfaces going aware while these
    // regressed would satisfy the count and break the product's only
    // scope-aware path.
    for (const f of [
      'app/api/devices/route.js',
      'app/api/devices/[id]/route.js',
      'app/(dashboard)/devices/page.js',
      'app/(dashboard)/devices/[id]/page.js',
    ]) {
      assert.equal(isScopeAware(f), true, `${f} must narrow by device scope`);
    }
  });
});

describe('⛔ a surface that reads device data is never silently unclassified', () => {
  // The register is hand-maintained, so it can drift from what the files
  // actually do. This re-derives the device-touching set from SOURCE and
  // asserts the register agrees — a file that grew a device query since it was
  // classified 'no-device-data' is exactly the silent leak this guards.
  const DEVICE_RE = /FROM devices|JOIN devices|\bdeviceId\b|\bdevice_id\b/;

  it('nothing classified no-device-data actually queries devices', () => {
    const offenders = [];
    for (const [file, cls] of Object.entries(COVERAGE)) {
      if (cls !== 'no-device-data') continue;
      const full = path.join(ROOT, file);
      if (!fs.existsSync(full)) continue;
      if (DEVICE_RE.test(fs.readFileSync(full, 'utf8'))) offenders.push(file);
    }
    assert.deepEqual(offenders, [],
      'these are classified as carrying no per-firewall data but reference it. Re-classify '
      + `them 'blocked' (or 'aware' once they narrow):\n  ${offenders.join('\n  ')}`);
  });

  it('and everything else is accounted for as aware or blocked', () => {
    const counts = countByClassification();
    assert.equal(
      counts.aware + counts.blocked + counts['no-device-data'],
      Object.keys(COVERAGE).length
    );
    assert.ok(counts.blocked > 0,
      'zero blocked surfaces would mean scoping is complete — if it genuinely is, delete '
      + 'this assertion and the blocked branch with it, deliberately.');
    assert.equal(touchesDeviceData('app/api/devices/route.js'), true);
  });
});
