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
  COVERAGE, CLASSIFICATIONS, TRANSITIVE_ALLOWED, isScopeAware, touchesDeviceData,
  countByClassification,
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

  // ⛔ COMMENTS ARE STRIPPED FIRST. lib/notificationChannels.js says, in
  // prose, "device_id-scoped and don't apply here" — a sentence explaining
  // that it holds no device data — and the raw-source check read that as
  // evidence that it does. A checker that fires on its own subject matter
  // being DISCUSSED produces noise, and noise is how a real hit gets waved
  // through. The [^:] guard keeps an https:// inside a string from eating
  // the rest of its line.
  const stripComments = (src) => src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');

  it('nothing classified no-device-data actually queries devices', () => {
    const offenders = [];
    for (const [file, cls] of Object.entries(COVERAGE)) {
      if (cls !== 'no-device-data') continue;
      const full = path.join(ROOT, file);
      if (!fs.existsSync(full)) continue;
      if (DEVICE_RE.test(stripComments(fs.readFileSync(full, 'utf8')))) offenders.push(file);
    }
    assert.deepEqual(offenders, [],
      'these are classified as carrying no per-firewall data but reference it. Re-classify '
      + `them 'blocked' (or 'aware' once they narrow):\n  ${offenders.join('\n  ')}`);
  });

  // ⛔ THE SAME QUESTION, ONE IMPORT DEEPER — and this is where it actually
  // found something. The check above reads only the surface FILE, so a route
  // whose device query lives in an engine it imports was invisible to it. Six
  // were: every /api/applications route imports applicationViewData, which
  // evaluates declared flows against each device's collected rulebase, while
  // the PAGE those routes back was already `blocked`; and
  // credential-profiles/[id] sat open beside its own already-blocked
  // collection route. Blocking a page and leaving its API open is precisely
  // the hole this register exists to prevent.
  //
  // ⛔ THE UNIVERSAL IMPORTS ARE NOT FOLLOWED, or the checker reports every
  // authenticated route and therefore reports nothing: `authOptions` reaches
  // lib/mfa.js -> lib/credStore.js, which mentions device_id, from all 88 of
  // them. That exclusion is the one judgement in here and it is narrow —
  // modules every surface imports BY CONSTRUCTION, never a module that happens
  // to be inconvenient.
  const UNIVERSAL = [
    'app/api/auth/[...nextauth]/route.js',
    'lib/credStore.js',
    'lib/mfa.js',
    'lib/db.js',
    'lib/rbac.js',
    'lib/deviceScope.js',
    'lib/deviceScopePaths.js',
  ];
  const SPEC = /(?:from\s*|require\()\s*['"](\.[^'"]+)['"]/g;

  function resolveSpec(from, spec) {
    const base = path.resolve(path.dirname(from), spec);
    for (const c of [base, `${base}.js`, path.join(base, 'index.js')]) {
      if (fs.existsSync(c) && fs.statSync(c).isFile()) return c;
    }
    return null;
  }

  function reachesDeviceData(file, seen, depth) {
    if (depth > 6) return null;
    const real = path.resolve(file);
    if (seen.has(real)) return null;
    seen.add(real);
    let src;
    try { src = fs.readFileSync(real, 'utf8'); } catch { return null; }
    const rel = path.relative(ROOT, real).split(path.sep).join('/');
    if (depth > 0 && UNIVERSAL.includes(rel)) return null;
    if (depth > 0 && DEVICE_RE.test(stripComments(src))) return rel;
    const kids = [];
    let m;
    SPEC.lastIndex = 0;
    while ((m = SPEC.exec(src))) kids.push(m[1]);
    for (const k of kids) {
      const r = resolveSpec(real, k);
      if (!r) continue;
      const hit = reachesDeviceData(r, seen, depth + 1);
      if (hit) return hit;
    }
    return null;
  }

  it('⛔ nor does anything it IMPORTS, unless the exemption is written down', () => {
    const offenders = [];
    for (const [file, cls] of Object.entries(COVERAGE)) {
      if (cls !== 'no-device-data') continue;
      if (TRANSITIVE_ALLOWED[file]) continue;
      const full = path.join(ROOT, file);
      if (!fs.existsSync(full)) continue;
      const via = reachesDeviceData(full, new Set(), 0);
      if (via) offenders.push(`${file}  (via ${via})`);
    }
    assert.deepEqual(offenders, [],
      'these are classified as carrying no per-firewall data but reach it through an import. '
      + "Re-classify them 'blocked', or add an entry to TRANSITIVE_ALLOWED saying exactly what "
      + `the import carries:\n  ${offenders.join('\n  ')}`);
  });

  it('⛔ every allowlist entry is still needed, and still resolves', () => {
    // An exemption for a surface that no longer reaches device data reads as a
    // known hole that is not there, and one for a deleted file is a line
    // nobody will ever remove. Both make the list less trustworthy than none.
    const stale = [];
    for (const file of Object.keys(TRANSITIVE_ALLOWED)) {
      if (!COVERAGE[file]) { stale.push(`${file} (not in the register)`); continue; }
      if (COVERAGE[file] !== 'no-device-data') {
        stale.push(`${file} (now classified ${COVERAGE[file]}, so the exemption is moot)`);
        continue;
      }
      const full = path.join(ROOT, file);
      if (!fs.existsSync(full)) { stale.push(`${file} (file is gone)`); continue; }
      if (!reachesDeviceData(full, new Set(), 0)) {
        stale.push(`${file} (no longer reaches device data — delete the exemption)`);
      }
    }
    assert.deepEqual(stale, [], `stale exemptions:\n  ${stale.join('\n  ')}`);
  });

  it('and every exemption states a REASON, not just a name', () => {
    for (const [file, why] of Object.entries(TRANSITIVE_ALLOWED)) {
      assert.equal(typeof why, 'string', file);
      assert.ok(why.trim().length >= 12,
        `${file}: an exemption with no explanation is a suppression`);
    }
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
