'use strict';
// ⛔ THE `getVpnTunnels()` ANSWER IS TRI-STATE, AND `[]` IS ONLY ONE OF THE
// THREE (2026-11-13). `storeVpnTunnels()` is DELETE+reinsert, so whatever it
// reads as "a measurement" decides whether a device's tunnel set survives.
//
// It used to open with `Array.isArray(tunnels) ? tunnels : []`, which turned
// EVERY unreadable answer into a wipe — and all four adapters degrade a parse
// failure to an empty list, while `undefined` is what any method that falls off
// its own end returns. One vendor shape the normalizer did not expect deleted
// the device's whole tunnel set, after which `topology.js`'s `buildVpnEdges()`
// drew that firewall with no tunnels at all: a confident wrong answer, not a
// gap, which is this codebase's signature bug.
//
// ⛔ THE ASSERTIONS ARE ON THE QUERIES ACTUALLY ISSUED, not on the source text.
// "Did the DELETE run" is the only thing that decides whether data is lost, and
// a source scan for the word `null` would pass over a branch that reaches the
// delete anyway. The stub records every statement.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { storeVpnTunnels } = require('../lib/engines/vpnTunnels');

/** A pool stub that records every statement it is handed. */
function stubPool() {
  const statements = [];
  const client = {
    query(sql) {
      statements.push(String(sql).trim());
      return Promise.resolve({ rows: [], rowCount: 0 });
    },
    release() { client.released = true; },
    released: false,
  };
  return {
    statements,
    client,
    connect: () => Promise.resolve(client),
    query(sql) { statements.push(String(sql).trim()); return Promise.resolve({ rows: [] }); },
  };
}

const deletes = (p) => p.statements.filter((q) => q.startsWith('DELETE FROM vpn_ipsec_tunnels'));
const inserts = (p) => p.statements.filter((q) => q.startsWith('INSERT INTO vpn_ipsec_tunnels'));

const TUNNEL = {
  name: 'to-branch-01', peer: '203.0.113.9', status: 'up', ike_version: '2',
  bytes_in: 10, bytes_out: 20, raw: { vdom: 'root' },
};

describe('⛔ an ARRAY is a measurement, and clears what it does not contain', () => {
  it('a populated array deletes then reinserts', async () => {
    const pool = stubPool();
    const r = await storeVpnTunnels('dev-1', [TUNNEL, { ...TUNNEL, name: 'b' }], pool);
    assert.equal(deletes(pool).length, 1);
    assert.equal(inserts(pool).length, 2);
    assert.deepEqual(r, { count: 2, measured: true });
  });

  it('⛔ an EMPTY array still deletes — it means "this device genuinely has none"', async () => {
    // This is the half that must NOT change. A device whose last tunnel came
    // down reports `[]`, and leaving the old row behind would show a tunnel
    // that is gone — the mirror-image wrong answer.
    const pool = stubPool();
    const r = await storeVpnTunnels('dev-1', [], pool);
    assert.equal(deletes(pool).length, 1, 'a measured zero must still clear the rows');
    assert.equal(inserts(pool).length, 0);
    assert.deepEqual(r, { count: 0, measured: true });
  });
});

describe('⛔ null/undefined is NOT MEASURED, and must not touch a single row', () => {
  for (const [label, value] of [['null', null], ['undefined', undefined]]) {
    it(`${label} issues NO statements at all`, async () => {
      const pool = stubPool();
      const r = await storeVpnTunnels('dev-1', value, pool);
      assert.deepEqual(
        pool.statements, [],
        'a not-measured answer reached the database; the last-known tunnel set is at risk',
      );
      assert.equal(deletes(pool).length, 0);
      assert.deepEqual(r, { count: null, measured: false });
    });
  }

  it('⛔ it returns BEFORE the transaction opens, so no BEGIN is left dangling', async () => {
    // Not cosmetic: a DELETE inside an opened transaction that never COMMITs
    // still holds a row lock, and there must be no path on which the delete has
    // run and the reinsert has not.
    const pool = stubPool();
    await storeVpnTunnels('dev-1', null, pool);
    assert.ok(!pool.statements.includes('BEGIN'));
    assert.equal(pool.client.released, false, 'a connection was taken for a no-op');
  });

  it('⛔ `count` is null, never 0 — our gap is not the device having no tunnels', async () => {
    const pool = stubPool();
    const notMeasured = await storeVpnTunnels('dev-1', null, pool);
    const measuredZero = await storeVpnTunnels('dev-1', [], stubPool());
    assert.equal(notMeasured.count, null);
    assert.equal(measuredZero.count, 0);
    assert.notEqual(
      notMeasured.measured, measuredZero.measured,
      'not-measured and measured-zero are reporting the same thing',
    );
  });
});

describe('⛔ a third shape is REFUSED, never coerced', () => {
  // Coercing is exactly what the `: []` fallback did, and a string or an object
  // is a shape nobody intended — guessing which of the other two states it
  // meant is how the wipe got there.
  for (const bad of ['', 'up', 0, 42, true, {}, { tunnels: [] }]) {
    it(`refuses ${JSON.stringify(bad)} without touching the rows`, async () => {
      const pool = stubPool();
      await assert.rejects(
        () => storeVpnTunnels('dev-1', bad, pool),
        (err) => err instanceof TypeError && /array of tunnels or null/.test(err.message),
      );
      assert.deepEqual(pool.statements, [], 'a refused shape still reached the database');
    });
  }
});

describe('⛔ every adapter reports a parse failure as not-measured', () => {
  const fs = require('node:fs');
  const path = require('node:path');

  // ⛔ THE SET IS RE-DERIVED FROM SOURCE, NEVER LISTED HERE. The first version
  // of this test hardcoded four files and MISSED `fortinet/ssh.js` — which is
  // the transport that actually carries tunnels on the live fleet (10 of the
  // 165 measured rows) and which had the defect in BOTH its single-VDOM and its
  // per-VDOM parse path. A hand-maintained list of the files to check is a list
  // that goes stale silently, and the thing it fails to mention is exactly the
  // thing nobody fixes. Same technique as `deviceScopeCoverage`'s register,
  // which re-derives the device-touching set rather than trusting a literal.
  const adapterDir = path.join(__dirname, '..', 'lib', 'adapters');

  function walk(dir) {
    const out = [];
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) out.push(...walk(full));
      else if (entry.name.endsWith('.js')) out.push(full);
    }
    return out;
  }

  /** Every method body in the file that pulls IPSec tunnels. */
  function tunnelMethods(src) {
    const bodies = [];
    const re = /\n {2}async (_?getVpnTunnels[A-Za-z]*)\(/g;
    let m = re.exec(src);
    while (m) {
      const from = m.index;
      const next = src.indexOf('\n  async ', from + 10);
      bodies.push({ name: m[1], body: src.slice(from, next === -1 ? src.length : next) });
      m = re.exec(src);
    }
    return bodies;
  }

  const files = walk(adapterDir)
    .map((f) => ({ file: path.relative(adapterDir, f), src: fs.readFileSync(f, 'utf8') }))
    .map((f) => ({ ...f, methods: tunnelMethods(f.src) }))
    .filter((f) => f.methods.length > 0);

  it('finds every implementation, and there are at least five', () => {
    // A floor, not an equality: a new vendor gaining the capability must not
    // fail the build, but the set silently SHRINKING must.
    const names = files.map((f) => f.file).sort();
    assert.ok(
      names.length >= 5,
      'only ' + names.length + ' adapter file(s) implement getVpnTunnels: ' + names.join(', '),
    );
    // And the two Fortinet transports are named, because they are separate
    // files and the SSH one is the easy one to forget.
    assert.ok(names.includes('fortinet/index.js'), 'fortinet/index.js (API transport) is missing');
    assert.ok(names.includes('fortinet/ssh.js'), 'fortinet/ssh.js (SSH transport) is missing');
  });

  for (const { file, methods } of files) {
    it(`${file}: no parse path degrades to an empty array`, () => {
      for (const { name, body } of methods) {
        // ⛔ The banned shape, in every spelling found in this family: a catch
        // that resolves to [] in front of a DELETE+reinsert reads as a measured
        // zero and deletes the device's real tunnels.
        assert.ok(
          !/catch \([^)]*\) \{\s*(?:tunnels = \[\];|return \[\];)/.test(body),
          `${file}:${name} still degrades a parse failure to [], which storeVpnTunnels reads `
          + "as a measured zero and deletes the device's tunnels",
        );
      }
    });

    it(`${file}: a parse failure is reported, not silent`, () => {
      // Every implementation must either return null itself or throw into a
      // caller that does — and must say which device and why.
      const joined = methods.map((m) => m.body).join('\n');
      assert.ok(
        /return null;/.test(joined) || /throw new Error/.test(joined),
        `${file}: a parse failure neither reports NOT MEASURED nor throws`,
      );
      assert.ok(
        /console\.warn/.test(joined) || /throw new Error/.test(joined),
        `${file}: the not-measured path produces no log line`,
      );
    });
  }

  it('⛔ BOTH Fortinet transports refuse a PARTIAL VDOM result', () => {
    // CLAUDE.md states this rule for getRules() — "collect every VDOM or fail
    // (a partial VDOM failure must throw, not return the rest)" — and both of
    // these are the same loop in front of the same destructive writer.
    // `fortinet/ssh.js` even advertised "graceful-per-VDOM degradation" in its
    // own comment, which is right for a read and wrong before a DELETE.
    for (const rel of ['fortinet/index.js', 'fortinet/ssh.js']) {
      const entry = files.find((f) => f.file === rel);
      assert.ok(entry, `${rel} no longer implements getVpnTunnels`);
      const joined = entry.methods.map((m) => m.body).join('\n');
      assert.ok(/failedVdoms\.push\(vdom\)/.test(joined), `${rel}: failed VDOMs are not tracked`);
      assert.ok(
        /if \(failedVdoms\.length > 0\)[\s\S]{0,900}?return null;/.test(joined),
        `${rel}: a partial VDOM result is still returned as a complete tunnel set`,
      );
      // And the every-VDOM-failed case still THROWS — that is a transport
      // failure, not an unreadable answer. Both keep the rows; they differ in
      // what the engine log says happened.
      assert.ok(
        /if \(!anySucceeded\) \{[\s\S]{0,400}?throw new Error/.test(joined),
        `${rel}: the every-VDOM-failed branch no longer throws`,
      );
    }
  });
});

describe('⛔ the engine-worker makes the skip visible', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const worker = fs.readFileSync(
    path.join(__dirname, '..', 'services', 'engine-worker.js'), 'utf8',
  );

  it('reads the measured flag back and logs the device', () => {
    // A correct skip that nothing reports is a tunnel snapshot that stops
    // advancing while every signal stays green — the failure shape this
    // codebase names most often.
    assert.match(worker, /const tunResult = await storeVpnTunnels\(/);
    assert.match(worker, /tunResult\.measured === false/);
    assert.match(worker, /NOT MEASURED/);
  });

  it('counts them into the job summary line', () => {
    assert.match(worker, /let vpnTunnelsNotMeasured = 0;/);
    assert.match(worker, /vpnTunnelsNotMeasured \+= 1;/);
    assert.match(worker, /\$\{vpnTunnelsNotMeasured\} device\(s\) NOT MEASURED/);
  });
});
