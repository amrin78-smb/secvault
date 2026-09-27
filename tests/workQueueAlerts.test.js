'use strict';
// tests/workQueueAlerts.test.js
//
// ⛔ THE WORK QUEUE, DISPATCHED OUTBOUND. Twelve source types already carrying
// severity, urgency and an evidence grade, and until now not one of them could
// reach a channel.
//
// ⛔ THE PROPERTY THIS FILE EXISTS FOR: an INCOMPLETE queue must change nothing.
// gatherWorkQueue isolates each source — a throwing one contributes zero items
// and reports {ok:false} — and the dispatch loop clears any natural_key absent
// from the fetcher's list. Hand it a short list and it marks real, still-open
// security work as RESOLVED, then re-notifies when the source recovers. So the
// fetcher THROWS instead, which makes the loop `continue` before the reconcile.
// Silence for one cycle is recoverable. A false all-clear is not.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

const DISPATCH_PATH = require.resolve('../lib/engines/notificationDispatch');
const DATA_PATH = require.resolve('../lib/engines/workQueueData');

// Swap gatherWorkQueue for a stub, then load the dispatcher fresh so it picks
// it up. Restores the loader afterwards — a leaked override would silently
// change every later test in the process.
function withGather(stub, fn) {
  const realLoad = Module._load;
  delete require.cache[DISPATCH_PATH];
  Module._load = function (request, parent, isMain) {
    const resolved = (() => {
      try { return Module._resolveFilename(request, parent, isMain); } catch { return null; }
    })();
    if (resolved === DATA_PATH) {
      return { ...realLoad.call(this, request, parent, isMain), gatherWorkQueue: stub };
    }
    return realLoad.call(this, request, parent, isMain);
  };
  try {
    return fn(require('../lib/engines/notificationDispatch'));
  } finally {
    Module._load = realLoad;
    delete require.cache[DISPATCH_PATH];
  }
}

const item = (over = {}) => ({
  type: 'cve',
  key: 'cve:CVE-2026-24858',
  title: 'Patch CVE-2026-24858 on 3 firewalls',
  severity: 'critical',
  urgency: 'now',
  evidence: 'reported',
  why: 'Listed in CISA KEV.',
  affects: '3 firewalls',
  action: 'Upgrade to 11.1.4-h1.',
  href: '/vulnerability/cve/CVE-2026-24858',
  deviceIds: ['d1', 'd2', 'd3'],
  ...over,
});

const ok = (items, sources) => async () => ({
  items,
  sources: sources || [{ key: 'cve', ok: true, count: items.length }],
});

describe('⛔ an incomplete queue must never clear an alert', () => {
  it('a FAILED source makes the fetcher throw, so the loop skips the reconcile', async () => {
    await withGather(
      ok([item()], [
        { key: 'cve', ok: true, count: 1 },
        { key: 'compliance', ok: false, error: 'relation does not exist' },
      ]),
      async (mod) => {
        await assert.rejects(
          () => mod.OPEN_ITEM_FETCHERS.work_act_now({}),
          /work queue incomplete/,
          'a short list would be read as "these are resolved"'
        );
      }
    );
  });

  it('the refusal names the source and its error, or it cannot be acted on', async () => {
    await withGather(
      ok([], [{ key: 'licence', ok: false, error: 'boom' }]),
      async (mod) => {
        const err = await mod.OPEN_ITEM_FETCHERS.work_act_now({}).catch((e) => e);
        assert.match(err.message, /licence/);
        assert.match(err.message, /boom/);
        assert.match(err.message, /Refusing to reconcile/);
      }
    );
  });

  it('⛔ a TRUNCATED source is just as dangerous, and also throws', async () => {
    // PER_SOURCE_CAP is 50 and has bitten live (compliance returned 50 of 74).
    // The 24 past the cap would be reconciled away as resolved.
    await withGather(
      ok([item()], [{ key: 'compliance', ok: true, count: 50, truncatedFrom: 74 }]),
      async (mod) => {
        await assert.rejects(
          () => mod.OPEN_ITEM_FETCHERS.work_act_now({}),
          /truncated/
        );
      }
    );
  });

  it('a healthy gather returns items rather than throwing', async () => {
    await withGather(ok([item()]), async (mod) => {
      const out = await mod.OPEN_ITEM_FETCHERS.work_act_now({});
      assert.equal(out.length, 1);
    });
  });
});

describe('⛔ only the act_now band is dispatched', () => {
  it('unmeasured never reaches it, however urgent the source claimed to be', async () => {
    // bandFor()'s load-bearing line: a source cannot promote a guess into
    // act_now by declaring urgency: 'now'.
    await withGather(
      ok([item({ evidence: 'unmeasured', urgency: 'now', key: 'licence:x' })]),
      async (mod) => {
        const out = await mod.OPEN_ITEM_FETCHERS.work_act_now({});
        assert.deepEqual(out, [], 'that item belongs in verify, not in an alert');
      }
    );
  });

  it('scheduled work is not mailed out', async () => {
    await withGather(
      ok([item({ urgency: 'soon', evidence: 'measured', key: 'cve:later' })]),
      async (mod) => {
        assert.deepEqual(await mod.OPEN_ITEM_FETCHERS.work_act_now({}), []);
      }
    );
  });

  it('measured + now is dispatched', async () => {
    await withGather(ok([item({ evidence: 'measured' })]), async (mod) => {
      const out = await mod.OPEN_ITEM_FETCHERS.work_act_now({});
      assert.equal(out.length, 1);
    });
  });
});

describe('the dispatcher shape', () => {
  it('⛔ a multi-device item names NO device rather than the first one', async () => {
    // Naming deviceIds[0] would be a fabricated attribution — the same rule
    // fetchOpenIngestDrop follows for a full buffer with no culprit firewall.
    await withGather(ok([item({ evidence: 'measured' })]), async (mod) => {
      const [out] = await mod.OPEN_ITEM_FETCHERS.work_act_now({});
      assert.equal(out.deviceId, null);
      assert.match(out.summary, /3 firewalls/, 'who is affected is still stated, in words');
    });
  });

  it('a single-device item does carry its device', async () => {
    await withGather(
      ok([item({ evidence: 'measured', deviceIds: ['only-one'] })]),
      async (mod) => {
        const [out] = await mod.OPEN_ITEM_FETCHERS.work_act_now({});
        assert.equal(out.deviceId, 'only-one');
      }
    );
  });

  it('the natural key is stable and namespaced, so one CVE is one alert', async () => {
    await withGather(ok([item({ evidence: 'measured' })]), async (mod) => {
      const [out] = await mod.OPEN_ITEM_FETCHERS.work_act_now({});
      assert.equal(out.naturalKey, 'work:cve:CVE-2026-24858');
    });
  });

  it('carries why, who and what to do — an alert with no action is noise', async () => {
    await withGather(ok([item({ evidence: 'measured' })]), async (mod) => {
      const [out] = await mod.OPEN_ITEM_FETCHERS.work_act_now({});
      assert.match(out.summary, /CISA KEV/);
      assert.match(out.summary, /Upgrade to/);
      assert.equal(out.path, '/vulnerability/cve/CVE-2026-24858');
    });
  });

  it('falls back to /work when an item has no href', async () => {
    await withGather(
      ok([item({ evidence: 'measured', href: undefined })]),
      async (mod) => {
        const [out] = await mod.OPEN_ITEM_FETCHERS.work_act_now({});
        assert.equal(out.path, '/work');
      }
    );
  });
});

// ────────────────────────────────────────────────────────────────────────────
// ⛔ THE COVERAGE SOURCE COULD PERMANENTLY SILENCE THIS ALERT TYPE
// ────────────────────────────────────────────────────────────────────────────
//
// It emits one item per non-fully-covered firewall, and the register's premise is
// that essentially every firewall has a gap (live: 16 of 16). Past PER_SOURCE_CAP
// (50) it sets `truncatedFrom`, and the guard above then throws on EVERY poll —
// so a fleet above ~50 firewalls would have silenced ALL `work_act_now` alerting,
// structurally, with no recovery, because of a source whose every item is
// `unmeasured` and therefore could never have produced an alert. It also paid the
// register's 2+N queries and a 720-hour aggregate every 15 minutes for items
// guaranteed to be discarded.

describe('⛔ a source that can never reach act_now is omitted, not merely discarded', () => {
  const { NEVER_ACT_NOW_SOURCES } = require('../lib/engines/workQueueData');

  it('the fetcher omits exactly the never-act_now sources', async () => {
    let seen = null;
    const stub = async (pool, opts) => {
      seen = opts;
      return { items: [item({ evidence: 'measured' })], sources: [{ key: 'cve', ok: true, count: 1 }] };
    };
    await withGather(stub, async (mod) => {
      await mod.OPEN_ITEM_FETCHERS.work_act_now({});
    });
    assert.ok(seen, 'the fetcher passed no opts at all');
    assert.deepEqual(seen.omitSources, NEVER_ACT_NOW_SOURCES);
  });

  it('⛔ it omits NOTHING that could produce an act_now item', async () => {
    // The reconcile step clears any natural_key absent from this list, so
    // omitting a source that CAN reach act_now would clear real, still-open work
    // as resolved — the exact failure the two guards above refuse to allow.
    let seen = null;
    const stub = async (pool, opts) => {
      seen = opts;
      return { items: [], sources: [] };
    };
    await withGather(stub, async (mod) => {
      await mod.OPEN_ITEM_FETCHERS.work_act_now({});
    });
    for (const key of seen.omitSources) {
      assert.ok(NEVER_ACT_NOW_SOURCES.includes(key),
        `${key} is omitted but is not declared incapable of act_now`);
    }
  });

  it('an OMITTED source is not read as a failure or as a truncation', async () => {
    // It reports {ok: true, omitted: true, count: 0} — stated, never silent —
    // and neither guard may fire on it.
    await withGather(
      ok([item({ evidence: 'measured' })], [
        { key: 'cve', ok: true, count: 1 },
        { key: 'coverage', ok: true, omitted: true, count: 0 },
      ]),
      async (mod) => {
        const out = await mod.OPEN_ITEM_FETCHERS.work_act_now({});
        assert.equal(out.length, 1, 'an omitted source must not throw the whole fetch away');
      }
    );
  });
});
