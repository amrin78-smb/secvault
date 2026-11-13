'use strict';
// Pins the fixes from the 2026-11-13 fan-out sweep that are not covered by an
// existing suite. Each block states the measurement that justified the change,
// because the roadmap row is the only other place it is recorded.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { hoursOf, minutesOf, planHourlyCron } = require('../lib/cronPlan');
const worker = fs.readFileSync(path.join(__dirname, '..', 'services', 'engine-worker.js'), 'utf8');
const dispatch = fs.readFileSync(
  path.join(__dirname, '..', 'lib', 'engines', 'notificationDispatch.js'), 'utf8',
);

describe('⛔ hoursOf understands every hour field the engine actually emits', () => {
  // `planHourlyCron` emits `0 */n * * *`, and hoursOf returned [] for it — so
  // the schedule-collision guard produced ZERO slots for feed-sync (`*/6`) and
  // rule-version-pull (`*/24`) and compared them against nothing. The guard's
  // own header claims it sees "EVERY schedule the engine registers".
  it('expands */n, which it used to drop on the floor', () => {
    assert.deepEqual(hoursOf('*/6'), [0, 6, 12, 18]);
    assert.deepEqual(hoursOf('*/24'), [0]);
    assert.deepEqual(hoursOf('*/8'), [0, 8, 16]);
  });

  it('⛔ every expression planHourlyCron can emit yields at least one hour', () => {
    // The real invariant: a planner output the parser cannot read is a hole in
    // the collision guard, whatever the step value happens to be today.
    for (let n = 1; n <= 24; n++) {
      const { expr } = planHourlyCron(n);
      const hours = hoursOf(expr.split(' ')[1]);
      assert.ok(
        hours.length > 0,
        `hoursOf returned nothing for planHourlyCron(${n}).expr = "${expr}" — the collision `
        + 'guard is blind to it',
      );
    }
  });

  it('still handles the forms it already did, and ignores junk', () => {
    assert.deepEqual(hoursOf('*'), Array.from({ length: 24 }, (_, i) => i));
    assert.deepEqual(hoursOf('2-5'), [2, 3, 4, 5]);
    assert.deepEqual(hoursOf('1,3,5'), [1, 3, 5]);
    assert.deepEqual(hoursOf('6'), [6]);
    assert.deepEqual(hoursOf('*/0'), [], 'a zero step must not divide by zero or loop for ever');
    assert.deepEqual(hoursOf('nonsense'), []);
  });

  it('minutesOf was never the blind axis, and still is not', () => {
    assert.deepEqual(minutesOf('*/15'), [0, 15, 30, 45]);
  });
});

describe('⛔ a missed single-tick cron is recovered, which CLAUDE.md said was impossible', () => {
  // node-cron 3.0.3 computes missedExecutions and replays the skipped seconds,
  // gated on `(i === 0 || this.autorecover)` — and `autorecover` comes from an
  // option that defaults to false and appeared NOWHERE in this repo. That is
  // the root cause of 4 permanently lost fleet-snapshot days.
  it('the option exists in the pinned node-cron version', () => {
    const scheduler = fs.readFileSync(
      path.join(__dirname, '..', 'node_modules', 'node-cron', 'src', 'scheduler.js'), 'utf8',
    );
    assert.match(scheduler, /autorecover/, 'node-cron no longer supports recovery; re-derive this fix');
    assert.match(scheduler, /i === 0 \|\| this\.autorecover/);
  });

  it('⛔ is enabled on the four fixed single-tick jobs that can lose a whole period', () => {
    // Scoped deliberately: recovery re-fires as soon as the loop frees up, so
    // it is only safe where a double run is harmless.
    for (const expr of ['10 1 * * *', '30 0 * * *', '45 0 * * *', '0 6 1 * *']) {
      const re = new RegExp(
        `cron\\.schedule\\('${expr.replace(/\*/g, '\\*')}'[\\s\\S]{0,400}?\\}, RECOVER_MISSED\\)`,
      );
      assert.match(worker, re, `the job on "${expr}" does not recover a missed tick`);
    }
    assert.match(worker, /const RECOVER_MISSED = \{ recoverMissedExecutions: true \}/);
  });

  it('⛔ is NOT enabled on notification-dispatch, which would duplicate alerts', () => {
    // The minute-scale schedules are computed, so assert on the variable: a
    // recovered tick on the one job with unbounded outbound calls and (until
    // today) no overlap guard is the one case recovery must not touch.
    const m = /const notificationsTask = cron\.schedule\(([\s\S]{0,400}?)\n/.exec(worker);
    assert.ok(m, 'the notifications task moved');
    const call = worker.slice(m.index, worker.indexOf('});', m.index) + 3);
    assert.ok(
      !call.includes('RECOVER_MISSED'),
      'recovery was enabled on [notification-dispatch]; a recovered tick can mail a duplicate alert',
    );
  });
});

describe('⛔ [notification-dispatch] cannot overlap itself', () => {
  // Its dedup decision is a check-then-act straddling the outbound sends: read
  // notification_dispatch_log, continue if notified, THEN send, THEN upsert.
  // Two passes both read zero and both send, and ON CONFLICT DO UPDATE hides it.
  it('has an in-flight flag that is checked and set', () => {
    assert.match(worker, /let notificationDispatchInFlight = false;/);
    assert.match(worker, /if \(notificationDispatchInFlight\) \{/);
    assert.match(worker, /notificationDispatchInFlight = true;/);
  });

  it('⛔ clears the flag in a `finally`, never only on success', () => {
    // On the success path alone, one throw would disable outbound alerting for
    // the life of the service — a permanent silent loss, far worse than the
    // duplicate the guard prevents. The catch swallows the error, so without
    // `finally` it would not clear on a caught failure either.
    const body = worker.slice(
      worker.indexOf('async function runNotificationDispatchJob'),
      worker.indexOf('\n}', worker.indexOf('async function runNotificationDispatchJob')),
    );
    assert.match(body, /\} finally \{[\s\S]*?notificationDispatchInFlight = false;/);
  });

  it('a skipped tick is logged, not silent', () => {
    assert.match(worker, /\[notification-dispatch\] SKIPPED/);
  });
});

describe('⛔ an ingest-drop list is never truncated into a false all-clear', () => {
  // openKeys is built from this fetcher and the reconcile clears every logged
  // row whose natural_key is ABSENT — so a list cut at the cap reads the oldest
  // drop windows as RESOLVED. fetchOpenWorkQueue already throws for this exact
  // reason, and CLAUDE.md documents the hazard under work_act_now.
  it('selects one past the cap so truncation is detectable', () => {
    assert.match(dispatch, /LIMIT \$\{INGEST_DROP_CAP \+ 1\}/);
  });

  it('⛔ THROWS past the cap rather than returning a shorter list', () => {
    assert.match(dispatch, /if \(rows\.length > INGEST_DROP_CAP\) \{[\s\S]{0,400}?throw new Error/);
  });

  it('the bare LIMIT 50 is gone', () => {
    assert.ok(
      !/ORDER BY recorded_at DESC\s*\n\s*LIMIT 50`/.test(dispatch),
      'the un-guarded LIMIT 50 is back',
    );
  });
});

describe('⛔ an unset interval setting is not reported as an invalid one', () => {
  // '' is neither null nor undefined, so a blank settings row entered the
  // validation branch and logged a warning on EVERY engine start. The
  // reference deployment holds exactly that today.
  it('treats a blank or whitespace value as unconfigured', () => {
    assert.match(worker, /String\(raw\)\.trim\(\) !== ''/);
    assert.match(worker, /const configured = raw !== null && raw !== undefined/);
  });

  it('⛔ still warns about a genuinely invalid value', () => {
    // The warning must survive for a real typo — removing it to silence the
    // blank case would trade one wrong signal for no signal.
    assert.match(worker, /is not a valid integer between 1 and 24/);
  });
});

describe('⛔ an unresolved NAT translation reaches the hop, instead of being dropped', () => {
  // applyNat() sets natUnresolved when a rule MATCHED but carries no literal
  // translation target (the FortiOS SD-WAN `virtual-wan-link` case). The
  // orchestrator copied only natApplied/natRuleName, so the UI claimed "NAT
  // applied" while the walk continued with the UNTRANSLATED address and judged
  // every later hop against it. Both topology.js's header and .ai-codex/lib.md
  // already claimed the flag was propagated.
  const { simulateMultiHopPath } = require('../lib/engines/topology');

  // One device, one interface, an any/any source-NAT rule with no translated
  // source — the exact shape measured on TSR-TL, whose lowest-sequence enabled
  // NAT row matches every query.
  const devices = [{ id: 'd1', name: 'TSR-TL', vendor: 'fortinet', active: true }];
  const interfacesByDevice = new Map([['d1', [
    { name: 'port1', ip_address: '192.168.3.1/24', enabled: true },
  ]]]);
  const natRulesByDevice = new Map([['d1', [
    {
      name: 'policy2',
      sequence_number: 2,
      nat_type: 'source',
      enabled: true,
      original_src_addresses: ['all'],
      original_dst_addresses: ['all'],
      translated_src_addresses: [],
      translated_dst_addresses: [],
    },
  ]]]);
  const rulesByDevice = new Map([['d1', [
    {
      rule_id_vendor: '1', sequence_number: 1, action: 'allow', enabled: true,
      src_addresses: ['any'], dst_addresses: ['any'], services: ['any'],
      src_zones: [], dst_zones: [], log_enabled: true, name: 'permit-all',
    },
  ]]]);

  // ⛔ TWO ARGUMENTS: (fleetData, query). Passing one merged object threw
  // "srcIp must be a single valid IPv4 address" — the guard rejecting an
  // absent query rather than a bad address.
  const QUERY = { srcIp: '192.168.3.50', dstIp: '8.8.8.8', port: 443, protocol: 'tcp' };
  const fleet = (nat) => ({
    devices,
    interfacesByDevice,
    routesByDevice: new Map(),
    natRulesByDevice: nat,
    rulesByDevice,
    objectsByDevice: new Map(),
  });

  function run() {
    return simulateMultiHopPath(fleet(natRulesByDevice), QUERY);
  }

  it('the engine still produces the flag', () => {
    const res = run();
    assert.ok(res && Array.isArray(res.hops) && res.hops.length > 0, 'no hop was produced');
  });

  it('⛔ the hop carries natUnresolved, not just natApplied', () => {
    const hop = run().hops.find((h) => h.natApplied);
    assert.ok(hop, 'the any/any NAT rule did not match — the fixture no longer reproduces it');
    assert.equal(
      hop.natUnresolved, true,
      'the hop claims NAT was applied and does not say the translation could not be resolved',
    );
  });

  it('⛔ and sets hasCaveat, which is what makes the existing UI honest', () => {
    // PathQueryTab already renders a caveat for hasCaveat. Carrying only a new
    // field would have left the page exactly as confident as before the fix.
    const hop = run().hops.find((h) => h.natApplied);
    assert.equal(hop.hasCaveat, true, 'nothing on screen would qualify the "NAT applied" badge');
  });

  it('a resolvable NAT rule is NOT marked unresolved', () => {
    // The guard must not fire on every NAT hop, or the caveat means nothing.
    const resolvable = new Map([['d1', [{
      name: 'policy3',
      sequence_number: 3,
      nat_type: 'source',
      enabled: true,
      original_src_addresses: ['all'],
      original_dst_addresses: ['all'],
      translated_src_addresses: ['203.0.113.7'],
      translated_dst_addresses: [],
    }]]]);
    const res = simulateMultiHopPath(fleet(resolvable), QUERY);
    const hop = res.hops.find((h) => h.natApplied);
    assert.ok(hop, 'the resolvable NAT rule did not match');
    assert.notEqual(hop.natUnresolved, true, 'a resolvable translation was flagged unresolved');
  });
});

describe('⛔ a directory account is TOLD it cannot change its password here', () => {
  // An Entra/LDAP session has no `users` row, so its password lives in the
  // directory. The MFA panel says exactly that, on the same screen — and the
  // password card beside it rendered a full, enabled form, so an operator
  // could type both fields and press Update before learning the control was
  // never theirs. Reported from a live Entra session.
  const { ownerOf, ownerRefusal, OWNER_STATES } = require('../lib/sessionOwner');

  const WORDS = {
    feature: 'Password changes',
    subject: 'password',
    belongs: 'where its password is managed',
  };
  const entra = { user: { id: '00000000-0000-4000-8000-000000000000', provider: 'entra', name: 'A' } };
  const ldap = { user: { id: 'amrin', provider: 'ldap', name: 'amrin' } };
  const local = { user: { id: '11111111-2222-4333-8444-555555555555', provider: 'local', name: 'admin' } };

  it('an Entra session is not an owner, so the password route must refuse it', () => {
    assert.notEqual(ownerOf(entra).state, OWNER_STATES.OWNER);
    assert.notEqual(ownerOf(ldap).state, OWNER_STATES.OWNER);
    assert.equal(ownerOf(local).state, OWNER_STATES.OWNER);
  });

  it('⛔ the refusal NAMES the provider and says where the password lives', () => {
    // "Password changes are only available for local accounts" named neither,
    // so it told the operator nothing about what to do next. The MFA sentence
    // already named both; these are now built by one shared function so they
    // cannot drift apart again.
    const msg = ownerRefusal(ownerOf(entra), WORDS);
    assert.match(msg, /Microsoft Entra ID/);
    assert.match(msg, /where its password is managed/);
    assert.match(msg, /only available for local accounts/);
  });

  it('LDAP gets its own label, not a generic one', () => {
    assert.match(ownerRefusal(ownerOf(ldap), WORDS), /through LDAP/);
  });

  it('⛔ an UNIDENTIFIABLE session is a fault, not a provider statement', () => {
    // "We do not know who this is" must never be reported as "your password
    // is managed in a directory" — they send the operator to different places.
    const msg = ownerRefusal(ownerOf({ user: {} }), WORDS);
    assert.match(msg, /could not be identified/);
    assert.match(msg, /This is a fault, not a permission/);
    assert.ok(!/local accounts/.test(msg), 'an unknown session was given the directory sentence');
  });

  describe('the API is the boundary', () => {
    const route = fs.readFileSync(
      path.join(__dirname, '..', 'app', 'api', 'settings', 'route.js'), 'utf8',
    );

    it('⛔ refuses on the PROVIDER, before any username lookup', () => {
      const guard = route.indexOf('if (owner.state !== OWNER_STATES.OWNER)');
      const lookup = route.indexOf('FROM users WHERE id = $1');
      assert.ok(guard > 0, 'the provider guard is gone');
      assert.ok(lookup > 0, 'the user lookup moved');
      assert.ok(guard < lookup, 'the lookup runs before the provider is checked');
    });

    it('⛔ looks the user up by ID, never by display name', () => {
      // By name, an Entra user whose session name collided with an unrelated
      // LOCAL username found THAT row and was bcrypt-compared against THEIR
      // hash, so the refusal read "Current password is incorrect" — a wrong
      // and alarming answer to a question that should not have been asked.
      assert.ok(
        !/FROM users WHERE username = \$1/.test(route),
        'the own-password branch still looks the account up by display name',
      );
    });

    it('⛔ a missing LOCAL row is a fault, not the directory sentence', () => {
      assert.match(route, /account for this session no longer exists/);
    });

    it('uses the same ownerOf() the MFA route uses', () => {
      const mfa = fs.readFileSync(
        path.join(__dirname, '..', 'app', 'api', 'mfa', 'route.js'), 'utf8',
      );
      for (const src of [route, mfa]) assert.match(src, /from '[^']*lib\/sessionOwner'/);
    });
  });

  describe('the UI matches the API, and is never stricter', () => {
    const page = fs.readFileSync(
      path.join(__dirname, '..', 'app', '(dashboard)', 'settings', 'page.js'), 'utf8',
    );

    it('renders the refusal instead of the form for an unsupported account', () => {
      assert.match(page, /passwordSupport && passwordSupport\.supported === false/);
      assert.match(page, /\{passwordSupport\.error\}/);
    });

    it('⛔ renders the form ONLY on an explicit yes', () => {
      // Not `!== false`: an unknown answer would then render a form that may
      // not work, which is the defect, and a failed read would leave it
      // rendered for good.
      assert.match(page, /passwordSupport && passwordSupport\.supported === true/);
      assert.match(page, /useState\(null\)/);
    });

    it('⛔ claims NOTHING while the answer is unknown', () => {
      // Neither control nor sentence: the form would be unverified and the
      // sentence would be a claim nobody measured.
      assert.match(page, /passwordSupport === null &&/);
      assert.match(page, /Checking how this account signs in/);
    });

    it('the supporting route exists and is open to any signed-in user', () => {
      const sweep = fs.readFileSync(path.join(__dirname, '..', 'scripts', 'apiSweep.js'), 'utf8');
      assert.match(sweep, /path: '\/api\/settings\/password', methods: \['GET'\], capability: null/);
      assert.ok(fs.existsSync(
        path.join(__dirname, '..', 'app', 'api', 'settings', 'password', 'route.js'),
      ));
    });
  });
});
