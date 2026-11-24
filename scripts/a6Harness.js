#!/usr/bin/env node
'use strict';

// scripts/a6Harness.js — A6's control harness.
//
// ⛔ WHY THIS EXISTS AT ALL. `analytics-proposal.md` records that the original
// "median + MAD, never mean + sigma" constraint WAS FALSIFIED on this data by
// A7: Iglewicz-Hoaglin's modified Z-score at its own standard 3.5 flagged
// 17.3% of ordinary change-free days (worst device 42.1%), because firewall
// traffic is heavy-tailed and a ROBUST estimator is not a DISTRIBUTION-FREE
// one. The decision taken was to "run A7's control harness against A6's grain
// and pick on the MEASURED false-positive rate, rather than inherit a
// constraint already falsified once on this data". This is that harness.
//
// ⛔ IT MEASURES TWO THINGS, AND ONE ALONE IS WORTHLESS. A detector that never
// fires has a perfect false-positive rate. So every configuration is scored on
// BOTH:
//   - FALSE POSITIVES, over change-free control data;
//   - SENSITIVITY, over the SAME data with anomalies PLANTED at known times.
// A configuration is only reportable if it finds planted events it was told
// nothing about. "Quiet" is not "correct".
//
// ⛔ THE ALERT-GRAIN ARITHMETIC IS THE WHOLE PROBLEM. A per-bucket false
// positive rate is not an alert rate: 16 devices x 168 hours = 2,688
// device-hours per week, so 5% per bucket is ~142 false alerts a week. That is
// how `new_finding` got pulled out of the Alerts feed in July on direct user
// feedback. The harness therefore reports alerts/day, not just a percentage,
// and sweeps PERSISTENCE (N consecutive anomalous hours) because isolated
// outliers are the shape almost every false positive takes while a real event
// — a scan, an outage, a spraying run — persists.
//
// Usage:
//   node scripts/a6Harness.js --synthetic                  # validate the harness itself
//   DATABASE_URL=... node scripts/a6Harness.js --metric denied --days 28
//
// ⛔ Against a real database it is READ-ONLY and touches ROLLUPS ONLY. It must
// never query `syslog_events`: no src_ip index, ~28M rows/day, and the write
// cost of one lands on the collector. The same refusal VPN traffic attribution
// makes.

const sb = require('../lib/engines/seasonalBaseline');
// 26d4 The REAL detector, so the registrable rate measures what ships.
const { detectSpike, detectVolumeCollapse } = require('../lib/engines/anomalyDetections');

const GRAINS = [sb.GRAINS.HOUR_OF_WEEK, sb.GRAINS.HOUR_OF_DAY_SPLIT, sb.GRAINS.HOUR_OF_DAY];
const QUANTILES = [0.90, 0.95, 0.975, 0.99];
const PERSISTENCE = [1, 2, 3];

// ---------------------------------------------------------------------------
// Real rollups
// ---------------------------------------------------------------------------
//
// ⛔ AGAINST REAL DATA THIS MEASURES AN **ALERT RATE**, NOT A FALSE-POSITIVE
// RATE, AND THE DIFFERENCE IS NOT PEDANTIC. A7 could measure false positives
// because it had LABELS — days with no config change are known-change-free. A6
// has no such label: an hour that looks anomalous may contain a real scan. So
// the rate reported here is an UPPER BOUND on false positives, and the number
// that matters operationally anyway: how many alerts a day would this have
// sent. Calling it a false-positive rate would claim a ground truth we do not
// have.
//
// Sensitivity is still measured honestly, by planting anomalies into the REAL
// series — a known event we can check the detector finds.
//
// ⛔ ROLLUPS ONLY. `syslog_events` is refused: no src_ip index, ~28M rows/day,
// and the write cost of adding one lands on the collector. The same refusal VPN
// traffic attribution makes, for the same reasons.

const METRICS = {
  // Denied traffic per device-hour — the roadmap's first candidate detector.
  denied: {
    table: 'syslog_rollup_hourly',
    sql: `
      WITH reporting AS (
        -- \u26d4 Hours in which the device reported ANYTHING. Within these, a
        -- denied count of zero is a GENUINE ZERO. Outside them the device said
        -- nothing at all, and that is MISSING, not zero -- counting it as zero
        -- would drag every threshold down and suppress real spikes.
        SELECT device_id, bucket_hour FROM syslog_rollup_hourly
         WHERE device_id IS NOT NULL AND bucket_hour >= now() - ($1 || ' days')::interval
         GROUP BY 1, 2
      )
      SELECT r.device_id::text AS device, r.bucket_hour AS at,
             COALESCE(SUM(s.event_count) FILTER (WHERE s.action = ANY($2::text[])), 0)::bigint AS value
        FROM reporting r
        LEFT JOIN syslog_rollup_hourly s
          ON s.device_id = r.device_id AND s.bucket_hour = r.bucket_hour
       GROUP BY 1, 2 ORDER BY 1, 2`,
    params: (days, denied) => [String(days), denied],
  },
  // VPN authentication FAILURES per device-hour. The detector that would have
  // caught the credential spraying found on 2026-09-08.
  // \u26d4 Only hours the device actually REPORTED vpn auth are included; an hour
  // with no row is a device that logged no VPN auth at all, which is missing,
  // not zero failures.
  vpn_auth_fail: {
    table: 'syslog_vpn_auth_hourly',
    sql: `
      WITH reporting AS (
        SELECT device_id, bucket_hour FROM syslog_vpn_auth_hourly
         WHERE device_id IS NOT NULL AND bucket_hour >= now() - ($1 || ' days')::interval
         GROUP BY 1, 2
      )
      SELECT r.device_id::text AS device, r.bucket_hour AS at,
             COALESCE(SUM(v.event_count) FILTER (WHERE v.auth_outcome = 'failure'), 0)::bigint AS value
        FROM reporting r
        LEFT JOIN syslog_vpn_auth_hourly v
          ON v.device_id = r.device_id AND v.bucket_hour = r.bucket_hour
       GROUP BY 1, 2 ORDER BY 1, 2`,
    params: (days) => [String(days)],
  },
  // Total events per device-hour. The inverse detector -- "this device stopped
  // logging" -- is the proposal's highest-value one and reads the same series.
  events: {
    table: 'syslog_rollup_hourly',
    sql: `
      SELECT device_id::text AS device, bucket_hour AS at, SUM(event_count)::bigint AS value
        FROM syslog_rollup_hourly
       WHERE device_id IS NOT NULL AND bucket_hour >= now() - ($1 || ' days')::interval
       GROUP BY 1, 2 ORDER BY 1, 2`,
    params: (days) => [String(days)],
  },
};

async function loadSeries(metric, days) {
  const { pool } = require('../lib/db');
  const spec = METRICS[metric];
  if (!spec) throw new Error(`unknown --metric ${JSON.stringify(metric)} (have: ${Object.keys(METRICS).join(', ')})`);
  const { DENIED_ACTIONS } = require('../lib/syslog/actions');
  const params = metric === 'denied'
    ? spec.params(days, [...DENIED_ACTIONS])
    : spec.params(days);
  const { rows } = await pool.query(spec.sql, params);
  const byDevice = new Map();
  for (const r of rows) {
    if (!byDevice.has(r.device)) byDevice.set(r.device, []);
    byDevice.get(r.device).push({ at: r.at, value: Number(r.value) });
  }
  await pool.end();
  return byDevice;
}

function parseArgs(argv) {
  const o = { synthetic: false, days: 28, metric: 'events', devices: 16, seed: 42, train: 0.7,
    plants: 6, magnitude: 6, detector: 'spike' };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--synthetic') { o.synthetic = true; continue; }
    const v = argv[i + 1];
    if (a === '--days') { o.days = Number(v); i += 1; }
    else if (a === '--metric') { o.metric = v; i += 1; }
    else if (a === '--devices') { o.devices = Number(v); i += 1; }
    else if (a === '--train') { o.train = Number(v); i += 1; }
    else if (a === '--plants') { o.plants = Number(v); i += 1; }
    else if (a === '--magnitude') { o.magnitude = Number(v); i += 1; }
    else if (a === '--detector') { o.detector = v; i += 1; }
  }
  if (!Number.isFinite(o.days) || o.days <= 0) throw new Error(`--days must be positive (got ${JSON.stringify(o.days)})`);
  if (!['spike', 'collapse'].includes(o.detector)) {
    throw new Error(`--detector must be spike or collapse (got ${JSON.stringify(o.detector)})`);
  }
  if (!(o.train > 0.5 && o.train < 1)) throw new Error(`--train must be between 0.5 and 1 (got ${JSON.stringify(o.train)})`);
  return o;
}

/** Deterministic PRNG, so a harness run is reproducible and comparable. */
function rng(seed) {
  let s = seed >>> 0;
  return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 4294967296; };
}

/**
 * Change-free synthetic traffic with a real daily rhythm and a heavy tail.
 * ⛔ The heavy tail is deliberate and is the whole difficulty: it is what broke
 * median+MAD for A7. A harness validated on clean Gaussian noise would approve
 * a method that fails on the real thing.
 */
function syntheticSeries(hours, rand, { weekendDip = true } = {}) {
  const rows = [];
  const start = Date.UTC(2026, 0, 5, 0, 0, 0);   // a Monday
  for (let h = 0; h < hours; h += 1) {
    const at = new Date(start + h * 3600e3);
    const hod = at.getUTCHours();
    const dow = at.getUTCDay();
    let base = 1200 + 1000 * Math.sin(((hod - 6) / 24) * 2 * Math.PI);
    if (weekendDip && (dow === 0 || dow === 6)) base *= 0.45;
    base = Math.max(60, base);
    // Lognormal-ish multiplicative noise => heavy right tail.
    const z = (rand() + rand() + rand() + rand() - 2) * 0.9;
    rows.push({ at, value: Math.max(1, Math.round(base * Math.exp(z * 0.35))) });
  }
  return rows;
}

/**
 * Plant sustained spikes at known indices. Returns the planted windows.
 *
 * \u26d4 ADDITIVE AGAINST THE SERIES' OWN NORMAL LEVEL, NOT MULTIPLICATIVE ON
 * THE EXISTING VALUE — AND THE FIRST VERSION GOT THIS WRONG IN A WAY THAT
 * PRODUCED A CONFIDENT FALSE CONCLUSION. Measured on the live fleet, **30.7% of
 * device-hours have ZERO denied events** (2,962 of 9,654). Multiplying zero by
 * 50 is still zero, so a third of planting sites were UNDETECTABLE BY
 * CONSTRUCTION, and with a 3-hour persistence rule any window overlapping one
 * could never fire. The symptom was sensitivity that barely moved with
 * magnitude — 57% at 3x, 42% at 6x, 41% at 10x — which is not how a threshold
 * detector behaves, and that is what gave the bug away. Reported as-is it would
 * have been a damning finding about the DETECTOR that was really a finding
 * about the HARNESS.
 *
 * A real scan or outage adds load that is large relative to what the device
 * NORMALLY does, regardless of what that particular hour happened to carry.
 */
// ⛔ `minIndex` CONFINES PLANTS TO A REGION, AND IT EXISTS FOR A MEASUREMENT
// REASON RATHER THAN A TIDINESS ONE (added 2026-11-24). Plants scattered over
// the WHOLE series land ~70% of the time in the TRAINING portion, where they
// raise the very quantile threshold the judged plants are then measured
// against -- so adding plants to grow the sample also degrades the baseline,
// and sensitivity moves for a reason that has nothing to do with the detector.
// Confining them to the judged region makes the scored sample equal to the
// planted count, which is what lets the interval below mean anything.
function plantAnomalies(rows, rand, count = 6, lengthHours = 3, magnitude = 6, minIndex = 0) {
  const planted = [];
  const usable = rows.length - lengthHours - 1;
  if (usable <= 0) return planted;
  // ⛔ NOT CLAMPED TO `usable - 1`. Found by mutation testing 2026-11-24: an
  // upper clamp puts EVERY plant on the final index when `minIndex` is past the
  // end, so 25 plants become one stacked event and the harness still prints a
  // confident sensitivity over a denominator of 25. Leaving `from` alone makes
  // `span` non-positive, nothing is planted, and `sensText` reports `n/a` — a
  // refusal to measure, which is the honest answer for a region that does not
  // exist. The lower clamp stays: a negative index is a caller slip, not a
  // region.
  const from = Math.max(0, Math.trunc(minIndex) || 0);
  const span = usable - from;
  if (span <= 0) return planted;
  // The device's own normal level, used as the unit of "how big is this spike".
  const positives = rows.map((r) => r.value).filter((v) => v > 0).sort((a, b) => a - b);
  const reference = positives.length
    ? positives[Math.floor(positives.length * 0.5)]
    : 1;
  for (let i = 0; i < count; i += 1) {
    const at = from + Math.floor(rand() * span);
    for (let k = 0; k < lengthHours; k += 1) {
      rows[at + k].value = Math.round(rows[at + k].value + reference * magnitude);
    }
    planted.push({ start: at, length: lengthHours, reference, magnitude });
  }
  return planted;
}

// ⛔ A SENSITIVITY FIGURE WITHOUT AN INTERVAL IS A NUMBER NOBODY CAN ACT ON.
// Measured 2026-11-24, the shipped config scored 25/28 = 89% against a >=90%
// viability bar -- and a 95% Wilson interval on 25/28 runs 73%-96%, so the bar
// sits INSIDE the noise and ONE event decides whether the detector passes. The
// harness's whole reason for existing is that a robust-looking estimator was
// already falsified once on this data (A7's modified Z-score); reporting a bare
// percentage here would repeat that in the other direction.
//
// ⛔ WILSON, NOT THE NORMAL APPROXIMATION. At small n and p near 1 the
// textbook p +/- z*sqrt(p(1-p)/n) runs past 100% and understates the lower
// bound -- 25/28 gives an upper limit of 1.006, which is not a probability.
function wilson(k, n, z = 1.96) {
  // ⛔ k OUTSIDE [0, n] IS NOT A PROPORTION, so it is refused rather than
  // clamped into one. The [0,1] clamp on the RETURN is belt-and-braces only:
  // with a valid k the Wilson interval is bounded by construction, so no test
  // can make that clamp fire — it is an EQUIVALENT MUTANT, recorded as such
  // rather than presented as a working guard (the call CLAUDE.md already makes
  // about isInRange's min-side check).
  if (!Number.isFinite(k) || !Number.isFinite(n) || n <= 0) return null;
  if (k < 0 || k > n) return null;
  const p = k / n;
  const d = 1 + (z * z) / n;
  const centre = p + (z * z) / (2 * n);
  const half = z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n));
  return [Math.max(0, (centre - half) / d), Math.min(1, (centre + half) / d)];
}

/** "89% (25/28, 95% CI 72-96%)" -- never a bare percentage. */
function sensText(k, n) {
  if (!n) return 'n/a';
  const ci = wilson(k, n);
  const pct = ((k / n) * 100).toFixed(0);
  if (!ci) return `${pct}% (${k}/${n})`;
  return `${pct}% (${k}/${n}, CI ${(ci[0] * 100).toFixed(0)}-${(ci[1] * 100).toFixed(0)}%)`;
}

/** Split: first 70% trains the baseline, last 30% is the control window. */
function split(rows, trainFrac = 0.7) {
  const cut = Math.floor(rows.length * trainFrac);
  return { train: rows.slice(0, cut), control: rows.slice(cut) };
}

function evaluate(train, control, { grain, quantile, persistence }) {
  const baseline = sb.buildSeasonalBaseline(train, { grain, quantile });
  const coverage = baseline.bucketCount ? baseline.usableBuckets / baseline.bucketCount : 0;
  if (coverage < 0.9) {
    return { usable: false, reason: 'insufficient_baseline', coverage };
  }
  const judgements = control.map((r) => sb.judge(r.value, baseline, r.at));
  const runs = sb.sustainedRuns(judgements, persistence);
  const judged = judgements.filter((j) => j.state === sb.STATES.ANOMALOUS || j.state === sb.STATES.NORMAL).length;
  const anomalousBuckets = judgements.filter((j) => j.state === sb.STATES.ANOMALOUS).length;
  return {
    usable: true,
    coverage,
    judged,
    anomalousBuckets,
    bucketRate: judged ? anomalousBuckets / judged : null,
    runs,
    runCount: runs.length,
    judgements,
  };
}

// ---------------------------------------------------------------------------
// ⛔ THE PASS THAT DRIVES THE REAL DETECTOR (added 2026-11-24)
// ---------------------------------------------------------------------------
//
// ⛔ WHY: THE SWEEP ABOVE DOES NOT MEASURE THE DETECTOR THAT SHIPS, AND THE
// REGISTERED RATE CAME FROM IT ANYWAY. `evaluate()` re-implements the pipeline
// out of `seasonalBaseline` primitives. `detectSpike` does three things it does
// not:
//   1. it applies `SPIKE_MIN_MARGIN_PCT` (5%), a floor that removes 12 of 32
//      live runs — the "0.0% above its ceiling" class;
//   2. it CHOOSES the grain per device via `selectGrain`, so sweeping a fixed
//      grain measures a model the product never runs;
//   3. it judges only `DEFAULT_JUDGE_WINDOW_HOURS` (24) and trains on the rest,
//      rather than a 70/30 split of the whole series.
//
// So `EVIDENCE.denied_spike.alertsPerDay = 1.0` describes an UNGATED detector,
// while `rateDrift()` counts findings produced by the GATED one. Measured
// 2026-11-24: that mismatch is what reported `denied_spike` as "drifted LOW,
// 3 alerts against an expected 28, p=2.9e-9" — a comparison between two
// different detectors, read as a fault in the fleet.
//
// ⛔ THIS IS THE NUMBER THAT MAY BE REGISTERED. The sweep above stays, because
// choosing a quantile still needs the grain/threshold exploration — but it is
// now labelled as exploration, and `assertRegisteredDetector`'s rate must come
// from here.
//
// ⛔ IT SIMULATES OPERATION RATHER THAN SCORING A SPLIT. The detector runs
// against a growing series and judges the most recent 24h, so the harness steps
// a cursor one DAY at a time and calls it exactly as the engine would, then
// dedupes runs by the natural key the dispatcher uses. Without the dedup a
// sustained event counts once per day and the rate is inflated — which is
// precisely why `DEFAULT_JUDGE_WINDOW_HOURS`' own comment says dedup "is a
// large part of why the measured rate is bearable".
//
// ⛔ KNOWN AND STATED OVER-COUNT: stepping daily means a run straddling two
// days can present two different `startAt` values and so two keys, where the
// hourly engine would hold one. The error is in the SAFE direction (it
// over-states the alert rate) and is recorded here rather than corrected,
// because correcting it means simulating 24x the calls for a bound that is
// already conservative.
function detectorKey(deviceIdx, run) {
  return `${deviceIdx}:${run.truncated ? 'start-before-window' : new Date(run.startAt).toISOString()}`;
}

/**
 * Run the REAL detectSpike across a device series, one simulated day at a time.
 * @returns {{keys:Set<string>, days:number, runs:Array, insufficient:number}}
 */
function runRealDetector(series, deviceIdx, { quantile, persistence, judgeWindowHours = 24, trainFrac }) {
  const keys = new Set();
  const runs = [];
  let days = 0;
  let insufficient = 0;
  const firstCursor = Math.floor(series.length * trainFrac);
  // Step a day at a time; each call judges the final `judgeWindowHours`.
  for (let cursor = Math.max(firstCursor, judgeWindowHours + 1);
    cursor <= series.length; cursor += 24) {
    const r = detectSpike(series.slice(0, cursor), {
      quantile, minHours: persistence, judgeWindowHours,
    });
    if (r.state !== 'measured') { insufficient += 1; continue; }
    days += 1;
    for (const run of r.runs) { keys.add(detectorKey(deviceIdx, run)); runs.push(run); }
  }
  return { keys, days, runs, insufficient };
}

/** Sweep every configuration against the live rollups. */
async function realRun(opts) {
  const byDevice = await loadSeries(opts.metric, opts.days);
  const devices = [...byDevice.values()].filter((s) => s.length >= 24 * 7);
  const hours = devices.length ? Math.max(...devices.map((d) => d.length)) : 0;
  console.log(`[a6Harness] LIVE rollups — metric=${opts.metric}, last ${opts.days} days`);
  console.log(`            ${devices.length} device(s) with >= 1 week of history, up to ${hours}h each\n`);
  if (devices.length === 0) {
    console.log('  No device has a week of history. Nothing to measure.');
    return;
  }

  const rand = rng(opts.seed);
  // ⛔ EVERY PLANT LANDS IN THE JUDGED REGION, so the scored sample is
  // `plants x devices` rather than the ~30% that happened to fall there.
  const planted = devices.map((d) => {
    const copy = d.map((r) => ({ at: r.at, value: r.value }));
    const cut = Math.floor(copy.length * opts.train);
    return {
      copy,
      windows: plantAnomalies(copy, rand, opts.plants, 3, opts.magnitude, cut),
    };
  });

  const header = '  grain                 q      persist  coverage  fired/bucket   alerts/day  found planted';
  console.log(header);
  console.log('  ' + '-'.repeat(header.length - 2));
  const results = [];
  for (const grain of GRAINS) {
    for (const q of QUANTILES) {
      for (const p of PERSISTENCE) {
        let judged = 0; let fired = 0; let runs = 0; let usable = 0; let coverage = 0;
        let plantedN = 0; let detected = 0;
        for (let i = 0; i < devices.length; i += 1) {
          const cs = split(devices[i], opts.train);
          const ev = evaluate(cs.train, cs.control, { grain, quantile: q, persistence: p });
          coverage = Math.max(coverage, ev.coverage || 0);
          if (!ev.usable) continue;
          usable += 1; judged += ev.judged; fired += ev.anomalousBuckets; runs += ev.runCount;

          const ds = split(planted[i].copy, opts.train);
          const dv = evaluate(ds.train, ds.control, { grain, quantile: q, persistence: p });
          const cut = Math.floor(planted[i].copy.length * opts.train);
          const inControl = planted[i].windows.filter((w) => w.start >= cut)
            .map((w) => ({ start: w.start - cut, length: w.length }));
          plantedN += inControl.length;
          if (dv.usable) {
            for (const w of inControl) {
              if (dv.runs.some((r) => r.startIndex < w.start + w.length && r.startIndex + r.length > w.start)) detected += 1;
            }
          }
        }
        if (usable === 0) { results.push({ grain, q, p, usable: false, coverage }); continue; }
        const controlHours = judged / usable;
        const alertsDay = runs / usable / (controlHours / 24) * devices.length;
        results.push({ grain, q, p, usable: true, coverage,
          bucketRate: judged ? fired / judged : 0, alertsDay,
          sens: plantedN ? detected / plantedN : null, plantedN, detected });
      }
    }
  }
  for (const r of results) {
    const g = r.grain.padEnd(20);
    if (!r.usable) { console.log(`  ${g} ${String(r.q).padEnd(6)} ${String(r.p).padEnd(8)} ${(r.coverage * 100).toFixed(0).padStart(7)}%  — insufficient baseline`); continue; }
    console.log(`  ${g} ${String(r.q).padEnd(6)} ${String(r.p).padEnd(8)} ${(r.coverage * 100).toFixed(0).padStart(7)}%`
      + `${(r.bucketRate * 100).toFixed(1).padStart(13)}%`
      + `${r.alertsDay.toFixed(2).padStart(13)}`
      + `${r.sens === null ? '      n/a' : `${(r.sens * 100).toFixed(0)}% (${r.detected}/${r.plantedN})`.padStart(15)}`);
  }
  const viable = results.filter((r) => r.usable && r.sens !== null && r.sens >= 0.9 && r.alertsDay <= 3);
  viable.sort((a, b) => a.alertsDay - b.alertsDay);
  console.log('\n  Viable (>=90% of planted events found AND <=3 alerts/day fleet-wide):');
  if (viable.length === 0) console.log('    NONE on this data. That is an answer, not a reason to loosen the bar.');
  else for (const r of viable.slice(0, 5)) {
    console.log(`    ${r.grain} q=${r.q} persist=${r.p} -> ${r.alertsDay.toFixed(2)} alerts/day, ${(r.sens * 100).toFixed(0)}% sensitivity`);
  }
  console.log('\n  \u26d4 "alerts/day" is an ALERT RATE, not a false-positive rate — this data carries no');
  console.log('     labels, so some firings may be real. It is an UPPER BOUND on false positives.');
  console.log('  ⛔ THE TABLE ABOVE IS EXPLORATION, NOT A REGISTRABLE RATE: it re-implements');
  console.log('     the pipeline and omits detectSpike\'s 5% margin floor and its grain selection.');

  // -------------------------------------------------------------------------
  // The pass that drives the SHIPPING detector.
  // -------------------------------------------------------------------------
  console.log('\n  REAL DETECTOR — detectSpike as it ships (grain self-selected, 5% margin');
  console.log('  floor, 24h judged per call, runs deduped by the dispatcher\'s natural key)\n');
  const h2 = '  q      persist  alerts/day         found planted (95% CI)  device-days  insufficient';
  console.log(h2);
  console.log('  ' + '-'.repeat(h2.length - 2));
  const real = [];
  for (const q of QUANTILES) {
    for (const p of PERSISTENCE) {
      let alerts = 0; let deviceDays = 0; let insufficient = 0;
      let plantedN = 0; let detected = 0;
      for (let i = 0; i < devices.length; i += 1) {
        const live = runRealDetector(devices[i], i,
          { quantile: q, persistence: p, trainFrac: opts.train });
        alerts += live.keys.size;
        deviceDays += live.days;
        insufficient += live.insufficient;

        // Sensitivity against the SAME series with anomalies planted, scored
        // by TIMESTAMP overlap -- the detector returns times, not indices.
        const pc = planted[i].copy;
        const cut = Math.floor(pc.length * opts.train);
        const windows = planted[i].windows
          .filter((w) => w.start >= cut)
          .map((w) => ({
            from: pc[w.start].at,
            to: pc[Math.min(w.start + w.length - 1, pc.length - 1)].at,
          }));
        if (windows.length === 0) continue;
        plantedN += windows.length;
        const pr = runRealDetector(pc, i, { quantile: q, persistence: p, trainFrac: opts.train });
        for (const w of windows) {
          const from = new Date(w.from).getTime();
          const to = new Date(w.to).getTime();
          if (pr.runs.some((r) => r.startAt && r.endAt
            && new Date(r.startAt).getTime() <= to
            && new Date(r.endAt).getTime() >= from)) detected += 1;
        }
      }
      const perDay = deviceDays ? alerts / (deviceDays / devices.length) : null;
      real.push({ q, p, alerts, perDay, deviceDays, insufficient,
        sens: plantedN ? detected / plantedN : null, plantedN, detected });
    }
  }
  for (const r of real) {
    console.log(`  ${String(r.q).padEnd(6)} ${String(r.p).padEnd(8)}`
      + `${r.perDay === null ? '    n/a' : r.perDay.toFixed(2).padStart(11)}`
      + `${sensText(r.detected, r.plantedN).padStart(30)}`
      + `${String(r.deviceDays).padStart(13)}${String(r.insufficient).padStart(14)}`);
  }
  const shipped = real.find((r) => r.q === 0.9 && r.p === 3);
  if (shipped && shipped.perDay !== null) {
    console.log(`\n  SHIPPED CONFIG (q=0.90, persist=3): ${shipped.perDay.toFixed(3)} alerts/day`
      + `, sensitivity ${sensText(shipped.detected, shipped.plantedN)}`);
    console.log('  ^ THIS is the figure EVIDENCE.denied_spike.alertsPerDay must carry.');
  }

  // ⛔ VIABILITY IS JUDGED ON THE INTERVAL'S LOWER BOUND, NOT THE POINT
  // ESTIMATE. A bare 89% and a bare 93% are the same measurement at n=28 (the
  // intervals overlap almost completely), so ranking configurations on the
  // point estimate picks noise -- which it did: the shipped config read 89% at
  // n=28 and 94% at n=375, and only the second can be acted on.
  console.log('\n  VIABLE on the REAL detector (sensitivity LOWER BOUND >= 90% AND <= 3 alerts/day):');
  const strict = real.filter((r) => {
    if (r.perDay === null || r.plantedN === 0) return false;
    const ci = wilson(r.detected, r.plantedN);
    return ci && ci[0] >= 0.90 && r.perDay <= 3;
  }).sort((a, b) => a.perDay - b.perDay);
  if (strict.length === 0) {
    console.log('    NONE on this data. That is an answer, not a reason to loosen the bar.');
    const sensOk = real.filter((r) => {
      const ci = r.plantedN ? wilson(r.detected, r.plantedN) : null;
      return r.perDay !== null && ci && ci[0] >= 0.90;
    }).sort((a, b) => a.perDay - b.perDay)[0];
    const rateOk = real.filter((r) => r.perDay !== null && r.perDay <= 3)
      .sort((a, b) => b.detected / (b.plantedN || 1) - a.detected / (a.plantedN || 1))[0];
    if (sensOk) {
      console.log(`    closest on RATE  (sensitivity proven): q=${sensOk.q} persist=${sensOk.p}`
        + ` -> ${sensOk.perDay.toFixed(2)}/day, ${sensText(sensOk.detected, sensOk.plantedN)}`);
    }
    if (rateOk) {
      console.log(`    closest on SENS  (rate within bar):    q=${rateOk.q} persist=${rateOk.p}`
        + ` -> ${rateOk.perDay.toFixed(2)}/day, ${sensText(rateOk.detected, rateOk.plantedN)}`);
    }
  } else {
    for (const r of strict.slice(0, 5)) {
      console.log(`    q=${r.q} persist=${r.p} -> ${r.perDay.toFixed(2)} alerts/day, `
        + sensText(r.detected, r.plantedN));
    }
  }
}

// ---------------------------------------------------------------------------
// THE VOLUME-COLLAPSE PASS (added 2026-11-24)
// ---------------------------------------------------------------------------
//
// detectVolumeCollapse cannot register without a measured alert rate AND a
// measured sensitivity (assertRegisteredDetector), and v2.237.6 is the standing
// argument for not guessing either: the same configuration of denied_spike read
// 89% at a 28-plant sample and 94% at 375, and only the second supports a
// decision.
//
// IT IS A DAILY DETECTOR, SO IT NEEDS ITS OWN LOADER. The spike metrics above
// are per device-HOUR; a collapse is a change in a device's DAILY level, and
// the question "has this firewall's volume fallen by 99% and stayed there" is
// not askable of one hour.
//
// JUDGEABILITY IS A FLEET FACT, NOT A DEVICE FACT. A day SecVault was not
// collecting must be excluded from every device, or a collector restart or a
// deploy gap reads as a simultaneous collapse of the whole fleet at a 2-day
// sustain. So a day is judgeable only when the FLEET covered all 24 hours of
// it, which is independent of any one firewall's own volume. The first and last
// day of the window are partial by construction and are therefore excluded --
// the same call capacityForecast.js makes when it counts only days with 24
// byte-bearing hours.
//
// A MISSING DEVICE-DAY IS A REAL ZERO AND MUST BE GRIDDED IN. A firewall that
// reported nothing on a judgeable day has no rollup row, so without the
// device x day cross join that day is absent rather than zero -- and absence is
// exactly what this detector must not confuse with silence.
//
// DAYS ARE BUCKETED IN THE DATABASE SERVER'S OWN ZONE, formatted with to_char
// IN SQL. Both halves are deliberate: CURRENT_DATE and every fixed-HH:MM cron
// job in this product evaluate in that zone, and formatting a pg DATE in JS
// with String()/toISOString() is the defect CLAUDE.md records twice -- once as
// a whole chart drawn a day early, and once in this session as a sweep that
// sorted "Fri Nov 06" alphabetically and reported nonsense.

const COLLAPSE_DROPS = [0.95, 0.99, 0.999];
const COLLAPSE_SUSTAINS = [2, 3, 5];
const COLLAPSE_BASELINES = [14, 28];

// MAGNITUDES ARE DEFINED RELATIVE TO THE BAR BEING TESTED, NOT AS ABSOLUTE
// FRACTIONS, and the first version of this got it wrong in a way that read as a
// detector fault. It planted a fixed [0.001, 0.01, 0.05] against each of three
// drop ratios, so every cell where the planted remainder EQUALLED the bar's own
// remainder sat exactly on the threshold -- and a threshold at its own boundary
// is a coin toss. Measured: those cells read 25-43% while every cell a factor of
// ten inside the bar read 91-93%, for the SAME detector. The 42% was the
// measurement design, not a miss.
//
// So each plant is a multiple of the bar's remainder: a tenth of it is clearly
// INSIDE and must be found; the remainder itself is AT the bar and is reported
// with NO verdict, because no sensitivity bar can be read there; ten times it is
// clearly OUTSIDE and must produce silence. The same lesson as the Wilson
// interval one release ago -- a measurement has to be capable of answering the
// question before its answer means anything.
const PLANT_FACTORS = [
  { name: 'inside', mult: 0.1, expect: 'fire' },
  { name: 'at-bar', mult: 1, expect: 'boundary' },
  { name: 'outside', mult: 10, expect: 'silent' },
];

const COLLAPSE_SQL = `
  WITH hourly AS (
    SELECT device_id,
           bucket_hour,
           to_char(bucket_hour, 'YYYY-MM-DD') AS day,
           SUM(event_count)::bigint AS events
      FROM syslog_rollup_hourly
     WHERE device_id IS NOT NULL
       AND bucket_hour >= date_trunc('day', now() - ($1 || ' days')::interval)
     GROUP BY 1, 2, 3
  ),
  fleet AS (
    SELECT day, COUNT(DISTINCT bucket_hour) AS fleet_hours
      FROM hourly GROUP BY 1
  ),
  devs AS (SELECT DISTINCT device_id FROM hourly),
  grid AS (
    SELECT d.device_id, f.day, f.fleet_hours
      FROM devs d CROSS JOIN fleet f
  )
  SELECT g.device_id::text AS device,
         g.day AS day,
         (g.fleet_hours >= 24) AS judgeable,
         COALESCE(SUM(h.events), 0)::bigint AS events
    FROM grid g
    LEFT JOIN hourly h
      ON h.device_id = g.device_id AND h.day = g.day
   GROUP BY 1, 2, 3
   ORDER BY 1, 2`;

async function loadDailySeries(days) {
  const { pool } = require('../lib/db');
  const { rows } = await pool.query(COLLAPSE_SQL, [String(days)]);
  const byDevice = new Map();
  for (const r of rows) {
    if (!byDevice.has(r.device)) byDevice.set(r.device, []);
    byDevice.get(r.device).push({
      day: r.day, events: Number(r.events), judgeable: r.judgeable !== false,
    });
  }
  await pool.end();
  return byDevice;
}

/**
 * Step the REAL detector across a device's daily series one day at a time and
 * return the distinct alerts it would have raised.
 *
 * Deduped by the natural key the dispatcher would use -- (device, onsetDay) --
 * so a collapse that persists for a fortnight is ONE alert, which is the whole
 * point of walking back to the onset. Counting one per day would inflate the
 * rate by the duration of the outage.
 */
function runCollapseDetector(series, deviceIdx, cfg) {
  const keys = new Set();
  const firings = [];
  let judged = 0;
  let insufficient = 0;
  const first = cfg.minBaselineDays + cfg.sustainDays;
  for (let cursor = first; cursor <= series.length; cursor += 1) {
    const r = detectVolumeCollapse(series.slice(0, cursor), cfg);
    if (r.state !== 'measured') { insufficient += 1; continue; }
    judged += 1;
    if (!r.collapsed) continue;
    const key = `${deviceIdx}:${r.onsetDay}`;
    if (!keys.has(key)) firings.push({ cursor, onsetDay: r.onsetDay, baseline: r.baseline, recent: r.recent });
    keys.add(key);
  }
  return { keys, firings, judged, insufficient };
}

/**
 * A copy of `series` with every judgeable day from `onsetIdx` onward scaled to
 * `remains` of its own value.
 *
 * FLOORED AT ONE EVENT, never zero. A device scaled to zero is FULLY DARK, and
 * detectVolumeCollapse deliberately hands that case to device_silent -- so an
 * unfloored plant would measure the hand-off rather than the collapse, and
 * would depress sensitivity for a reason that is correct behaviour.
 *
 * AN UNJUDGEABLE DAY IS LEFT ALONE. It is excluded from the detector's view
 * either way, and scaling it would quietly change the sample.
 */
function plantCollapse(series, onsetIdx, remains) {
  return series.map((r, i) => {
    if (i < onsetIdx || r.judgeable === false) return { ...r };
    return { ...r, events: Math.max(1, Math.round(r.events * remains)) };
  });
}

async function collapseRun(opts) {
  const byDevice = await loadDailySeries(opts.days);
  const devices = [...byDevice.entries()]
    .map(([id, rows]) => ({ id, rows }))
    .filter((d) => d.rows.filter((r) => r.judgeable).length >= 1);
  console.log(`[a6Harness] VOLUME COLLAPSE — live daily rollups, last ${opts.days} days`);
  if (devices.length === 0) {
    console.log('  No device has a judgeable day. Nothing to measure.');
    return;
  }
  const spanAll = devices[0].rows.length;
  const judgeableDays = devices[0].rows.filter((r) => r.judgeable).length;
  const excluded = spanAll - judgeableDays;
  console.log(`            ${devices.length} device(s), ${spanAll} days in window, `
    + `${judgeableDays} judgeable fleet-wide (${excluded} excluded: partial or not collecting)\n`);
  if (excluded > 0) {
    const bad = devices[0].rows.filter((r) => !r.judgeable).map((r) => r.day);
    console.log(`  Excluded days: ${bad.join(', ')}`);
    console.log('  ^ the FLEET did not cover all 24 hours. Counted as zero these would read');
    console.log('    as every firewall collapsing at once.\n');
  }

  // -----------------------------------------------------------------------
  // Alert rate on the UNMODIFIED fleet.
  // -----------------------------------------------------------------------
  //
  // THIS FLEET CONTAINS A REAL COLLAPSE, so some of what follows is a TRUE
  // positive and the rate is an UPPER BOUND on false positives -- stronger
  // than the spike harness's version of the same disclaimer, because there we
  // only suspected the firings might be real and here we have measured one.
  // TFM-MH fell from ~5.9M/day to ~30/day on 2026-11-08 and is still down.
  const header = '  drop     sustain  baseline   alerts  alerts/day  device-days  insufficient';
  console.log(header);
  console.log('  ' + '-'.repeat(header.length - 2));
  const rates = [];
  for (const drop of COLLAPSE_DROPS) {
    for (const sustain of COLLAPSE_SUSTAINS) {
      for (const minBaselineDays of COLLAPSE_BASELINES) {
        const cfg = { dropRatio: drop, sustainDays: sustain, minBaselineDays };
        let alerts = 0; let judged = 0; let insufficient = 0;
        const who = [];
        for (let i = 0; i < devices.length; i += 1) {
          const run = runCollapseDetector(devices[i].rows, i, cfg);
          alerts += run.keys.size;
          judged += run.judged;
          insufficient += run.insufficient;
          for (const f of run.firings) who.push({ device: devices[i].id, ...f });
        }
        const perDay = judged ? (alerts / (judged / devices.length)) : null;
        rates.push({ drop, sustain, minBaselineDays, alerts, perDay, judged, insufficient, who });
      }
    }
  }
  for (const r of rates) {
    console.log(`  ${String(r.drop).padEnd(8)} ${String(r.sustain).padEnd(8)} ${String(r.minBaselineDays).padEnd(10)}`
      + `${String(r.alerts).padStart(7)}`
      + `${r.perDay === null ? '         n/a' : r.perDay.toFixed(3).padStart(12)}`
      + `${String(r.judged).padStart(13)}${String(r.insufficient).padStart(14)}`);
  }

  // -----------------------------------------------------------------------
  // Sensitivity, per planted magnitude.
  // -----------------------------------------------------------------------
  //
  // ONE PLANT IS ONE (device, onset day) PAIR, and every onset lands in the
  // JUDGED region -- a plant before `minBaseline + sustain` is never reached
  // by the detector at all and would silently shrink the denominator.
  //
  // A DEVICE THAT HAS ALREADY COLLAPSED IS EXCLUDED FROM ITS OWN PLANTS. On
  // this fleet that is TFM-MH, and scoring a plant there would credit the
  // detector for finding the collapse that was already in the data -- a true
  // positive counted as a measurement of the plant, which is the sample-purity
  // version of the same error the spike harness made by scoring plants that
  // fell in the training region.
  console.log('\n  SENSITIVITY — synthetic collapses planted into each real series');
  console.log('  (one plant per device per judged onset day; the detector is the one that ships)');
  console.log('  Magnitudes are MULTIPLES OF THE BAR: inside = a tenth of the bar\'s remainder');
  console.log('  (must be found), at-bar = exactly the bar (no verdict is readable there),');
  console.log('  outside = ten times it (see the synthetic check below for why a few still fire).\n');
  const h2 = '  magnitude  remains   drop     sustain  baseline   found planted (95% CI)        verdict';
  console.log(h2);
  console.log('  ' + '-'.repeat(h2.length - 2));
  const sens = [];
  for (const factor of PLANT_FACTORS) {
    for (const drop of COLLAPSE_DROPS) {
      for (const sustain of COLLAPSE_SUSTAINS) {
        for (const minBaselineDays of COLLAPSE_BASELINES) {
          const cfg = { dropRatio: drop, sustainDays: sustain, minBaselineDays };
          const remains = (1 - drop) * factor.mult;
          let planted = 0; let found = 0; let skipped = 0;
          for (let i = 0; i < devices.length; i += 1) {
            const rows = devices[i].rows;
            // Already collapsed? Its own history is not a clean canvas.
            if (detectVolumeCollapse(rows, cfg).collapsed) { skipped += 1; continue; }
            const firstOnset = minBaselineDays + sustain;
            for (let onset = firstOnset; onset <= rows.length - sustain; onset += 1) {
              if (rows[onset] && rows[onset].judgeable === false) continue;
              const copy = plantCollapse(rows, onset, remains);
              const r = detectVolumeCollapse(copy.slice(0, onset + sustain), cfg);
              planted += 1;
              if (r.state === 'measured' && r.collapsed) found += 1;
            }
          }
          const ci = planted ? wilson(found, planted) : null;
          let verdict = 'n/a';
          if (ci) {
            if (factor.expect === 'fire') verdict = ci[0] >= 0.90 ? 'PASS >=90%' : 'BELOW BAR';
            else if (factor.expect === 'silent') verdict = found === 0 ? 'silent' : `${found}x compounded with real variation`;
            else verdict = 'at threshold — no verdict';
          }
          sens.push({ factor: factor.name, expect: factor.expect, remains, drop, sustain,
            minBaselineDays, planted, found, ci, verdict, skipped });
        }
      }
    }
  }
  for (const s2 of sens) {
    console.log(`  ${s2.factor.padEnd(10)} ${s2.remains.toExponential(0).padEnd(9)} ${String(s2.drop).padEnd(8)} `
      + `${String(s2.sustain).padEnd(8)} ${String(s2.minBaselineDays).padEnd(10)}`
      + `${sensText(s2.found, s2.planted).padStart(28)}`
      + `  ${s2.verdict}`);
  }

  // -----------------------------------------------------------------------
  // SPECIFICITY — the threshold, isolated on a FLAT canvas.
  // -----------------------------------------------------------------------
  //
  // THE REAL-SERIES "outside" ROWS ABOVE CANNOT MEASURE THIS, AND READING THEM
  // AS A FAILURE WAS THE FIRST DRAFT'S MISTAKE. A plant is applied ON TOP OF the
  // device's own variation, so a day whose natural volume was already a tenth of
  // the device's median -- TFM-RN's 2026-10-26 was 98,374 against ~1.6M, 6% --
  // plus a ten-times-the-bar plant is a genuine hundred-fold fall. The detector
  // firing there is CORRECT: the series it was handed really did collapse. ~9 of
  // ~900 live device-days have that shape, which is the 1% in those rows.
  //
  // So the threshold is tested where nothing else moves: a flat synthetic level
  // with modest multiplicative noise. A plant ten times OUTSIDE the bar must
  // produce silence there, and if it does not, the ratio guard is wrong rather
  // than the fleet being lumpy. The empirical answer on the real fleet is the
  // ALERT RATE itself -- one alert in 930 device-days, and that one is real.
  const synthDevices = 16;
  const synthDays = 76;
  const srand = rng(opts.seed);
  const flat = [];
  for (let d = 0; d < synthDevices; d += 1) {
    const level = 1e6;
    const rows = [];
    for (let i = 0; i < synthDays; i += 1) {
      // +/-20% day-to-day, which is wider than any healthy device here.
      rows.push({ day: `synth-${String(i).padStart(3, '0')}`,
        events: Math.round(level * (0.8 + 0.4 * srand())), judgeable: true });
    }
    flat.push(rows);
  }
  console.log('\n  SPECIFICITY — the same plants on a FLAT synthetic level (+/-20% noise),');
  console.log('  where nothing but the plant can move the series\n');
  const h3 = '  magnitude  drop     sustain  baseline   fired/planted        verdict';
  console.log(h3);
  console.log('  ' + '-'.repeat(h3.length - 2));
  const spec = [];
  for (const factor of PLANT_FACTORS) {
    for (const drop of COLLAPSE_DROPS) {
      for (const sustain of COLLAPSE_SUSTAINS) {
        for (const minBaselineDays of COLLAPSE_BASELINES) {
          const cfg = { dropRatio: drop, sustainDays: sustain, minBaselineDays };
          const remains = (1 - drop) * factor.mult;
          let planted = 0; let found = 0;
          for (const rows of flat) {
            for (let onset = minBaselineDays + sustain; onset <= rows.length - sustain; onset += 1) {
              const copy = plantCollapse(rows, onset, remains);
              const r = detectVolumeCollapse(copy.slice(0, onset + sustain), cfg);
              planted += 1;
              if (r.state === 'measured' && r.collapsed) found += 1;
            }
          }
          let verdict = 'n/a';
          if (factor.expect === 'silent') verdict = found === 0 ? 'correctly silent' : `FIRED ${found}x OUTSIDE BAR`;
          else if (factor.expect === 'fire') verdict = found === planted ? 'all found' : `missed ${planted - found}`;
          else verdict = 'at threshold — no verdict';
          spec.push({ factor: factor.name, expect: factor.expect, drop, sustain, minBaselineDays, planted, found, verdict });
        }
      }
    }
  }
  for (const x of spec) {
    console.log(`  ${x.factor.padEnd(10)} ${String(x.drop).padEnd(8)} ${String(x.sustain).padEnd(8)} `
      + `${String(x.minBaselineDays).padEnd(10)}${`${x.found}/${x.planted}`.padStart(13)}        ${x.verdict}`);
  }

  // -----------------------------------------------------------------------
  // The registrable answer.
  // -----------------------------------------------------------------------
  //
  // THREE CONDITIONS, AND THE THIRD IS THE ONE A SENSITIVITY FIGURE ALONE
  // HIDES. A detector that fires on everything scores 100% sensitivity, so a
  // configuration must ALSO be silent at ten times the bar; without that the
  // first two can be satisfied by a detector with no discrimination at all.
  console.log('\n  REGISTRABLE CONFIGURATIONS (sensitivity LOWER BOUND >= 90% a tenth inside the');
  console.log('  bar, <= 3 alerts/day on the real fleet, AND silent at ten times the bar on a');
  console.log('  flat canvas):\n');
  const viable = [];
  for (const r of rates) {
    const same = (x) => x.drop === r.drop && x.sustain === r.sustain
      && x.minBaselineDays === r.minBaselineDays;
    const inside = sens.find((x) => same(x) && x.factor === 'inside');
    const outside = spec.find((x) => same(x) && x.factor === 'outside');
    if (!inside || !inside.ci || !outside || r.perDay === null) continue;
    if (inside.ci[0] >= 0.90 && r.perDay <= 3 && outside.found === 0) {
      viable.push({ ...r, inside, outside });
    }
  }
  viable.sort((a, b) => a.perDay - b.perDay);
  if (viable.length === 0) {
    console.log('    NONE on this data. That is an answer, not a reason to loosen the bar.');
  } else {
    for (const v of viable.slice(0, 8)) {
      console.log(`    drop=${v.drop} sustain=${v.sustain} baseline=${v.minBaselineDays}`
        + ` -> ${v.perDay.toFixed(3)} alerts/day, sensitivity ${sensText(v.inside.found, v.inside.planted)}`);
    }
    const best = viable[0];
    console.log(`\n  ^ EVIDENCE.volume_collapse would carry alertsPerDay=${best.perDay.toFixed(3)},`
      + ` sensitivity=${(best.inside.found / best.inside.planted).toFixed(2)}`);
  }

  // What actually fired on the real fleet, at the shipped defaults.
  const shipped = rates.find((r) => r.drop === 0.99 && r.sustain === 2 && r.minBaselineDays === 14);
  if (shipped) {
    console.log(`\n  AT THE CURRENT DEFAULTS (drop=0.99, sustain=2, baseline=14): `
      + `${shipped.alerts} alert(s) over ${shipped.judged} device-days`);
    for (const f of shipped.who) {
      console.log(`    ${f.device}  onset ${f.onsetDay}  ${Math.round(f.baseline).toLocaleString()}`
        + ` -> ${Math.round(f.recent).toLocaleString()} events/day`);
    }
    if (shipped.who.length === 0) console.log('    (none)');
  }

  console.log('\n  "alerts/day" is an ALERT RATE, not a false-positive rate. This fleet contains');
  console.log('     at least one REAL collapse (TFM-MH, 2026-11-08), so the figure is an upper');
  console.log('     bound on false positives and is known to include a true positive.');
}


function main() {
  const opts = parseArgs(process.argv.slice(2));
  // The collapse detector is daily and has its own loader; --synthetic is a
  // spike-only mode, so asking for both is a contradiction rather than a default.
  if (opts.detector === 'collapse') {
    if (opts.synthetic) throw new Error('--synthetic is not implemented for --detector collapse');
    return collapseRun(opts);
  }
  if (!opts.synthetic) return realRun(opts);

  const hours = opts.days * 24;
  const rand = rng(opts.seed);
  console.log(`[a6Harness] synthetic validation — ${opts.days} days (${hours}h) x ${opts.devices} devices`);
  console.log('            change-free control + planted anomalies, heavy-tailed noise\n');

  // Per-device series so the alert arithmetic is fleet-realistic.
  const clean = [];
  const dirty = [];
  const plantedPerDevice = [];
  for (let d = 0; d < opts.devices; d += 1) {
    const c = syntheticSeries(hours, rand);
    clean.push(c);
    const copy = c.map((r) => ({ at: r.at, value: r.value }));
    plantedPerDevice.push(plantAnomalies(copy, rand));
    dirty.push(copy);
  }

  const header = '  grain                 q      persist  coverage  FP/bucket  false alerts/day  found planted';
  console.log(header);
  console.log('  ' + '-'.repeat(header.length - 2));

  const results = [];
  for (const grain of GRAINS) {
    for (const q of QUANTILES) {
      for (const p of PERSISTENCE) {
        let judged = 0; let anomalous = 0; let falseRuns = 0; let usableDevices = 0;
        let planted = 0; let detected = 0; let coverage = 0;

        for (let d = 0; d < opts.devices; d += 1) {
          const cs = split(clean[d]);
          const ev = evaluate(cs.train, cs.control, { grain, quantile: q, persistence: p });
          if (!ev.usable) { coverage = ev.coverage; continue; }
          usableDevices += 1;
          coverage = ev.coverage;
          judged += ev.judged; anomalous += ev.anomalousBuckets; falseRuns += ev.runCount;

          // Sensitivity: same model, data WITH planted events.
          const ds = split(dirty[d]);
          const dv = evaluate(ds.train, ds.control, { grain, quantile: q, persistence: p });
          const cut = Math.floor(dirty[d].length * 0.7);
          const inControl = plantedPerDevice[d]
            .filter((pl) => pl.start >= cut)
            .map((pl) => ({ start: pl.start - cut, length: pl.length }));
          planted += inControl.length;
          if (dv.usable) {
            for (const pl of inControl) {
              const hit = dv.runs.some((r) => r.startIndex < pl.start + pl.length && r.startIndex + r.length > pl.start);
              if (hit) detected += 1;
            }
          }
        }

        if (usableDevices === 0) {
          results.push({ grain, q, p, usable: false, coverage });
          continue;
        }
        const controlDays = (hours * 0.3) / 24;
        const alertsDay = falseRuns / (controlDays * usableDevices) * opts.devices;
        const sens = planted ? detected / planted : null;
        results.push({ grain, q, p, usable: true, coverage, bucketRate: judged ? anomalous / judged : 0, alertsDay, sens, planted, detected });
      }
    }
  }

  for (const r of results) {
    const g = r.grain.padEnd(20);
    if (!r.usable) {
      console.log(`  ${g} ${String(r.q).padEnd(6)} ${String(r.p).padEnd(8)} ${(r.coverage * 100).toFixed(0).padStart(7)}%  — insufficient baseline`);
      continue;
    }
    console.log(`  ${g} ${String(r.q).padEnd(6)} ${String(r.p).padEnd(8)} ${(r.coverage * 100).toFixed(0).padStart(7)}%`
      + `${(r.bucketRate * 100).toFixed(1).padStart(10)}%`
      + `${r.alertsDay.toFixed(2).padStart(18)}`
      + `${r.sens === null ? '      n/a' : `${(r.sens * 100).toFixed(0)}% (${r.detected}/${r.planted})`.padStart(15)}`);
  }

  // ⛔ A recommendation is only offered among configurations that ACTUALLY
  // DETECT planted events. Ranking on false positives alone would crown the
  // blindest configuration in the sweep.
  const viable = results.filter((r) => r.usable && r.sens !== null && r.sens >= 0.9 && r.alertsDay <= 3);
  viable.sort((a, b) => a.alertsDay - b.alertsDay);
  console.log('\n  Viable (>=90% of planted events found AND <=3 false alerts/day fleet-wide):');
  if (viable.length === 0) {
    console.log('    NONE — do not ship a detector on this data. Either the history is too short');
    console.log('    or the method is wrong; both are answers, and neither is "pick the quietest".');
  } else {
    for (const r of viable.slice(0, 5)) {
      console.log(`    ${r.grain} q=${r.q} persist=${r.p} -> ${r.alertsDay.toFixed(2)} false alerts/day, `
        + `${(r.sens * 100).toFixed(0)}% sensitivity`);
    }
  }
  console.log('\n  ⛔ THIS IS SYNTHETIC. It validates that the harness can tell a good configuration');
  console.log('     from a blind one. It does NOT choose the shipping threshold — real firewall');
  console.log('     traffic is what falsified the last method, and only real rollups can pick.');
}

if (require.main === module) {
  try { main(); } catch (e) { console.error('[a6Harness]', e.message); process.exit(1); }
}

module.exports = { parseArgs, syntheticSeries, plantAnomalies, split, evaluate, rng, METRICS,
  plantCollapse, runCollapseDetector, COLLAPSE_SQL,
  wilson, sensText };
