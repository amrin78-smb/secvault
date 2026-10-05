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
  const o = { synthetic: false, days: 28, metric: 'events', devices: 16, seed: 42, train: 0.7 };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--synthetic') { o.synthetic = true; continue; }
    const v = argv[i + 1];
    if (a === '--days') { o.days = Number(v); i += 1; }
    else if (a === '--metric') { o.metric = v; i += 1; }
    else if (a === '--devices') { o.devices = Number(v); i += 1; }
    else if (a === '--train') { o.train = Number(v); i += 1; }
  }
  if (!Number.isFinite(o.days) || o.days <= 0) throw new Error(`--days must be positive (got ${JSON.stringify(o.days)})`);
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
function plantAnomalies(rows, rand, count = 6, lengthHours = 3, magnitude = 6) {
  const planted = [];
  const usable = rows.length - lengthHours - 1;
  if (usable <= 0) return planted;
  // The device's own normal level, used as the unit of "how big is this spike".
  const positives = rows.map((r) => r.value).filter((v) => v > 0).sort((a, b) => a - b);
  const reference = positives.length
    ? positives[Math.floor(positives.length * 0.5)]
    : 1;
  for (let i = 0; i < count; i += 1) {
    const at = Math.floor(rand() * usable);
    for (let k = 0; k < lengthHours; k += 1) {
      rows[at + k].value = Math.round(rows[at + k].value + reference * magnitude);
    }
    planted.push({ start: at, length: lengthHours, reference, magnitude });
  }
  return planted;
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
  const planted = devices.map((d) => {
    const copy = d.map((r) => ({ at: r.at, value: r.value }));
    return { copy, windows: plantAnomalies(copy, rand) };
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
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
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

module.exports = { parseArgs, syntheticSeries, plantAnomalies, split, evaluate, rng, METRICS };
