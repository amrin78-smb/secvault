#!/usr/bin/env node
'use strict';

// scripts/mockSyslog.js — emit synthetic firewall syslog at a controlled rate.
//
// Exercises the real path: collector -> syslogParser -> vendorParsers -> spool
// -> syslog_events -> hourly rollups -> rule-hit correlation -> log-derived rule
// usage. None of that can be tested from stored data alone.
//
// ⛔ THE LINE SHAPES COME FROM THE PARSER FIXTURES, NOT FROM VENDOR DOCS. This
// repo's rule is that every vendor field mapping was read off REAL CAPTURED
// LOGS, because documentation lies. A generator invented from documentation
// would test the parser against the same guess the parser was written from, and
// agree with itself.
//
// ⛔ DEFAULTS TO localhost:1514, NOT :514. Sending to loopback needs no inbound
// firewall rule and exposes nothing; 1514 avoids the privileged port entirely.
// SecVault listens on both by default (SYSLOG_UDP_PORT=514,1514).
//
// ⛔ RATE-LIMITED AND FINITE BY DEFAULT. The reference fleet produces ~93M
// events/day and ~31GB/day of raw rows; an unbounded generator pointed at a
// laptop would fill its disk. `--count` bounds the run and `--rate` bounds the
// pressure, so a mistake costs seconds rather than a volume.
//
// \u26d4 DO NOT SIZE STORAGE FROM THIS. The action mix here is deliberately
// denial-heavy so both branches of SYSLOG_RAW_MESSAGE=security get exercised,
// which keeps the raw line on ~31% of rows. The live fleet's figure is ~8.3%,
// so bytes/row measured against mock traffic over-states production by ~3x.
// Size from events/sec on the real fleet, per docs/SIZING-AND-BACKUP.md.
//
// Usage:
//   node scripts/mockSyslog.js --count 5000 --rate 200
//   node scripts/mockSyslog.js --host 127.0.0.1 --port 1514 --count 100000 --rate 1000
//   node scripts/mockSyslog.js --dry-run --count 5      # print, send nothing

const dgram = require('node:dgram');

const DEFAULTS = { host: '127.0.0.1', port: 1514, count: 1000, rate: 200 };

// Mock devices' source addresses. ⛔ These must match `devices.mgmt_ip` in
// scripts/seedMockFleet.js, or the collector stores every event with
// `device_id NULL` — which it is RIGHT to do (an unmatched sender is still
// evidence) but which means none of the rule-hit correlation lights up.
const SENDERS = {
  fortinet: '10.99.0.11',
  paloalto: '10.99.0.21',
};

function pick(a) { return a[Math.floor(Math.random() * a.length)]; }
function ip(prefix) { return `${prefix}.${1 + Math.floor(Math.random() * 253)}`; }

/**
 * FortiOS key=value, the shape `vendorParsers.js` parses.
 *
 * ⛔ THREE TIMESTAMP PATHS ARE EXERCISED ON PURPOSE, and the first draft of
 * this function exercised NONE of them. It emitted `date=` and `time=` with no
 * `tz=` and no `eventtime=`, so `parseFortinet` correctly refused to invent a
 * zone and every mock Fortinet event carried a NULL `eventAt` — right
 * behaviour, and it meant the mock fleet never tested the timestamp logic at
 * all. The live fleet sends both fields. So:
 *
 *   ~70%  `eventtime` (19-digit NANOSECOND epoch) + `tz`  -> the preferred path
 *   ~20%  no `eventtime`, but `date`+`time`+`tz`          -> the fallback path
 *   ~10%  no `eventtime` and no `tz`                      -> eventAt stays NULL
 *
 * ⛔ That last 10% is the one that matters most here. An unanchored local time
 * is exactly the ambiguity this codebase refuses to guess at, and a generator
 * that never produces it would leave the refusal untested — the same reason the
 * seeded fleet carries a device nothing could be collected from.
 */
function fortinetLine(now) {
  const ts = now.toISOString();
  const date = ts.slice(0, 10);
  const time = ts.slice(11, 19);
  // ⛔ NANOSECONDS, 19 digits. `parseFortinet` scales by DIGIT LENGTH, so a
  // 16-digit value is read as microseconds and silently backdates the row to
  // 1970 — a wrong-length epoch is worse than none, because the row is present
  // and simply outside every time window.
  const roll = Math.random();
  const eventtime = roll < 0.7 ? `eventtime=${now.getTime()}000000 ` : '';
  const tz = roll < 0.9 ? 'tz="+0700" ' : '';
  // ⛔ `close` and `client-rst` are deliberately represented: CLAUDE.md records
  // that FortiGate logs a session that was established and then ended as
  // close/client-rst, NEVER as `allow`, and that matching only `allow` misses
  // the most exposed service on the fleet.
  const action = pick(['accept', 'close', 'client-rst', 'deny', 'accept', 'close']);
  const policyid = 1 + Math.floor(Math.random() * 6);
  const dstport = pick([443, 53, 22, 10443, 80, 3389]);
  return `<189>date=${date} time=${time} ${eventtime}${tz}devname="MOCK-FGT-Branch-01" devid="FGMOCK0000000001" `
    + `logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" `
    + `srcip=${ip('10.1.0')} srcport=${1024 + Math.floor(Math.random() * 60000)} srcintf="internal" `
    + `dstip=${ip('203.0.113')} dstport=${dstport} dstintf="wan1" `
    + `policyid=${policyid} sessionid=${Math.floor(Math.random() * 9e6)} proto=6 action="${action}" `
    + `policytype="policy" service="${dstport === 443 ? 'HTTPS' : 'tcp/' + dstport}" `
    + `duration=${Math.floor(Math.random() * 300)} sentbyte=${Math.floor(Math.random() * 90000)} `
    + `rcvdbyte=${Math.floor(Math.random() * 900000)}`;
}

const MON = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

/** RFC 3164 header: `Mmm _d HH:MM:SS` — the day is SPACE-padded, not zero-padded. */
function rfc3164Stamp(d) {
  const day = String(d.getDate()).padStart(2, ' ');
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  return `${MON[d.getMonth()]} ${day} ${hh}:${mm}:${ss}`;
}

/**
 * PAN-OS positional CSV TRAFFIC log.
 *
 * ⛔ TWO FORMAT DETAILS THAT THE PARSER ACTUALLY REQUIRES, both of which the
 * first draft of this generator got wrong — and the only reason that was caught
 * is that the lines were run through the REAL parser instead of being eyeballed:
 *
 *  1. The receive-time field is `YYYY/MM/DD HH:MM:SS` with SLASHES. An ISO
 *     `YYYY-MM-DD` fails `PALOALTO_RE` outright.
 *  2. `PALOALTO_RE` is ANCHORED, so the CSV must begin the syslog MESSAGE —
 *     which means a valid RFC 3164 header (`<pri>Mmm _d HH:MM:SS host `) has to
 *     precede it so `syslogParser` strips it. With an unparseable header the
 *     frame stays `pri-only`, the message keeps the timestamp and hostname, and
 *     `detectVendor` returns null.
 *
 * The cost of getting this wrong is quiet: the collector still STORES the event
 * (an unmatched sender is evidence, and dropping it would make the fleet look
 * quieter than it is) — it just stores it with no vendor and no device, so
 * nothing correlates and the mock fleet looks like it produced no Palo Alto
 * traffic at all.
 */
function paloAltoLine(now) {
  const pan = `${now.getFullYear()}/${String(now.getMonth() + 1).padStart(2, '0')}/`
    + `${String(now.getDate()).padStart(2, '0')} `
    + `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:`
    + `${String(now.getSeconds()).padStart(2, '0')}`;
  const ts = pan;
  // ⛔ `reset-both` is included and is a BLOCK (PAN-OS's IPS resetting both
  // ends) — it looks like Fortinet's `close` family and is the opposite.
  const action = pick(['allow', 'allow', 'deny', 'drop', 'reset-both']);
  const rule = pick(['app-to-db', 'users-to-app', 'outbound-web', 'default-deny']);
  const dport = pick([1521, 8443, 443, 445]);
  return `<14>${rfc3164Stamp(now)} MOCK-PAN-DC-01 1,${ts},001801000000,TRAFFIC,end,2561,${ts},`
    + `${ip('10.20.5')},${ip('10.20.9')},0.0.0.0,0.0.0.0,${rule},,,`
    + `${dport === 443 ? 'ssl' : 'oracle'},vsys1,users,db,ethernet1/1,ethernet1/2,`
    + `MOCK-LOG,${ts},${Math.floor(Math.random() * 9e5)},1,`
    + `${1024 + Math.floor(Math.random() * 60000)},${dport},0,0,0x0,tcp,${action},`
    + `${Math.floor(Math.random() * 90000)},${Math.floor(Math.random() * 500)},`
    + `${Math.floor(Math.random() * 400)},${Math.floor(Math.random() * 60)}`;
}

function parseArgs(argv) {
  const o = Object.assign({}, DEFAULTS, { dryRun: false });
  const raw = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--dry-run') { o.dryRun = true; continue; }
    const v = argv[i + 1];
    if (a === '--host') { o.host = v; i++; }
    else if (a === '--port') { raw.port = v; o.port = Number(v); i++; }
    else if (a === '--count') { raw.count = v; o.count = Number(v); i++; }
    else if (a === '--rate') { raw.rate = v; o.rate = Number(v); i++; }
  }
  // ⛔ A NaN from a typo must not become an unbounded run. Every numeric option
  // is validated, not coerced — `Number('fast')` is NaN and NaN comparisons are
  // false, which would silently remove the bound this file exists to keep.
  for (const k of ['port', 'count', 'rate']) {
    if (!Number.isFinite(o[k]) || o[k] <= 0) {
      // Report what was TYPED. `Number('fast')` is NaN and JSON.stringify(NaN)
      // is "null", so echoing the coerced value tells the reader nothing.
      throw new Error(`--${k} must be a positive number (got ${JSON.stringify(raw[k])})`);
    }
  }
  return o;
}

async function run(opts) {
  const sock = opts.dryRun ? null : dgram.createSocket('udp4');
  let sent = 0;
  const started = Date.now();
  const perTick = Math.max(1, Math.round(opts.rate / 10));
  const tickMs = 100;

  return new Promise((resolve, reject) => {
    const timer = setInterval(() => {
      try {
        for (let i = 0; i < perTick && sent < opts.count; i++) {
          const now = new Date();
          const fortinet = Math.random() < 0.6;
          const line = fortinet ? fortinetLine(now) : paloAltoLine(now);
          if (opts.dryRun) {
            console.log(`[${fortinet ? 'fortinet' : 'paloalto'} from ${fortinet ? SENDERS.fortinet : SENDERS.paloalto}] ${line}`);
          } else {
            sock.send(Buffer.from(line), opts.port, opts.host);
          }
          sent++;
        }
        if (sent >= opts.count) {
          clearInterval(timer);
          if (sock) sock.close();
          const secs = (Date.now() - started) / 1000;
          console.log(`[mockSyslog] sent ${sent} events to ${opts.host}:${opts.port} in `
            + `${secs.toFixed(1)}s (~${Math.round(sent / Math.max(secs, 0.001))}/sec)`);
          // \u26d4 SENT IS NOT RECEIVED, AND THIS LINE EXISTS SO NOBODY READS IT
          // AS ONE. UDP drops under burst even on loopback: measured here,
          // 360 of 400 arrived at 400/sec with an 8 MB receive buffer. So a
          // shortfall in `syslog_ingest_stats` after a run is EXPECTED and is
          // not by itself a collector defect \u2014 and matching numbers are not
          // proof there was no loss either. Read the collector's own `dropped`
          // counter, which is the only thing that distinguishes "the buffer
          // overflowed" from "the network lost it".
          if (!opts.dryRun) {
            console.log('[mockSyslog] note: UDP is lossy under burst \u2014 `sent` is what this '
              + 'process emitted, NOT what arrived. Compare against syslog_ingest_stats '
              + '(received/parsed/stored/dropped), not against this number.');
          }
          resolve(sent);
        }
      } catch (err) {
        clearInterval(timer);
        if (sock) sock.close();
        reject(err);
      }
    }, tickMs);
  });
}

if (require.main === module) {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (e) {
    console.error(`[mockSyslog] ${e.message}`);
    process.exit(1);
  }
  run(opts).catch((e) => { console.error('[mockSyslog]', e.message); process.exit(1); });
}

module.exports = { fortinetLine, paloAltoLine, parseArgs, SENDERS };
