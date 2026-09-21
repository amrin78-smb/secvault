#!/usr/bin/env node
'use strict';
//
// scripts/analyseFwaArchive.js — can we actually read the preserved FWA
// archive, and what would an import produce?
//
// ⛔ READ-ONLY. No database connection, no writes, no deletions. This exists to
// answer the questions that decide whether the import is worth running at all,
// BEFORE anything touches a permanent table:
//
//   1. Do SecVault's own parsers read these lines, and what fraction fails?
//   2. Which vendor is each sender, and does it map to a device we still have?
//   3. What timestamp can we honestly assign, given RFC 3164 carries no year?
//   4. How many rollup rows would nine months actually produce?
//   5. How fast does it go — i.e. how long is the real batch run?
//
// ⛔ EVERY FAILURE IS COUNTED AND CATEGORISED, never skipped quietly. An
// importer that silently drops what it cannot parse produces a history that is
// wrong by an amount nobody can measure afterwards, which is worse than no
// history — the same rule the collector already applies to unparsed datagrams.
//
// Usage (on the SecVault server, where the archive lives):
//   node scripts/analyseFwaArchive.js --root E:\FWA_archive_preserved --files 20

const fs = require('node:fs');
const path = require('node:path');

const { listEntries, streamEntryLines, stampFromName, senderFromPath } = require('./fwaArchive');
const { parseSyslogLine } = require('../lib/syslog/syslogParser');
const { parseVendorPayload } = require('../lib/syslog/vendorParsers');
const { classifyAction } = require('../lib/syslog/actions');

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const ROOT = arg('root', 'E:\\FWA_archive_preserved');
const MAX_FILES = Number(arg('files', 20));
const MAX_LINES_PER_ENTRY = Number(arg('lines', 0)); // 0 = no cap

function walkZips(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walkZips(p, out);
    else if (e.name.toLowerCase().endsWith('.zip')) out.push(p);
  }
  return out;
}

const stats = {
  filesTried: 0, filesFailed: 0, entries: 0, lines: 0,
  frameFailed: 0, payloadEmpty: 0, noTimestamp: 0,
  bytesUncompressed: 0,
  vendors: new Map(),
  senders: new Map(),
  actions: new Map(),
  logClasses: new Map(),
  buckets: new Set(),
  ruleBuckets: new Set(),
  oldest: null, newest: null,
  fileErrors: [],
};

const bump = (m, k) => m.set(k, (m.get(k) || 0) + 1);

function noteLine(sender, fileStamp, line) {
  stats.lines++;
  let frame;
  try {
    // The archive has no received_at of its own; FWA's rotation stamp is the
    // only trustworthy anchor for the YEAR, which RFC 3164 omits.
    frame = parseSyslogLine(line, fileStamp);
  } catch {
    stats.frameFailed++;
    return;
  }
  if (!frame || !frame.message) { stats.frameFailed++; return; }

  const payload = parseVendorPayload(frame.message);
  if (!payload || !payload.vendor) { stats.payloadEmpty++; }

  const vendor = (payload && payload.vendor) || 'unparsed';
  bump(stats.vendors, vendor);

  // ⛔ THE HONEST TIMESTAMP. Live rows bucket on received_at ("when WE observed
  // it"); nothing here was observed by SecVault. The best available statement
  // is the event's own time, anchored to the file's year.
  // Vendor payload time first (PAN-OS and FortiOS both carry a full date);
  // the RFC 3164 frame time, year-anchored by the file stamp, is the fallback.
  const when = (payload && payload.eventAt) || frame.eventAt || null;
  if (!when) { stats.noTimestamp++; return; }
  const t = when instanceof Date ? when : new Date(when);
  if (Number.isNaN(t.getTime())) { stats.noTimestamp++; return; }

  if (stats.oldest === null || t < stats.oldest) stats.oldest = t;
  if (stats.newest === null || t > stats.newest) stats.newest = t;

  const hour = new Date(Math.floor(t.getTime() / 3600000) * 3600000).toISOString();
  const action = (payload && payload.action) || null;
  const logClass = (payload && payload.logClass) || null;
  bump(stats.actions, action === null ? '(none)' : `${action} -> ${classifyAction(action)}`);
  bump(stats.logClasses, logClass || '(none)');

  // The grain of syslog_rollup_hourly, minus device_id (resolved at import).
  stats.buckets.add(`${hour}|${sender}|${vendor}|${action}|${frame.severity}|${logClass}`);
  const rule = (payload && (payload.ruleName || payload.ruleId)) || null;
  if (rule) stats.ruleBuckets.add(`${hour}|${sender}|${vendor}|${rule}|${action}`);
}

(async () => {
  const started = Date.now();
  console.log(`[fwa-analyse] root ${ROOT}`);
  if (!fs.existsSync(ROOT)) {
    console.error(`[fwa-analyse] not found: ${ROOT}`);
    process.exit(2);
  }

  const all = walkZips(ROOT);
  console.log(`[fwa-analyse] ${all.length.toLocaleString()} zip files found`);

  // Spread the sample across the whole corpus — the first N are all December
  // and all from one sender, which would prove nothing about the rest.
  const step = Math.max(1, Math.floor(all.length / MAX_FILES));
  const sample = all.filter((_, i) => i % step === 0).slice(0, MAX_FILES);
  console.log(`[fwa-analyse] sampling ${sample.length} of them, evenly spread\n`);

  for (const file of sample) {
    stats.filesTried++;
    const rel = path.relative(ROOT, file);
    const sender = senderFromPath(rel) || '(unknown)';
    bump(stats.senders, sender);
    let entries;
    try {
      entries = listEntries(file);
    } catch (err) {
      stats.filesFailed++;
      stats.fileErrors.push(`${rel}: ${err.message}`);
      continue;
    }
    for (const entry of entries) {
      stats.entries++;
      stats.bytesUncompressed += entry.uncompressedSize;
      const stamp = stampFromName(entry.name) || stampFromName(path.basename(file));
      if (!stamp) { stats.fileErrors.push(`${rel}#${entry.name}: no date in the name`); continue; }
      let seen = 0;
      try {
        await streamEntryLines(file, entry, (line) => {
          if (MAX_LINES_PER_ENTRY && seen >= MAX_LINES_PER_ENTRY) return;
          seen++;
          noteLine(sender, stamp, line);
        });
      } catch (err) {
        stats.filesFailed++;
        stats.fileErrors.push(`${rel}#${entry.name}: ${err.message}`);
      }
    }
  }

  const secs = (Date.now() - started) / 1000;
  const mb = stats.bytesUncompressed / 1048576;
  const top = (m, n = 8) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n)
    .map(([k, v]) => `    ${String(k).slice(0, 62).padEnd(62)} ${v.toLocaleString()}`).join('\n');

  console.log('── files ───────────────────────────────────────────────');
  console.log(`  tried ${stats.filesTried}, failed ${stats.filesFailed}, entries ${stats.entries}`);
  console.log(`  uncompressed ${mb.toFixed(1)} MB in ${secs.toFixed(1)}s  =>  ${(mb / secs).toFixed(1)} MB/s`);
  console.log('── lines ───────────────────────────────────────────────');
  console.log(`  total ${stats.lines.toLocaleString()}`);
  console.log(`  frame unparseable ${stats.frameFailed.toLocaleString()}`);
  console.log(`  vendor payload empty ${stats.payloadEmpty.toLocaleString()}`);
  console.log(`  NO USABLE TIMESTAMP ${stats.noTimestamp.toLocaleString()}`);
  console.log('── vendors ─────────────────────────────────────────────');
  console.log(top(stats.vendors));
  console.log('── senders sampled ─────────────────────────────────────');
  console.log(top(stats.senders, 10));
  console.log('── action -> classified ────────────────────────────────');
  console.log(top(stats.actions, 10));
  console.log('── log_class ───────────────────────────────────────────');
  console.log(top(stats.logClasses, 8));
  console.log('── what would be written ───────────────────────────────');
  console.log(`  event span ${stats.oldest ? stats.oldest.toISOString() : '-'} .. ${stats.newest ? stats.newest.toISOString() : '-'}`);
  console.log(`  syslog_rollup_hourly rows (this sample)    ${stats.buckets.size.toLocaleString()}`);
  console.log(`  syslog_rule_hits_hourly rows (this sample) ${stats.ruleBuckets.size.toLocaleString()}`);
  if (stats.lines > 0) {
    const perLine = stats.buckets.size / stats.lines;
    console.log(`  => ~${perLine.toFixed(6)} rollup rows per event`);
  }
  if (stats.fileErrors.length) {
    console.log('── failures (first 15) ─────────────────────────────────');
    console.log(stats.fileErrors.slice(0, 15).map((e) => `    ${e}`).join('\n'));
  }
})().catch((err) => {
  console.error('[fwa-analyse] failed:', err && err.stack ? err.stack : err);
  process.exit(3);
});
