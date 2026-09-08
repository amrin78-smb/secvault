// lib/syslog/collectorConfig.js
//
// Configuration parsing for services/collector.js. Pure and dependency-free so
// it can be unit-tested — the collector itself binds sockets on load and
// cannot be imported in a test.
//
// ⛔ WHY MULTI-PORT EXISTS. The collector originally bound a single port (514)
// and saw almost nothing: host-wide UDP fell from ~1,373/sec under Firewall
// Analyzer to ~7.5/sec. FWA listened on BOTH 514 and 1514, and ManageEngine's
// documented default for Firewall Analyzer is UDP **1514** — so most of the
// fleet had been configured to 1514 and was still sending there, into a port
// nothing was holding. Datagrams sent to an unbound UDP port are discarded
// silently by the OS; there is no error anywhere to notice.
//
// The lesson is the one this codebase keeps relearning: "we are listening and
// receiving nothing" and "we are not listening where they are sending" look
// identical from the inside. Accepting a LIST is what makes a migration from
// another collector survivable.

'use strict';

const MIN_PORT = 1;
const MAX_PORT = 65535;

/**
 * Parse a port list like "514,1514" or a single "514".
 *
 * ⛔ Returns the DEFAULTS when the value is absent, and drops only the invalid
 * entries when some are usable — a typo in one port must not silently take the
 * collector deaf on the others. Duplicates are collapsed because binding the
 * same port twice throws EADDRINUSE against ourselves.
 *
 * @param {string|undefined} raw
 * @param {number[]} defaults
 * @returns {{ports: number[], rejected: string[], usedDefault: boolean}}
 */
function parsePortList(raw, defaults) {
  const fallback = Array.isArray(defaults) ? defaults.slice() : [];
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return { ports: fallback, rejected: [], usedDefault: true };
  }
  const ports = [];
  const rejected = [];
  for (const piece of String(raw).split(',')) {
    const token = piece.trim();
    if (token === '') continue;
    // Reject anything that is not purely digits BEFORE Number(), because
    // Number(' 514 ') and Number('514abc') behave very differently and only
    // one of them is a port.
    if (!/^\d+$/.test(token)) { rejected.push(token); continue; }
    const n = Number(token);
    if (!Number.isInteger(n) || n < MIN_PORT || n > MAX_PORT) { rejected.push(token); continue; }
    if (!ports.includes(n)) ports.push(n);
  }
  if (ports.length === 0) {
    // Everything was junk. Fall back rather than start a collector that
    // listens nowhere and looks healthy doing it.
    return { ports: fallback, rejected, usedDefault: true };
  }
  return { ports, rejected, usedDefault: false };
}

/**
 * Bounded integer from the environment.
 * @returns {{value: number, usedDefault: boolean, reason: string|null}}
 */
function intSetting(raw, def, min, max) {
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return { value: def, usedDefault: true, reason: null };
  }
  const n = Number(String(raw).trim());
  if (!Number.isFinite(n)) return { value: def, usedDefault: true, reason: 'not a number' };
  const t = Math.trunc(n);
  if (min !== undefined && t < min) return { value: def, usedDefault: true, reason: `below ${min}` };
  if (max !== undefined && t > max) return { value: def, usedDefault: true, reason: `above ${max}` };
  return { value: t, usedDefault: false, reason: null };
}

module.exports = { parsePortList, intSetting, MIN_PORT, MAX_PORT };
