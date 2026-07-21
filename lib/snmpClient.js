// lib/snmpClient.js
// Shared net-snmp session/get wrapper for every vendor adapter's optional
// getSnmpMetrics() capability. CommonJS ONLY — required by adapters which
// are in turn required by services/engine-worker.js (plain node).
//
// FROZEN CONTRACT — every vendor's getSnmpMetrics() is built against this
// exact API. Do not change signatures without updating every adapter that
// consumes this module (cisco_asa, fortinet, paloalto, forcepoint, sangfor).
//
// Why an outer hard timeout wraps every call: net-snmp's own `timeout`
// option only bounds a single request/retry cycle at the PDU level — it has
// documented edge cases (a wrong SNMPv3 auth/priv passphrase in particular)
// where the callback never fires at all. An outer Promise.race with a
// second, slightly longer deadline guarantees this module always settles,
// even if net-snmp's own internal timeout logic doesn't.

'use strict';

const snmp = require('net-snmp');

const DEFAULT_TIMEOUT_MS = 8000;
const DEFAULT_RETRIES = 1;
// Outer hard-timeout margin over the per-request timeout passed to
// createSession — gives net-snmp's own timeout/retry cycle a chance to fire
// normally first; this is strictly a backstop for the cases it doesn't.
const HARD_TIMEOUT_MARGIN_MS = 3000;

const AUTH_PROTOCOL_MAP = {
  MD5: snmp.AuthProtocols.md5,
  SHA: snmp.AuthProtocols.sha,
};
const PRIV_PROTOCOL_MAP = {
  DES: snmp.PrivProtocols.des,
  AES: snmp.PrivProtocols.aes,
};

/**
 * @param {{version:'v1'|'v2c',community:string}|{version:'v3',username:string,authProtocol:string|null,authPassword:string|null,privProtocol:string|null,privPassword:string|null}} credential
 *   — the shape returned by lib/adapters/snmpCredential.js's parseSnmpCredential.
 * @param {string} host
 * @param {number} port
 * @param {number} [timeoutMs]
 * @returns {import('net-snmp').Session}
 */
function createSession(credential, host, port, timeoutMs = DEFAULT_TIMEOUT_MS) {
  if (!credential || !host) {
    throw new Error('createSession requires a parsed SNMP credential and a target host');
  }

  const options = { port: port || 161, timeout: timeoutMs, retries: DEFAULT_RETRIES, version: snmp.Version2c };

  if (credential.version === 'v3') {
    const hasAuth = Boolean(credential.authProtocol && credential.authPassword);
    const hasPriv = Boolean(hasAuth && credential.privProtocol && credential.privPassword);
    const level = hasPriv
      ? snmp.SecurityLevel.authPriv
      : hasAuth
        ? snmp.SecurityLevel.authNoPriv
        : snmp.SecurityLevel.noAuthNoPriv;

    const user = {
      name: credential.username,
      level,
    };
    if (hasAuth) {
      user.authProtocol = AUTH_PROTOCOL_MAP[credential.authProtocol] || snmp.AuthProtocols.sha;
      user.authKey = credential.authPassword;
    }
    if (hasPriv) {
      user.privProtocol = PRIV_PROTOCOL_MAP[credential.privProtocol] || snmp.PrivProtocols.aes;
      user.privKey = credential.privPassword;
    }

    return snmp.createV3Session(host, user, { port: port || 161, timeout: timeoutMs, retries: DEFAULT_RETRIES });
  }

  options.version = credential.version === 'v1' ? snmp.Version1 : snmp.Version2c;
  return snmp.createSession(host, credential.community, options);
}

function withHardTimeout(promise, timeoutMs, label, host) {
  let timer;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      reject(
        new Error(
          `SNMP ${label} to ${host} timed out after ${timeoutMs + HARD_TIMEOUT_MARGIN_MS}ms — no response. ` +
            'Check the community string / SNMPv3 credentials, that SNMP is enabled on the device, and that ' +
            'firewall/ACL rules allow UDP/161 from this server.'
        )
      );
    }, timeoutMs + HARD_TIMEOUT_MARGIN_MS);
  });
  return Promise.race([promise, timeoutPromise]).finally(() => clearTimeout(timer));
}

/**
 * GETs a flat map of named scalar OIDs. A per-OID error (no such
 * instance/object, or an OID this device doesn't implement) resolves that
 * one entry to null rather than failing the whole call — most vendors don't
 * implement every OID in a metric set, and a partial result is still useful
 * (mirrors this codebase's "a partial object catalog is still useful data"
 * philosophy for optional collection — see lib/adapters/interface.js's
 * getObjects() contract).
 *
 * @param {import('net-snmp').Session} session
 * @param {Object<string,string>} oidMap  metricName -> dotted OID string
 * @param {number} [timeoutMs]
 * @param {string} [host] for the timeout error message only
 * @returns {Promise<Object<string,string|null>>}
 */
function getMetrics(session, oidMap, timeoutMs = DEFAULT_TIMEOUT_MS, host = 'device') {
  const names = Object.keys(oidMap);
  const oids = names.map((n) => oidMap[n]);

  const p = new Promise((resolve, reject) => {
    session.get(oids, (err, varbinds) => {
      if (err) return reject(err);
      const out = {};
      names.forEach((name, i) => {
        const vb = varbinds[i];
        if (!vb || snmp.isVarbindError(vb)) {
          out[name] = null;
        } else {
          out[name] = vb.value && typeof vb.value.toString === 'function' ? vb.value.toString() : vb.value;
        }
      });
      resolve(out);
    });
  });

  return withHardTimeout(p, timeoutMs, 'get', host);
}

/**
 * WALKs a subtree, collecting {oid, value} rows. Used where a metric is a
 * table (e.g. per-processor CPU load) rather than a scalar. Same per-row
 * error tolerance as getMetrics — a row that errors is skipped, not fatal.
 *
 * @param {import('net-snmp').Session} session
 * @param {string} baseOid
 * @param {number} [timeoutMs]
 * @param {string} [host]
 * @returns {Promise<Array<{oid:string,value:*}>>}
 */
function walkSubtree(session, baseOid, timeoutMs = DEFAULT_TIMEOUT_MS, host = 'device') {
  const rows = [];
  const p = new Promise((resolve, reject) => {
    session.subtree(
      baseOid,
      (varbinds) => {
        for (const vb of varbinds) {
          if (vb && !snmp.isVarbindError(vb)) {
            rows.push({ oid: vb.oid, value: vb.value && typeof vb.value.toString === 'function' ? vb.value.toString() : vb.value });
          }
        }
      },
      (err) => {
        if (err) return reject(err);
        resolve(rows);
      }
    );
  });
  return withHardTimeout(p, timeoutMs, 'walk', host);
}

function closeSession(session) {
  if (!session) return;
  try {
    session.close();
  } catch (_err) {
    // best-effort — nothing meaningful to do if close() itself throws
  }
}

module.exports = { createSession, getMetrics, walkSubtree, closeSession, DEFAULT_TIMEOUT_MS };
