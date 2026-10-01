#!/usr/bin/env node
'use strict';

// scripts/seedMockFleet.js — a mock fleet, for a TEST database only.
//
// Inserts devices, versions, rulesets and parsed configs directly, bypassing the
// adapters. Every read-time engine then has something real to chew on: CVE
// matching, compliance, rule hygiene, segmentation, applications, the work
// queue, the coverage register and remediation velocity.
//
// ── ⛔ IT REFUSES TO RUN AGAINST ANYTHING THAT LOOKS LIKE PRODUCTION ──────
//
// This writes fabricated firewalls into a database. On the real fleet that is
// not a test fixture, it is corrupted evidence on a security product — mock
// rules would feed real compliance scores, real CVE assessments and real
// deletion recommendations, and nothing downstream could tell them apart.
// So the guard is expressed THREE ways and all three must pass: an explicit
// --i-know confirmation, a database name that declares itself a test, and a
// refusal of the production host. A single flag is too easy to paste.
//
// ⛔ EVERY MOCK DEVICE IS NAMED `MOCK-…`, so anything that leaks into a report
// is identifiable on sight rather than looking like a firewall somebody owns.
//
// ── ⛔ THE DATA IS DELIBERATELY UNEVEN ───────────────────────────────────
//
// A uniformly healthy fleet proves nothing: it exercises only the green path,
// and this codebase's whole failure mode is a gap rendered as a fact. So the
// seed includes, on purpose:
//   - a device with NULL hit_count on every rule (the Fortinet-over-SSH shape)
//     so `unused` must NOT be claimed — a measured zero and an unmeasured one
//     have to come out different;
//   - a device with NO ruleset and NO config at all, which must read as a
//     coverage gap rather than as the healthiest firewall on the fleet;
//   - a device whose version string is unparseable, so the upgrade planner has
//     to report `unreadable_running_version` instead of guessing a branch;
//   - rules that are genuinely shadowed, genuinely duplicated, and genuinely
//     any-any, so the hygiene findings are real rather than manufactured.
//
// Usage:
//   DATABASE_URL=postgres://…/secvault_mock node scripts/seedMockFleet.js --i-know
//   …add --wipe to clear previously-seeded MOCK- devices first.

const { Pool } = require('pg');

const PRODUCTION_HOSTS = ['192.168.7.69'];
const NAME_PREFIX = 'MOCK-';

function parseArgs(argv) {
  return {
    confirmed: argv.includes('--i-know'),
    wipe: argv.includes('--wipe'),
  };
}

/** ⛔ Three independent refusals; see the header for why one is not enough. */
function assertSafeTarget(urlString, confirmed) {
  if (!urlString) {
    throw new Error('DATABASE_URL is not set. Point it at a TEST database.');
  }
  let url;
  try {
    url = new URL(urlString);
  } catch {
    throw new Error('DATABASE_URL could not be parsed.');
  }
  const dbName = decodeURIComponent((url.pathname || '').replace(/^\//, ''));
  const host = url.hostname;

  if (PRODUCTION_HOSTS.includes(host)) {
    throw new Error(
      `REFUSING: ${host} is the production fleet server. This script writes fabricated `
      + 'firewalls; on production they would feed real compliance scores and real CVE '
      + 'assessments with nothing downstream able to tell them apart.'
    );
  }
  if (!/mock|test|staging|scratch/i.test(dbName)) {
    throw new Error(
      `REFUSING: database "${dbName}" does not declare itself a test database. Name it with `
      + 'mock/test/staging/scratch so a mis-pasted URL cannot quietly seed something real.'
    );
  }
  if (!confirmed) {
    throw new Error('REFUSING: pass --i-know. This inserts fabricated firewalls.');
  }
  return { host, dbName };
}

// ── the fleet ──────────────────────────────────────────────────────────────

const RULES_FORTINET = [
  { seq: 1, name: 'Allow-Web-Out', action: 'allow', src: ['LAN-10.1.0.0_16'], dst: ['any'], svc: ['HTTPS', 'HTTP'], szone: ['internal'], dzone: ['wan'] },
  { seq: 2, name: 'Allow-DNS-Out', action: 'allow', src: ['LAN-10.1.0.0_16'], dst: ['DNS-Servers'], svc: ['DNS'], szone: ['internal'], dzone: ['wan'] },
  // ⛔ A genuine any-any allow, so `rule-no-any-any-allow` has something true to find.
  { seq: 3, name: 'TEMP-Troubleshooting', action: 'allow', src: ['any'], dst: ['any'], svc: ['ALL'], szone: ['any'], dzone: ['any'] },
  // ⛔ Shadowed by #3 above it: unreachable in practice.
  { seq: 4, name: 'Allow-SSH-Mgmt', action: 'allow', src: ['MGMT-10.9.0.0_24'], dst: ['LAN-10.1.0.0_16'], svc: ['SSH'], szone: ['mgmt'], dzone: ['internal'] },
  // ⛔ A true duplicate of #2.
  { seq: 5, name: 'Allow-DNS-Out-dup', action: 'allow', src: ['LAN-10.1.0.0_16'], dst: ['DNS-Servers'], svc: ['DNS'], szone: ['internal'], dzone: ['wan'] },
  { seq: 6, name: 'Deny-All', action: 'deny', src: ['any'], dst: ['any'], svc: ['ALL'], szone: ['any'], dzone: ['any'] },
];

const RULES_PALOALTO = [
  { seq: 1, name: 'app-to-db', action: 'allow', src: ['10.20.1.0/24'], dst: ['10.20.9.0/24'], svc: ['tcp-1521'], szone: ['app'], dzone: ['db'] },
  { seq: 2, name: 'users-to-app', action: 'allow', src: ['10.20.5.0/24'], dst: ['10.20.1.0/24'], svc: ['tcp-8443'], szone: ['users'], dzone: ['app'] },
  { seq: 3, name: 'deny-users-to-db', action: 'deny', src: ['10.20.5.0/24'], dst: ['10.20.9.0/24'], svc: ['any'], szone: ['users'], dzone: ['db'] },
  { seq: 4, name: 'outbound-web', action: 'allow', src: ['10.20.0.0/16'], dst: ['any'], svc: ['service-https'], szone: ['trust'], dzone: ['untrust'] },
  { seq: 5, name: 'default-deny', action: 'deny', src: ['any'], dst: ['any'], svc: ['any'], szone: ['any'], dzone: ['any'] },
];

const DEVICES = [
  {
    name: `${NAME_PREFIX}FGT-Branch-01`,
    vendor: 'fortinet', mgmt_method: 'ssh', mgmt_ip: '10.99.0.11',
    site: 'Branch', criticality: 'medium',
    version: 'v7.4.9,build2702', tuple: [7, 4, 9, 0],
    rules: RULES_FORTINET,
    // ⛔ NULL, not 0 — Fortinet over SSH reports no hit counts at all. The whole
    // point of including this device is that `unused` must not be claimed here.
    hitCounts: null,
    config: {
      ssl_vpn: { 'source-interface': ['wan1'], 'ssl-min-proto-ver': 'tls1-2', 'idle-timeout': '300' },
      ntp: { ntpsync: 'enable' },
      dns: { primary: '10.1.0.53' },
      log_syslogd: { status: 'enable' },
      password_policy: { 'minimum-length': '8' },
      admins: [{ name: 'admin', accprofile: 'super_admin' }],
    },
  },
  {
    name: `${NAME_PREFIX}PAN-DC-01`,
    vendor: 'paloalto', mgmt_method: 'api', mgmt_ip: '10.99.0.21',
    site: 'DC', criticality: 'critical',
    version: '11.1.2-h3', tuple: [11, 1, 2, 3],
    rules: RULES_PALOALTO,
    // A real, MEASURED mix: some hits, one measured zero.
    hitCounts: [48210, 9123, 0, 77430, 1],
    config: {
      'mgt-config': { users: { entry: [{ '@name': 'admin', permissions: { 'role-based': { superuser: 'yes' } } }] } },
      deviceconfig: { system: { 'timezone': 'Asia/Bangkok', 'update-server': 'updates.paloaltonetworks.com' } },
    },
  },
  {
    name: `${NAME_PREFIX}FGT-Edge-02`,
    vendor: 'fortinet', mgmt_method: 'ssh', mgmt_ip: '10.99.0.12',
    site: 'Edge', criticality: 'high',
    // ⛔ Deliberately unparseable: the upgrade planner must report
    // `unreadable_running_version` rather than inventing branch "0.0".
    version: 'unknown', tuple: null,
    rules: RULES_FORTINET.slice(0, 3),
    hitCounts: null,
    config: {
      ssl_vpn: { 'source-interface': ['wan1', 'wan2'], 'ssl-min-proto-ver': 'tls1-1' },
      ntp: { ntpsync: 'disable' },
    },
  },
  {
    // ⛔ THE IMPORTANT ONE. No ruleset, no config, no version — a firewall
    // nothing could be collected from. It must surface as a COVERAGE GAP, not
    // as the healthiest device on the fleet, which is what it looks like
    // everywhere that counts findings.
    name: `${NAME_PREFIX}UNREACHABLE-03`,
    vendor: 'cisco_asa', mgmt_method: 'ssh', mgmt_ip: '10.99.0.31',
    site: 'Remote', criticality: 'high',
    version: null, tuple: null, rules: [], hitCounts: null, config: null,
    collected: false,
  },
];

async function seed(pool, { wipe }) {
  const out = { devices: 0, rules: 0, configs: 0, versions: 0, wiped: 0 };

  if (wipe) {
    const r = await pool.query('DELETE FROM devices WHERE name LIKE $1', [`${NAME_PREFIX}%`]);
    out.wiped = r.rowCount || 0;
  }

  for (const d of DEVICES) {
    const dev = await pool.query(
      `INSERT INTO devices (name, vendor, mgmt_method, mgmt_ip, site, asset_criticality,
                            active, last_connectivity_ok, last_collected_at)
       VALUES ($1,$2,$3,$4,$5,$6,true,$7,$8) RETURNING id`,
      [d.name, d.vendor, d.mgmt_method, d.mgmt_ip, d.site, d.criticality,
        d.collected === false ? false : true,
        // ⛔ NULL last_collected_at for the unreachable one — never now(), which
        // would assert a collection that did not happen.
        d.collected === false ? null : new Date()]
    );
    const id = dev.rows[0].id;
    out.devices++;

    if (d.version) {
      await pool.query(
        `INSERT INTO device_versions (device_id, version_string, version_tuple, collected_at)
         VALUES ($1,$2,$3::jsonb,now())`,
        [id, d.version, JSON.stringify(d.tuple)]
      );
      out.versions++;
    }

    if (d.config) {
      await pool.query(
        `INSERT INTO device_configs (device_id, config_raw, config_parsed, collected_at)
         VALUES ($1,$2,$3::jsonb,now())`,
        [id, `! mock config for ${d.name}`, JSON.stringify(d.config)]
      );
      out.configs++;
    }

    for (let i = 0; i < d.rules.length; i++) {
      const r = d.rules[i];
      const hit = d.hitCounts === null ? null
        : (d.hitCounts[i] === undefined ? null : d.hitCounts[i]);
      await pool.query(
        `INSERT INTO firewall_rules
           (device_id, rule_name, rule_id_vendor, sequence_number, enabled, action,
            src_zones, dst_zones, src_addresses, dst_addresses, services,
            log_enabled, hit_count, collected_at)
         VALUES ($1,$2,$3,$4,true,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9::jsonb,$10::jsonb,true,$11,now())`,
        [id, r.name, String(r.seq), r.seq, r.action,
          JSON.stringify(r.szone), JSON.stringify(r.dzone),
          JSON.stringify(r.src), JSON.stringify(r.dst), JSON.stringify(r.svc), hit]
      );
      out.rules++;
    }
  }
  return out;
}

async function main() {
  const { confirmed, wipe } = parseArgs(process.argv.slice(2));
  const url = process.env.DATABASE_URL;
  let target;
  try {
    target = assertSafeTarget(url, confirmed);
  } catch (err) {
    console.error(`[seedMockFleet] ${err.message}`);
    process.exit(1);
  }

  const pool = new Pool({ connectionString: url });
  try {
    const out = await seed(pool, { wipe });
    console.log(`[seedMockFleet] target ${target.dbName} on ${target.host}`);
    if (wipe) console.log(`[seedMockFleet] removed ${out.wiped} previously-seeded ${NAME_PREFIX} device(s)`);
    console.log(`[seedMockFleet] inserted ${out.devices} devices, ${out.versions} versions, `
      + `${out.configs} configs, ${out.rules} rules`);
    console.log('[seedMockFleet] deliberately uneven: one device with NULL hit counts, '
      + 'one with an unreadable version, one with nothing collected at all.');
  } finally {
    await pool.end();
  }
}

if (require.main === module) {
  main().catch((e) => { console.error('[seedMockFleet]', e.message); process.exit(1); });
}

module.exports = { assertSafeTarget, DEVICES, NAME_PREFIX };
