'use strict';
// Pins Palo Alto config-secret redaction — both transports, plus the migrate.js
// backfill that re-redacts rows already written before the fix.
//
// WHY THIS FILE EXISTS. On 2026-09-09 a live audit found PAN-OS secret-bearing
// tags sitting UNREDACTED in device_configs.config_raw and
// config_backups.config_raw — ~1,019 rows across 5 devices. Both tables are
// GRANT SELECT'd to claude_readonly / nocvault_readonly, the exact roles
// CLAUDE.md bars from credential material. Two independent causes:
//
//   1. THE MATCHER REQUIRED A BARE OPENING TAG.
//      `new RegExp('(<' + tag + '>)([\\s\\S]*?)(</' + tag + '>)')`
//      PAN-OS stamps `ptpl="<template>"` on every node pushed down from a
//      Panorama template, so `<private-key ptpl="PA-220-Ranode">` never matched.
//      ⛔ This is the failure shape worth remembering: the tag LIST was correct
//      and the bare-tag occurrences on the very same device redacted perfectly,
//      so any spot check of `<phash>` looked clean. Only the template-pushed
//      nodes leaked.
//   2. THREE REAL TAGS WERE ABSENT, and matching here is EXACT-NAME, not
//      substring — so `wmi-password` was never covered by `password`.
//      (gotchas.md's documented "universal keyword pattern" IS substring-based
//      and does include `community`; this Palo Alto copy had drifted from the
//      convention the other five vendors still follow.)
//
// ⛔ ACCURACY, in comments and in commit text: the leaked values are PAN-OS
// `-AQ=`-prefixed MASTER-KEY-ENCRYPTED blobs, NOT literal plaintext passwords.
// They are reversible with the device master key and are exactly the field class
// SECRET_TAGS exists to strip — but calling them plaintext would be wrong. The
// SNMP `<community>` values are the exception: those are ordinary strings.
//
// ⛔ NO REAL SECRET APPEARS HERE. Every fixture below reproduces a SHAPE read
// off the live fleet — the exact `ptpl=` attribute form, the exact
// `user-id-collector > setting > wmi-account/wmi-password` nesting, the exact
// `snmp-setting > version > v2c > server > entry > manager/community` nesting —
// with SYNTHETIC values (`-AQ==FAKE…`). Assertions are on SHAPE (redacted vs
// not) and on counts, never on a value.
//
// ⛔ NO DATABASE. The redactors are pure string functions. The one function that
// talks to a pool takes a stub that records the statements it was handed.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  redactConfigXml,
  redactConfigTree,
  SECRET_TAGS,
  SECRET_LEAF_TAGS,
} = require('../lib/adapters/paloalto/parser');
const { redactConfig: redactSshConfig } = require('../lib/adapters/paloalto/sshParser');
const {
  redactStoredPaloAltoConfigRaw,
  backfillPaloAltoConfigRedaction,
} = require('../lib/migrate');

const REDACTED = '<redacted>';
// Synthetic stand-ins for the PAN-OS master-key-encrypted blob form. Never real.
const FAKE_AQ = '-AQ==FAKEwmiSECRETvalue';
const FAKE_AQ2 = '-AQ==FAKEbindSECRETvalue';
const FAKE_AQ3 = '-AQ==FAKEprivkeySECRETvalue';
const FAKE_COMMUNITY = 'FAKEcommunityString';

// ---------------------------------------------------------------------------
// Fixtures — real stored SHAPES, synthetic values
// ---------------------------------------------------------------------------

// The Panorama-template-pushed form. `ptpl="PA-220-Ranode"` is the exact
// attribute name and shape observed on the fleet; the template name is not a
// secret, it names a Panorama template.
const PTPL_ATTRIBUTED = [
  '<ssl-tls-service-profile>',
  '  <entry name="gp-portal">',
  `    <private-key ptpl="PA-220-Ranode">${FAKE_AQ3}</private-key>`,
  '  </entry>',
  '</ssl-tls-service-profile>',
  '<ldap>',
  '  <entry name="corp-ldap">',
  `    <bind-password ptpl="PA-220-Ranode">${FAKE_AQ2}</bind-password>`,
  '  </entry>',
  '</ldap>',
].join('\n');

// User-ID agentless WMI probing. ⛔ `<wmi-account>` sits right beside the
// password and holds a Windows DOMAIN service account, which is why this is the
// most consequential of the four leaked tags — the blast radius reaches past the
// firewall. (The account below is synthetic; the real one is not reproduced.)
const WMI_BLOCK = [
  '<user-id-collector>',
  '  <server-monitor/>',
  '  <setting>',
  '    <wmi-account>EXAMPLEDOM\\svc.fixture</wmi-account>',
  `    <wmi-password>${FAKE_AQ}</wmi-password>`,
  '  </setting>',
  '</user-id-collector>',
].join('\n');

// SNMP trap manager — `<community>` as a TEXT LEAF. This is a credential.
const SNMP_COMMUNITY_BLOCK = [
  '<snmp-setting>',
  '  <access-setting>',
  '    <version>',
  '      <v2c>',
  '        <server>',
  '          <entry name="PRTG">',
  '            <manager>192.168.1.111</manager>',
  `            <community>${FAKE_COMMUNITY}</community>`,
  '          </entry>',
  '        </server>',
  '      </v2c>',
  '    </version>',
  '  </access-setting>',
  '</snmp-setting>',
].join('\n');

// ⛔ THE SAME TAG NAME, A COMPLETELY DIFFERENT THING. BGP route policy uses
// `<community>` as a CONTAINER for a route-tagging attribute list. It is not a
// secret and must survive. Also present on the fleet, on the same devices.
const BGP_COMMUNITY_BLOCK = [
  '<bgp>',
  '  <policy>',
  '    <import>',
  '      <rules>',
  '        <entry name="from-isp">',
  '          <action>',
  '            <allow>',
  '              <update>',
  '                <community>',
  '                  <type><none/></type>',
  '                  <member>65000:100</member>',
  '                </community>',
  '                <extended-community>',
  '                  <member>rt:65000:1</member>',
  '                </extended-community>',
  '              </update>',
  '            </allow>',
  '          </action>',
  '        </entry>',
  '      </rules>',
  '    </import>',
  '  </policy>',
  '</bgp>',
].join('\n');

// Tags that merely LOOK like the secret names and must never be touched. Every
// one of these was observed sitting alongside the real secrets on the fleet.
const LOOKALIKES = [
  '<keyxchg-algo-rsa>yes</keyxchg-algo-rsa>',
  '<keyxchg-algo-dhe>yes</keyxchg-algo-dhe>',
  '<keyxchg-algo-ecdhe>yes</keyxchg-algo-ecdhe>',
  '<public-key>MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA</public-key>',
  '<password-label>Password</password-label>',
  '<password-change-on-first-login>no</password-change-on-first-login>',
  '<password-complexity><enabled>yes</enabled></password-complexity>',
].join('\n');

const AGENT_KEY_BLOCK = `<mdm-enrollment-port>443</mdm-enrollment-port><agent-user-override-key>${FAKE_AQ}</agent-user-override-key>`;

const FULL_XML_FIXTURE = [
  '<config>',
  PTPL_ATTRIBUTED,
  WMI_BLOCK,
  SNMP_COMMUNITY_BLOCK,
  BGP_COMMUNITY_BLOCK,
  AGENT_KEY_BLOCK,
  LOOKALIKES,
  '<phash></phash>',
  '</config>',
].join('\n');

// Every synthetic secret VALUE that must be gone after redaction.
const ALL_FAKE_SECRETS = [FAKE_AQ, FAKE_AQ2, FAKE_AQ3, FAKE_COMMUNITY];

function assertNoSecretsRemain(text, label) {
  for (const secret of ALL_FAKE_SECRETS) {
    assert.ok(!text.includes(secret), `${label}: a secret body survived redaction`);
  }
}

// ---------------------------------------------------------------------------
// Cause 1 — the opening tag may carry attributes
// ---------------------------------------------------------------------------

describe('redactConfigXml — Panorama `ptpl=` attributed opening tags (cause 1)', () => {
  it('redacts a secret whose opening tag carries an attribute', () => {
    const out = redactConfigXml(PTPL_ATTRIBUTED);
    assert.ok(!out.includes(FAKE_AQ3), '<private-key ptpl="…"> leaked');
    assert.ok(!out.includes(FAKE_AQ2), '<bind-password ptpl="…"> leaked');
    assert.match(out, /<private-key ptpl="PA-220-Ranode"><redacted><\/private-key>/);
    assert.match(out, /<bind-password ptpl="PA-220-Ranode"><redacted><\/bind-password>/);
  });

  it('keeps the attribute itself — only the BODY is replaced', () => {
    // The attribute names a Panorama template. It is not a secret, it is real
    // config provenance, and destroying it would alter non-secret content.
    const out = redactConfigXml(PTPL_ATTRIBUTED);
    assert.equal((out.match(/ptpl="PA-220-Ranode"/g) || []).length, 2);
  });

  it('⛔ REGRESSION GUARD: the PRE-FIX matcher provably missed these', () => {
    // This is the exact expression that shipped, reconstructed. If someone
    // "simplifies" the matcher back to a bare opening tag, the assertion below
    // still passes but the two above start failing — which is the point.
    const preFix = new RegExp(`(<${'private-key'}>)([\\s\\S]*?)(</${'private-key'}>)`, 'gi');
    assert.equal(
      PTPL_ATTRIBUTED.match(preFix),
      null,
      'the pre-fix bare-tag matcher must NOT match the attributed form — that was the bug'
    );
    // ...while it did match the bare form on the very same device, which is why
    // the defect stayed invisible to a spot check.
    assert.notEqual('<private-key>x</private-key>'.match(preFix), null);
  });

  it('still redacts the bare (non-attributed) form', () => {
    const out = redactConfigXml('<phash>$1$FAKEhash</phash>');
    assert.equal(out, `<phash>${REDACTED}</phash>`);
  });
});

// ---------------------------------------------------------------------------
// Cause 2 — the three missing tags, and the over-redaction line
// ---------------------------------------------------------------------------

describe('redactConfigXml — the three tags that were missing (cause 2)', () => {
  it('redacts <wmi-password> — NOT covered by `password`, matching is exact-name', () => {
    assert.ok(SECRET_TAGS.includes('wmi-password'));
    const out = redactConfigXml(WMI_BLOCK);
    assert.ok(!out.includes(FAKE_AQ), 'wmi-password leaked');
    assert.match(out, /<wmi-password><redacted><\/wmi-password>/);
  });

  it('leaves <wmi-account> alone — it is not a secret, it is the account NAME', () => {
    // Deliberately NOT redacted. It is operationally meaningful, and an operator
    // needs to see WHICH domain account User-ID probing runs as. Its presence
    // beside the password is what makes the password's exposure serious; that is
    // an argument for redacting the password, not for blanking the account.
    const out = redactConfigXml(WMI_BLOCK);
    assert.match(out, /<wmi-account>EXAMPLEDOM\\svc\.fixture<\/wmi-account>/);
  });

  it('redacts <agent-user-override-key>', () => {
    assert.ok(SECRET_TAGS.includes('agent-user-override-key'));
    const out = redactConfigXml(AGENT_KEY_BLOCK);
    assert.ok(!out.includes(FAKE_AQ));
    assert.match(out, /<agent-user-override-key><redacted><\/agent-user-override-key>/);
    assert.match(out, /<mdm-enrollment-port>443<\/mdm-enrollment-port>/);
  });

  it('redacts an SNMP <community> TEXT LEAF', () => {
    assert.ok(SECRET_LEAF_TAGS.includes('community'));
    const out = redactConfigXml(SNMP_COMMUNITY_BLOCK);
    assert.ok(!out.includes(FAKE_COMMUNITY), 'SNMP community string leaked');
    assert.match(out, /<community><redacted><\/community>/);
    // The trap manager's IP is not a secret and must survive.
    assert.match(out, /<manager>192\.168\.1\.111<\/manager>/);
  });
});

describe('⛔ over-redaction — the checks that ruled out widening too far', () => {
  it('leaves the BGP <community> CONTAINER completely intact', () => {
    // PAN-OS reuses this tag name for a route-tagging attribute list. Putting
    // `community` in SECRET_TAGS would have replaced this whole subtree with
    // <redacted>, destroying real routing policy for zero security benefit.
    const out = redactConfigXml(BGP_COMMUNITY_BLOCK);
    assert.equal(out, BGP_COMMUNITY_BLOCK, 'BGP community subtree was altered');
  });

  it('never matches <extended-community> — a different tag entirely', () => {
    const src = '<extended-community><member>rt:65000:1</member></extended-community>';
    assert.equal(redactConfigXml(src), src);
  });

  it('the ATTRIBUTE matcher does not bleed across a hyphen either', () => {
    // ⛔ `\b` matches between '-' and a letter, so a `\bcommunity="` matcher
    // would also fire inside `extended-community="`. The leaf matcher uses
    // `(?<![\w-])` for exactly this reason.
    const out = redactConfigXml('<a community="FAKEcomm" extended-community="rt:1:1"/>');
    assert.match(out, /community="<redacted>"/);
    assert.match(out, /extended-community="rt:1:1"/);
    assert.ok(!out.includes('FAKEcomm'));
  });

  it('leaves every lookalike tag untouched', () => {
    // keyxchg-algo-* / public-key / password-label / password-complexity all sit
    // next to the real secrets on the fleet. A matcher that allowed the tag name
    // to be a PREFIX would eat all of them.
    assert.equal(redactConfigXml(LOOKALIKES), LOOKALIKES);
  });

  it('separates the SNMP leaf from the BGP container in ONE document', () => {
    const src = `${SNMP_COMMUNITY_BLOCK}\n${BGP_COMMUNITY_BLOCK}`;
    const out = redactConfigXml(src);
    assert.ok(!out.includes(FAKE_COMMUNITY), 'SNMP community leaked');
    assert.ok(out.includes('<member>65000:100</member>'), 'BGP community member was destroyed');
    assert.ok(out.includes('<member>rt:65000:1</member>'), 'extended-community was destroyed');
  });
});

describe('redactConfigXml — whole-document behaviour', () => {
  it('removes every secret and is idempotent', () => {
    const once = redactConfigXml(FULL_XML_FIXTURE);
    assertNoSecretsRemain(once, 'redactConfigXml');
    // Idempotence is load-bearing: two pulls of an unchanged config must redact
    // identically, or redaction itself manufactures a change.
    assert.equal(redactConfigXml(once), once, 'redaction is not idempotent');
  });

  it('fills an EMPTY secret element too — pre-existing behaviour, deliberately unchanged', () => {
    // The live redactor has always written <redacted> into an empty body. That
    // is why an empty body is effectively absent from stored PAN-OS data: any
    // snapshot that passed through this function already has one. Left as-is,
    // because changing it would alter what every fresh snapshot looks like.
    // ⛔ The BACKFILL deliberately diverges here and skips an empty body — see
    // its own test below for why rewriting stored history buys nothing there.
    assert.equal(redactConfigXml('<phash></phash>'), `<phash>${REDACTED}</phash>`);
  });
});

// ---------------------------------------------------------------------------
// The parsed tree
// ---------------------------------------------------------------------------

describe('redactConfigTree — the same leaf/container split, in tree form', () => {
  it('redacts a primitive `community` (the SNMP string)', () => {
    const out = redactConfigTree({ manager: '192.168.1.111', community: FAKE_COMMUNITY });
    assert.equal(out.community, REDACTED);
    assert.equal(out.manager, '192.168.1.111');
  });

  it('walks a `community` OBJECT (the BGP list) instead of blanking it', () => {
    const bgp = { community: { type: { none: null }, member: '65000:100' } };
    const out = redactConfigTree(bgp);
    assert.deepEqual(out, bgp);
  });

  it('redacts wmi-password / agent-user-override-key but not their neighbours', () => {
    const out = redactConfigTree({
      'wmi-account': 'EXAMPLEDOM\\svc.fixture',
      'wmi-password': FAKE_AQ,
      'agent-user-override-key': FAKE_AQ,
      'mdm-enrollment-port': 443,
    });
    assert.equal(out['wmi-password'], REDACTED);
    assert.equal(out['agent-user-override-key'], REDACTED);
    assert.equal(out['wmi-account'], 'EXAMPLEDOM\\svc.fixture');
    assert.equal(out['mdm-enrollment-port'], 443);
  });

  it('matches key names EXACTLY — a compound name is not matched by its suffix', () => {
    // The mirror image of the bug: `community_container` must not be caught by
    // `community`, just as `wmi-password` was not caught by `password`.
    const out = redactConfigTree({ community_container: 1, extended_community: 'x' });
    assert.equal(out.community_container, 1);
    assert.equal(out.extended_community, 'x');
  });
});

// ---------------------------------------------------------------------------
// SSH transport
// ---------------------------------------------------------------------------

describe('sshParser redactConfig — brace format, same tag names', () => {
  it('redacts wmi-password / agent-user-override-key leaves', () => {
    const src = [
      'user-id-collector {',
      '  setting {',
      '    wmi-account "EXAMPLEDOM\\svc.fixture";',
      `    wmi-password ${FAKE_AQ};`,
      '  }',
      '}',
      `agent-user-override-key ${FAKE_AQ};`,
    ].join('\n');
    const out = redactSshConfig(src);
    assert.ok(!out.includes(FAKE_AQ), 'brace-format secret leaked');
    assert.match(out, /wmi-password <redacted>;/);
    assert.match(out, /agent-user-override-key <redacted>;/);
  });

  it('redacts a `community <value>;` leaf but preserves a `community {` SECTION', () => {
    const src = [
      'snmp-setting {',
      `  community ${FAKE_COMMUNITY};`,
      '}',
      'bgp {',
      '  community {',
      '    member 65000:100;',
      '  }',
      '}',
    ].join('\n');
    const out = redactSshConfig(src);
    assert.ok(!out.includes(FAKE_COMMUNITY), 'SNMP community leaked on SSH transport');
    assert.match(out, /community <redacted>;/);
    // redactLine already skips a keyword whose remainder is just '{', so the BGP
    // container survives — the brace-tree structure must never be swallowed.
    assert.match(out, /community \{/);
    assert.match(out, /member 65000:100;/);
  });

  it('preserves brace/quote structure (the 2026-07-20 corruption guard)', () => {
    const src = 'description "Manage Change Password here";';
    const out = redactSshConfig(src);
    // Quotes and the trailing ';' must survive, or tokenizeBraceConfig desyncs.
    assert.equal(out, `description "${REDACTED}";`);
  });
});

// ---------------------------------------------------------------------------
// The backfill — what actually closes the exposure
// ---------------------------------------------------------------------------

describe('redactStoredPaloAltoConfigRaw — the backfill transform', () => {
  it('rewrites the attributed and the newly-listed leaves', () => {
    const res = redactStoredPaloAltoConfigRaw(FULL_XML_FIXTURE);
    assertNoSecretsRemain(res.text, 'backfill');
    assert.equal(res.redacted, 5, 'expected 5 secret leaf bodies (3 attributed/AQ + wmi + snmp)');
  });

  it('⛔ THE UNSURE CASE — a non-leaf secret element is LEFT ALONE and COUNTED', () => {
    // This is the case that would regress silently. The live redactor blanks a
    // whole subtree; the backfill must NOT, because it cannot re-derive content
    // it destroys in already-stored history. It must say so rather than guess.
    const container = '<private-key ptpl="T1"><entry name="a">x</entry></private-key>';
    const res = redactStoredPaloAltoConfigRaw(container);
    assert.equal(res.text, container, 'the backfill rewrote a container it could not identify');
    assert.equal(res.redacted, 0);
    assert.equal(res.skippedContainer, 1, 'an unsure element must be counted, not silently dropped');
  });

  it('leaves an EMPTY body alone — it carries no secret', () => {
    const res = redactStoredPaloAltoConfigRaw('<phash></phash><password>   </password>');
    assert.equal(res.text, '<phash></phash><password>   </password>');
    assert.equal(res.redacted, 0);
    assert.equal(res.skippedEmpty, 2);
  });

  it('⛔ alters NOTHING structural — no tag, attribute or non-secret value moves', () => {
    // The safety argument in one assertion: a text-leaf body contains no '<', so
    // replacing it provably cannot delete or reshape any element. Compare the
    // full tag stream on both sides, allowing only the <redacted> markers added.
    const res = redactStoredPaloAltoConfigRaw(FULL_XML_FIXTURE);
    const tags = (s) => (s.match(/<\/?[a-zA-Z0-9_-]+/g) || []).filter((t) => t !== '<redacted');
    assert.deepEqual(tags(res.text), tags(FULL_XML_FIXTURE));
    // ...and every non-secret value survives verbatim.
    for (const keep of [
      'ptpl="PA-220-Ranode"',
      '<wmi-account>EXAMPLEDOM\\svc.fixture</wmi-account>',
      '<manager>192.168.1.111</manager>',
      '<member>65000:100</member>',
      '<member>rt:65000:1</member>',
      '<public-key>MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA</public-key>',
      '<password-label>Password</password-label>',
    ]) {
      assert.ok(res.text.includes(keep), `backfill altered non-secret content: ${keep}`);
    }
  });

  it('is idempotent — re-running a migrate changes nothing', () => {
    const once = redactStoredPaloAltoConfigRaw(FULL_XML_FIXTURE).text;
    const twice = redactStoredPaloAltoConfigRaw(once);
    assert.equal(twice.text, once);
    assert.equal(twice.redacted, 0, 'a second run must find nothing left to redact');
  });

  it('converges on what the LIVE redactor would store for a leaf-only document', () => {
    // A backfilled row and a freshly-collected one holding the same content must
    // agree, or content_hash and any future dedupe stop meaning anything.
    const leafOnly = [PTPL_ATTRIBUTED, WMI_BLOCK, SNMP_COMMUNITY_BLOCK].join('\n');
    assert.equal(redactStoredPaloAltoConfigRaw(leafOnly).text, redactConfigXml(leafOnly));
  });

  it('is a no-op on a non-XML (SSH brace) config and on empty input', () => {
    const brace = 'wmi-password <redacted>;\nsecurity { rules { } }';
    assert.equal(redactStoredPaloAltoConfigRaw(brace).text, brace);
    assert.equal(redactStoredPaloAltoConfigRaw('').text, '');
    assert.equal(redactStoredPaloAltoConfigRaw(null).text, null);
  });
});

// ---------------------------------------------------------------------------
// The backfill's DB plumbing — stub pool, no database
// ---------------------------------------------------------------------------

function stubPool(rowsByTable) {
  const calls = [];
  return {
    calls,
    sql: () => calls.map((c) => c.sql),
    async query(sql, params) {
      calls.push({ sql, params });
      if (sql.includes('JOIN devices')) {
        const table = sql.includes('FROM device_configs') ? 'device_configs' : 'config_backups';
        return { rows: (rowsByTable[table] || []).map((r) => ({ id: r.id })) };
      }
      if (sql.startsWith('SELECT config_raw')) {
        const table = sql.includes('FROM device_configs') ? 'device_configs' : 'config_backups';
        const row = (rowsByTable[table] || []).find((r) => r.id === params[0]);
        return { rows: row ? [{ config_raw: row.config_raw }] : [] };
      }
      return { rows: [], rowCount: 1 };
    },
  };
}

describe('backfillPaloAltoConfigRedaction — DB plumbing', () => {
  it('rewrites both tables and reports what it did', async () => {
    const pool = stubPool({
      device_configs: [{ id: 'cfg-1', config_raw: FULL_XML_FIXTURE }],
      config_backups: [{ id: 'bak-1', config_raw: PTPL_ATTRIBUTED }],
    });
    const res = await backfillPaloAltoConfigRedaction(pool);
    assert.equal(res.checked, 2);
    assert.equal(res.updated, 2);
    assert.ok(res.secretsRedacted >= 7);

    const updates = pool.calls.filter((c) => c.sql.includes('UPDATE'));
    assert.equal(updates.length, 2);
    for (const u of updates) {
      assertNoSecretsRemain(u.params[1], 'UPDATE payload');
    }
  });

  it('⛔ never touches config_parsed and never deletes a row', async () => {
    // config_parsed already redacts correctly via redactConfigTree, and it is the
    // column configDiff actually diffs — so writing it here could manufacture a
    // false config-change alert on a security product.
    const pool = stubPool({ device_configs: [{ id: 'cfg-1', config_raw: FULL_XML_FIXTURE }] });
    await backfillPaloAltoConfigRedaction(pool);
    for (const sql of pool.sql()) {
      assert.ok(!/\bDELETE\b/i.test(sql), 'the backfill must never delete a row');
      assert.ok(!/SET[\s\S]*config_parsed\s*=/i.test(sql), 'config_parsed must never be written');
    }
  });

  it('recomputes content_hash alongside config_raw', async () => {
    // content_hash is derived from config_raw; rewriting one without the other
    // leaves the column meaning nothing for that row.
    const pool = stubPool({ device_configs: [{ id: 'cfg-1', config_raw: FULL_XML_FIXTURE }] });
    await backfillPaloAltoConfigRedaction(pool);
    const update = pool.calls.find((c) => c.sql.includes('UPDATE device_configs'));
    assert.ok(update, 'no device_configs UPDATE issued');
    assert.match(update.sql, /content_hash = encode\(/);
    assert.match(update.sql, /sha256\(convert_to\(coalesce\(\$2, ''\) \|\| chr\(10\) \|\| coalesce\(config_parsed::text, ''\), 'UTF8'\)\)/);
    // config_backups has no content_hash column — it must not be named there.
    const backupUpdate = pool.calls.find((c) => c.sql.includes('UPDATE config_backups'));
    if (backupUpdate) assert.ok(!backupUpdate.sql.includes('content_hash'));
  });

  it('scopes candidate selection to Palo Alto devices', async () => {
    const pool = stubPool({});
    await backfillPaloAltoConfigRedaction(pool);
    const selects = pool.sql().filter((s) => s.includes('JOIN devices'));
    assert.equal(selects.length, 2, 'both tables must be scanned');
    for (const s of selects) assert.match(s, /d\.vendor = 'paloalto'/);
  });

  it('writes nothing when a row needs no change', async () => {
    const pool = stubPool({
      device_configs: [{ id: 'cfg-1', config_raw: BGP_COMMUNITY_BLOCK }],
    });
    const res = await backfillPaloAltoConfigRedaction(pool);
    assert.equal(res.checked, 1);
    assert.equal(res.updated, 0, 'a clean row must not be rewritten');
    assert.equal(pool.calls.filter((c) => c.sql.includes('UPDATE')).length, 0);
  });
});
