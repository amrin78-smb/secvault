'use strict';
// tests/consoleAddress.test.js
//
// ⛔ THE MOST DANGEROUS FIELD IN SETTINGS. NEXTAUTH_URL is what NextAuth builds
// its sign-in callback from. Point it at a name the browser is not using and
// every login bounces silently back to the login page — no error in the UI,
// none in the console — and the person who set it CANNOT LOG IN TO UNDO IT.
//
// So the validation is not input polish, it is the safety mechanism, and the
// env writer is guarding the file that holds CREDENTIAL_KEY, the database
// password and the NextAuth secret. Both are tested as such.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { validateConsoleUrl, hostPointsHere } = require('../lib/consoleUrl');
const { parseEnv, setEnvValue } = require('../lib/envFile');

describe('⛔ the scheme must follow the transport', () => {
  it('refuses http while TLS is active — the silent-sign-in-failure case', () => {
    const r = validateConsoleUrl('http://secvault.example.com:3010', { tlsActive: true });
    assert.equal(r.ok, false);
    assert.match(r.error, /must be https/);
    // Refused, not warned: an operator told "this may not work" and proceeding
    // is locked out exactly as thoroughly.
    assert.match(r.error, /every login silently fails/);
  });

  it('refuses https while TLS is NOT active', () => {
    const r = validateConsoleUrl('https://secvault.example.com:3010', { tlsActive: false });
    assert.equal(r.ok, false);
    assert.match(r.error, /must be http:/);
  });

  it('accepts the matching pair', () => {
    const r = validateConsoleUrl('https://secvault.example.com:3010', { tlsActive: true });
    assert.equal(r.ok, true);
    assert.equal(r.url, 'https://secvault.example.com:3010');
    assert.equal(r.host, 'secvault.example.com');
    assert.equal(r.port, 3010);
  });
});

describe('⛔ shapes that parse successfully and then break sign-in', () => {
  it('a trailing path is refused — NextAuth appends to this value', () => {
    const r = validateConsoleUrl('https://secvault.example.com:3010/secvault', { tlsActive: true });
    assert.equal(r.ok, false);
    assert.match(r.error, /no path/);
  });

  it('a query string or fragment is refused', () => {
    assert.equal(validateConsoleUrl('https://a.example.com/?x=1', { tlsActive: true }).ok, false);
    assert.equal(validateConsoleUrl('https://a.example.com/#f', { tlsActive: true }).ok, false);
  });

  it('credentials in the address are refused', () => {
    const r = validateConsoleUrl('https://user:pw@a.example.com', { tlsActive: true });
    assert.equal(r.ok, false);
    assert.match(r.error, /username and password/);
  });

  it('⛔ a missing scheme gets useful advice, not a nonsense protocol error', () => {
    // `new URL('host:3010')` parses "host" as the SCHEME and SUCCEEDS, so the
    // naive path tells the operator their hostname is an unsupported protocol.
    const r = validateConsoleUrl('secvault.example.com:3010', { tlsActive: true });
    assert.equal(r.ok, false);
    assert.match(r.error, /Include the scheme/);
    assert.doesNotMatch(r.error, /not "secvault/);
  });

  it('a non-web scheme is named', () => {
    const r = validateConsoleUrl('ftp://a.example.com', { tlsActive: true });
    assert.equal(r.ok, false);
    assert.match(r.error, /not "ftp"/);
  });

  it('an empty value asks for one rather than throwing', () => {
    assert.match(validateConsoleUrl('', {}).error, /Enter the address/);
    assert.match(validateConsoleUrl(null, {}).error, /Enter the address/);
  });
});

describe('warnings that are not refusals', () => {
  it('an IP address is allowed but flagged for the certificate problem', () => {
    const r = validateConsoleUrl('https://192.168.7.69:3010', { tlsActive: true });
    assert.equal(r.ok, true);
    assert.equal(r.warnings.length, 1);
    assert.match(r.warnings[0], /IP SAN/);
  });

  it('localhost is allowed but flagged as unreachable from anywhere else', () => {
    const r = validateConsoleUrl('https://localhost:3010', { tlsActive: true });
    assert.equal(r.ok, true);
    assert.match(r.warnings.join(' '), /Only this machine/);
  });
});

describe('⛔ the lockout guard', () => {
  const HERE = ['127.0.0.1', '192.168.7.69'];

  it('a name resolving to this server points here', async () => {
    const r = await hostPointsHere('secvault.example.com', {
      lookup: async () => [{ address: '192.168.7.69' }],
      localAddresses: HERE,
    });
    assert.equal(r.pointsHere, true);
  });

  it('a name resolving ELSEWHERE is reported, not accepted', async () => {
    const r = await hostPointsHere('someone-elses.example.com', {
      lookup: async () => [{ address: '10.9.9.9' }],
      localAddresses: HERE,
    });
    assert.equal(r.resolved, true);
    assert.equal(r.pointsHere, false);
    assert.deepEqual(r.addresses, ['10.9.9.9']);
  });

  it('⛔ an unresolvable name is UNKNOWN, never a silent pass or a hard refusal', async () => {
    // An internal name may resolve from every workstation and not from this
    // host. Refusing a correct address because our resolver is unhappy is its
    // own lockout; passing it silently defeats the guard. Neither: null.
    const r = await hostPointsHere('nowhere.invalid', {
      lookup: async () => { throw new Error('ENOTFOUND'); },
      localAddresses: HERE,
    });
    assert.equal(r.resolved, false);
    assert.equal(r.pointsHere, null);
    assert.match(r.error, /ENOTFOUND/);
  });

  it('an empty answer is unknown too, not "points nowhere"', async () => {
    const r = await hostPointsHere('empty.example.com', { lookup: async () => [], localAddresses: HERE });
    assert.equal(r.resolved, false);
    assert.equal(r.pointsHere, null);
  });

  it('an IP literal is checked against this machine directly', async () => {
    const mine = await hostPointsHere('192.168.7.69', { lookup: async () => [], localAddresses: HERE });
    assert.equal(mine.pointsHere, true);
    const theirs = await hostPointsHere('10.1.1.1', { lookup: async () => [], localAddresses: HERE });
    assert.equal(theirs.pointsHere, false);
  });
});

// ── the env writer ──────────────────────────────────────────────────────────

function tmpEnv(contents) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secvault-env-'));
  const file = path.join(dir, '.env.local');
  fs.writeFileSync(file, contents, 'utf8');
  return file;
}

const SAMPLE = [
  '# Server',
  'SERVER_IP=192.168.7.69',
  'NEXTAUTH_URL=https://old.example.com:3010',
  '',
  '# Credentials encryption (SEPARATE from NEXTAUTH_SECRET)',
  'CREDENTIAL_KEY=deadbeef00112233445566778899aabbccddeeff00112233445566778899aabb',
  'DATABASE_URL=postgresql://secvault_user:p@ss=word@192.168.7.69:5432/secvault',
  'NEXTAUTH_SECRET=abc+def/ghi=',
  '',
].join('\n');

describe('⛔ .env.local holds every secret the product has', () => {
  it('a value containing = and / survives a round trip', () => {
    // DATABASE_URL and base64 secrets both contain '='. A naive split('=')
    // would truncate the database password and the NextAuth secret.
    const v = parseEnv(SAMPLE);
    assert.equal(v.DATABASE_URL, 'postgresql://secvault_user:p@ss=word@192.168.7.69:5432/secvault');
    assert.equal(v.NEXTAUTH_SECRET, 'abc+def/ghi=');
  });

  it('changing one key leaves every other value byte-identical', () => {
    const file = tmpEnv(SAMPLE);
    const before = parseEnv(fs.readFileSync(file, 'utf8'));
    const r = setEnvValue(file, 'NEXTAUTH_URL', 'https://secvault.example.com:3010');
    assert.equal(r.ok, true);
    const after = parseEnv(fs.readFileSync(file, 'utf8'));
    for (const k of Object.keys(before)) {
      if (k === 'NEXTAUTH_URL') continue;
      assert.equal(after[k], before[k], `${k} must not change`);
    }
    assert.equal(after.NEXTAUTH_URL, 'https://secvault.example.com:3010');
  });

  it('comments and blank lines survive — this file is read by people', () => {
    const file = tmpEnv(SAMPLE);
    setEnvValue(file, 'NEXTAUTH_URL', 'https://x.example.com');
    const text = fs.readFileSync(file, 'utf8');
    assert.match(text, /# Server/);
    assert.match(text, /# Credentials encryption \(SEPARATE from NEXTAUTH_SECRET\)/);
  });

  it('a backup is written before the change', () => {
    const file = tmpEnv(SAMPLE);
    const r = setEnvValue(file, 'NEXTAUTH_URL', 'https://x.example.com');
    assert.ok(r.backupPath && fs.existsSync(r.backupPath));
    assert.equal(fs.readFileSync(r.backupPath, 'utf8'), SAMPLE, 'the backup is the ORIGINAL');
  });

  it('an absent key is appended rather than silently dropped', () => {
    const file = tmpEnv('FOO=1\n');
    const r = setEnvValue(file, 'NEXTAUTH_URL', 'https://x.example.com');
    assert.equal(r.ok, true);
    assert.equal(r.previous, null);
    assert.equal(parseEnv(fs.readFileSync(file, 'utf8')).NEXTAUTH_URL, 'https://x.example.com');
  });

  it('setting the same value is a no-op with no backup churn', () => {
    const file = tmpEnv(SAMPLE);
    const r = setEnvValue(file, 'NEXTAUTH_URL', 'https://old.example.com:3010');
    assert.equal(r.ok, true);
    assert.equal(r.unchanged, true);
    assert.equal(r.backupPath, null);
  });

  it('⛔ a newline in the value is refused — it would inject a second key', () => {
    const file = tmpEnv(SAMPLE);
    const r = setEnvValue(file, 'NEXTAUTH_URL', 'https://x.example.com\nCREDENTIAL_KEY=hijacked');
    assert.equal(r.ok, false);
    assert.equal(parseEnv(fs.readFileSync(file, 'utf8')).CREDENTIAL_KEY, parseEnv(SAMPLE).CREDENTIAL_KEY);
  });

  it('⛔ a DUPLICATED key is refused rather than one copy silently edited', () => {
    // Found BY this test. The writer replaced the FIRST occurrence while
    // parseEnv read the LAST, so a save would have reported success and
    // changed nothing the loader ever sees. Which copy wins belongs to the
    // loader, not to us, so the ambiguous case is refused with the line
    // numbers to fix.
    const original = 'NEXTAUTH_URL=http://a\nNEXTAUTH_URL=http://b\n';
    const file = tmpEnv(original);
    const r = setEnvValue(file, 'NEXTAUTH_URL', 'http://c');
    assert.equal(r.ok, false);
    assert.match(r.error, /appears 2 times/);
    assert.match(r.error, /lines 1, 2/);
    assert.equal(fs.readFileSync(file, 'utf8'), original,
      'nothing may be written when the outcome is ambiguous');
  });});
