// tests/discoveredDeviceNotes.test.js
//
// ⛔ WHY THIS EXISTS — A NOTE THAT RENDERED FOR NOBODY ON THE ONE ROW THAT
// MATTERED. v2.237.0 let any brand be added as logs-only and put the sentence
// naming that option on `/devices/discovered`, where an operator who cannot log
// into a firewall actually meets the problem. It gated that sentence on
// "was the detected vendor manageable", which assumes a vendor was DETECTED.
//
// `discovered_devices.observed_vendor` is NULLABLE — its own schema comment
// reads "NULL = never identified" — so a third shape exists, and on the
// reference fleet it is the ONLY live one. Measured on production 2026-11-24
// right after the v2.237.1 deploy: seven rows, six already decided, and the one
// still `new` and still sending (10.248.40.254, "StarUnion", 48 observed hours)
// has `observed_vendor IS NULL`. Both notes were gated out —
// `manageable` false because there is nothing to look up, `vendor && !manageable`
// false because `vendor` is falsy — so that row rendered two bare buttons and
// no mention of the capability the release was built to deliver.
//
// ⛔ RENDERED, NEVER SOURCE-SCANNED, AND THAT IS THE POINT OF THE FILE.
// `.ai-codex/roadmap.md` row 4 names three existing `DiscoveredDeviceActions`
// guards that stay GREEN when the note is made unrenderable, and project memory
// (feedback_verify_outcome_not_mechanism) records that a source scan and an
// attribute check shipped three broken features here in one day. The wrong
// answer for a conditional note is an EMPTY RENDER: invisible in source,
// obvious in markup. So the component is mounted with react-dom/server and its
// WORDS are read, using the same swc-on-require harness as
// tests/syslogOnlyAnyVendor.test.js and tests/deltaBadge.test.js (no
// devDependency — `next` is already a runtime dependency).
//
// ⛔ AND IT ASSERTS THE PARTITION, NOT FOUR SEPARATE SENTENCES. The defect was
// not a wrong note, it was a HOLE BETWEEN notes, which no per-note assertion
// can see. Every shape a discovered row can take is enumerated here and each is
// required to produce EXACTLY ONE note, or a deliberate zero — so the next
// condition added to this component cannot reopen a gap without going red.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');

const REPO = path.join(__dirname, '..');

// ─────────────────────────────────────────────────────────────────────────────
// Harness: compile JSX on require, stub the Next/UI imports.
// ─────────────────────────────────────────────────────────────────────────────
function installCompileHook() {
  const swc = require('next/dist/build/swc');
  const origExt = Module._extensions['.js'];
  Module._extensions['.js'] = function (mod, filename) {
    if (filename.split(path.sep).join('/').includes('/node_modules/')) {
      return origExt(mod, filename);
    }
    const out = swc.transformSync(fs.readFileSync(filename, 'utf8'), {
      filename,
      jsc: {
        parser: { syntax: 'ecmascript', jsx: true },
        target: 'es2020',
        transform: { react: { runtime: 'automatic' } },
      },
      module: { type: 'commonjs' },
    });
    return mod._compile(out.code, filename);
  };
}

// ⛔ THE STUBS ARE INJECTED INTO THE MODULE CACHE, NOT WRITTEN TO DISK, AND THE
// FIRST DRAFT GOT THAT WRONG IN A WAY WORTH RECORDING: written into a tmpdir,
// their own `require('react')` could not resolve — node resolves from the
// REQUIRING file's directory, and /tmp has no node_modules — so all 26 tests
// failed identically and said nothing about the component. A pre-populated
// cache entry is also the only form that cannot be reached by a stray relative
// require from elsewhere in the tree.
//
// ⛔ They are deliberately DUMB — each renders its children and nothing else. A
// stub that swallowed children would make every assertion in this file vacuous,
// which is the exact failure shape the file exists to catch.
function installStubs(React) {
  const fake = (id, exports) => {
    const m = new Module(id, null);
    m.filename = id;
    m.loaded = true;
    m.exports = exports;
    Module._cache[id] = m;
    return id;
  };
  const R = React.createElement;
  const map = {
    'next/navigation': fake(path.join(REPO, '.stub.navigation.js'),
      { useRouter: () => ({ refresh() {} }) }),
    'next/link': fake(path.join(REPO, '.stub.link.js'),
      { __esModule: true, default: ({ href, children }) => R('a', { href }, children) }),
    '../ui/Button': fake(path.join(REPO, '.stub.button.js'),
      { __esModule: true,
        default: ({ children, variant, size, ...p }) => R('button', p, children) }),
    '../ui/LoadingSpinner': fake(path.join(REPO, '.stub.spinner.js'),
      { __esModule: true, default: () => R('span', null, '...') }),
  };
  const origResolve = Module._resolveFilename;
  Module._resolveFilename = function (req, ...rest) {
    if (map[req]) return map[req];
    return origResolve.call(this, req, ...rest);
  };
}

let React = null;
let renderToStaticMarkup = null;
let Actions = null;
let loadError = null;
try {
  installCompileHook();
  React = require('react');
  ({ renderToStaticMarkup } = require('react-dom/server'));
  installStubs(React);
  Actions = require('../components/devices/DiscoveredDeviceActions').default;
} catch (err) {
  // ⛔ A FAILURE, NEVER A SKIP. A suite that quietly stops checking is the same
  // shape of problem as the bug it covers.
  loadError = err;
}

const BASE = {
  id: 'dd-1',
  sourceIp: '10.248.40.254',
  hostname: 'StarUnion',
  deviceId: 'dev-1',
  deviceName: 'TUM(TUTH1)',
};

function html(props) {
  assert.ok(Actions, 'could not load DiscoveredDeviceActions: '
    + (loadError ? loadError.message : 'unknown'));
  return renderToStaticMarkup(React.createElement(Actions, { ...BASE, ...props }));
}
const textOf = (markup) => markup
  .replace(/<[^>]+>/g, ' ')
  .replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/&amp;/g, '&')
  .replace(/\s+/g, ' ')
  .trim();

// The three notes, identified by a phrase each that no other note contains.
const NOTES = {
  credentials: /No credentials for this firewall\?/,
  unmanageable: /cannot manage \S+ devices yet/,
  unidentified: /could not identify this firewall's brand/,
};
function notesIn(markup) {
  const t = textOf(markup);
  return Object.keys(NOTES).filter((k) => NOTES[k].test(t));
}

// ─────────────────────────────────────────────────────────────────────────────
// ⛔ THE REGRESSION ITSELF, named and measured.
// ─────────────────────────────────────────────────────────────────────────────
describe("⛔ an UNDETECTED vendor is a third state, not a quiet fourth", () => {
  it('the live production row (observed_vendor IS NULL) gets a note', () => {
    const markup = html({ kind: 'unmanaged', vendor: null });
    const notes = notesIn(markup);
    assert.deepEqual(notes, ['unidentified'],
      'a discovered sender whose vendor was never identified rendered '
      + JSON.stringify(notes) + ' — on the reference fleet this is the ONLY '
      + 'row still awaiting a decision, so no note here means the logs-only '
      + 'capability is unreachable from the page that exists to offer it');
  });

  it('an empty-string vendor takes the same branch as NULL', () => {
    // A projection that coalesces NULL to '' must not fall through the hole.
    assert.deepEqual(notesIn(html({ kind: 'unmanaged', vendor: '' })),
      ['unidentified']);
  });

  it('it names the vendor gap AND the logs-only remedy, not just one', () => {
    const t = textOf(html({ kind: 'unmanaged', vendor: null }));
    assert.match(t, /no vendor is prefilled/,
      'the note must say why the vendor field is empty — otherwise an operator '
      + 'reads the Forcepoint default as a detection');
    assert.match(t, /"Syslog only"/,
      'the note must name the control by the words on the selector; a note that '
      + 'only explains the gap leaves the dead end v2.237.0 removed');
    assert.match(t, /never assessed/,
      'it must say what the device will then REPORT as, or logs-only reads as '
      + 'a way to make a firewall look fine');
    // ⛔ And it must not claim the brand. Guessing one is the
    // VENDOR_META[vendor] || VENDOR_META.forcepoint trap reached from this link.
    assert.doesNotMatch(t, /forcepoint/i,
      'the note must not name a vendor SecVault merely defaults to');
  });

  it('is HUELESS — our parser gap is not the customer\'s severity', () => {
    const markup = html({ kind: 'unmanaged', vendor: null });
    assert.match(markup, /var\(--unmeasured\)/,
      'the unidentified-vendor note must use --unmeasured');
    for (const banned of ['--red', '--orange', '--yellow', '--sev-crit',
      '--sev-high', '--sev-med', '--tint-danger', '--tint-warn']) {
      assert.ok(!markup.includes(banned),
        'a brand SecVault could not parse is a gap in OUR reach, never a '
        + 'severity: found ' + banned);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// ⛔ THE PARTITION. The defect was a hole BETWEEN notes, which no per-note
// assertion can see — so every shape is enumerated and each must yield exactly
// one note, or a deliberate and REASONED zero.
// ─────────────────────────────────────────────────────────────────────────────
describe('⛔ every discovered-row shape yields exactly one note (or a reasoned none)', () => {
  const SHAPES = [
    // vendor,        expected notes,    why
    [null, ['unidentified'], 'never identified — the live production row'],
    ['', ['unidentified'], 'coalesced NULL'],
    ['fortinet', ['credentials'], 'managed, several access methods'],
    ['paloalto', ['credentials'], 'managed, several access methods'],
    ['checkpoint', ['credentials'], 'managed, api + syslog'],
    ['forcepoint', ['credentials'], 'managed, smc + syslog'],
    ['cisco_asa', ['credentials'], 'managed, ssh + syslog'],
    ['sangfor', ['credentials'], 'managed, ssh + syslog'],
    ['sophos', ['credentials'], 'managed, api + syslog'],
    // ⛔ A DELIBERATE ZERO, and the reason is load-bearing: these two have ONE
    // access method, so DeviceForm renders no Access Method selector at all and
    // the note would send an operator hunting for a control that is not there.
    // The OUTCOME is already correct — both default to logs-only.
    ['juniper', [], 'adapter-less: one method, already logs-only'],
    ['sonicwall', [], 'adapter-less: one method, already logs-only'],
    // Outside VENDOR_META entirely: named, so the sentence is actionable.
    ['zyxel', ['unmanageable'], 'detected but SecVault cannot manage it'],
  ];

  for (const [vendor, expected, why] of SHAPES) {
    it(`vendor=${JSON.stringify(vendor)} -> ${JSON.stringify(expected)} (${why})`, () => {
      const notes = notesIn(html({ kind: 'unmanaged', vendor }));
      assert.deepEqual(notes, expected,
        `vendor=${JSON.stringify(vendor)} (${why}) rendered `
        + JSON.stringify(notes));
    });
  }

  it('NO shape renders two notes at once', () => {
    for (const [vendor] of SHAPES) {
      const notes = notesIn(html({ kind: 'unmanaged', vendor }));
      assert.ok(notes.length <= 1,
        `vendor=${JSON.stringify(vendor)} rendered ${notes.length} notes `
        + `(${notes.join(' + ')}) — two notes saying different things about one `
        + 'firewall is worse than none');
    }
  });

  it('every vendor outside the two adapter-less ones is covered', () => {
    // ⛔ Derived from the REGISTRY, so a vendor added later cannot be left out
    // of the table above: that silent omission is how the NULL case survived.
    const { VENDOR_SLUGS } = require('../components/devices/vendorMeta');
    const tabled = new Set(SHAPES.map(([v]) => v));
    for (const slug of VENDOR_SLUGS) {
      assert.ok(tabled.has(slug),
        `${slug} is in VENDOR_META and has no row in this partition table — `
        + 'add it, with the note it should produce and why');
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// ⛔ The OTHER kinds must stay silent. A note under an already-managed address
// would be advice to duplicate a firewall somebody already manages.
// ─────────────────────────────────────────────────────────────────────────────
describe('⛔ only an UNMANAGED sender gets a note', () => {
  for (const kind of ['managed', 'ha-peer', 'known-alias']) {
    it(`kind=${kind} renders no note, whatever the vendor`, () => {
      for (const vendor of [null, 'fortinet', 'zyxel']) {
        assert.deepEqual(notesIn(html({ kind, vendor })), [],
          `kind=${kind} vendor=${JSON.stringify(vendor)} rendered a note`);
      }
    });
  }

  it('a managed address offers no "Add to inventory" at all', () => {
    const t = textOf(html({ kind: 'managed', vendor: 'fortinet' }));
    assert.doesNotMatch(t, /Add to inventory/,
      'the address is already this device\'s own, so adding it is the '
      + 'duplicate-firewall trap');
    assert.match(t, /Dismiss/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// ⛔ The prefill link, rendered rather than scanned (roadmap row 4's three
// source-text guards are what this replaces).
// ─────────────────────────────────────────────────────────────────────────────
describe('⛔ the prefill link never carries a vendor SecVault cannot manage', () => {
  const hrefOf = (markup) => {
    const m = markup.match(/href="([^"]*)"/);
    return m ? m[1].replace(/&amp;/g, '&') : null;
  };

  it('a manageable vendor is passed through', () => {
    const href = hrefOf(html({ kind: 'unmanaged', vendor: 'fortinet' }));
    assert.match(href, /vendor=fortinet/);
    assert.match(href, /mgmt_ip=10\.248\.40\.254/);
    assert.match(href, /name=StarUnion/);
  });

  it('an unmanageable vendor is DROPPED, not substituted', () => {
    const href = hrefOf(html({ kind: 'unmanaged', vendor: 'zyxel' }));
    assert.doesNotMatch(href, /vendor=/,
      'DeviceForm resolves VENDOR_META[vendor] || VENDOR_META.forcepoint, so a '
      + 'slug it does not know renders the FORCEPOINT form with this '
      + 'firewall\'s address prefilled and nothing on screen saying so');
  });

  it('an undetected vendor sends no empty vendor param', () => {
    const href = hrefOf(html({ kind: 'unmanaged', vendor: null }));
    assert.doesNotMatch(href, /vendor=/);
  });

  it('the link still carries what WAS observed', () => {
    // ⛔ Dropping the vendor must not drop the address — that is the whole
    // value of the link, and the prefill was dead on arrival for its first two
    // releases because the form read none of these params.
    const href = hrefOf(html({ kind: 'unmanaged', vendor: null }));
    assert.match(href, /mgmt_ip=10\.248\.40\.254/);
    assert.match(href, /name=StarUnion/);
  });
});
