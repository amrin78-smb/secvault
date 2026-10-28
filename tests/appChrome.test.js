'use strict';
// tests/appChrome.test.js
//
// The two strings every browser tab shows: the favicon and the title. Both are
// outside every other gate in this repo, and one of them had been inert since
// the day it shipped.
//
// ⛔ app/icon.svg WAS INVALID XML AND HAD NEVER RENDERED IN ANY BROWSER. Its
// comment explained — correctly and usefully — why the two brand hues are
// hardcoded, and it named them "--navy / --primary". XML FORBIDS A DOUBLE
// HYPHEN INSIDE A COMMENT, and an SVG served as image/svg+xml is parsed
// strictly, so the whole document was rejected: Chromium reported
// naturalWidth 0, the tab kept the browser's blank default, and the favicon
// added in v2.199.0 did nothing at all. The comment written to explain the
// file is what broke it.
//
// ⛔ IT SHIPPED THAT WAY BECAUSE NOTHING IN THE REPO PARSED IT. 5,887 passing
// tests, a clean `npm run build`, a verified deploy and a green page-render
// sweep all said nothing — the build copied the broken bytes through verbatim
// (md5sum app/icon.svg == md5sum .next/server/app/icon.svg.body) and served
// them with max-age=31536000, so a browser that cached the failure cached it
// for a year. An asset nothing parses is an asset nothing protects.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { XMLValidator, XMLParser } = require('fast-xml-parser');

const ROOT = path.join(__dirname, '..');
const ICON = path.join(ROOT, 'app', 'icon.svg');
const LAYOUT = path.join(ROOT, 'app', 'layout.js');

const icon = fs.readFileSync(ICON, 'utf8');

/**
 * Every XML comment in `src`, as { body, terminated }.
 *
 * Deliberately a scanner and not a parser: the ONE rule it exists to enforce
 * is the one a parser we can reach does not enforce (see below).
 */
function comments(src) {
  const found = [];
  let i = 0;
  for (;;) {
    const open = src.indexOf('<!--', i);
    if (open === -1) return found;
    const close = src.indexOf('-->', open + 4);
    if (close === -1) {
      found.push({ body: src.slice(open + 4), terminated: false });
      return found;
    }
    found.push({ body: src.slice(open + 4, close), terminated: true });
    i = close + 3;
  }
}

describe('⛔ app/icon.svg must be well-formed XML, or no browser renders it', () => {
  it('parses, and parses to an <svg> root', () => {
    // fast-xml-parser is already a RUNTIME dependency (lib/feeds/fortinet.js
    // parses the FortiGuard RSS with it), so this gate costs no devDependency
    // — package.json deliberately has none, because Update-SecVault.ps1 runs
    // `npm ci` on a firewall-management server.
    const verdict = XMLValidator.validate(icon, { allowBooleanAttributes: true });
    assert.equal(verdict, true,
      `app/icon.svg is not well-formed XML: ${JSON.stringify(verdict)}`);

    const parsed = new XMLParser({ ignoreAttributes: false }).parse(icon);
    assert.ok(parsed && parsed.svg, 'the document has no <svg> root — nothing would render');
  });

  it('⛔ has no double hyphen inside a comment — and the check above CANNOT see this', () => {
    // ⛔ THIS IS NOT REDUNDANT WITH THE VALIDATOR, AND THAT WAS MEASURED, NOT
    // ASSUMED (2026-10-28). Handed the exact bytes that shipped,
    // XMLValidator.validate() returns `true`, while Chromium refuses the same
    // file outright (naturalWidth 0 against 133 for the fixed copy, same
    // server, same browser, same request). The validator is the lenient
    // parser; the browser is the authoritative one, and the browser is the
    // only one whose opinion ships. CLAUDE.md names this shape directly — a
    // second parser disagreeing with the authoritative one — and the answer is
    // the same here: assert the rule the strict parser enforces, not the one
    // the convenient library happens to check.
    //
    // ⛔ DO NOT "SIMPLIFY" THIS AWAY on the grounds that the file already
    // validates above. If fast-xml-parser ever becomes strict about comments,
    // this assertion simply keeps passing; deleting it restores the exact
    // blind spot that let the favicon ship dead. It is also not asserted from
    // the other side (that the validator is still lenient), because a gate
    // that fails on a dependency upgrade is a gate someone deletes.
    for (const c of comments(icon)) {
      assert.ok(c.terminated, 'an XML comment in app/icon.svg is never closed');
      assert.ok(!c.body.includes('--'),
        'a comment in app/icon.svg contains a double hyphen, which XML forbids — '
        + 'the whole file is then rejected and the tab falls back to the browser default. '
        + 'Name CSS custom properties in words here; never write their two-dash prefix.');
      // `<!-- text- -->` is the same refusal spelled differently: the content
      // of a comment may not end with a hyphen either.
      assert.ok(!c.body.endsWith('-'),
        'a comment in app/icon.svg ends with a hyphen, which XML forbids');
    }
  });

  it('keeps the explanation the broken comment was carrying', () => {
    // ⛔ THE FIX IS NOT "DELETE THE COMMENT". The reason those hues are literal
    // hex is genuinely worth recording — a static file served by Next's
    // app/icon convention is never inside a SecVault document and has no
    // palette to read, so a later session WILL otherwise try to replace them
    // with var() and find the icon silently blank. Pinned as an outcome (the
    // reason is still stated) rather than as a particular sentence.
    const body = comments(icon).map((c) => c.body).join('\n');
    assert.match(body, /app\/icon/, 'the note no longer says what serves this file');
    assert.match(body, /custom propert/i,
      'the note no longer explains why the hues cannot be tokens — that is why they get "fixed"');
  });
});

describe('⛔ the browser-tab title comes from the branding surface', () => {
  const layout = fs.readFileSync(LAYOUT, 'utf8');

  it('reads the product name from lib/branding, never a literal', () => {
    // The same leak v2.199.0 fixed on the login eyebrow one file away, where a
    // hardcoded "FIREWALL SECURITY PLATFORM" sat beside a branding.js that had
    // said "Firewall Intelligence Platform" since it was written. A rebrand is
    // meant to be one file; a hardcoded copy is one a rebrand misses, and this
    // copy is the most visible string in the product.
    assert.match(layout, /from '\.\.\/lib\/branding'/,
      'app/layout.js no longer imports the branding surface');
    assert.match(layout, /title:\s*PRODUCT_NAME/, 'the tab title is not coming from branding');
    assert.doesNotMatch(layout, /title:\s*['"`]/, 'the tab title is a hardcoded literal again');
  });
});
