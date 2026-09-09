// tests/savedViews.test.js
//
// The three normalizers in lib/savedViews.js. They are pure, and two of them
// are the only thing standing between a stored string and the address bar.
//
// ⛔ WHY THIS IS WORTH A TEST. A saved view's `query` is REPLAYED into the URL
// to restore a filter. That makes it untrusted input that ends up shaping a
// page's own navigation, so "what is rejected" is a security property, not a
// formatting preference. The rest of the module talks to a database and is out
// of scope here (tests/README.md: nothing in this directory touches a DB).

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  normalizeScope,
  normalizeName,
  normalizeQuery,
} = require('../lib/savedViews');

describe('normalizeScope', () => {
  it('accepts a plain table scope and lowercases it', () => {
    assert.equal(normalizeScope('devices'), 'devices');
    assert.equal(normalizeScope('  Rules  '), 'rules');
    assert.equal(normalizeScope('device_cve'), 'device_cve');
  });

  it('rejects anything that is not a bare identifier', () => {
    // A scope is used only to look rows up, but a junk value would create a
    // phantom scope that silently hides someone's views forever.
    for (const bad of ['', '  ', '../devices', 'a b', 'x'.repeat(41), '-leading', null, 42, {}]) {
      assert.equal(normalizeScope(bad), null, `should reject ${JSON.stringify(bad)}`);
    }
  });
});

describe('normalizeName', () => {
  it('collapses internal whitespace and trims', () => {
    assert.equal(normalizeName('  Internet   facing  '), 'Internet facing');
  });

  it('rejects an empty name and one over 60 characters', () => {
    assert.equal(normalizeName(''), null);
    assert.equal(normalizeName('   '), null);
    assert.equal(normalizeName('x'.repeat(61)), null);
    assert.equal(normalizeName('x'.repeat(60)), 'x'.repeat(60));
  });
});

describe('normalizeQuery', () => {
  it('stores the query without its leading question mark', () => {
    assert.equal(normalizeQuery('?vendor=fortinet&risk=high'), 'vendor=fortinet&risk=high');
    assert.equal(normalizeQuery('vendor=fortinet'), 'vendor=fortinet');
  });

  it('accepts an EMPTY query, which means the unfiltered table', () => {
    // ⛔ Not the same as invalid. "The whole table, no filters" is a perfectly
    // reasonable thing to save as a default, and returning null here would
    // make saveView() reject it as a bad query.
    assert.equal(normalizeQuery(''), '');
    assert.equal(normalizeQuery('?'), '');
  });

  it('rejects anything that could redirect rather than filter', () => {
    // The stored value is replayed into the address bar. A scheme or a path
    // separator would make a "view" navigate somewhere else entirely.
    for (const bad of [
      'https://evil.example/x',
      '//evil.example',
      'javascript:alert(1)',
      'a=1 b=2',
      'a="1"',
      "a='1'",
      'a=<script>',
      'a=1\\2',
    ]) {
      assert.equal(normalizeQuery(bad), null, `should reject ${JSON.stringify(bad)}`);
    }
  });

  it('rejects a query over the length cap, and a non-string', () => {
    assert.equal(normalizeQuery('a=' + 'x'.repeat(2000)), null);
    assert.equal(normalizeQuery(null), null);
    assert.equal(normalizeQuery(undefined), null);
    assert.equal(normalizeQuery(123), null);
  });

  it('distinguishes an empty query from a rejected one', () => {
    // ⛔ The caller checks `q === null`, not `!q`. An empty string is falsy,
    // so treating "no filters" and "invalid" as the same falsy value would
    // reject every attempt to save the unfiltered table — the exact class of
    // bug where a legitimate absence is read as a failure.
    assert.notEqual(normalizeQuery(''), null);
    assert.equal(normalizeQuery('a b'), null);
  });
});
