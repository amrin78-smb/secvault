'use strict';
// tests/configDiffHeadingName.test.js
//
// ⛔ "A DESCRIPTION EXISTS" IS NOT "THE DESCRIPTION SAYS THE NAME".
// The diff row drops an object's `@_name` field from its Field|Value table
// when the heading above already carries the name. The caller was deciding
// that with `hasDescription` — a different question — so the two builders
// that are name-BLIND by design (a field under an indexed parent, and a
// deviceconfig setting) also had the row removed. The object's identity then
// appeared nowhere at all: not in the heading, not in the table, and the raw
// path only carries an array index.
//
// Lives here rather than in DiffViewer.js because a client component cannot
// be required from node — the same blindness that let a blank /reports ship.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { headingNamesObject, displayRowsFor } = require('../lib/configDiffDisplay');

const asText = (rows) => (rows === null
  ? null
  : rows.map((r) => `${r.path.join(' ')}=${JSON.stringify(r.value)}`).join(' | '));

describe('⛔ the name row goes only when the heading really said the name', () => {
  const tag = { color: 'color13', '@_name': 'TUIP' };

  it('a heading that names it drops the duplicate row', () => {
    assert.equal(headingNamesObject('Tag "TUIP" was added', tag), true);
    assert.equal(asText(displayRowsFor(tag, headingNamesObject('Tag "TUIP" was added', tag))), 'color="color13"');
  });

  it('⛔ a heading that does NOT name it keeps the row', () => {
    // This is the exact sentence friendlyDescriptionForIndexedParentField
    // produces: true, useful, and deliberately silent about which parent —
    // so it cannot stand in for the name.
    const heading = 'IPsec tunnel tunnel monitor destination ip was changed';
    assert.equal(headingNamesObject(heading, tag), false);
    assert.match(asText(displayRowsFor(tag, headingNamesObject(heading, tag))), /@_name="TUIP"/);
  });

  it('⛔ a deviceconfig sentence names a SETTING, not the object', () => {
    const ha = { '@_name': 'HA-Group-1', mode: { 'active-passive': {} } };
    assert.equal(headingNamesObject('High availability group entry was added', ha), false);
    assert.match(asText(displayRowsFor(ha, false)), /@_name="HA-Group-1"/);
  });

  it('every spelling of the name key is recognised', () => {
    for (const key of ['@_name', '@name', 'name']) {
      assert.equal(headingNamesObject(`Thing "X" was added`, { [key]: 'X' }), true, key);
    }
  });

  it('a nested name does not count — the heading is about the object itself', () => {
    const iface = { layer3: { ip: { '@_name': '10.0.0.1/24' } } };
    assert.equal(headingNamesObject('Interface "10.0.0.1/24" was changed', iface), false);
  });

  it('no description, no name, or a non-object all answer false rather than throw', () => {
    assert.equal(headingNamesObject(null, { '@_name': 'X' }), false);
    assert.equal(headingNamesObject('', { '@_name': 'X' }), false);
    assert.equal(headingNamesObject('Tag "X" was added', null), false);
    assert.equal(headingNamesObject('Tag "X" was added', 'a string'), false);
    assert.equal(headingNamesObject('Tag "X" was added', ['X']), false);
    assert.equal(headingNamesObject('Tag "X" was added', { '@_name': '   ' }), false);
  });

  it('⛔ an object whose ONLY field was the name still renders no table', () => {
    // The caller uses this to suppress both the table AND the colon that
    // promised one: a heading followed by a bare `:` and nothing else.
    assert.deepEqual(displayRowsFor({ '@_name': 'X' }, true), []);
  });
});

// ⛔ READ AS SOURCE, BECAUSE NOTHING IN `npm test` RENDERS A PAGE. The
// component cannot be required from node, and the three defects below all
// build cleanly, pass every static check and are invisible until someone
// opens the page — which is exactly the blindness this repo keeps paying for.
describe('⛔ the component asks the right questions of this module', () => {
  const SRC = fs.readFileSync(
    path.join(__dirname, '..', 'components', 'config', 'DiffViewer.js'),
    'utf8'
  );

  it('the name row is decided by headingNamesObject, never by hasDescription', () => {
    assert.match(SRC, /displayRowsFor\(value, headingNamesObject\(friendlyDescription, value\)\)/);
    assert.equal(/displayRowsFor\(value,\s*hasDescription\)/.test(SRC), false,
      '"a description exists" is not "the description says the name"');
  });

  it('⛔ FlatObjectTable is never handed a `value` prop', () => {
    // It takes ROWS. `value={value}` left `rows` undefined, the component
    // returned null, and a whole changed object vanished from the cell with
    // no fallback and no error.
    assert.equal(/<FlatObjectTable\s+value=/.test(SRC), false,
      'FlatObjectTable takes rows; a value prop renders nothing at all');
    assert.match(SRC, /<FlatObjectTable rows=\{rows\}\s*\/>/);
  });

  it('⛔ the colon is not promised when no table follows it', () => {
    assert.match(SRC, /const showsBlock = block && !\(flatTable && rows\.length === 0\);/);
    assert.match(SRC, /\{label\}\{showsBlock \? ':' : ''\}/);
  });
});
