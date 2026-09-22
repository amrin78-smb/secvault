'use strict';
// tests/configDiffDisplay.test.js
//
// ⛔ THIS LOGIC LIVED INSIDE A CLIENT COMPONENT AND SO COULD NOT BE TESTED.
// The only way to check it was to load the page and look — the same blindness
// that let a blank /reports ship past 2,399 passing tests. It is now a pure
// module and this is the test it could not have had.
//
// What it does: turns one changed config object into the rows of the
// Field | Value table under a diff row.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  flattenForDisplay, displayRowsFor, MAX_FLATTEN_ROWS,
} = require('../lib/configDiffDisplay');

const asText = (rows) => (rows === null
  ? null
  : rows.map((r) => `${r.path.join(' ')}=${JSON.stringify(r.value)}`).join(' | '));

describe('⛔ nesting is flattened for display, not dropped', () => {
  it('a PAN-OS service object becomes readable rows', () => {
    // {"protocol":{"tcp":{"port":"7903",...}}} is not a flat object, so it fell
    // through to raw JSON and rendered as a wall of braces directly beneath a
    // clean two-column table.
    const rows = displayRowsFor({
      '@_name': 'Lucanet-7903',
      protocol: { tcp: { port: '7903', override: { no: '' } } },
    }, true);
    assert.match(asText(rows), /protocol tcp port="7903"/);
  });

  it('⛔ an EMPTY object is kept as a row — PAN-OS uses the key as the value', () => {
    // `"override": {"no": ""}` means override=no. Treating {} as nothing would
    // delete a real setting from the display.
    const rows = displayRowsFor({ override: { no: {} } }, false);
    assert.match(asText(rows), /override no=""/);
  });

  it('an array stays one row rather than exploding into indices', () => {
    assert.equal(asText(displayRowsFor({ members: ['a', 'b'] }, false)), 'members=["a","b"]');
  });

  it('a non-object has no rows at all', () => {
    for (const v of ['a string', 42, null, undefined, ['a']]) {
      assert.equal(displayRowsFor(v, false), null, JSON.stringify(v));
    }
  });
});

describe('⛔ it gives up rather than truncating', () => {
  it('too deep falls back to raw JSON, which shows everything', () => {
    // A table quietly cut short looks complete while hiding part of a
    // configuration change.
    assert.equal(flattenForDisplay({ a: { b: { c: { d: { e: 1 } } } } }), null);
    assert.equal(displayRowsFor({ a: { b: { c: { d: { e: 1 } } } } }, false), null);
  });

  it('too wide falls back too, and the boundary is the documented one', () => {
    const wide = {};
    for (let i = 0; i < MAX_FLATTEN_ROWS + 1; i += 1) wide[`f${i}`] = i;
    assert.equal(displayRowsFor(wide, false), null);

    const justUnder = {};
    for (let i = 0; i < MAX_FLATTEN_ROWS - 1; i += 1) justUnder[`f${i}`] = i;
    assert.ok(Array.isArray(displayRowsFor(justUnder, false)));
  });
});

describe('⛔ the name row is dropped ONLY when the heading already says it', () => {
  const tag = { color: 'color13', '@_name': 'TUIP' };

  it('named in the heading -> the duplicate row goes', () => {
    // The row is headed `Tag "TUIP" was added`, so `Name | TUIP` beneath it
    // repeats the heading and pushes the field that actually changed down.
    assert.equal(asText(displayRowsFor(tag, true)), 'color="color13"');
  });

  it('⛔ NOT named in the heading -> the row STAYS', () => {
    // When the description fell back to a raw config path it names nothing.
    // Dropping the name there would remove the only place it appears.
    assert.match(asText(displayRowsFor(tag, false)), /@_name="TUIP"/);
  });

  it('every spelling of the name key is recognised', () => {
    for (const key of ['@_name', '@name', 'name']) {
      const rows = displayRowsFor({ [key]: 'X', other: 1 }, true);
      assert.equal(asText(rows), 'other=1', key);
    }
  });

  it('⛔ a NESTED key called name is NOT dropped', () => {
    // `ip.entry.@_name` is the address of an interface, not the object's own
    // name, and the heading did not say it.
    const rows = displayRowsFor({ layer3: { ip: { '@_name': '10.0.0.1/24' } } }, true);
    assert.match(asText(rows), /layer3 ip @_name="10\.0\.0\.1\/24"/);
  });

  it('an object whose only field was the name renders no table', () => {
    // The heading has already said everything there is; an empty table is
    // furniture around nothing.
    assert.deepEqual(displayRowsFor({ '@_name': 'X' }, true), []);
  });
});

describe('reproduces the live fleet', () => {
  it('a static route drops its name and flattens its profile', () => {
    const rows = displayRowsFor({
      bfd: { profile: 'None' },
      '@_name': 'AzureLD-10.238.89.0_24',
      metric: '10',
      interface: 'tunnel.26',
    }, true);
    const text = asText(rows);
    assert.match(text, /bfd profile="None"/);
    assert.match(text, /metric="10"/);
    assert.equal(/AzureLD/.test(text), false, 'the name is in the heading');
  });

  it('a local user shows its redacted hash and nothing invented', () => {
    assert.equal(
      asText(displayRowsFor({ phash: '<redacted>', '@_name': 'abeam_abap' }, true)),
      'phash="<redacted>"'
    );
  });
});
