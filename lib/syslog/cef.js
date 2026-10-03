// lib/syslog/cef.js
//
// ArcSight Common Event Format (CEF) — the grammar only.
//
// ── WHY THIS IS A SEPARATE FILE, AND WHY CEF IS DIFFERENT ────────────────
//
// Every other parser in this directory reverse-engineers one vendor's
// proprietary layout from captured logs, because documentation lies. CEF is the
// exception: it is a PUBLISHED, SELF-DESCRIBING format. The header names the
// vendor and product, and the extension carries its own field labels. There is
// no layout to guess at, so one implementation serves every vendor that emits
// it — today Forcepoint NGFW and Check Point's Log Exporter in CEF mode.
//
// That does NOT make it documentation-derived in the sense this codebase warns
// about. What the grammar cannot tell us is which SLOT a given vendor puts a
// given fact in, and that part was still read off captured samples — see
// tests/fixtures/cefSyslog.js for provenance.
//
// ⛔ THREE THINGS A NAIVE CEF PARSER GETS WRONG, all of them observed in real
// captures rather than imagined:
//
//  1. EXTENSION VALUES CONTAIN SPACES. Forcepoint sends
//     `deviceExternalId=NGFW2 node 1 dvchost=...` — the value is "NGFW2 node 1",
//     three tokens. Splitting the extension on whitespace yields
//     `deviceExternalId=NGFW2` and two tokens of garbage. A value runs until the
//     next ` <key>=`, nothing else.
//  2. `=` IS ESCAPED INSIDE VALUES. Check Point sends
//     `originsicname=CN\=gate2,O\=pgkeeper...`. Splitting on a bare `=` cuts the
//     value in half and invents a key called `O\`.
//  3. `|` IS ESCAPED INSIDE HEADER FIELDS. A product name containing a pipe
//     would otherwise shift every subsequent header field left by one — and
//     because the header is positional, that silently relabels the severity as
//     a signature name rather than failing.
//
// ⛔ AND THE `cs<N>` SLOTS ARE VENDOR-ASSIGNED, WHICH IS THE WHOLE POINT OF THE
// LABELS. Forcepoint puts its rule id in `cs1` (`cs1Label=RuleID`); Check Point
// puts its rule NAME in `cs2` (`cs2Label=Rule Name`). Hardcoding "cs1 is the
// rule" would read Check Point's NAT rule id as a rule name. This module
// therefore resolves every custom slot through its `<slot>Label` companion and
// never by position.
//
// Pure: no DB, no clock, no I/O. Never throws.

'use strict';

/** Does this message carry a CEF record at all? */
const CEF_RE = /CEF:(\d+)\|/;

// A key in the extension: starts with a letter, then letters/digits/_/.
// Anchored to a space or the start of the extension so a `=` inside a value
// cannot be mistaken for the start of a new field.
const EXT_KEY_RE = /(?:^|\s)([A-Za-z][A-Za-z0-9_.]*)=/g;

/**
 * Split on a delimiter that may be backslash-escaped.
 * ⛔ Hand-rolled rather than a regex with lookbehind, because `\\|` is an
 * ESCAPED BACKSLASH followed by a real delimiter, and a lookbehind for "not
 * preceded by a backslash" gets that case backwards.
 */
function splitEscaped(text, delim) {
  const parts = [];
  let cur = '';
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (ch === '\\' && i + 1 < text.length) {
      // Keep the escape sequence intact; unescaping happens per-field later,
      // so that a `\|` inside a value survives this split unharmed.
      cur += ch + text[i + 1];
      i += 1;
    } else if (ch === delim) {
      parts.push(cur);
      cur = '';
    } else {
      cur += ch;
    }
  }
  parts.push(cur);
  return parts;
}

/** Resolve CEF's escape sequences to the characters they stand for. */
function unescapeCef(v) {
  if (typeof v !== 'string') return v;
  let out = '';
  for (let i = 0; i < v.length; i += 1) {
    if (v[i] === '\\' && i + 1 < v.length) {
      const n = v[i + 1];
      if (n === 'n') out += '\n';
      else if (n === 'r') out += '\r';
      else out += n;          // covers \= \| \\ and anything else
      i += 1;
    } else {
      out += v[i];
    }
  }
  return out;
}

/**
 * Parse the extension (the 8th header field onward) into a plain object.
 * ⛔ Last value wins for a repeated key, matching parseKeyValue's convention
 * in vendorParsers.js. Check Point really does repeat `layer_name` and
 * `match_id` when a connection matches two policy layers; only one survives,
 * and that loss is stated here rather than hidden.
 */
function parseCefExtension(ext) {
  const out = {};
  if (typeof ext !== 'string' || ext === '') return out;

  // Locate every key boundary first, then take each value as the text between
  // one boundary and the next. This is what makes space-containing values work.
  const bounds = [];
  EXT_KEY_RE.lastIndex = 0;
  let m;
  while ((m = EXT_KEY_RE.exec(ext)) !== null) {
    bounds.push({ key: m[1], valueStart: m.index + m[0].length });
    // Step back one so two adjacent keys cannot be skipped.
    EXT_KEY_RE.lastIndex = m.index + m[0].length;
  }

  for (let i = 0; i < bounds.length; i += 1) {
    const { key, valueStart } = bounds[i];
    const end = i + 1 < bounds.length
      // The next key's match consumed a leading space; trim back to before it.
      ? ext.lastIndexOf(bounds[i + 1].key + '=', bounds[i + 1].valueStart)
      : ext.length;
    const raw = ext.slice(valueStart, end).trim();
    // An explicitly empty value is absent information, not an empty string —
    // the same call parseKeyValue makes.
    out[key] = raw === '' ? null : unescapeCef(raw);
  }
  return out;
}

/**
 * Parse a full CEF record.
 * @returns {null|{version,deviceVendor,deviceProduct,deviceVersion,signatureId,name,severity,extension}}
 *          null when the message carries no CEF record at all.
 */
function parseCef(message) {
  if (typeof message !== 'string') return null;
  const at = message.search(CEF_RE);
  if (at === -1) return null;

  // Everything from `CEF:` onward; anything before it is the syslog header,
  // which the caller has usually already stripped but may not have.
  const record = message.slice(at);
  const body = record.slice(record.indexOf(':') + 1);
  const fields = splitEscaped(body, '|');

  // version|vendor|product|deviceVersion|sigId|name|severity|extension
  // ⛔ A record with fewer than 8 fields is REFUSED rather than padded. The
  // header is positional, so padding would silently relabel every field after
  // the gap — a severity read as a signature name looks like data, not an error.
  if (fields.length < 8) return null;

  // The extension may itself contain unescaped pipes, so rejoin the tail.
  const extension = fields.slice(7).join('|');

  return {
    version: unescapeCef(fields[0]),
    deviceVendor: unescapeCef(fields[1]),
    deviceProduct: unescapeCef(fields[2]),
    deviceVersion: unescapeCef(fields[3]),
    signatureId: unescapeCef(fields[4]),
    name: unescapeCef(fields[5]),
    severity: unescapeCef(fields[6]),
    extension: parseCefExtension(extension),
  };
}

/**
 * Find a custom slot (cs1..cs6, cn1..cn3, flexString1..) by what its LABEL
 * says it holds, never by position.
 *
 * ⛔ THIS IS THE FUNCTION THAT MAKES ONE PARSER SERVE SEVERAL VENDORS.
 * Forcepoint: cs1Label=RuleID. Check Point: cs2Label=Rule Name. Reading cs1
 * unconditionally would take Check Point's NAT rule id as its rule name — a
 * wrong value that looks entirely plausible.
 *
 * @param {object} ext parsed extension
 * @param {RegExp} labelPattern tested against the LABEL's value
 * @returns {string|null}
 */
function bySlotLabel(ext, labelPattern) {
  if (!ext || typeof ext !== 'object') return null;
  for (const [k, v] of Object.entries(ext)) {
    if (!k.endsWith('Label') || typeof v !== 'string') continue;
    if (!labelPattern.test(v)) continue;
    const slot = k.slice(0, -'Label'.length);
    const val = ext[slot];
    if (val !== undefined && val !== null && val !== '') return val;
  }
  return null;
}

module.exports = { CEF_RE, parseCef, parseCefExtension, unescapeCef, splitEscaped, bySlotLabel };
