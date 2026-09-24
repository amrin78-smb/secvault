'use strict';
// lib/csv.js
//
// CSV cell escaping, shared. Pure, no dependencies.
//
// This was `csvEscape` inside lib/engines/ruleChangeRequestReport.js, which is
// where it was first needed. It moved here when the log export became the
// second caller: two files deciding independently how to neutralise a
// spreadsheet formula would eventually disagree, and the one that disagreed
// quietly would be the one writing a document that runs code on open.
//
// ── ⛔ FORMULA INJECTION IS THE WHOLE POINT OF THIS FILE ──────────────────
// A cell beginning `=`, `+`, `-` or `@` is evaluated as a FORMULA by Excel,
// LibreOffice and Google Sheets. On this product the values being exported are
// attacker-influenced by construction — a rule name pulled from a firewall
// config, and now a raw syslog line written by whoever sent the packet. A
// leading apostrophe is the standard neutralisation and is visible in the
// cell, which is the honest trade: a slightly odd-looking value beats a
// spreadsheet that executes.
//
// ⛔ AND THE CHECK LOOKS PAST LEADING WHITESPACE, WHICH IT DID NOT USED TO.
// The version this was extracted from carried a comment saying a leading tab
// or CR "defeats a naive check that looks at index 0" — and then folded those
// characters to a SPACE *before* testing `/^[=+\-@]/`, so on the exact input
// the comment names the test ran against a string starting with a space and
// never fired. A guard that could not fire, documented as though it did.
// Found 2026-09-24, when the log export added a test for the case the comment
// described: `neutralises one hidden behind whitespace Excel strips first` in
// tests/logExport.test.js.
//
// Newlines are folded to a space rather than quoted through: RFC 4180 permits
// a quoted newline, but a multi-line cell helps nobody here, and a value that
// STARTS with one would otherwise carry the formula character to the head of
// the second physical line.

/**
 * One CSV cell, always quoted.
 *
 * ⛔ ALWAYS QUOTED, even when nothing requires it. Quoting conditionally means
 * deciding, per value, whether it contains a separator — and the cost of
 * getting that wrong once is a row that silently shifts every column after it.
 */
function csvEscape(value) {
  let s = value === null || value === undefined ? '' : String(value);
  s = s.replace(/[\r\n\t]+/g, ' ');
  // ⛔ `^\s*`, not `^` — see the note above. The whitespace is KEPT rather than
  // trimmed: the apostrophe is what neutralises the formula, and silently
  // deleting leading characters from an attacker-controlled log line would
  // tidy the evidence rather than protect the reader.
  if (/^\s*[=+\-@]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

/** One CSV record, without its line terminator. */
function csvRow(values) {
  return values.map(csvEscape).join(',');
}

// ⛔ EXCEL IGNORES `charset=utf-8` ON A DOWNLOADED FILE and falls back to the
// system codepage, so a Thai or accented username exports correctly and opens
// as mojibake — which on an evidence export is a corrupted identifier, not a
// cosmetic problem. A BOM is what Excel actually reads.
//
// It is an OPT-IN rather than the default because a BOM is not free: some
// strict parsers hand the first header name back with a zero-width character
// glued to it. Each caller therefore makes a visible choice — the change-request
// CSV, read by a change board in Excel but also diffed by hand, does without;
// the log export, whose stated destination is a spreadsheet, takes it.
const UTF8_BOM = '﻿';

/**
 * Join rows into a CSV document.
 *
 * ⛔ CRLF, per RFC 4180 — Excel is tolerant but some Windows tooling is not.
 * ⛔ And a document with no data rows still gets its header: "the export is
 * broken" and "nothing matched" must never look the same.
 */
function csvDocument(rows, opts = {}) {
  const body = rows.join('\r\n') + '\r\n';
  return opts.bom ? UTF8_BOM + body : body;
}

module.exports = { csvEscape, csvRow, csvDocument, UTF8_BOM };
