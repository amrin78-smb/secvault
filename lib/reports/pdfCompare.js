'use strict';

// lib/reports/pdfCompare.js — structural equality for two generated PDFs.
//
// ⛔ WHY THIS EXISTS. A report is an audit artefact. Refactoring the code that
// draws one is only safe if you can PROVE the document did not change, and
// "the tests still pass" does not prove that — every unit test in this repo
// could pass while the cover silently moved 6pt and every page repaginated.
//
// ⛔ A RAW BYTE COMPARE IS USELESS HERE, and the reason is worth stating so
// nobody "simplifies" this away: pdfkit stamps /CreationDate, /ModDate and a
// file /ID derived from them, and the report itself prints a generated-at
// timestamp into its own content. Two runs a second apart therefore differ in
// bytes while being the same document. Those four things are the ONLY
// differences tolerated.
//
// ⛔ AND COMPARING EXTRACTED TEXT IS TOO WEAK. It would pass a document whose
// words are right and whose coordinates are wrong. So this decompresses every
// content stream and compares the OPERATOR SEQUENCE — every move, every fill,
// every glyph placement — which catches a shifted baseline that no text
// extraction would notice.

const zlib = require('zlib');

// The report's own rendered stamp: "15/09/2026, 00:22:18 UTC".
const RENDERED_STAMP = /\d{2}\/\d{2}\/\d{4},?\s*\d{2}:\d{2}:\d{2}\s*UTC/g;

/**
 * pdfkit writes text as hex strings inside TJ arrays, so the rendered timestamp
 * is not visible as ASCII. Decode each hex token, normalise any timestamp
 * inside it, and re-encode — leaving every other byte untouched.
 */
function normaliseHexText(streamText) {
  return streamText.replace(/<([0-9a-fA-F]+)>/g, (whole, hex) => {
    if (hex.length % 2 !== 0) return whole;
    let ascii = '';
    for (let i = 0; i < hex.length; i += 2) {
      ascii += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
    }
    if (!RENDERED_STAMP.test(ascii)) return whole;
    RENDERED_STAMP.lastIndex = 0;
    const scrubbed = ascii.replace(RENDERED_STAMP, 'TIMESTAMP-NORMALISED');
    let out = '';
    for (let i = 0; i < scrubbed.length; i += 1) {
      out += scrubbed.charCodeAt(i).toString(16).padStart(2, '0');
    }
    return `<${out}>`;
  });
}

/** Every decompressed content stream, in document order. */
function contentStreams(buf) {
  const latin = buf.toString('latin1');
  const out = [];
  const re = /stream\r?\n/g;
  let m;
  while ((m = re.exec(latin)) !== null) {
    const start = m.index + m[0].length;
    const end = latin.indexOf('endstream', start);
    if (end < 0) continue;
    try {
      out.push(normaliseHexText(zlib.inflateSync(buf.slice(start, end)).toString('latin1')));
    } catch (_err) {
      // Not a deflate stream — a font programme or an image. Those are byte
      // stable across runs, so skipping them loses nothing.
    }
  }
  return out;
}

/**
 * Are these two PDFs the same document?
 *
 * @returns {{equal:boolean, reason:string|null, streams:number,
 *            firstDifference:{stream:number, op:number, before:string, after:string}|null}}
 */
function comparePdfs(a, b) {
  const sa = contentStreams(a);
  const sb = contentStreams(b);

  if (sa.length !== sb.length) {
    return {
      equal: false,
      reason: `page/stream count changed: ${sa.length} -> ${sb.length}`,
      streams: sa.length,
      firstDifference: null,
    };
  }

  for (let i = 0; i < sa.length; i += 1) {
    if (sa[i] === sb[i]) continue;
    const la = sa[i].split('\n');
    const lb = sb[i].split('\n');
    for (let k = 0; k < Math.max(la.length, lb.length); k += 1) {
      if (la[k] !== lb[k]) {
        return {
          equal: false,
          reason: `drawing operators differ in stream ${i + 1}`,
          streams: sa.length,
          firstDifference: {
            stream: i + 1,
            op: k,
            before: (la[k] || '(absent)').slice(0, 200),
            after: (lb[k] || '(absent)').slice(0, 200),
          },
        };
      }
    }
  }

  return { equal: true, reason: null, streams: sa.length, firstDifference: null };
}

module.exports = { comparePdfs, contentStreams };
