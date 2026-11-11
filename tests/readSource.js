'use strict';
// tests/readSource.js
//
// ⛔ READ A SOURCE FILE FOR ASSERTION, WITH CRLF NORMALISED AWAY.
//
// A Windows checkout stores source with CRLF. Every regex in this suite was
// written against the bytes a Linux checkout produces, so any pattern anchored
// on `\n` — `,\n`, `\n\s+`, `;\n}` — silently stops matching on Windows and the
// assertion fails for a reason that has nothing to do with the code under test.
//
// ⛔ THIS IS NOT HYPOTHETICAL AND IT IS NOT NEW. `tests/psScripts.js` already
// carries `readPs()` for exactly this reason, and CLAUDE.md records the rule for
// `.ps1` files. The same trap applies to `.js`, and it was found the only way it
// can be: by running `npm test` on a genuine Windows install.
//
//   tests/cloudDeclare.test.js:577
//   /partial:\s*failed\.length > 0[\s\S]{0,200}?,\n/
//
// Measured on the fresh install at C:\Apps\SecVault: route.js is 151 lines, 151
// of them CRLF. That regex returns null there and matches on Linux — one failure
// out of 6,508 tests, for a file nobody had touched.
//
// ⛔ NORMALISING IS SAFE AND ASYMMETRIC. It makes a Windows read byte-identical
// to a Linux one, which is what every existing pattern already assumes. It can
// only make a check match the thing it was written to match.
//
// ⛔ IT DOES NOT TRIM OR REFORMAT. Only the line terminator changes; indentation,
// blank lines and content are untouched, so offsets within a line still hold.

const fs = require('node:fs');

function readSource(filePath) {
  return fs.readFileSync(filePath, 'utf8').replace(/\r\n/g, '\n');
}

module.exports = { readSource };
