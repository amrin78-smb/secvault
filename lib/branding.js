// lib/branding.js
//
// The BRANDING SURFACE: the small set of strings a rebrand would change.
//
// ⛔ SCOPE, and why it is this small. The product name appears ~41 times in the
// codebase, and 35 of those are PROSE — "questions SecVault could not ask of
// this device", "SecVault does not guess a username", "that is a gap in what
// SecVault can read, not a measured zero". Those sentences are the product's
// VOICE, not its chrome. Turning them into `${PRODUCT_NAME} could not ask`
// would make every one of them harder to read and harder to edit, in exchange
// for nothing: a customer who rebrands the header does not need the
// explanatory copy rewritten in their name, and if they ever did, that is a
// translation problem rather than a token problem.
//
// So this file covers the CHROME only — the wordmark, the version line, the
// update banner, the report cover. Six places, one file, no configuration UI.
//
// ⛔ NO CONFIG UI, DELIBERATELY (decision: "internal now, sellable later").
// These are constants, not settings: nothing reads them from the database and
// nothing exposes them over HTTP. That keeps the door open cheaply — a rebrand
// is one file — without building a customisation surface that nobody is asking
// for yet and that would need its own validation, storage and admin gating.
// When a real white-label customer appears, the work is to back these three
// values with a settings row, not to go hunting for hardcoded strings.
//
// The accent hue is the other half of the branding surface and lives in
// app/globals.css as --primary/--accent-teal. A rebrand is those tokens plus
// this file.

'use strict';

const PRODUCT_NAME = 'SecVault';

// Shown under the wordmark on the login panel and on the PDF report cover.
const PRODUCT_TAGLINE = 'Firewall Security Platform';

// The wordmark splits here: the first part renders in the shell foreground and
// the second in the brand accent. Keeping the split as DATA rather than as two
// hardcoded <tspan> strings means a one-word product name still works — the
// second half simply comes out empty rather than the logo breaking.
const PRODUCT_NAME_PARTS = ['Sec', 'Vault'];

module.exports = {
  PRODUCT_NAME,
  PRODUCT_TAGLINE,
  PRODUCT_NAME_PARTS,
};
