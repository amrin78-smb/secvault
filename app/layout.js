import './globals.css';
import { PRODUCT_NAME } from '../lib/branding';
import { THEME_INIT_SCRIPT } from '../lib/theme';
import { CORNERS_INIT_SCRIPT } from '../lib/corners';
import { DENSITY_INIT_SCRIPT } from '../lib/density';
import { NAV_MODE_INIT_SCRIPT } from '../lib/navLayout';

export const metadata = {
  // ⛔ FROM THE BRANDING SURFACE, NOT A LITERAL. This was hardcoded 'SecVault'
  // — the same leak v2.199.0 fixed on the login eyebrow one file away, which
  // had been printing its own copy of the tagline while lib/branding.js held
  // a different one. A rebrand is meant to be one file; a hardcoded copy
  // beside it is one a rebrand MISSES, and this particular copy is the text
  // in the browser tab, i.e. the most visible string in the product.
  title: PRODUCT_NAME,
  // ⛔ DELIBERATELY STILL A LITERAL. lib/branding.js draws its own scope line
  // at the CHROME — the wordmark, the version line, the update banner, the
  // report cover — and excludes PROSE on the grounds that a customer who
  // rebrands the header does not need the explanatory copy rewritten. This
  // sentence is a category description, true of a white-labelled build as it
  // stands, and it carries no product name to go stale. It is NOT a second
  // copy of PRODUCT_TAGLINE, which is the wordmark's eyebrow; do not "finish
  // the job" by replacing it with one.
  description: 'Firewall security and management platform',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
        {/* Applies the saved theme to <html> before first paint, avoiding a
            flash of the wrong theme. Reads localStorage directly — cannot be
            an import, must run synchronously in <head>. See lib/theme.js. */}
        <script dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }} />
        {/* Same no-flash contract as the theme script above, for the rounded/
            square corner switch. See lib/corners.js. */}
        <script dangerouslySetInnerHTML={{ __html: CORNERS_INIT_SCRIPT }} />
        {/* Third of the same family, for table density. See lib/density.js. */}
        <script dangerouslySetInnerHTML={{ __html: DENSITY_INIT_SCRIPT }} />
        {/* ⛔ FOURTH OF THE FAMILY, AND THE ONLY ONE THAT ALSO LISTENS. The
            other three read a stored preference once; the shape of the
            navigation rail depends on the VIEWPORT, which changes while the
            page is open, so this one installs a resize handler as well.
            app/globals.css carries no widths for the rail at all — it keys
            purely on the `data-nav` attribute this stamps, which is what keeps
            the breakpoints to a single definition. See lib/navLayout.js. */}
        <script dangerouslySetInnerHTML={{ __html: NAV_MODE_INIT_SCRIPT }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
