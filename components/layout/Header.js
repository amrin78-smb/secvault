// components/layout/Header.js
// Server component — queries feed_sync_log directly via lib/feedStatus.js for
// the sync-status pill (no client round-trip needed for that one value).
// Interactive pieces (search, bell, theme toggle, avatar dropdown) are their
// own 'use client' children.
import { pool } from '../../lib/db';
import { getSyncPillStatus } from '../../lib/feedStatus';
import HeaderSearch from './HeaderSearch';
import NavDrawerToggle from './NavDrawerToggle';
import ThemeToggle from './ThemeToggle';
import NotificationBell from './NotificationBell';
import Link from 'next/link';
import JobCentre from './JobCentre';
import { getCollectionHealth } from '../../lib/dataHealth';
import UserMenu from './UserMenu';
import { PRODUCT_NAME_PARTS, PRODUCT_TAGLINE } from '../../lib/branding';
import BrandMark from '../ui/BrandMark';

function SecVaultLogo() {
  return (
    <div className="sv-brand" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      {/* ⛔ --shell-accent, NOT --accent-teal (which IS --primary and FLIPS).
          FOURTH occurrence of the trap --shell-accent was created to end, one
          release after the token appeared: .sv-topbar is --navy, which does not
          flip. Measured on --navy: --accent-teal is 3.92:1 in LIGHT (the
          default) and 8.36:1 in dark, while --shell-accent is 8.19:1 in both.
          So the shield and the "Vault" half of the wordmark rendered in a dull
          dark teal while the active sidebar item an inch below glowed bright
          cyan -- two brand hues on the same non-flipping ground, 2.1x apart, on
          the first thing a customer looks at. It clears large-text 3:1, so this
          is brand consistency rather than legibility, which is why nothing
          caught it. The test is not which element it is, it is WHAT GROUND IT
          SITS ON. */}
      <BrandMark
        markId="header"
        height={32}
        structure="var(--shell-fg)"
        accent="var(--shell-accent)"
      />
      {/* ⛔ REAL TEXT, not <text> inside the SVG as this was until v2.199.0.
          The SVG form could not be selected, found by the browser's own find,
          or read out, and it carried its own fontFamily — which had silently
          pointed at Inter for months after the fonts were self-hosted, so the
          one word a customer reads first was set in a face used nowhere else
          in the product. A span cannot drift from the body face. */}
      {/* ⛔ `whiteSpace: nowrap` WITH NO min-width WAS AN UNSHRINKABLE BITE out
          of a bar that overflows below ~950px — the same defect the tagline
          beside it already carries a sixteen-line comment about, on the
          element directly above it. `.sv-wordmark` lets it ellipsise, so at
          phone width the brand gives way and the CONTROLS survive. */}
      <span
        className="sv-wordmark"
        style={{
          fontFamily: 'var(--font-sans)',
          fontSize: 22,
          fontWeight: 700,
          letterSpacing: '-0.3px',
          lineHeight: 1,
          whiteSpace: 'nowrap',
        }}
      >
        <span style={{ color: 'var(--shell-fg)' }}>{PRODUCT_NAME_PARTS[0]}</span>
        {/* --shell-accent, same reason as the mark above. */}
        <span style={{ color: 'var(--shell-accent)' }}>{PRODUCT_NAME_PARTS[1]}</span>
      </span>
    </div>
  );
}

// ⛔ THE PILL IS TRI-STATE, because "is the advisory data complete" is.
// It was a boolean (green/red) and read green FEEDS OK over an NVD feed that
// had logged 464 'partial' runs and zero clean ones — see the ⛔ block at the
// top of lib/feedStatus.js. Amber is the state that was missing: the feeds ran,
// they came back INCOMPLETE, and every CVE number under this bar is computed
// from what arrived.
//
// ⛔ TOKENS. This pill sits on --navy, which is dark in BOTH themes, so the
// foreground colours are --shell-fg/--shell-fg-ok/--shell-fg-bad, which do NOT
// flip. A --tint-*-fg here would be a dark colour on a dark bar in light mode,
// i.e. invisible (gotchas.md, "The shell is dark in BOTH themes").
// There is no --shell-fg-warn, so the DEGRADED row carries its hue in the dot
// and the ring (--sev-med, the amber the severity ramp already uses for
// medium) and keeps --shell-fg for the words, which is legible on navy in both
// themes by construction.
//
// SYNCING is the design system's NOT-MEASURED state — an in-flight sync is not
// a verdict, and an unmeasured state gets NO HUE. ⛔ But it is written here as a
// white alpha, NOT as var(--unmeasured), for the same reason the words are not
// a --tint-*-fg: --unmeasured FLIPS between themes because it is picked for a
// light card and a dark card respectively, and this bar is dark in BOTH. The
// light-theme value measures 2.83:1 against the pill's own wash here — under
// even WCAG 1.4.11's 3:1 for a graphical object — while the dark-theme value
// reads 4.64:1, so the same "syncing" dot would be crisp for half the users and
// nearly invisible for the other half. A white alpha is hueless (which is the
// property that actually matters) and does not flip: 6.5:1 on both grounds.
const PILL_TONE = {
  ok: {
    dot: 'var(--green)',
    fg: 'var(--shell-fg-ok)',
    bg: 'rgba(22,163,74,0.15)',
    ring: 'rgba(22,163,74,0.3)',
    pulse: true,
  },
  degraded: {
    dot: 'var(--sev-med)',
    fg: 'var(--shell-fg)',
    bg: 'rgba(183,121,31,0.20)',
    ring: 'rgba(183,121,31,0.45)',
    pulse: false,
  },
  error: {
    dot: 'var(--red)',
    fg: 'var(--shell-fg-bad)',
    bg: 'rgba(220,38,38,0.15)',
    ring: 'rgba(220,38,38,0.3)',
    pulse: false,
  },
  running: {
    dot: 'rgba(255,255,255,0.65)',
    fg: 'var(--shell-fg)',
    bg: 'rgba(255,255,255,0.08)',
    ring: 'rgba(255,255,255,0.18)',
    pulse: false,
  },
};
// No advisory feed has ever run, or the status query itself failed. Both are
// gaps, not all-clears, and both keep the alarming treatment they already had.
PILL_TONE.none = PILL_TONE.error;
// ⛔ EVERY FEED SKIPPED IS HUELESS, NOT AMBER AND NOT RED. A skip is a recorded
// decision rather than a verdict about the data, and this product's own rule is
// that a permanent warning chip for correct behaviour teaches an operator to
// ignore the chip that matters. It is not green either: with every feed skipped
// nothing is collecting advisories, which the title says in words. Without this
// entry the state fell through to PILL_TONE.none and painted danger red.
PILL_TONE.skipped = PILL_TONE.running;
// ⛔ And a feed the PUBLISHER refused gets the same hueless treatment. It is not
// green (nothing was collected from it), not amber (there is nothing to fix here)
// and not red (SecVault is not broken). The pill title names it; see feedStatus.js
// for why this is only the right call while another feed covers the same vendor.
PILL_TONE.blocked = PILL_TONE.running;

export default async function Header({ session }) {
  let syncStatus = {
    state: 'none',
    ok: false,
    label: 'FEEDS UNKNOWN',
    title: 'SecVault could not read feed_sync_log, so it cannot say whether advisory data is complete.',
  };
  try {
    syncStatus = await getSyncPillStatus(pool);
  } catch (_err) {
    // Sync status is informational only — never let a query failure here
    // break the whole header/page render. ⛔ The fallback above is NOT green:
    // failing to read the feed log tells us nothing good.
  }
  const tone = PILL_TONE[syncStatus.state] || PILL_TONE.none;

  // ⛔ A SECOND, SEPARATELY-NAMED FACT — NOT FOLDED INTO THE PILL ABOVE.
  // The sync pill says whether the ADVISORY CORPUS is current; this says
  // whether SecVault has pulled from the FIREWALLS recently. They fail
  // independently and are fixed in different places, so merging them would
  // produce one figure covering two problems with two different first steps.
  // It renders ONLY when there is something to say, so a healthy fleet sees
  // nothing new. Measured on the mock fleet: 0 of 8 collected within 7 days,
  // a caveat that until now appeared on the Overview and nowhere else.
  const collection = await getCollectionHealth(pool);

  return (
    <header className="sv-topbar">
      {/* ⛔ FIRST IN THE HEADER, AND INVISIBLE ABOVE 1023px. Below that width
          the rail is off-canvas and this button is the ONLY way to reach the
          navigation, so it leads the bar rather than sitting among the
          secondary controls on the right. Its visibility is a stylesheet rule
          keyed on `html[data-nav]`, not React state, so it is correct on the
          first paint and is not in the tab order at widths where it does
          nothing — see components/layout/NavDrawerToggle.js. */}
      <NavDrawerToggle />
      {/* ⛔ NO WRAPPER. This used to be <div style={{height:'100%'}}> around
          SecVaultLogo, which made the WRAPPER the flex child of .sv-topbar —
          so `.sv-brand { min-width: 0 }` on the inner div could never fire and
          the brand stayed rigid however the stylesheet asked it to yield. The
          height:100% it added was visually inert under the bar's own
          align-items:center. */}
      <SecVaultLogo />

      <div className="sv-topbar-divider" />

      <div className="sv-topbar-subtitle">{PRODUCT_TAGLINE.toUpperCase()}</div>

      <div className="sv-topbar-left">
        <HeaderSearch />
      </div>

      <div className="sv-topbar-right">
        {/* ⛔ EVERY BRANCH HERE READS `tone`, NEVER `syncStatus.ok`. PILL_TONE
            above has four entries and getSyncPillStatus() returns five states,
            but this JSX branched on the BOOLEAN — and `ok` is true for exactly
            one of those states, so `degraded`, `running`, `error` and `none`
            all collapsed into the same full-red pill. The tri-state the block
            at the top of this file describes, and that lib/feedStatus.js goes to
            real trouble to compute, was dead code: `tone` was assigned and
            never referenced.

            Two concrete wrongs that fixed:
              - FEEDS SYNCING painted DANGER RED. A sync that is merely IN
                FLIGHT is not a verdict at all, and this file's own palette
                reserves red for danger; alarming an operator about a job that
                is still running is exactly the fabricated-fact pattern, in
                pixels. It is now the hueless --unmeasured treatment, which is
                what the design system says an unmeasured state gets.
              - FEEDS DEGRADED was indistinguishable from FEED ERROR. Those
                demand different responses — a partial advisory set still
                produces numbers (which are understated), a hard failure
                produces none — and a reader who cannot tell them apart learns
                to treat both as noise.

            ⛔ The foregrounds stay --shell-fg*: this pill sits on --navy, which
            is dark in BOTH themes, so a --tint-*-fg would flip and become a dark
            colour on a dark bar in light mode. There is no --shell-fg-warn, so
            `degraded` carries its amber in the DOT and the ring and keeps plain
            --shell-fg for the words. */}
        {/* ⛔ THE LAYOUT IS IN THE STYLESHEET AND ONLY THE TONE IS INLINE, and
            that split is load-bearing rather than tidiness. `display: 'flex'`
            used to be inline here, so `html[data-nav="drawer"] .sv-sync-pill
            { display: none }` could not win — an author inline style beats any
            selector. Measured before this moved: the rule was live, the pill
            was still 120px wide, and the header still clipped. It is the third
            time this exact shape has cost something in this product: the MFA
            code field shipped with `hidden=""` and fully visible because
            `.login-field { display: flex }` beat the UA sheet, and the v2.200.0
            KPI border could not be removed in CSS because three call sites set
            it inline. ⛔ Tone colours stay inline because they are DATA — they
            come from PILL_TONE and no stylesheet can know the sync state. */}
        <div
          className="sv-sync-pill"
          style={{
            background: tone.bg,
            border: `1px solid ${tone.ring}`,
          }}
          // The explanatory sentence getSyncPillStatus() already composes —
          // which feed, what shape of failure, and what it means for the CVE
          // numbers under this bar. It was being discarded in favour of a
          // static "Feed sync status (NVD + KEV)" that said nothing the label
          // beside it did not already say.
          title={syncStatus.title}
        >
          <div
            style={{
              width: 7,
              height: 7,
              borderRadius: '50%',
              flex: 'none',
              background: tone.dot,
              // ⛔ The glow and the pulse are reserved for `ok` — they are the
              // "live and healthy" affordance. A pulsing red would read as an
              // active incident and a pulsing grey as a spinner, and neither is
              // what this pill is saying.
              boxShadow: tone.pulse ? `0 0 6px ${tone.dot}` : 'none',
              animation: tone.pulse ? 'pulse 2s infinite' : 'none',
            }}
          />
          <span
            style={{
              fontSize: 'var(--text-xs)',
              fontWeight: 600,
              color: tone.fg,
              letterSpacing: '0.03em',
            }}
          >
            {syncStatus.label}
          </span>
        </div>

        {/* ⛔ A LINK, NOT A `title`-ONLY DIV. The sync pill beside it is a
            <div> whose whole explanation lives in a `title` attribute —
            unreachable by keyboard and unreadable on touch. An indicator that
            says your numbers may be stale has to be actionable, so this one
            is a real link to the page that explains which firewalls and why.
            ⛔ It is ABSENT when collection is healthy: a permanent chip for
            the system working correctly teaches an operator to ignore the
            chip that matters. */}
        {collection.label && (
          <Link
            href="/coverage"
            className="dh-pill"
            data-state={collection.state}
            title={collection.title}
          >
            <span aria-hidden="true">⚠</span>
            <span>{collection.label}</span>
            <span className="sr-only"> — {collection.title}</span>
          </Link>
        )}

        <JobCentre />
        <NotificationBell />
        <ThemeToggle />
        <UserMenu session={session} />
      </div>
    </header>
  );
}
