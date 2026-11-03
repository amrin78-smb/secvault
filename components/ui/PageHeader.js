import Link from 'next/link';

// The compact page header every workspace opens with.
//
// ⛔ BACKWARD COMPATIBLE BY CONSTRUCTION. Thirty-one pages already call this
// with `{title, subtitle, actions}` and every one of them still renders
// exactly as it did; the four additions below are opt-in. A shared header that
// required a migration to adopt would simply not get adopted, and the product
// would keep two header shapes.
//
// The additions, and what each is FOR:
//
//   `back`     — {href, label}. A breadcrumb for a page you arrived at from
//                somewhere specific (a device, a CVE, a finding). Rendered
//                ABOVE the title, because a back link beside a title competes
//                with it for the first thing read.
//   `eyebrow`  — the object count or scope this page is about ("8 firewalls",
//                "FLEET OF 8 · 7 REACHABLE"). Small, above the title.
//   `meta`     — data-as-of / assessment freshness. ⛔ It sits in the HEADER
//                rather than somewhere down the page because "when was this
//                measured" qualifies everything below it, and a freshness note
//                placed after the numbers it qualifies has already been
//                overtaken by the reader.
//   `primary`  — ONE primary action, rendered last and visually dominant.
//   `titleAs`  — the heading LEVEL, default `h1`. See below.
//
// ⛔ THE TITLE IS A REAL HEADING, AND FOR THIRTY PAGES IT WAS A `<div>`.
// Every workspace in this product opened with its name marked up as a styled
// div, so the document outline of the whole console was empty: a screen-reader
// user listing a page's headings got the card titles and not the name of the
// page they were on, and "jump to the main heading" — the first thing a
// keyboard user does on arrival — had nothing to jump to. Nothing caught it
// because it is invisible: the pixels are identical either way, which is the
// same reason the `hidden` attribute on the MFA field survived a live check.
//
// ⛔ `titleAs` EXISTS BECAUSE FIVE PAGES ALREADY HAVE AN h1 AND IT IS NOT THIS
// ONE. The six per-device routes mount DeviceContextHeader, whose `<h1>` is the
// FIREWALL'S NAME — and globals.css says of it "a REAL <h1>, and the only one
// on the page", recording the earlier defect where the device name and a
// PageHeader title competed as headings. On those pages the firewall is the
// subject and "Policy" / "Changes" / "Metrics" is a section of it, so the
// honest outline is h1 <device> > h2 <view>. Defaulting to `h1` and demoting
// the five by hand is the safe direction: a new page gets a correct h1 for
// free, and the only way to get it wrong is to add a SECOND heading source,
// which tests/pageHeading.test.js fails the build on.
//
// ⛔ ONE PRIMARY ACTION, AND IT IS A SEPARATE PROP RATHER THAN A CONVENTION
// ABOUT THE FIRST CHILD OF `actions`. A convention cannot be enforced and
// cannot be tested; a prop that holds exactly one node can be both. Pages with
// two equally-weighted buttons today keep passing both through `actions`,
// which is honest — it says this page has no single primary action, rather
// than promoting one arbitrarily.

const HEADING_LEVELS = new Set(['h1', 'h2', 'h3']);

export default function PageHeader({
  title,
  subtitle,
  actions,
  back,
  eyebrow,
  meta,
  primary,
  titleAs,
}) {
  // A plain string, never a component reference, so a page cannot pass an
  // arbitrary element in. Anything outside the set falls back to h1 — the
  // level a page title should have — rather than to a div, which is the
  // defect this prop exists to end.
  const Title = HEADING_LEVELS.has(titleAs) ? titleAs : 'h1';
  return (
    <div className="page-header">
      <div className="page-header-main">
        {back && back.href && (
          <Link href={back.href} className="page-back">
            <span aria-hidden="true">←</span> {back.label || 'Back'}
          </Link>
        )}
        {eyebrow && <div className="page-eyebrow">{eyebrow}</div>}
        <Title className="page-title">{title}</Title>
        {subtitle && <div className="page-subtitle">{subtitle}</div>}
        {/* ⛔ Below the subtitle, not beside the title: it is a qualifier on
            the page, not part of its name. */}
        {meta && <div className="page-meta">{meta}</div>}
      </div>
      {(actions || primary) && (
        <div className="page-header-actions">
          {actions}
          {primary}
        </div>
      )}
    </div>
  );
}
