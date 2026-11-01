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
//
// ⛔ ONE PRIMARY ACTION, AND IT IS A SEPARATE PROP RATHER THAN A CONVENTION
// ABOUT THE FIRST CHILD OF `actions`. A convention cannot be enforced and
// cannot be tested; a prop that holds exactly one node can be both. Pages with
// two equally-weighted buttons today keep passing both through `actions`,
// which is honest — it says this page has no single primary action, rather
// than promoting one arbitrarily.

export default function PageHeader({
  title,
  subtitle,
  actions,
  back,
  eyebrow,
  meta,
  primary,
}) {
  return (
    <div className="page-header">
      <div className="page-header-main">
        {back && back.href && (
          <Link href={back.href} className="page-back">
            <span aria-hidden="true">←</span> {back.label || 'Back'}
          </Link>
        )}
        {eyebrow && <div className="page-eyebrow">{eyebrow}</div>}
        <div className="page-title">{title}</div>
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
