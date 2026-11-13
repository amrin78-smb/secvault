import Link from 'next/link';
import { pool } from '../../../../../lib/db';
import PageHeader from '../../../../../components/ui/PageHeader';
import EmptyState from '../../../../../components/ui/EmptyState';
import ComplianceTabs from '../../../../../components/compliance/ComplianceTabs';
import ControlDetail from '../../../../../components/compliance/ControlDetail';
import { gatherControlDetail } from '../../../../../lib/engines/complianceControlsData';
import { CONTROL_CLAIM } from '../../../../../lib/engines/complianceControls';

export const dynamic = 'force-dynamic';

// /compliance/controls/[slug] — ONE control, everything SecVault knows about it.
//
// ⛔ WHY THIS ROUTE EXISTS. `audit_checks.remediation_guidance` — the only
// plain-English statement in this product of how to FIX a control — was
// reachable only by opening a firewall, then one of its 74 findings. So you
// could read how to fix a control only for the one firewall you happened to
// pick, and only if that firewall had been audited at all. "What is this
// control, how do I fix it, and which firewalls fail it" is one question and
// had no page.
//
// ⛔ THE ROLL-UP IS `buildControl`'s, UNCHANGED. The badge at the top of this
// page is the same object the row on /compliance/controls rendered, built from
// the same findings and the same applicable count. A detail page that
// recomputed its own status would eventually disagree with the row that linked
// to it, and a reader would have no way to tell which one was wrong.
//
// ⛔ NO PERCENTAGE, HERE OR ANYWHERE UNDER IT. `scorePct` is the single
// compliance figure this product publishes; a per-control percentage computed
// over a different denominator would sit on the same screen disagreeing with
// it. Counts of firewalls, and a state.
//
// ⛔ AN UNKNOWN SLUG IS A RESULT, NOT AN ERROR AND NOT A 404 PAGE. A check can
// LEAVE the seed library — `compliance_exceptions` declines a foreign key for
// exactly that reason, so an operator's recorded decision can outlive the
// check it was recorded against — which means a link that was correct last
// month lands here legitimately. A crash or a generic not-found page would
// make a retired control indistinguishable from a broken product.

export default async function ControlDetailPage({ params }) {
  const slug = typeof params?.slug === 'string' ? decodeURIComponent(params.slug) : '';

  // ⛔ NO try/catch. A failed read must reach the error boundary rather than
  // render as "this control is not in the library", which is a confident wrong
  // answer built from a read that failed — this codebase's signature bug, on
  // the page whose job is to say what a control is.
  const detail = await gatherControlDetail(pool, slug);

  if (!detail.found) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
        <PageHeader
          eyebrow={<Link href="/compliance/controls">Compliance · Controls</Link>}
          title="Control not in the library"
          subtitle="This page names a check that the compliance library does not currently contain."
        />
        <ComplianceTabs active="controls" />
        <EmptyState
          message={`No check with the slug “${slug}” is in the compliance library. A check can be removed from the library while exceptions and links to it remain, so a link that worked before can legitimately land here. This says nothing about the fleet — it is a statement about SecVault's curated check library.`}
        />
        <p style={{ margin: 0, fontSize: 'var(--text-sm)' }}>
          <Link href="/compliance/controls">Back to every control</Link>
        </p>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* ⛔ THE BREADCRUMB IS PageHeader's `eyebrow`, not headings. It renders
          above the h1, keeps "exactly one h1 per page" intact, and earns its
          place on a narrow viewport where the sidebar carrying the same
          hierarchy is behind a drawer. */}
      <PageHeader
        eyebrow={<Link href="/compliance/controls">Compliance · Controls</Link>}
        title={detail.control.name}
        subtitle="One control, every firewall's answer to it, and how to fix it. A control has no single fleet-wide verdict — the counts below are the split behind the roll-up."
      />

      <ComplianceTabs active="controls" />

      <ControlDetail detail={detail} />

      <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-muted)', maxWidth: '72ch' }}>
        {CONTROL_CLAIM}{' '}
        <Link href="/compliance/controls">Every control</Link> ranks the library by what is failing
        on the most firewalls; <Link href="/compliance/exceptions">Exceptions</Link> lists every
        accepted risk across the fleet.
      </p>
    </div>
  );
}
