'use client';

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import Table from '../ui/Table';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';
import NotMeasured from '../ui/NotMeasured';
import { paginateArray } from '../../lib/pagination';

// Deliberate deviation from this app's usual `?tab=` server-navigation
// convention (see app/(dashboard)/devices/[id]/analysis/page.js) -- see
// app/(dashboard)/compliance/[deviceId]/page.js's own comment for why:
// switching standards here only re-filters an already-fetched findings
// array, there is no new per-tab DB query the way analysis's tabs each run.

// Compliance status -> Badge color. pass=green, fail=red, warning=amber,
// na=muted/gray, per the task's own status-badge spec.
const STATUS_BADGE = {
  pass: { label: 'Pass', color: 'success' },
  fail: { label: 'Fail', color: 'danger' },
  warning: { label: 'Warning', color: 'warning' },
  na: { label: 'N/A', color: 'muted' },
};

// audit_checks.severity is 'critical'|'high'|'medium'|'low'|'info' (per
// lib/schema.sql) -- one more value ('low') than
// components/analysis/SeverityBadge.js's rule-analysis severity set, so a
// local map is used here rather than reusing that component and having it
// silently fall back to 'info' styling for 'low'.
const SEVERITY_BADGE = {
  critical: { label: 'Critical', color: 'danger' },
  high: { label: 'High', color: 'warning' },
  medium: { label: 'Medium', color: 'info' },
  low: { label: 'Low', color: 'muted' },
  info: { label: 'Info', color: 'muted' },
};

// Pass/Fail/All sub-filter, layered on top of the existing standard-tab
// filter. Default 'all' preserves the pre-existing behavior for anyone not
// touching the new control.
const STATUS_FILTERS = [
  { key: 'all', label: 'All' },
  { key: 'fail', label: 'Fail' },
  { key: 'pass', label: 'Pass' },
];

// ── Pagination: CLIENT state, not the URL ────────────────────────────────────
// The rest of this app pages through the query string (lib/pagination.js), and
// that is right for a server-rendered list. It is wrong HERE: the two filters
// this table already has (the standard tab and the pass/fail chips) are client
// state by deliberate design — see this file's header comment — so a page
// number in the URL would be the only one of the three that survives a reload,
// and `?page=3` left over from the CIS tab would describe a different list the
// moment the reader clicks ISO 27001. Page, tab and filter therefore live and
// reset together. The paging ARITHMETIC is still paginateArray(), with its
// clamp (a page past the end shows the LAST page, never a blank table).
const CHECKS_PAGE_SIZE = 20;

// Prev/next strip. components/ui/Pagination is the shared control but is
// href-driven, which the client state above rules out; this renders the same
// shape (honest range on the left, controls on the right, count shown even
// when there is only one page) off local state instead.
//
// Module top level, never nested inside StandardTabs (CLAUDE.md).
const PAGER_BTN = (enabled) => ({
  padding: '4px 10px',
  fontSize: 'var(--text-sm)',
  fontWeight: 600,
  borderRadius: 'var(--radius-sm)',
  border: '1px solid var(--border)',
  background: 'var(--bg-card)',
  color: enabled ? 'var(--text-primary)' : 'var(--text-muted)',
  opacity: enabled ? 1 : 0.45,
  cursor: enabled ? 'pointer' : 'default',
  whiteSpace: 'nowrap',
});

function ChecksPager({ page, totalPages, total, pageSize, onPage }) {
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(page * pageSize, total);
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 10,
        marginTop: 12,
        paddingTop: 12,
        borderTop: '1px solid var(--border)',
      }}
    >
      <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
        {total === 0
          ? 'No checks'
          : `${from.toLocaleString()}–${to.toLocaleString()} of ${total.toLocaleString()} checks in this view`}
      </div>
      {totalPages > 1 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <button type="button" onClick={() => onPage(page - 1)} disabled={page <= 1} style={PAGER_BTN(page > 1)}>
            ← Prev
          </button>
          <span
            style={{
              fontSize: 'var(--text-sm)',
              color: 'var(--text-secondary)',
              padding: '0 6px',
              fontVariantNumeric: 'tabular-nums',
            }}
          >
            Page {page.toLocaleString()} of {totalPages.toLocaleString()}
          </span>
          <button
            type="button"
            onClick={() => onPage(page + 1)}
            disabled={page >= totalPages}
            style={PAGER_BTN(page < totalPages)}
          >
            Next →
          </button>
        </div>
      )}
    </div>
  );
}

export default function StandardTabs({ standards, findings, deviceId }) {
  const [active, setActive] = useState(standards?.[0]?.key || '');
  const [statusFilter, setStatusFilter] = useState('all');
  const [page, setPage] = useState(1);
  const containerRef = useRef(null);

  // Nice-to-have deep-link support: /compliance/[deviceId]#CIS_V8 preselects
  // that tab, so the fleet matrix's per-standard chip links
  // (ComplianceMatrix.js) land directly on the right tab instead of always
  // opening to the first standard.
  //
  // ⛔ Extended 2026-07-19: this used to only read the hash once, on mount.
  // The new StandardCard "failed check" / "view more" links
  // (compliance/[deviceId]/page.js) point at `#STANDARD_KEY` anchors on this
  // SAME page — a same-page hash change via next/link's <Link> does not
  // remount this component (App Router treats it as a client-side hash
  // navigation on the same route), so the mount-only effect never re-ran and
  // clicking a failed-check link did nothing to the active tab. A
  // `hashchange` listener makes both the original cross-page case (fleet
  // matrix → per-device page, still works via the initial-read branch below)
  // and this same-page case work identically.
  //
  // ⛔ Extended again 2026-07-19 (scroll fix): matching a hash also updated
  // `active`, but nothing ever scrolled the tab/table into view -- on a
  // same-page click (the hashchange branch) the content changes far below
  // the fold with zero visible motion, so it looked like the link did
  // nothing. Now scrolls containerRef into view whenever a real standard
  // hash is matched, on BOTH the initial mount-time read (cross-page
  // arrival, e.g. fleet matrix -> per-device page -- explicit scroll is
  // harmless/consistent even though browser-native anchor scroll may
  // already help there) and the hashchange listener (same-page click, the
  // actual bug -- this path previously had no scroll at all). Deliberately
  // NOT called on a bare initial load with no hash -- scrolling the page on
  // every normal visit would itself be unwanted motion.
  useEffect(() => {
    if (typeof window === 'undefined') return undefined;

    const applyHash = () => {
      const hash = window.location.hash.replace('#', '');
      if (hash && standards.some((s) => s.key === hash)) {
        setActive(hash);
        // Arriving at a different standard means a different list — page 1 of
        // it, never whatever page number the previous standard was on.
        setPage(1);
        containerRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    };

    applyHash();
    window.addEventListener('hashchange', applyHash);
    return () => window.removeEventListener('hashchange', applyHash);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filtered = findings.filter(
    (f) =>
      Array.isArray(f.standards) &&
      f.standards.includes(active) &&
      (statusFilter === 'all' || f.status === statusFilter)
  );

  // ⛔ This count is every finding in the current view, INCLUDING `na` — the
  // table shows all four states, and `na` rows are the ones SecVault could not
  // ask of this device at all. They are deliberately excluded from the
  // compliance score (see CLAUDE.md's warning-vs-na rule), so the caption below
  // says which number this is; a reader must never infer the score's
  // denominator from this table's row count.
  const pageInfo = paginateArray(filtered, page, CHECKS_PAGE_SIZE);
  const naCount = filtered.filter((f) => f.status === 'na').length;

  return (
    <div ref={containerRef} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 4, borderBottom: '1px solid var(--border)' }}>
        {standards.map((s) => {
          const isActive = active === s.key;
          return (
            <button
              key={s.key}
              type="button"
              onClick={() => {
                setActive(s.key);
                setPage(1);
              }}
              style={{
                padding: '8px 12px',
                fontSize: 'var(--text-base)',
                background: 'none',
                border: 'none',
                borderBottom: isActive ? '2px solid var(--primary)' : '2px solid transparent',
                color: isActive ? 'var(--primary)' : 'var(--text-secondary)',
                cursor: 'pointer',
              }}
            >
              {s.label}
            </button>
          );
        })}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
        {STATUS_FILTERS.map((sf) => {
          const isActive = statusFilter === sf.key;
          return (
            <button
              key={sf.key}
              type="button"
              onClick={() => {
                setStatusFilter(sf.key);
                setPage(1);
              }}
              style={{
                padding: '4px 10px',
                fontSize: 'var(--text-sm)',
                borderRadius: 'var(--radius-sm)',
                border: `1px solid ${isActive ? 'var(--primary)' : 'var(--border)'}`,
                background: isActive ? 'var(--primary)' : 'transparent',
                color: isActive ? '#fff' : 'var(--text-secondary)',
                cursor: 'pointer',
              }}
            >
              {sf.label}
            </button>
          );
        })}
      </div>

      {filtered.length === 0 ? (
        // ⛔ "No findings" is ambiguous between "this device passed everything"
        // and "this audit never ran / this filter hides everything". Say which
        // one, using the state this component actually has.
        <EmptyState
          message={
            statusFilter === 'all'
              ? 'No checks have been evaluated against this standard on this device — the audit has not run, or no check in the library maps to it. This is not a clean result.'
              : `No ${statusFilter === 'fail' ? 'failing' : 'passing'} checks in this standard. Switch to "All" to see every check, including the ones SecVault could not evaluate.`
          }
        />
      ) : (
        <>
        <Table>
          <colgroup>
            <col style={{ width: '28%' }} />
            <col style={{ width: '10%' }} />
            <col style={{ width: '10%' }} />
            <col style={{ width: '30%' }} />
            <col style={{ width: '22%' }} />
          </colgroup>
          <thead>
            <tr>
              <th>Check Name</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Detail</th>
              <th>Remediation</th>
            </tr>
          </thead>
          <tbody>
            {pageInfo.rows.map((f) => {
              const sev = SEVERITY_BADGE[f.severity] || SEVERITY_BADGE.info;
              const st = STATUS_BADGE[f.status] || STATUS_BADGE.na;
              const hasEvidence = f.status === 'fail' && Array.isArray(f.ruleEvidence) && f.ruleEvidence.length > 0;
              return (
                <tr key={f.id}>
                  <td title={f.name}>
                    {deviceId ? (
                      <Link href={`/compliance/${deviceId}/checks/${f.id}`} className="link-quiet">
                        {f.name}
                      </Link>
                    ) : (
                      f.name
                    )}
                  </td>
                  <td>
                    <Badge color={sev.color}>{sev.label}</Badge>
                  </td>
                  <td>
                    {/* ⛔ `na` is not a fourth grade, it is the absence of one:
                        a question SecVault could not ask of this device at all,
                        excluded from the score's denominator (CLAUDE.md's
                        warning-vs-na rule). A muted Badge put it in the same
                        visual family as pass/fail/warning; the hueless marker
                        says it is a different KIND of answer. `warning`, by
                        contrast, IS a graded result about this device and keeps
                        its badge. */}
                    {f.status === 'na' ? (
                      <NotMeasured
                        text="N/A"
                        reason={
                          f.detail ||
                          'SecVault could not ask this question of this device — no usable config, no collected ruleset, or a check a config snapshot cannot answer. Excluded from the score, not failed.'
                        }
                      />
                    ) : (
                      <Badge color={st.color}>{st.label}</Badge>
                    )}
                  </td>
                  <td style={{ color: 'var(--text-secondary)' }} title={f.detail || ''}>
                    {f.detail || (
                      <NotMeasured reason="This check recorded no detail line." />
                    )}
                    {hasEvidence && (
                      <div style={{ marginTop: 4, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                        {f.ruleEvidence.length} offending rule{f.ruleEvidence.length === 1 ? '' : 's'} — click the check name for details
                      </div>
                    )}
                  </td>
                  <td style={{ color: 'var(--text-secondary)' }} title={f.remediationGuidance || ''}>
                    {f.remediationGuidance || (
                      <NotMeasured reason="The check library carries no remediation text for this check." />
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </Table>
        <ChecksPager
          page={pageInfo.page}
          totalPages={pageInfo.totalPages}
          total={pageInfo.total}
          pageSize={pageInfo.pageSize}
          onPage={setPage}
        />
        {naCount > 0 && (
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
            {naCount} of these {naCount === 1 ? 'is' : 'are'} N/A — questions SecVault could not ask of this device
            (no usable config, no collected ruleset, or a check that a config snapshot cannot answer). They are
            listed here for manual verification but are excluded from the compliance score.
          </div>
        )}
        </>
      )}
    </div>
  );
}
