'use client';

import { Fragment, useEffect, useRef, useState } from 'react';
import Table from '../ui/Table';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';
import RuleEvidenceTable from './RuleEvidenceTable';

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

export default function StandardTabs({ standards, findings }) {
  const [active, setActive] = useState(standards?.[0]?.key || '');
  const [statusFilter, setStatusFilter] = useState('all');
  const [expanded, setExpanded] = useState({});
  const containerRef = useRef(null);

  function toggleExpanded(id) {
    setExpanded((prev) => ({ ...prev, [id]: !prev[id] }));
  }

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

  return (
    <div ref={containerRef} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 4, borderBottom: '1px solid var(--border)' }}>
        {standards.map((s) => {
          const isActive = active === s.key;
          return (
            <button
              key={s.key}
              type="button"
              onClick={() => setActive(s.key)}
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
              onClick={() => setStatusFilter(sf.key)}
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
        <EmptyState message="No findings for this standard yet." />
      ) : (
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
            {filtered.map((f) => {
              const sev = SEVERITY_BADGE[f.severity] || SEVERITY_BADGE.info;
              const st = STATUS_BADGE[f.status] || STATUS_BADGE.na;
              const hasEvidence = f.status === 'fail' && Array.isArray(f.ruleEvidence) && f.ruleEvidence.length > 0;
              const isExpanded = !!expanded[f.id];
              return (
                <Fragment key={f.id}>
                  <tr>
                    <td title={f.name}>{f.name}</td>
                    <td>
                      <Badge color={sev.color}>{sev.label}</Badge>
                    </td>
                    <td>
                      <Badge color={st.color}>{st.label}</Badge>
                    </td>
                    <td style={{ color: 'var(--text-secondary)' }} title={f.detail || ''}>
                      {f.detail || '—'}
                      {hasEvidence && (
                        <div style={{ marginTop: 4 }}>
                          <button
                            type="button"
                            onClick={() => toggleExpanded(f.id)}
                            style={{
                              background: 'none',
                              border: 'none',
                              padding: 0,
                              color: 'var(--primary)',
                              fontSize: 'var(--text-sm)',
                              textDecoration: 'underline',
                              cursor: 'pointer',
                            }}
                          >
                            {isExpanded
                              ? 'Hide'
                              : `Show ${f.ruleEvidence.length} offending rule${f.ruleEvidence.length === 1 ? '' : 's'}`}
                          </button>
                        </div>
                      )}
                    </td>
                    <td style={{ color: 'var(--text-secondary)' }} title={f.remediationGuidance || ''}>
                      {f.remediationGuidance || '—'}
                    </td>
                  </tr>
                  {hasEvidence && isExpanded && (
                    <tr key={`${f.id}-evidence`}>
                      <td colSpan={5} style={{ background: 'var(--bg-primary)', padding: 12 }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                          <RuleEvidenceTable rules={f.ruleEvidence} />
                          {f.remediationGuidance && (
                            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                              <strong style={{ color: 'var(--text-primary)' }}>Recommendation: </strong>
                              {f.remediationGuidance}
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </Table>
      )}
    </div>
  );
}
