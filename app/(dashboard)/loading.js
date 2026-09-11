import LoadingSpinner from '../../components/ui/LoadingSpinner';

// app/(dashboard)/loading.js
//
// Route-level loading boundary for EVERY dashboard page. Next renders this the
// instant a navigation to a different route segment begins, so the operator gets
// feedback immediately instead of a page that appears frozen while the server
// queries.
//
// ⛔ This does NOT cover tab changes. Every tab in this product is a SEARCH PARAM
// on the same segment (/vpn?vtab=…, /vulnerability?tab=…), and a
// searchParams-only navigation does not remount this boundary. That case is
// handled by components/layout/NavProgress.js — the two are complementary and
// removing either leaves a real gap.
//
// ⛔ Deliberately NOT a content-shaped skeleton. A fake table of grey bars
// implies a shape the answer may not have — on a page that might legitimately
// come back empty, or as a coverage gap, a skeleton pre-announces rows that will
// never arrive. This says only what is true: something is loading.
export default function DashboardLoading() {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 'var(--s3)',
        minHeight: '40vh',
        color: 'var(--text-muted)',
      }}
    >
      <LoadingSpinner size={22} />
      <span style={{ fontSize: 'var(--text-base)' }}>Loading…</span>
    </div>
  );
}
