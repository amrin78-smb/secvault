'use client';

import Button from '../ui/Button';

// Tiny, single-purpose client boundary for
// app/(dashboard)/compliance/[deviceId]/print/page.js, which is otherwise a
// Server Component (async function, direct pool.query() calls for the
// report data) -- window.print() needs an onClick handler, and Server
// Components can't hold one. Rather than converting the whole report page
// to 'use client' (which would lose its ability to `await pool.query()`
// directly, the exact thing this report needs), this is the smallest
// possible client island: no props, no state, no data of its own.
// `.no-print` (app/globals.css's print stylesheet) hides this button
// automatically once printing actually starts, so it never shows up in the
// printed/PDF output itself.
export default function PrintReportButton() {
  return (
    <Button type="button" variant="primary" className="no-print" onClick={() => window.print()}>
      Print / Save as PDF
    </Button>
  );
}
