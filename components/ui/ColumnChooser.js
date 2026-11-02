'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { mergeFilterQuery } from '../../lib/urlFilters';
import { resolveColumns, toggleColumn } from '../../lib/tableColumns';

// Choose which columns a wide table shows.
//
// ⛔ IT WRITES THE URL THROUGH `mergeFilterQuery`, like every other control in
// this product. Rebuilding the query here would discard the filters and the
// sort — the exact defect Phase 1 removed from four separate filter bars, and
// this is the fifth control that would have reintroduced it.
//
// ⛔ `page` IS NOT RESET. Hiding a column changes what you can SEE of a row,
// never which rows match, so the page you are on is still the right page.
// Every other control in this product resets it, so the exception is stated
// rather than left to be inferred from its absence.
export default function ColumnChooser({ basePath, defs, param = 'cols', label = 'Columns' }) {
  const router = useRouter();
  const params = useSearchParams();
  const [open, setOpen] = useState(false);
  const wrapRef = useRef(null);
  const btnRef = useRef(null);

  const qs = params ? params.toString() : '';
  const value = params ? params.get(param) || '' : '';
  const { columns, hiddenCount } = resolveColumns(defs, value);

  useEffect(() => {
    if (!open) return undefined;
    const onKey = (e) => { if (e.key === 'Escape') { setOpen(false); btnRef.current?.focus(); } };
    const onClick = (e) => { if (wrapRef.current && !wrapRef.current.contains(e.target)) setOpen(false); };
    document.addEventListener('keydown', onKey);
    document.addEventListener('mousedown', onClick);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('mousedown', onClick);
    };
  }, [open]);

  const toggle = (key) => {
    const next = toggleColumn(defs, value, key);
    router.push(`${basePath}?${mergeFilterQuery(qs, { [param]: next }, { reset: [] })}`);
  };

  return (
    <div className="colch" ref={wrapRef}>
      <button
        ref={btnRef}
        type="button"
        className="colch-btn"
        aria-expanded={open}
        aria-haspopup="true"
        onClick={() => setOpen((v) => !v)}
      >
        {label}
        {/* ⛔ THE COUNT IS PART OF THE BUTTON, not a dot. A table missing
            three columns looks like a table, so the control has to say so
            from the outside — otherwise the operator's own earlier choice is
            indistinguishable from a product that never had those columns. */}
        {hiddenCount > 0 && <span className="colch-count">{hiddenCount} hidden</span>}
        <span aria-hidden="true">▾</span>
      </button>

      {open && (
        <div className="colch-menu" role="group" aria-label={`${label} shown`}>
          {columns.map((c) => (
            <label key={c.key} className="colch-row" data-required={c.required ? '' : undefined}>
              <input
                type="checkbox"
                checked={!c.hidden}
                disabled={Boolean(c.required)}
                onChange={() => toggle(c.key)}
              />
              <span>{c.label}</span>
              {/* ⛔ A REQUIRED COLUMN IS SHOWN AND DISABLED, not omitted. An
                  operator looking for "Device" in this list and not finding
                  it would conclude the control is broken; finding it greyed
                  out tells them it cannot be turned off and why not. */}
              {c.required && <span className="colch-req">always shown</span>}
            </label>
          ))}
        </div>
      )}
    </div>
  );
}
