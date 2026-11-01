'use client';

// The shared results-first filter row: controls, then what is applied, then the
// table. Used by /devices, /alerts and /exposure.
//
// ⛔ WHAT THIS REPLACED, AND WHY IT IS WORTH A SHARED COMPONENT. Four pages
// each hand-rolled the same bar and each got a different subset of it right.
// `DeviceFilters` had a debounced search, a "showing N of M" line and a clear
// affordance; `AlertsFilters` had none of those; `ExposureFilters` styled its
// own <select> with hardcoded padding and a hardcoded border, opting that one
// control out of the density and corner settings the rest of the product
// honours. None of the four showed WHICH filters were applied — which is the
// one thing a narrowed table cannot say for itself.
//
// ⛔ THE CHIPS ARE THE POINT, NOT DECORATION. A short table and a filtered
// table look identical. On this product that is not a cosmetic problem: an
// operator looking at /exposure with a forgotten device filter sees a near
// empty table and reads it as "no exposure", which is the failed-read-as-a-fact
// rule wearing a UI costume. Every applied filter gets a chip, INCLUDING one
// this bar has no definition for — an unrecognised filter is one we could not
// LABEL, never one that is not there.
//
// ⛔ THE URL IS THE STATE, and the arithmetic on it is pure and lives in
// lib/urlFilters.js. These components only render and push.

import { useEffect, useRef, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  activeFilterChips,
  clearedFilterQuery,
  filterHref,
  hasActiveFilters,
} from '../../lib/urlFilters';

/**
 * Push a filter change, merging into whatever else is in the URL.
 *
 * ⛔ Returns a pusher rather than an href so the caller cannot forget the
 * merge. The four copies this replaces all rebuilt the query from the handful
 * of parameters each knew about, which is how `/exposure` silently reset a
 * reader's rows-per-page.
 */
export function useFilterNav(basePath) {
  const router = useRouter();
  const params = useSearchParams();
  const qs = params ? params.toString() : '';
  return {
    qs,
    set: (changes, opts) => router.push(filterHref(basePath, qs, changes, opts)),
    clear: () => {
      const next = clearedFilterQuery(qs);
      router.push(next ? `${basePath}?${next}` : basePath);
    },
  };
}

/**
 * One labelled control. Module top level, never nested — CLAUDE.md's first
 * Critical Rule.
 */
export function FilterField({ label, htmlFor, grow = false, children }) {
  return (
    <div className="filter-field" data-grow={grow ? 'true' : undefined}>
      <label className="filter-label" htmlFor={htmlFor}>{label}</label>
      {children}
    </div>
  );
}

export function FilterSelect({ label, param, value, options, onChange, idPrefix = 'filter' }) {
  const id = `${idPrefix}-${param}`;
  return (
    <FilterField label={label} htmlFor={id}>
      {/* ⛔ className="select", not an inline style block. A control that
          hardcodes its own padding and border opts itself out of the density
          and corner settings silently — the same failure mode CLAUDE.md
          records for a table cell that hardcodes `padding: 12px 16px`. */}
      <select
        id={id}
        className="select filter-control"
        value={value || ''}
        onChange={(e) => onChange(param, e.target.value)}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    </FilterField>
  );
}

// Typing used to push a navigation on EVERY keystroke, so "TSR-TL" was six full
// server round trips over the whole fleet query.
const SEARCH_DEBOUNCE_MS = 350;

export function FilterSearch({
  label = 'Search',
  param = 'q',
  placeholder,
  value,
  onChange,
  idPrefix = 'filter',
}) {
  const id = `${idPrefix}-${param}`;
  // Controlled, so the box never fights the debounced URL update.
  const [text, setText] = useState(value || '');
  const timer = useRef(null);

  // Re-sync when the URL changes from somewhere else (a cleared filter, the
  // back button) WITHOUT clobbering what is being typed right now.
  useEffect(() => {
    if (timer.current === null) setText(value || '');
  }, [value]);
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);

  return (
    <FilterField label={label} htmlFor={id} grow>
      <input
        id={id}
        className="input filter-control"
        type="search"
        placeholder={placeholder}
        value={text}
        onChange={(e) => {
          const next = e.target.value;
          setText(next);
          if (timer.current) clearTimeout(timer.current);
          timer.current = setTimeout(() => {
            timer.current = null;
            onChange(param, next.trim());
          }, SEARCH_DEBOUNCE_MS);
        }}
      />
    </FilterField>
  );
}

/**
 * The bar.
 *
 * @param {React.ReactNode} children   the controls
 * @param {{key,label,options?}[]} [defs]  so a chip can read as its control did
 * @param {string} [basePath]          required for the chips to be removable
 * @param {{shown:number,total:number,noun:string}} [count]
 * @param {React.ReactNode} [advanced] controls shown only when expanded
 */
export default function FilterBar({
  children,
  defs = [],
  basePath,
  count,
  advanced,
  advancedLabel = 'More filters',
}) {
  const params = useSearchParams();
  const qs = params ? params.toString() : '';
  const router = useRouter();
  const chips = activeFilterChips(qs, defs);
  const active = hasActiveFilters(qs);

  // ⛔ An advanced panel OPENS ITSELF when something inside it is applied.
  // Otherwise an active filter sits inside a collapsed section with nothing on
  // screen to say so — and the chips below are the only trace. Starting open
  // when it has state is cheaper to understand than a badge on the toggle.
  const advancedKeys = new Set(defs.filter((d) => d.advanced).map((d) => d.key));
  const advancedApplied = chips.some((c) => advancedKeys.has(c.key));
  const [showAdvanced, setShowAdvanced] = useState(false);
  const open = showAdvanced || advancedApplied;

  function removeChip(key) {
    router.push(filterHref(basePath, qs, { [key]: '' }));
  }

  return (
    <div className="filter-bar">
      <div className="filter-controls">
        {children}
        {advanced && (
          <button
            type="button"
            className="filter-more"
            aria-expanded={open}
            aria-controls="filter-advanced"
            onClick={() => setShowAdvanced((v) => !v)}
          >
            {open ? 'Fewer filters' : advancedLabel}
          </button>
        )}
      </div>

      {advanced && (
        <div id="filter-advanced" className="filter-controls" hidden={!open}>
          {advanced}
        </div>
      )}

      {(active || count) && (
        <div className="filter-summary">
          {count && (
            <span className="filter-count">
              {/* ⛔ The numerator and the denominator together, always. "47
                  devices" over a filtered fleet is a true sentence that reads
                  as the whole fleet. */}
              Showing {count.shown} of {count.total} {count.noun}
            </span>
          )}
          {chips.map((c) => (
            <button
              key={c.key}
              type="button"
              className="filter-chip"
              data-unknown={c.known ? undefined : 'true'}
              onClick={() => removeChip(c.key)}
              aria-label={`Remove filter ${c.label}: ${c.valueLabel}`}
              title={`Remove filter ${c.label}: ${c.valueLabel}`}
            >
              <span className="filter-chip-key">{c.label}</span>
              <span className="filter-chip-val">{c.valueLabel}</span>
              <span className="filter-chip-x" aria-hidden="true">×</span>
            </button>
          ))}
          {active && (
            <button type="button" className="filter-clear" onClick={() => {
              const next = clearedFilterQuery(qs);
              router.push(next ? `${basePath}?${next}` : basePath);
            }}>
              Clear filters
            </button>
          )}
        </div>
      )}
    </div>
  );
}
