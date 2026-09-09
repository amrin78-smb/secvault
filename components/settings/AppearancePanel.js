'use client';

import { useEffect, useState } from 'react';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import { getCorners, applyCorners } from '../../lib/corners';
import { getTheme, applyTheme } from '../../lib/theme';
import { getDensity, applyDensity, DENSITIES, DENSITY_LABELS } from '../../lib/density';

/**
 * Appearance controls — purely client-side presentation preferences stored in
 * localStorage and applied as attributes on <html>. Nothing here touches the
 * database or the `settings` table, so it is NOT admin-gated: a viewer
 * changing their own corner style affects only their own browser.
 *
 * Both controls read their current value in an effect rather than at render,
 * because the source of truth is the <html> attribute stamped by the no-flash
 * scripts in app/layout.js — which does not exist during server rendering.
 * Reading it at render time would produce a hydration mismatch.
 */

const SEGMENT_OPTIONS = {
  corners: [
    { value: 'rounded', label: 'Rounded' },
    { value: 'square', label: 'Square' },
  ],
  theme: [
    { value: 'light', label: 'Light' },
    { value: 'dark', label: 'Dark' },
  ],
  // Built from lib/density.js rather than written out here, so the list
  // cannot drift from the values applyDensity() will actually accept.
  density: DENSITIES.map((v) => ({ value: v, label: DENSITY_LABELS[v] })),
};

// Small segmented control. Module top level, never nested inside the panel
// component (CLAUDE.md: a component defined inside another remounts on every
// render and loses focus).
function Segmented({ options, value, onChange, ariaLabel }) {
  return (
    <div
      role="group"
      aria-label={ariaLabel}
      style={{
        display: 'inline-flex',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius-sm)',
        overflow: 'hidden',
      }}
    >
      {options.map((opt) => {
        const active = opt.value === value;
        return (
          <button
            key={opt.value}
            type="button"
            onClick={() => onChange(opt.value)}
            aria-pressed={active}
            style={{
              padding: '6px 16px',
              border: 'none',
              cursor: 'pointer',
              fontFamily: 'inherit',
              fontSize: 'var(--text-base)',
              fontWeight: active ? 600 : 400,
              background: active ? 'var(--primary)' : 'transparent',
              color: active ? '#fff' : 'var(--text-secondary)',
              transition: 'background 0.12s, color 0.12s',
            }}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}

const ROW_STYLE = {
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  gap: 16,
  flexWrap: 'wrap',
};

const HINT_STYLE = { fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 2 };

export default function AppearancePanel() {
  const [corners, setCorners] = useState('rounded');
  const [theme, setTheme] = useState('light');
  const [density, setDensity] = useState('comfortable');

  useEffect(() => {
    setCorners(getCorners());
    setTheme(getTheme());
    setDensity(getDensity());
    const onCorners = (e) => setCorners(e.detail);
    const onTheme = (e) => setTheme(e.detail);
    const onDensity = (e) => setDensity(e.detail);
    window.addEventListener('secvault:corners', onCorners);
    window.addEventListener('secvault:theme', onTheme);
    window.addEventListener('secvault:density', onDensity);
    return () => {
      window.removeEventListener('secvault:corners', onCorners);
      window.removeEventListener('secvault:theme', onTheme);
      window.removeEventListener('secvault:density', onDensity);
    };
  }, []);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Appearance</CardTitle>
      </CardHeader>
      <CardBody>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          <div style={ROW_STYLE}>
            <div>
              <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Table density</div>
              <div style={HINT_STYLE}>
                {/* ⛔ Says what density does NOT do, on purpose. A setting
                    that might hide information is one an operator has to
                    think about before touching; this one never can. */}
                Row height and cell text size in every table. A denser table shows the same
                columns and the same values in less space — nothing is hidden or truncated.
              </div>
            </div>
            <Segmented
              ariaLabel="Table density"
              options={SEGMENT_OPTIONS.density}
              value={density}
              onChange={(v) => {
                applyDensity(v);
                setDensity(v);
              }}
            />
          </div>

          <div style={ROW_STYLE}>
            <div>
              <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Corners</div>
              <div style={HINT_STYLE}>
                Applies to cards, panels, tables, buttons and inputs. Status dots and avatars stay
                circular either way.
              </div>
            </div>
            <Segmented
              ariaLabel="Corner style"
              options={SEGMENT_OPTIONS.corners}
              value={corners}
              onChange={(v) => {
                applyCorners(v);
                setCorners(v);
              }}
            />
          </div>

          <div style={ROW_STYLE}>
            <div>
              <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Theme</div>
              <div style={HINT_STYLE}>
                Same switch as the sun/moon button in the header.
              </div>
            </div>
            <Segmented
              ariaLabel="Theme"
              options={SEGMENT_OPTIONS.theme}
              value={theme}
              onChange={(v) => {
                applyTheme(v);
                setTheme(v);
              }}
            />
          </div>

          <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>
            Both settings are stored in this browser only — they are not shared with other users and
            never leave this machine.
          </p>
        </div>
      </CardBody>
    </Card>
  );
}
