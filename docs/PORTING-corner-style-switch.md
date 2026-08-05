# Handoff prompt — port the corner-style switch to the rest of the NocVault suite

Paste everything below the line into a session working on NetVault, LogVault,
DDIVault or SpanVault. Reference implementation: SecVault v2.52.0 (commit
`0d7d6c5`), plus the wrap fixes in v2.51.1 (`f66eacf`) that it depends on.

---

SecVault implemented a **rounded/square corner-style switch**: a Rounded/Square
control in Settings → General → Appearance that reskins the entire UI instantly
and reverts with one click. No deploy is needed to flip it either way, and both
looks are first-class — neither is "the temporary one". It shipped as SecVault
v2.52.0 (commit `0d7d6c5`).

**The user has asked to adapt the same for the NocVault suite apps.** Please
implement it in this app, following the guide below.

This ports cleanly because all five suite apps share `app/globals.css` tokens
byte-for-byte (SecVault adds only `--accent-teal`), so the mechanism is
identical. But read the warning in Step 1 before estimating the work.

---

## Step 1 — Measure the strays first (this is the real job)

**The switch itself is 4 lines of CSS. Do not let that mislead you.** Roughly
80% of the work is finding the places that bypass the radius tokens and hardcode
their own value. In SecVault that was **~32 spots**: 12 in `globals.css`, 22
inline in JS.

⛔ **A component that hardcodes `borderRadius: 8` opts itself out silently.** It
stays rounded while everything around it squares off, which reads as a rendering
bug rather than a style choice. Nothing errors, nothing fails to build, and it
will not show up in any type check.

Measure *this* app's count — do not assume SecVault's:

```bash
# Tokenized usages (these already work, no action needed)
grep -ro "var(--radius[a-z-]*)" app/ components/ --include=*.js --include=*.css | wc -l

# CSS strays
grep -n "border-radius:" app/globals.css | grep -v "var(--radius"

# JS inline strays (excluding true circles, which stay)
grep -rn "borderRadius: *[0-9]" app/ components/ --include=*.js | grep -v "'50%'"
```

Classify every hit into exactly one of three buckets:

| Bucket | Action | Examples from SecVault |
|---|---|---|
| Standard surface | → `var(--radius)` | cards, panels, nav items, icon buttons (8–10px) |
| Small surface | → `var(--radius-sm)` | chips, skeletons, tooltips, nav sub-chips (5–7px) |
| Fully-rounded | → `var(--radius-pill)` | badges (20px), progress tracks (3px on a 6px bar), count bubbles |

**Leave these alone** — deliberate exemptions, and comment each one so a later
session doesn't "fix" it:

- `borderRadius: '50%'` — status dots, avatars. Squaring a status dot looks
  broken, not hard-edged.
- Browser chrome — the `::-webkit-scrollbar-thumb` radius.
- Decorative slivers — SecVault has a 3px active-nav accent bar (`0 3px 3px 0`).
- **Any radius small relative to its element.** SecVault kept one 10×10px legend
  swatch at 2px: `--radius-sm` is 6px, which on a 10px square renders as a
  *circle*. Using the token there would have damaged the rounded look in order
  to fix the square one.

---

## Step 2 — Tokens (`app/globals.css`)

Add `--radius-pill` alongside the existing two, then the override block
immediately after the `:root` block closes:

```css
:root {
  --radius:         8px;
  --radius-sm:      6px;
  /* Fully-rounded surfaces (badges, progress tracks). A SEPARATE token from
     --radius so the square switch can flatten it too — a squared page still
     full of pill badges reads as unfinished. */
  --radius-pill:    999px;
}

/* ── Square corners (opt-in) ─────────────────────────────────────
   Overrides ONLY the three radius tokens, which is why it works at all:
   every rounded surface resolves its radius through one of them.
   A component that hardcodes a numeric border-radius opts itself out
   SILENTLY — it stays rounded while everything around it squares off.
   Always use the token.

   True circles (status dots, avatars) use 50% directly and are
   deliberately NOT covered — squaring those looks broken. */
:root[data-corners="square"] {
  --radius:         0;
  --radius-sm:      0;
  --radius-pill:    0;
}
```

⛔ Rounded is `:root`'s default, and square **removes** the attribute rather than
setting a second branch. Do not add a `[data-corners="rounded"]` selector — the
rounded state is the *absence* of the attribute.

---

## Step 3 — `lib/corners.js`

Mirror this app's existing `lib/theme.js` **structurally**: same storage-key
shape, same `data-*` attribute on `<html>`, same CustomEvent, same no-flash
script. One pattern to learn for both, not two.

⛔ **Change the localStorage key and event name per app** — `netvault-corners`,
`logvault-corners`, etc. Match whatever prefix that app's theme key already
uses. Two suite apps served from the same origin would otherwise share state.

```js
'use client';

export const CORNERS_KEY = 'APPNAME-corners';   // ← match your theme key's prefix

export function getCorners() {
  if (typeof document === 'undefined') return 'rounded';
  return document.documentElement.getAttribute('data-corners') === 'square' ? 'square' : 'rounded';
}

export function applyCorners(corners) {
  if (typeof document === 'undefined') return;
  if (corners === 'square') document.documentElement.setAttribute('data-corners', 'square');
  else document.documentElement.removeAttribute('data-corners');
  try { localStorage.setItem(CORNERS_KEY, corners); } catch (_err) { /* just won't persist */ }
  window.dispatchEvent(new CustomEvent('APPNAME:corners', { detail: corners }));
}

export function toggleCorners() {
  const next = getCorners() === 'square' ? 'rounded' : 'square';
  applyCorners(next);
  return next;
}

/** Inline <script> body that sets data-corners before first paint (no flash). */
export const CORNERS_INIT_SCRIPT =
  `(function(){try{var c=localStorage.getItem('${CORNERS_KEY}');if(c==='square'){document.documentElement.setAttribute('data-corners','square');}}catch(e){}})();`;
```

If this app is TypeScript (`lib/theme.ts`), write `lib/corners.ts` to match —
the logic is identical.

---

## Step 4 — No-flash script in the root layout

Next to the existing theme script, in `<head>`:

```jsx
import { CORNERS_INIT_SCRIPT } from '../lib/corners';
...
<script dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }} />
<script dangerouslySetInnerHTML={{ __html: CORNERS_INIT_SCRIPT }} />
```

It must run synchronously in `<head>` — it reads `localStorage`, so it cannot be
an import.

---

## Step 5 — Settings control

Add an `AppearancePanel` (SecVault: `components/settings/AppearancePanel.js`,
dropped into the General tab's existing grid). Two segmented controls, Corners
and Theme.

⛔ **Read the current value in a `useEffect`, never at render.** The source of
truth is the `<html>` attribute stamped by the no-flash script, which does not
exist during server rendering — reading it at render time produces a hydration
mismatch.

⛔ **Do not admin-gate it.** It touches no DB and no settings table; it is a
per-browser preference affecting only the person who set it. Don't wire it
through `isAdmin`.

Define the segmented-control component at **module top level**, never nested
inside the panel — the suite-wide React rule (a component defined inside another
remounts on every render and loses input focus).

---

## Step 6 — Verify with Playwright, by geometry not by text

Flip to square, then walk every page and assert **zero** elements still have a
non-zero, non-`%` computed `border-radius`:

```js
await p.evaluate(() => {
  localStorage.setItem('APPNAME-corners', 'square');
  document.documentElement.setAttribute('data-corners', 'square');
});
// then, per page:
const census = await p.evaluate(() => {
  let rounded = 0, circles = 0;
  document.querySelectorAll('*').forEach((el) => {
    const r = getComputedStyle(el).borderTopLeftRadius;
    if (!r || r === '0px') return;
    if (r.includes('%')) { circles++; return; }   // intentional circles
    if (parseFloat(r) > 0) rounded++;             // ← a stray
  });
  return { rounded, circles };
});
```

`rounded` must be **0** on every page. `circles` should be non-zero (the status
dots survived). SecVault's final run: 0 strays across 8 pages, with
598/489/292/457/1169/178/580/201 squared elements per page and no console errors.

Then confirm the round trip: cold-load with the attribute set (proves no-flash
works), click Rounded, assert `--radius` is back to `8px`.

---

## ⚠️ The trap that cost SecVault an extra release

Squaring exposed **pre-existing** clipping that the rounded look had been
hiding. Shipped as v2.51.1:

1. **`white-space` inherits.** Several ancestors set `nowrap`, and a `nowrap`
   cell cannot wrap however generous its `word-break` is — long values laid out
   as one enormous line, clipped by the cell, with the row not being a scroll
   container. Fix: value cells reset `white-space: normal` **explicitly** and add
   `overflow-wrap: anywhere` for unbroken tokens (base64, certificate bodies).

2. One live device carried a **~300KB base64 image** in its config, which
   rendered as a single table cell **307,241px wide**.

**Measure `getBoundingClientRect().right` against the viewport — not
`innerText`.** `innerText` returns clipped text perfectly happily, which is
exactly how this class of bug ships unnoticed.

---

## Optional but recommended: `Table` layout escape hatch

Unrelated to corners, but SecVault hit it the same week and every suite app
shares this component. `tableLayout: 'fixed'` is **required** when a table sets
colgroup/percentage widths, but is actively wrong for one that sets neither: it
slices the width into N equal columns and truncates every heading (`RULE…`,
`SRC …`).

```jsx
export default function Table({ children, className = '', layout = 'fixed', minWidth }) {
  return (
    <div style={{ overflowX: 'auto', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
      <table className={className}
             style={{ tableLayout: layout, width: '100%', minWidth, borderCollapse: 'collapse' }}>
        {children}
      </table>
    </div>
  );
}
```

The defaults keep every existing caller pixel-identical. ⛔ Never pass
`layout="auto"` to a table that sets colgroup/percentage widths.

---

## Checklist

- [ ] Counted strays in *this* app (don't assume SecVault's 32)
- [ ] `--radius-pill` added; `:root[data-corners="square"]` override added
- [ ] All strays tokenized; circles/scrollbar/slivers left alone **and commented**
- [ ] `lib/corners.js` with an **app-specific** localStorage key + event name
- [ ] No-flash script in the root layout `<head>`
- [ ] AppearancePanel in Settings; value read in `useEffect`; not admin-gated
- [ ] Playwright: 0 strays per page by geometry; circles survive; round trip works
- [ ] Wrap fix applied (`white-space: normal` + `overflow-wrap: anywhere`) if this
      app has dense data tables
- [ ] Version bump + release notes; index/architecture docs updated
