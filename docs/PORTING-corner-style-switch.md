# Porting guide — rounded/square corner switch

Reference implementation: **SecVault v2.52.0** (commit `0d7d6c5`, plus the wrap
fixes in `v2.51.1`/`f66eacf` that this depends on). Written to be handed to a
session working on **NetVault / LogVault / DDIVault / SpanVault**.

**What it does:** adds a Rounded/Square control to Settings that reskins the
whole app instantly and reverts with one click. No deploy needed to flip, and
both looks are first-class — neither is "the temporary one".

---

## Why this is cheap in the suite

All five apps share `app/globals.css` byte-for-byte on tokens (SecVault adds
only `--accent-teal`). So the switch mechanism ports verbatim.

**The switch itself is 4 lines of CSS. Do not let that mislead you about the
job.** The actual work — ~80% of it — is finding the places that bypass the
radius tokens and hardcode their own value. In SecVault that was **~32 spots**:
12 in `globals.css`, 22 inline in JS. Expect a similar order in each app; the
counts will differ, so *measure yours*, don't assume SecVault's.

⛔ **A component that hardcodes `borderRadius: 8` opts itself out silently.** It
stays rounded while everything around it squares off, which reads as a
rendering bug rather than a style. Nothing errors, nothing fails to build.

---

## Step 1 — Measure the strays first

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

**Leave alone** (deliberate exemptions):
- `borderRadius: '50%'` — status dots, avatars. Squaring a status dot looks
  broken, not hard-edged.
- Browser chrome — the `::-webkit-scrollbar-thumb` radius.
- Decorative slivers — SecVault has a 3px active-nav accent bar (`0 3px 3px 0`).
- **Any radius small relative to its element.** SecVault kept one 10×10px legend
  swatch at 2px: `--radius-sm` is 6px, which on a 10px square renders as a
  *circle*. Using the token there would have damaged the rounded look to fix the
  square one. Comment the exemption so nobody "fixes" it later.

---

## Step 2 — Tokens (`app/globals.css`)

Add `--radius-pill` alongside the existing two, then the override block right
after the `:root` block closes:

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

⛔ Rounded is `:root`'s default and square **removes** rather than sets a second
branch. Don't add `[data-corners="rounded"]` — it's the absence of the attribute.

---

## Step 3 — `lib/corners.js`

Mirror your existing `lib/theme.js` **structurally**: same storage-key shape,
same `data-*` attribute on `<html>`, same CustomEvent, same no-flash script. One
pattern to learn for both.

⛔ **Change the localStorage key per app** — `netvault-corners`, `logvault-corners`,
etc. Match whatever prefix that app's theme key already uses. Two suite apps on
the same origin would otherwise share state.

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

If the app is TypeScript (`lib/theme.ts`), write `lib/corners.ts` to match — the
logic is identical.

---

## Step 4 — No-flash script in the root layout

Next to the existing theme script, in `<head>`:

```jsx
import { CORNERS_INIT_SCRIPT } from '../lib/corners';
...
<script dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }} />
<script dangerouslySetInnerHTML={{ __html: CORNERS_INIT_SCRIPT }} />
```

Must run synchronously in `<head>` — it reads `localStorage`, so it cannot be an
import.

---

## Step 5 — Settings control

Add an `AppearancePanel` (SecVault: `components/settings/AppearancePanel.js`,
dropped into the General tab's existing grid). Two segmented controls, Corners
and Theme.

⛔ **Read the current value in an `useEffect`, never at render.** The source of
truth is the `<html>` attribute stamped by the no-flash script, which does not
exist during SSR — reading it at render time produces a hydration mismatch.

⛔ **Not admin-gated.** It touches no DB and no settings table; it's a
per-browser preference affecting only the person who set it. Don't wire it
through `isAdmin`.

Also define the segmented-control component at **module top level**, never
nested inside the panel — the suite-wide React rule (a component defined inside
another remounts every render and loses focus).

---

## Step 6 — Verify with Playwright, by geometry not by text

Flip to square, then walk every page and assert **zero** elements still have a
non-zero, non-`%` computed `border-radius`:

```js
await p.evaluate(() => {
  localStorage.setItem('APPNAME-corners', 'square');
  document.documentElement.setAttribute('data-corners', 'square');
});
// then per page:
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

`rounded` must be **0** on every page. `circles` should be non-zero (status dots
survived). SecVault's final run: 0 strays across 8 pages, 598/489/292/457/1169/
178/580/201 squared elements, no console errors.

Then confirm the round trip: cold-load with the attribute set (no-flash works),
click Rounded, assert `--radius` is back to `8px`.

---

## ⚠️ The trap that cost SecVault an extra release

Squaring exposed **pre-existing** clipping the rounded look had been hiding.
Shipped as `v2.51.1`:

1. **`white-space` inherits.** Several ancestors set `nowrap`, and a `nowrap`
   cell cannot wrap however generous its `word-break` is — long values laid out
   as one enormous line, clipped by the cell, with the row not being a scroll
   container. Fix: value cells reset `white-space: normal` **explicitly** and add
   `overflow-wrap: anywhere` for unbroken tokens (base64, cert bodies).

2. One live device carried a **~300KB base64 image** in its config, rendering as
   a single table cell **307,241px wide**.

**Measure `getBoundingClientRect().right` against the viewport — not
`innerText`.** `innerText` returns clipped text perfectly happily, which is
exactly how this class of bug ships unnoticed.

---

## Optional but recommended: `Table` layout escape hatch

Unrelated to corners, but SecVault hit it in the same week and every suite app
shares the component. `tableLayout: 'fixed'` is **required** when a table sets
colgroup/percentage widths, but is actively wrong for one that sets neither: it
slices width into N equal columns and truncates every heading (`RULE…`, `SRC …`).

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

Defaults keep every existing caller pixel-identical. ⛔ Never pass `layout="auto"`
to a table with colgroup/percentage widths.

---

## Checklist

- [ ] Counted strays in *this* app (don't assume SecVault's 32)
- [ ] `--radius-pill` added; `:root[data-corners="square"]` override added
- [ ] All strays tokenized; circles/scrollbar/slivers left alone **and commented**
- [ ] `lib/corners.js` with an **app-specific** localStorage key + event name
- [ ] No-flash script in root layout `<head>`
- [ ] AppearancePanel in Settings; value read in `useEffect`; not admin-gated
- [ ] Playwright: 0 strays per page by geometry; circles survive; round trip works
- [ ] Wrap fix applied (`white-space: normal` + `overflow-wrap: anywhere`) if the
      app has dense data tables
- [ ] Version bump + release notes; index docs updated
