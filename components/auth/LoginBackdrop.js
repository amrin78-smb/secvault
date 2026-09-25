'use client';

// components/auth/LoginBackdrop.js
//
// The animated ground behind the sign-in page: traffic drifting in from the
// left and being absorbed at an inspection boundary.
//
// ⛔ THE BOUNDARY IS THE SIGN-IN CARD ITSELF — measured from the DOM, never
// drawn. v2.184.0 drew a standalone vertical plane at 46% width, and on a real
// screen it read as a PANEL DIVIDER: a hard full-height seam between the pitch
// and the form, which is precisely the navy/white split the redesign existed to
// remove. It also had nothing to do with the packets, so it looked accidental.
// Deriving the boundary from `.login-card`'s rect fixes both at once — the
// motion now explains the card's position instead of competing with it, and
// there is no line to misread.
//
// ⛔ AND MOST TRAFFIC PASSES. v2.184.1 absorbed EVERY packet at the card's
// leading edge, which was wrong twice over: a firewall that dropped everything
// would be a broken one, so the picture told a false story about the product —
// and with nothing emerging on the far side, the whole region right of the card
// (a quarter of a wide viewport) was dead space. Packets now fade INTO the
// card's left edge, are invisible while inside it, and fade back out brighter
// on the right — inspected, then allowed. Only the ~1 in 6 that flare are
// stopped, and those never re-emerge. The composition and the metaphor are the
// same fix here; that is usually the sign the metaphor was the problem.
//
// ⛔ THE MOTIF IS SECVAULT'S OWN, NOT NETVAULT'S. The sibling's login draws a
// drifting node graph, which is right for an asset and topology product and
// wrong for one that filters traffic against a rulebase. What was taken from it
// is the LEVEL of finish, never its content.
//
// ⛔ COLOURS ARE LITERALS HERE, DELIBERATELY. This canvas only ever sits on the
// login page's --navy ground, which is dark in BOTH themes — so it is
// shell-family, and the theme-flipping tokens are wrong for it for exactly the
// reason CLAUDE.md gives for --tint-*-fg on the header and sidebar.

import { useEffect, useRef } from 'react';

// ⛔ DENSITY IS A LEGIBILITY SETTING, NOT A TASTE ONE. v2.184.0 ran 20 lanes x 6
// packets = 120 at near-identical length and alpha, which resolved as STATIC
// rather than flow — and put noise behind the headline. Fewer, more varied, and
// arranged in depth reads as movement; more does not.
const LANE_COUNT = 11;
const PER_LANE = 4;
// How far either side of the card a packet fades out of / back into view.
const ENTER_PX = 150;
const EXIT_PX = 130;
// Roughly one in six is stopped at the boundary and never re-emerges.
const FLARE_RATE = 0.17;
// Allowed traffic reads brighter on the far side than on the way in: it has
// been inspected, and the difference is what makes the crossing legible.
const PASSED_GAIN = 1.5;
const DPR_CAP = 2;
const FALLBACK_LEFT = 0.62;
const FALLBACK_RIGHT = 0.82;

const TEAL = '34,193,214';

export default function LoginBackdrop() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return undefined;
    const ctx = canvas.getContext('2d');
    if (!ctx) return undefined;

    // ⛔ HONOURED, NOT IGNORED. Someone who has asked their OS for less motion
    // gets ONE static frame — the composition without the movement — rather
    // than an empty ground, so the page does not look broken to them.
    const reduceMotion =
      typeof window.matchMedia === 'function' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // A tiny deterministic PRNG. Decoration needs no cryptographic randomness,
    // and a fixed seed means the composition is identical on every load — which
    // makes a visual regression reviewable instead of a new arrangement every
    // time somebody looks.
    let seed = 0x5ec5a17;
    const rand = () => {
      seed = (seed * 1664525 + 1013904223) >>> 0;
      return seed / 0x100000000;
    };

    let width = 0;
    let height = 0;
    let cardLeft = 0;
    let cardRight = 0;
    let packets = [];

    const spawn = (lane) => ({
      lane,
      x: rand() * 0.9,
      // Depth: near packets are longer, brighter and faster. Parallax is what
      // turns a flat scatter of dashes into something with an inside.
      depth: rand(),
      flare: rand() < FLARE_RATE,
      flared: 0,
    });

    const measure = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, DPR_CAP);
      width = canvas.clientWidth;
      height = canvas.clientHeight;
      canvas.width = Math.max(1, Math.round(width * dpr));
      canvas.height = Math.max(1, Math.round(height * dpr));
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      // ⛔ READ THE CARD, DO NOT ASSUME IT. Its position depends on the
      // viewport, the breakpoint and the pitch column's presence; a hardcoded
      // fraction is wrong on most of those. Falls back to fractions only when
      // the card is not in the DOM at all.
      const card = document.querySelector('.login-card');
      if (card) {
        const cardRect = card.getBoundingClientRect();
        const canvasRect = canvas.getBoundingClientRect();
        cardLeft = cardRect.left - canvasRect.left;
        cardRight = cardRect.right - canvasRect.left;
      }
      if (!cardLeft || cardLeft < 80) cardLeft = width * FALLBACK_LEFT;
      if (cardRight <= cardLeft) cardRight = width * FALLBACK_RIGHT;
    };

    const build = () => {
      packets = [];
      for (let lane = 0; lane < LANE_COUNT; lane += 1) {
        for (let i = 0; i < PER_LANE; i += 1) packets.push(spawn(lane));
      }
    };

    const draw = () => {
      if (width <= 0 || height <= 0) return;
      ctx.clearRect(0, 0, width, height);

      const laneGap = height / (LANE_COUNT + 1);

      for (const p of packets) {
        const y = laneGap * (p.lane + 1);
        const px = p.x * width;
        const len = 14 + p.depth * 44;
        const base = 0.1 + p.depth * 0.26;
        let alpha;
        let drawX = px;

        if (p.flare && p.flared > 0) {
          // Stopped at the boundary: a brief bright flare, then nothing. This
          // one never reaches the far side.
          alpha = 0.55 * p.flared;
          drawX = cardLeft - 14;
        } else if (px >= cardLeft && px <= cardRight) {
          // Inside the card — under inspection, and not drawn. The card's own
          // backdrop-filter would otherwise smear these across the form fields.
          continue;
        } else if (px < cardLeft) {
          // Inbound: fades out as it enters.
          alpha = base * Math.min(1, Math.max(0, (cardLeft - px) / ENTER_PX));
        } else {
          // ⛔ PASSED INSPECTION. Fades back in on the far side and runs to the
          // edge, brighter than it arrived.
          alpha = base * PASSED_GAIN * Math.min(1, Math.max(0, (px - cardRight) / EXIT_PX));
        }

        if (alpha <= 0.004) continue;

        // A leading-edge gradient, so direction reads even in a still frame.
        const grad = ctx.createLinearGradient(drawX - len, 0, drawX, 0);
        grad.addColorStop(0, `rgba(${TEAL},0)`);
        grad.addColorStop(1, `rgba(${TEAL},${alpha.toFixed(3)})`);
        ctx.fillStyle = grad;
        ctx.fillRect(drawX - len, y - 1, len, 1.6);
      }
    };

    const respawn = (p) => {
      p.x = -0.05 - rand() * 0.2;
      p.depth = rand();
      p.flare = rand() < FLARE_RATE;
      p.flared = 0;
    };

    const step = () => {
      for (const p of packets) {
        const px = p.x * width;

        // A blocked packet holds at the boundary while it flares out, and is
        // then recycled at the left — it never crosses.
        if (p.flare && px >= cardLeft - 14) {
          if (p.flared === 0) p.flared = 1;
          p.flared -= 0.06;
          if (p.flared <= 0) respawn(p);
          continue;
        }

        p.x += (0.0007 + p.depth * 0.0016) * (width ? 1200 / width : 1);
        if (p.x > 1.05) respawn(p);
      }
    };

    let raf = 0;
    const frame = () => {
      step();
      draw();
      raf = window.requestAnimationFrame(frame);
    };

    const start = () => {
      if (raf || reduceMotion) return;
      raf = window.requestAnimationFrame(frame);
    };
    const stop = () => {
      if (!raf) return;
      window.cancelAnimationFrame(raf);
      raf = 0;
    };

    // ⛔ PAUSED WHEN THE TAB IS HIDDEN. A sign-in page is frequently left open
    // in a background tab all day; an unpaused RAF there is a laptop fan and a
    // battery, for a picture nobody is looking at.
    const onVisibility = () => (document.hidden ? stop() : start());
    const onResize = () => {
      measure();
      draw();
    };

    measure();
    build();
    draw();
    if (!reduceMotion) start();

    window.addEventListener('resize', onResize);
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      stop();
      window.removeEventListener('resize', onResize);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, []);

  return <canvas ref={canvasRef} className="login-backdrop" aria-hidden="true" />;
}
