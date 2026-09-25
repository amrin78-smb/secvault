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
// How far in front of the card packets begin to dissolve.
const ABSORB_PX = 230;
// Roughly one in six flares as it is stopped.
const FLARE_RATE = 0.17;
const DPR_CAP = 2;
const FALLBACK_BOUNDARY = 0.62;

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
    let boundary = 0;
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
      // fraction is wrong on most of those. Falls back to a fraction only when
      // the card is not in the DOM at all.
      const card = document.querySelector('.login-card');
      if (card) {
        const cardRect = card.getBoundingClientRect();
        const canvasRect = canvas.getBoundingClientRect();
        boundary = cardRect.left - canvasRect.left;
      }
      if (!boundary || boundary < 80) boundary = width * FALLBACK_BOUNDARY;
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
        const px = p.x * boundary;
        const len = 14 + p.depth * 44;

        // Fade to nothing over the last stretch before the card: the traffic is
        // absorbed at the boundary rather than sliding under the form.
        const ramp = Math.min(1, Math.max(0, (boundary - px) / ABSORB_PX));
        let alpha = (0.1 + p.depth * 0.28) * ramp;

        // A flaring packet brightens sharply right at the boundary — the one
        // that was stopped — then vanishes.
        if (p.flare && p.flared > 0) {
          alpha = Math.max(alpha, 0.55 * p.flared);
        }
        if (alpha <= 0.004) continue;

        // A leading-edge gradient, so direction reads even in a still frame.
        const grad = ctx.createLinearGradient(px - len, 0, px, 0);
        grad.addColorStop(0, `rgba(${TEAL},0)`);
        grad.addColorStop(1, `rgba(${TEAL},${alpha.toFixed(3)})`);
        ctx.fillStyle = grad;
        ctx.fillRect(px - len, y - 1, len, 1.6);
      }
    };

    const step = () => {
      for (const p of packets) {
        const px = p.x * boundary;
        if (p.flare && px > boundary - 26 && p.flared === 0) p.flared = 1;
        if (p.flared > 0) p.flared -= 0.055;

        p.x += (0.0006 + p.depth * 0.0016) * (boundary ? 640 / boundary : 1);

        if (p.x > 1.02 || (p.flare && p.flared < 0)) {
          p.x = -0.06 - rand() * 0.22;
          p.depth = rand();
          p.flare = rand() < FLARE_RATE;
          p.flared = 0;
        }
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
