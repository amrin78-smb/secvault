'use client';

// components/auth/LoginBackdrop.js
//
// The animated ground behind the sign-in page: lanes of packets drifting into
// an inspection plane, most passing through and brightening, a few stopping at
// the plane and dissolving.
//
// ⛔ THE MOTIF IS SECVAULT'S OWN, NOT NETVAULT'S. NetVault's login draws a
// drifting NODE GRAPH with connecting lines, which is right for an asset and
// topology product. Copying it here would put a network-topology metaphor on a
// product that filters traffic against a rulebase — the same mistake as copying
// the suite palette, one layer up. What is taken from NetVault is the LEVEL of
// finish (an animated ground, a glass card, real chrome), never its content.
//
// ⛔ COLOURS ARE LITERALS HERE, DELIBERATELY. This canvas only ever sits on the
// login page's --navy ground, which is dark in BOTH themes — so it is
// shell-family, and the theme-flipping tokens are wrong for it for exactly the
// reason CLAUDE.md gives for --tint-*-fg on the header and sidebar: they flip,
// and a flipped foreground on an unflipped ground is invisible. They are
// SecVault's own teal, not the suite red.

import { useEffect, useRef } from 'react';

const LANE_COUNT = 20;
const PER_LANE = 6;
// Where the inspection plane sits, as a fraction of width. Left of centre so it
// falls in the gap between the pitch and the card rather than behind either.
const PLANE_X = 0.46;
// Roughly one in seven packets is stopped. High enough to read as "this thing
// makes decisions", low enough not to look broken.
const BLOCK_RATE = 0.14;
const DPR_CAP = 2;

const TEAL_DIM = 'rgba(34,193,214,0.20)';
const TEAL_LIVE = 'rgba(34,193,214,0.60)';
const PLANE_LINE = 'rgba(34,193,214,0.13)';

function makePacket(lane, rand) {
  return {
    lane,
    x: rand(),
    speed: 0.00035 + rand() * 0.00075,
    blocked: rand() < BLOCK_RATE,
    // 1 while travelling, decays to 0 once a blocked packet reaches the plane.
    life: 1,
    len: 8 + rand() * 26,
  };
}

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

    // A tiny deterministic PRNG. Decoration does not need cryptographic
    // randomness, and a fixed seed means the composition is the same on every
    // load — which makes a visual regression reviewable instead of a new
    // arrangement every time somebody looks.
    let seed = 0x5ec5a17;
    const rand = () => {
      seed = (seed * 1664525 + 1013904223) >>> 0;
      return seed / 0x100000000;
    };

    let width = 0;
    let height = 0;
    let packets = [];

    const resize = () => {
      // ⛔ DEVICE PIXEL RATIO. A canvas sized in CSS pixels and drawn at 1x is
      // visibly soft on every laptop sold in the last decade; the sibling this
      // was benchmarked against has that bug. Capped at 2 so a 3x phone does
      // not pay for nine times the fill.
      const dpr = Math.min(window.devicePixelRatio || 1, DPR_CAP);
      width = canvas.clientWidth;
      height = canvas.clientHeight;
      canvas.width = Math.max(1, Math.round(width * dpr));
      canvas.height = Math.max(1, Math.round(height * dpr));
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    const build = () => {
      packets = [];
      for (let lane = 0; lane < LANE_COUNT; lane += 1) {
        for (let i = 0; i < PER_LANE; i += 1) packets.push(makePacket(lane, rand));
      }
    };

    const draw = () => {
      if (width <= 0 || height <= 0) return;
      ctx.clearRect(0, 0, width, height);

      const planePx = width * PLANE_X;
      const laneGap = height / (LANE_COUNT + 1);

      // The inspection plane itself — a soft vertical seam, not a hard rule.
      const grad = ctx.createLinearGradient(planePx - 14, 0, planePx + 14, 0);
      grad.addColorStop(0, 'rgba(34,193,214,0)');
      grad.addColorStop(0.5, PLANE_LINE);
      grad.addColorStop(1, 'rgba(34,193,214,0)');
      ctx.fillStyle = grad;
      ctx.fillRect(planePx - 14, 0, 28, height);

      for (const p of packets) {
        const y = laneGap * (p.lane + 1);
        const px = p.x * width;
        const past = px > planePx;

        if (p.blocked && past) {
          // Stopped at the plane: hold position, fade out, then respawn left.
          p.life -= 0.02;
          if (p.life <= 0) {
            p.x = -0.05 - rand() * 0.1;
            p.life = 1;
            p.blocked = rand() < BLOCK_RATE;
            continue;
          }
          ctx.globalAlpha = p.life;
          ctx.fillStyle = TEAL_DIM;
          ctx.fillRect(planePx - p.len, y - 1, p.len, 2);
          ctx.globalAlpha = 1;
          continue;
        }

        ctx.fillStyle = past ? TEAL_LIVE : TEAL_DIM;
        ctx.fillRect(px - p.len, y - 1, p.len, 2);
      }
    };

    const step = () => {
      for (const p of packets) {
        const planeFrac = PLANE_X;
        if (p.blocked && p.x > planeFrac) continue; // held at the plane
        p.x += p.speed;
        if (p.x > 1.1) {
          p.x = -0.05 - rand() * 0.1;
          p.blocked = rand() < BLOCK_RATE;
          p.life = 1;
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
      resize();
      draw();
    };

    resize();
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
