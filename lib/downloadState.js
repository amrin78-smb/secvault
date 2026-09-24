'use strict';
// lib/downloadState.js
//
// The decision logic behind a download control that actually says something
// while it works. Pure: no React, no DOM, no fetch, no clock it is not handed —
// which is the only reason any of it can be pinned by node:test at all.
//
// ── WHY THIS EXISTS ──────────────────────────────────────────────────────
// SecVault's slow downloads are links. `/api/logs/export` walks the syslog
// window in one-hour slices and can spend 45 seconds doing it; the compliance
// and report PDFs are rendered on demand by pdfkit. A plain `<a href>` gives an
// operator nothing between the click and the file — no spinner, no failure, no
// reason. Reported verbatim: "Now i dont see anything."
//
// ⛔ AND A SILENT FAILURE IS THE WORSE HALF. When the export refuses, the
// browser owns the response: `/api/logs/export`'s own comment records what that
// looked like — "export.json — Couldn't download. Something went wrong", with
// the carefully worded reason visible to nobody. An operator cannot tell a
// refusal they could act on ("narrow the window") from a broken button, so they
// stop clicking it. That is this codebase's failed-read-as-a-fact rule wearing a
// download manager: the product knew exactly what went wrong and rendered
// nothing.
//
// ── ⛔ THE STATE MACHINE IS NOT DECORATION ───────────────────────────────
// It exists so a LATE answer cannot speak for a control that has moved on. A
// user who clicks, waits, gives up, and clicks again has two requests in
// flight; the first one's `failure` must not paint an error over the second
// one's progress, and its `success` must not revive a control the operator
// already reset. Every terminal event is therefore accepted ONLY out of
// `preparing`, and anything else returns the current state untouched.

/**
 * The four states a download control can be in.
 *
 * Frozen because the component compares against these by reference-free string
 * equality; a typo'd state assigned somewhere else would render as "no class
 * matched" — a control stuck looking idle while a request is in flight.
 */
const STATES = Object.freeze({
  IDLE: 'idle',
  PREPARING: 'preparing',
  DONE: 'done',
  ERROR: 'error',
});

const KNOWN_STATES = new Set(Object.values(STATES));

/** How long `done` shows before the control returns to idle. */
const DONE_LINGER_MS = 2500;

/**
 * Advance the control's state.
 *
 * @param {string} current one of STATES' values
 * @param {string} event   'start' | 'success' | 'failure' | 'reset'
 * @returns {string} the next state, or `current` unchanged
 *
 * ⛔ NEVER THROWS AND NEVER INVENTS A STATE. This runs inside a React event
 * handler and a promise continuation; a throw from either is an unhandled
 * rejection that leaves the control frozen mid-`preparing` with a spinner that
 * never stops — strictly worse than the plain link this replaces. An
 * unrecognised event or an unrecognised current state is a bug somewhere else,
 * and the honest response is to change nothing.
 */
function nextState(current, event) {
  // ⛔ Checked FIRST. If we do not recognise where we are, we have no business
  // deciding where to go — including on 'reset', which would otherwise quietly
  // paper over the real defect by snapping an unknown state back to idle.
  if (!KNOWN_STATES.has(current)) return current;

  switch (event) {
    // A new click always supersedes whatever came before, from any state:
    // retrying after an error, or downloading again after a success, are the
    // two things an operator does most.
    case 'start':
      return STATES.PREPARING;

    // Explicit teardown — the linger timer firing, or the component unmounting.
    case 'reset':
      return STATES.IDLE;

    // ⛔ TERMINAL EVENTS ARE ACCEPTED ONLY OUT OF `preparing`. A response from a
    // request the operator has already superseded or dismissed arrives here
    // with no way of knowing it is stale; refusing it anywhere else is what
    // stops one download's outcome being reported as another's.
    case 'success':
      return current === STATES.PREPARING ? STATES.DONE : current;
    case 'failure':
      return current === STATES.PREPARING ? STATES.ERROR : current;

    default:
      return current;
  }
}

/**
 * Should the component handle this click itself, or stand aside?
 *
 * @param {{button?:number, metaKey?:boolean, ctrlKey?:boolean,
 *          shiftKey?:boolean, altKey?:boolean, defaultPrevented?:boolean}} click
 * @returns {boolean} true only for a plain left click
 *
 * ⛔ THE FALSE CASES ARE LOAD-BEARING. Ctrl/Cmd-click and middle-click mean
 * "open in a new tab" and are muscle memory for anyone who works several
 * exports at once; shift-click means "new window"; alt-click means "save
 * target" in several browsers. Intercepting any of them would break the
 * gesture AND lose the download, because this component's own fetch has no
 * idea it was meant to land in a different tab. Standing aside costs only the
 * progress indicator — the browser still gets the file.
 *
 * ⛔ AND THE DEFAULT DIRECTION IS "STAND ASIDE". Anything unrecognisable here
 * — a null, a synthetic object from a test, a future event shape — falls
 * through to the browser, which has downloaded this link correctly for the
 * whole life of the product. A bug in this function must degrade to the old
 * behaviour, never to a dead button.
 */
function shouldIntercept(click) {
  if (!click || typeof click !== 'object') return false;

  // Something upstream (a parent handler, a modal) has already claimed this
  // click. Acting on it anyway would run the download twice.
  if (click.defaultPrevented) return false;

  // ⛔ Missing means ABSENT, not truthy: React always supplies `button`, but a
  // caller constructing the object by hand may not, and 0 (left) is the value
  // we want. Only a button we can read AND that is not 0 stands us down.
  const { button } = click;
  if (button !== undefined && button !== null && button !== 0) return false;

  // Undefined is falsy, so an absent modifier reads as "not held" without
  // needing a separate branch.
  if (click.metaKey || click.ctrlKey || click.shiftKey || click.altKey) return false;

  return true;
}

// Control characters, including the NUL that a crafted header uses to truncate
// a name early. Stripped BEFORE anything else looks at the string.
const CONTROL_CHARS = /[\u0000-\u001F\u007F]/g;

/**
 * Reduce a name taken off the network to something safe to hand a browser.
 *
 * ⛔ THE HEADER IS UNTRUSTED INPUT even though we wrote the server that emits
 * it: `/api/logs/export` interpolates `out.filename` straight into
 * Content-Disposition, and that name is derived from operator-supplied search
 * filters. A name carrying `../` or a drive letter is an attempt to steer where
 * the browser saves; modern browsers defend themselves, but a product that
 * hands a path separator to the save dialog is relying on someone else's guard.
 *
 * @returns {string} the sanitised name, or '' when nothing usable survives
 */
function sanitiseFilename(name) {
  if (typeof name !== 'string') return '';

  let out = name.replace(CONTROL_CHARS, '');
  // Keep only the last segment: `../../etc/passwd` becomes `passwd`, and a
  // trailing separator collapses to '' so the caller falls back.
  out = out.split(/[\\/]/).pop();
  // Any run of dots — a lone `..` is the traversal, and `....//` is the
  // encoding trick that survives a single-pass `..` removal.
  out = out.replace(/\.{2,}/g, '');
  // ⛔ Colons too, which is one step beyond "path separators": on Windows — the
  // only platform this product ships on — `C:name` is drive-relative and
  // `file.csv:stream` names an NTFS alternate data stream. Neither is a legal
  // filename anyway, so nothing legitimate is lost.
  out = out.replace(/:/g, '');
  // ⛔ AND THE QUOTE CHARACTERS THEMSELVES. Found by this module's own test:
  // `filename="/"` left the unquoted parser holding a lone `"`, which is a
  // non-empty string and would have been handed to the browser as the file's
  // name. A quote is not legal in a Windows filename either, so removing it can
  // only ever turn a name we would have refused into the fallback.
  out = out.replace(/"/g, '');

  return out.trim();
}

/**
 * Pull the download's filename out of a Content-Disposition header.
 *
 * @param {string} headerValue the raw header, e.g. `attachment; filename="x.csv"`
 * @param {string} fallback    the name to use when the header says nothing usable
 * @returns {string}
 *
 * ⛔ THE FALLBACK IS NOT SANITISED, DELIBERATELY. It comes from our own call
 * site, not from the wire, and quietly rewriting it would hide a bad literal
 * from whoever wrote it. Everything that arrives over the network goes through
 * `sanitiseFilename`; nothing else does.
 */
function filenameFromDisposition(headerValue, fallback) {
  if (typeof headerValue !== 'string' || headerValue.trim() === '') return fallback;

  // ⛔ RFC 5987 `filename*` WINS WHEN BOTH ARE PRESENT, which is the shape a
  // server uses when the real name is not ASCII: it emits an ASCII-safe
  // `filename` for old clients and the true name in `filename*`. Preferring the
  // plain one would silently downgrade every non-ASCII export to the
  // transliterated placeholder.
  const ext = /(?:^|;)\s*filename\*\s*=\s*([^;]+)/i.exec(headerValue);
  if (ext) {
    const raw = ext[1].trim();
    // charset'language'percent-encoded. A malformed header missing the
    // apostrophes is taken as the encoded value itself rather than discarded —
    // the worst case is that it decodes to the same bytes.
    const parts = raw.split("'");
    const encoded = parts.length >= 3 ? parts.slice(2).join("'") : raw;
    let decoded = null;
    try {
      decoded = decodeURIComponent(encoded);
    } catch {
      // ⛔ A BAD PERCENT-ESCAPE IS NOT A REASON TO FAIL THE DOWNLOAD. We fall
      // through to `filename` and then to the caller's fallback; the file is
      // the point, its name is not.
      decoded = null;
    }
    const cleaned = sanitiseFilename(decoded);
    if (cleaned !== '') return cleaned;
  }

  // The `(?:^|;)` anchor is what keeps this from matching the `filename*` above
  // — between `filename` and `=` there is a `*`, so the pattern cannot reach
  // the `=`. No lookbehind needed.
  const quoted = /(?:^|;)\s*filename\s*=\s*"([^"]*)"/i.exec(headerValue);
  if (quoted) {
    const cleaned = sanitiseFilename(quoted[1]);
    if (cleaned !== '') return cleaned;
  }

  // ⛔ ONLY WHEN THE QUOTED FORM DID NOT MATCH. Found by this module's own test:
  // for `filename=""` the quoted parser correctly produced an empty name, and
  // this one then re-read the SAME parameter as the unquoted token `""` — a
  // non-empty string, which was returned as the filename. A server that states
  // an empty name has stated one; the answer is the caller's fallback, not the
  // punctuation around it.
  const bare = !quoted && /(?:^|;)\s*filename\s*=\s*([^;]+)/i.exec(headerValue);
  if (bare) {
    const cleaned = sanitiseFilename(bare[1]);
    if (cleaned !== '') return cleaned;
  }

  return fallback;
}

/**
 * Coerce a status into a number, or into null when it is not one.
 *
 * ⛔ `Number(null)` IS 0 AND 0 IS FINITE — the same trap CLAUDE.md records
 * against `maxDevices`, where a bare `Number.isFinite` guard turned "this
 * licence does not state a count" into "this licence covers no firewalls".
 * Here it would turn "the server never answered" into "HTTP 0", sending an
 * operator hunting a status code that does not exist.
 */
function statusCode(status) {
  if (typeof status === 'number') return Number.isFinite(status) ? status : null;
  if (typeof status === 'string' && status.trim() !== '') {
    const n = Number(status);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

// Ends a sentence without doubling punctuation the server already wrote.
function asSentence(text) {
  const t = String(text).trim();
  return /[.!?]$/.test(t) ? t : `${t}.`;
}

/**
 * One operator-facing sentence explaining why a download did not arrive.
 *
 * @param {{status?:number|string, reason?:string, detail?:string}} failure
 * @returns {string} always a readable sentence, always ending in a full stop
 *
 * ⛔ THIS FUNCTION MAY NEVER RETURN '' , 'undefined' OR 'null'. The whole
 * reason the component exists is that the browser swallowed the server's
 * explanation and the operator saw "Something went wrong"; replacing that with
 * our own empty string would be the identical defect with our name on it. Every
 * branch below — including the one for a failure carrying no information at all
 * — produces something a person can act on or quote in a ticket.
 */
function describeFailure(failure) {
  const f = failure && typeof failure === 'object' ? failure : {};

  // ⛔ THE SERVER'S OWN WORDS WIN. `/api/logs/export` answers a refusal with a
  // `detail` that already names the remedy ("stopped at the row cap; narrow the
  // window"); paraphrasing it from a status code would throw away the only
  // part of the message that tells the operator what to do differently.
  if (typeof f.detail === 'string' && f.detail.trim() !== '') {
    return asSentence(f.detail);
  }

  const code = statusCode(f.status);
  // A machine token such as `row_cap` or `time_cap`. Not a sentence, so it is
  // never shown alone — but it is worth carrying into a ticket, so it rides
  // along in parentheses when the server gave us nothing better.
  const reason =
    typeof f.reason === 'string' && f.reason.trim() !== '' ? f.reason.trim() : null;
  const withReason = (sentence) => (reason ? `${sentence.slice(0, -1)} (${reason}).` : sentence);

  // ⛔ NO RESPONSE AT ALL IS ITS OWN CASE. A `fetch` that never reached the
  // server reports no status, and browsers surface an opaque failure as status
  // 0. Printing "HTTP 0" or "HTTP undefined" would look like a server verdict
  // and would be one more thing the operator cannot act on.
  if (code === null || code === 0) {
    return withReason('The download failed before the server answered — the connection may have dropped or the request was cancelled.');
  }

  if (code === 401 || code === 403) {
    return withReason('You are not permitted to download this file.');
  }
  if (code === 413) {
    return withReason('The file is too large to produce — narrow the search and try again.');
  }
  // Checked before the general 5xx branch: a timeout has a remedy the operator
  // can apply, and "the server could not produce the file" does not.
  if (code === 504) {
    return withReason('The server took too long to produce this file — narrow the window and try again.');
  }
  if (code >= 500 && code <= 599) {
    return withReason('The server could not produce the file.');
  }

  // ⛔ NAMES THE CODE. An unmapped status is a case nobody anticipated, and the
  // number is the only durable fact we hold about it — it is what makes the
  // difference between a support ticket that can be diagnosed and "the download
  // button is broken".
  return withReason(`The download failed (HTTP ${code}).`);
}

/**
 * Read one header from either a real `Headers` (case-insensitive `.get`) or a
 * plain lowercase-keyed object.
 *
 * Both shapes exist for a real reason: the component holds a `Response.headers`
 * at runtime, while a test — and any server-side caller — has a plain object.
 * A helper that only understood one of them would be pinned by tests that
 * exercise a code path production never takes.
 */
function headerValue(headersLike, name) {
  if (!headersLike || typeof headersLike !== 'object') return null;

  if (typeof headersLike.get === 'function') {
    try {
      const v = headersLike.get(name);
      return typeof v === 'string' ? v : null;
    } catch {
      // A `.get` that throws is not a header we can read; treated exactly like
      // an absent one rather than allowed to take down the caller.
      return null;
    }
  }

  const direct = headersLike[name];
  if (typeof direct === 'string') return direct;

  // A plain object is documented as lowercase-keyed, but a caller building one
  // from a raw response may not have normalised it. Matching case-insensitively
  // costs one scan and removes a way for the coverage note to go missing.
  for (const key of Object.keys(headersLike)) {
    if (key.toLowerCase() === name && typeof headersLike[key] === 'string') {
      return headersLike[key];
    }
  }
  return null;
}

const HDR_SHORTENED = 'x-secvault-window-shortened';
const HDR_FROM = 'x-secvault-covered-from';
const HDR_TO = 'x-secvault-covered-to';

/**
 * Say, in the operator's words, when a file covers LESS than the search that
 * produced it.
 *
 * @param {Headers|Object} headersLike
 * @returns {string|null} null when the response does not claim a shortened window
 *
 * ⛔ THIS IS THE FACT THE FILE ITSELF CANNOT CARRY. `/api/logs/export` stops
 * early when it hits the row cap or the time budget, and today the only place
 * that shows is inside the generated filename. A file whose limits are
 * discoverable only by reading its own name is a limit the operator will miss —
 * and a CSV that looks like "the last 24 hours" but holds six of them is
 * evidence that will be read as complete. The audit row already records the
 * truth (`window SHORTENED from ...`); the person who asked for the file
 * deserves it too.
 *
 * ⛔ AND THE FILE IS STILL GOOD. The note says "complete for the range it
 * covers" because that is what the export guarantees — it truncates the WINDOW,
 * never the rows inside it. Wording this as a failure would push an operator to
 * discard usable evidence.
 */
function coverageNote(headersLike) {
  const shortened = headerValue(headersLike, HDR_SHORTENED);
  // ⛔ 'true' IN ANY CASE, AND NOTHING ELSE. Absent, 'false', or a truncating
  // proxy's empty value all mean "no claim was made", and inventing a coverage
  // warning from one would teach operators to ignore the one that matters.
  //
  // ⛔ But the match is CASE-INSENSITIVE, deliberately, and the asymmetry is the
  // reason: only the word `true` can match in any case, so relaxing it cannot
  // manufacture a false warning — while an exact match would MISS a real one the
  // day a producer or a proxy changes the case, and a missed warning means an
  // operator reads a six-hour file as a twenty-four-hour one. Our only producer
  // emits lowercase today, so this is latent either way; it is written in the
  // direction whose failure is harmless.
  if (shortened === null || shortened.trim().toLowerCase() !== 'true') return null;

  const from = headerValue(headersLike, HDR_FROM);
  const to = headerValue(headersLike, HDR_TO);

  const lead =
    'This file is complete for the range it covers, but that range is shorter than the search you asked for';

  // ⛔ THE UNREADABLE CASE IS NAMED, NOT PAPERED OVER. A response that says it
  // was shortened but does not say to what is still a warning worth showing;
  // rendering `undefined to undefined` would make the product look broken at
  // precisely the moment it is being careful, and dropping the note entirely
  // would hide a stated limitation because a second header went missing.
  if (!from || !to) {
    return `${lead}, and the response did not state which range it covers.`;
  }

  return `${lead}: it covers ${from} to ${to}.`;
}

// ⛔ NEVER SAVE A PAGE AS A FILE — the judgement, kept pure so it can be tested.
//
// `fetch` follows redirects transparently, and /api/logs/export answers a
// refusal with a 303 back to /logs for any request that does not ask for JSON.
// Without a check the browser lands on the HTML error page at status 200 and
// writes it out as `export.csv`. A corrupt file that downloads successfully is
// worse than a refusal: the operator has evidence they believe in.
//
// ⛔ AN ALLOWLIST, NOT A DENYLIST. The first version asked `ctype.includes
// ('text/html')`, which is the wrong question — it admits everything nobody
// thought to name. A refusal served as `application/xhtml+xml`, as an error
// page with no content-type at all (`|| ''` turned that into a pass), or by a
// proxy that rewrote the type, all produced a saved file.
//
// ⛔ AND `redirected` IS THE STRONGER SIGNAL. On the 303 path the final
// response is an ordinary 200 from a DIFFERENT route, so nothing in its status
// or its headers says a refusal happened. That a redirect occurred is the only
// durable evidence.
const FILE_CONTENT_TYPES = [
  'text/csv',
  'application/csv',
  'application/pdf',
  'application/json',
  'application/octet-stream',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-excel',
  // A .txt/.log export is legitimate. No page in this product is served as
  // text/plain, so admitting it cannot let an error page through.
  'text/plain',
];

// Returns null when the response really is a file, or an object describing why
// it is not: { reason, detail } ready for describeFailure.
function fileResponseRefusal(response) {
  // ⛔ A destructure in the signature only defends against `undefined`; `null`
  // and every other junk value still throw. A throw here happens inside a
  // promise continuation and leaves the control frozen mid-preparing with a
  // spinner that never stops — strictly worse than the plain link this
  // replaced. Anything unreadable is treated as "not a file", which refuses
  // rather than saves.
  const r = response && typeof response === 'object' ? response : {};
  const { contentType, redirected } = r;
  if (redirected) {
    return {
      reason: 'redirected',
      detail:
        'The server sent the request somewhere else instead of returning a file, so nothing was saved. '
        + 'That is usually a refusal or an expired session — reload the page and try again.',
    };
  }
  const ctype = String(contentType || '').toLowerCase().split(';')[0].trim();
  if (FILE_CONTENT_TYPES.includes(ctype)) return null;
  return {
    reason: ctype || 'no-content-type',
    detail:
      'The server did not return a file, so nothing was saved. '
      + 'Reload the page and try again; if it persists, the export route is misrouting.',
  };
}

module.exports = {
  STATES,
  nextState,
  shouldIntercept,
  filenameFromDisposition,
  describeFailure,
  coverageNote,
  fileResponseRefusal,
  FILE_CONTENT_TYPES,
  DONE_LINGER_MS,
};
