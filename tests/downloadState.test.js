'use strict';
// tests/downloadState.test.js
//
// Pins lib/downloadState.js — the decision half of the download control that
// replaced a plain `<a href>` on SecVault's slow exports.
//
// ⛔ THE CASES THAT REGRESS SILENTLY ARE THE ONES WHERE NOTHING THROWS. Every
// defect this module exists to fix looked healthy from the outside: the link
// worked, the request was made, and the operator saw nothing. So the assertions
// that carry the design are the negative ones —
//
//   · a LATE response must not speak for a control that has moved on. A stale
//     `success` reviving a reset control renders "Downloaded" over a file that
//     never arrived, which is a lie the operator has no way to detect.
//   · a modified click must NOT be intercepted. Ctrl-click is muscle memory;
//     hijacking it breaks the gesture and loses the download, and the only
//     symptom is a tab that never opens.
//   · a failure must NEVER describe itself as '' or 'undefined'. The bug being
//     fixed is the browser's own "Something went wrong"; reproducing it in our
//     own words would be the same defect with our name on it.
//   · a header we cannot read is its own state. Per CLAUDE.md's most-repeated
//     rule, "we could not measure this" may not be rendered as a clean result —
//     a missing coverage header must not turn a shortened file into a complete
//     one, and an unparseable filename must not produce an empty name.
//
// So each block below asserts the refusal alongside the happy path, and the
// invariant tests (`never empty`, `always a known state`) are run over MATRICES
// rather than over hand-picked inputs, because the input nobody thought of is
// the one that reaches production.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  STATES,
  nextState,
  shouldIntercept,
  filenameFromDisposition,
  describeFailure,
  coverageNote,
  fileResponseRefusal,
  FILE_CONTENT_TYPES,
  DONE_LINGER_MS,
} = require('../lib/downloadState');

const ALL_STATES = Object.values(STATES);
const ALL_EVENTS = ['start', 'success', 'failure', 'reset'];

// Values that arrive when something upstream is absent, wrong, or hostile.
// Reused by every block so no function gets to be robust only against the junk
// its own author imagined.
const JUNK = [null, undefined, '', 0, 42, true, false, 'nope', [], {}, () => {}];

describe('STATES', () => {
  it('names exactly the four states the control can be in', () => {
    assert.deepEqual(STATES, {
      IDLE: 'idle',
      PREPARING: 'preparing',
      DONE: 'done',
      ERROR: 'error',
    });
  });

  it('is frozen, so a stray assignment cannot invent a fifth', () => {
    // The component matches on these strings. A state added at runtime would
    // match no branch and render as a control stuck looking idle with a request
    // in flight — a spinner that never starts.
    assert.ok(Object.isFrozen(STATES));
  });

  it('lingers on done long enough to be read, then returns to idle', () => {
    assert.equal(DONE_LINGER_MS, 2500);
    assert.ok(DONE_LINGER_MS > 0, 'a zero linger makes success invisible');
  });
});

describe('nextState — the happy path', () => {
  it('a click starts preparing', () => {
    assert.equal(nextState(STATES.IDLE, 'start'), STATES.PREPARING);
  });

  it('a completed request lands on done', () => {
    assert.equal(nextState(STATES.PREPARING, 'success'), STATES.DONE);
  });

  it('a refused request lands on error', () => {
    assert.equal(nextState(STATES.PREPARING, 'failure'), STATES.ERROR);
  });

  it('reset returns to idle from every state', () => {
    for (const s of ALL_STATES) {
      assert.equal(nextState(s, 'reset'), STATES.IDLE, `reset failed from ${s}`);
    }
  });

  it('start supersedes every state, so retry and re-download both work', () => {
    // Retrying after an error and downloading a second time after a success are
    // the two things an operator actually does. A machine that only accepted
    // `start` from idle would need a reset between every download.
    for (const s of ALL_STATES) {
      assert.equal(nextState(s, 'start'), STATES.PREPARING, `start failed from ${s}`);
    }
  });
});

describe('nextState — a late answer may not speak for a superseded request', () => {
  // ⛔ THIS IS THE REASON THE MACHINE EXISTS. An operator who clicks, waits 40
  // seconds, gives up, and clicks again has two requests in flight. The first
  // one's outcome arrives with no idea it is stale.

  it('a success arriving after reset does not revive the control', () => {
    // Would otherwise render "Downloaded" for a file that never arrived.
    assert.equal(nextState(STATES.IDLE, 'success'), STATES.IDLE);
  });

  it('a failure arriving after reset does not paint an error', () => {
    // Would otherwise show a refusal the operator has already dismissed, with
    // no request behind it to explain where it came from.
    assert.equal(nextState(STATES.IDLE, 'failure'), STATES.IDLE);
  });

  it('a stale failure does not overwrite an already-finished success', () => {
    assert.equal(nextState(STATES.DONE, 'failure'), STATES.DONE);
  });

  it('a stale success does not overwrite a displayed error', () => {
    assert.equal(nextState(STATES.ERROR, 'success'), STATES.ERROR);
  });

  it('the first request cannot terminate the second one it was superseded by', () => {
    // The sequence that actually happens: click, click again, then the FIRST
    // response returns. `preparing` belongs to request two.
    let s = nextState(STATES.IDLE, 'start');   // request one
    s = nextState(s, 'start');                 // request two supersedes it
    assert.equal(s, STATES.PREPARING);
    // Request one now answers. It must not terminate request two's progress —
    // if it did, the spinner would stop while a download was still running.
    const afterStale = nextState(s, 'failure');
    assert.equal(afterStale, STATES.ERROR, 'a terminal event out of preparing is still honoured');
    // ...which is the accepted cost: this module cannot tell WHICH request
    // answered. The component pins that with a request token; what is pinned
    // here is that nothing terminal is honoured OUTSIDE preparing.
  });
});

describe('nextState — what it does when it does not understand', () => {
  it('an unknown event changes nothing', () => {
    for (const s of ALL_STATES) {
      for (const bad of ['cancel', 'START', '', null, undefined, 0, {}]) {
        assert.equal(nextState(s, bad), s, `event ${String(bad)} moved state ${s}`);
      }
    }
  });

  it('an unknown current state is returned untouched, even on reset', () => {
    // ⛔ Snapping an unrecognised state back to idle would paper over the real
    // defect — the control would look like it recovered while whatever wrote
    // the bad state kept writing it.
    for (const bad of JUNK) {
      for (const e of ALL_EVENTS) {
        assert.equal(nextState(bad, e), bad, `${e} altered unknown state ${String(bad)}`);
      }
    }
  });

  it('never throws, for every state x event pair including junk', () => {
    // A throw here is an unhandled rejection inside a promise continuation,
    // which leaves the control frozen mid-preparing with a spinner that never
    // stops — strictly worse than the plain link this replaced.
    for (const s of [...ALL_STATES, ...JUNK]) {
      for (const e of [...ALL_EVENTS, ...JUNK]) {
        assert.doesNotThrow(() => nextState(s, e));
      }
    }
  });

  it('never invents a state: every result is an input or a known state', () => {
    for (const s of ALL_STATES) {
      for (const e of [...ALL_EVENTS, ...JUNK]) {
        const out = nextState(s, e);
        assert.ok(ALL_STATES.includes(out), `produced unknown state ${String(out)}`);
      }
    }
  });
});

describe('shouldIntercept', () => {
  const plain = { button: 0, metaKey: false, ctrlKey: false, shiftKey: false, altKey: false, defaultPrevented: false };

  it('handles a plain left click', () => {
    assert.equal(shouldIntercept(plain), true);
  });

  it('handles a left click whose fields are simply absent', () => {
    // ⛔ Missing means ABSENT, not truthy. A caller constructing the object by
    // hand omits what it does not know; reading undefined as "modifier held"
    // would stand the control down on every such click and it would look like
    // the feature was never wired up.
    assert.equal(shouldIntercept({}), true);
    assert.equal(shouldIntercept({ button: 0 }), true);
  });

  it('stands aside for every modifier key', () => {
    // ⛔ Ctrl/Cmd-click means "open in a new tab" and is muscle memory for
    // anyone working several exports at once. Intercepting breaks the gesture
    // AND loses the download — this component's fetch has no idea it was meant
    // to land in another tab.
    for (const key of ['metaKey', 'ctrlKey', 'shiftKey', 'altKey']) {
      assert.equal(shouldIntercept({ ...plain, [key]: true }), false, `${key} was intercepted`);
    }
  });

  it('stands aside for a middle or right click', () => {
    assert.equal(shouldIntercept({ ...plain, button: 1 }), false, 'middle click was intercepted');
    assert.equal(shouldIntercept({ ...plain, button: 2 }), false, 'right click was intercepted');
  });

  it('stands aside when something upstream already handled the click', () => {
    // Acting on a click a parent handler has claimed would run the download
    // twice — two 45-second exports for one gesture.
    assert.equal(shouldIntercept({ ...plain, defaultPrevented: true }), false);
  });

  it('stands aside for anything it cannot read, rather than killing the link', () => {
    // ⛔ THE DEFAULT DIRECTION IS "LET THE BROWSER DO IT". The browser has
    // downloaded this link correctly for the whole life of the product; a bug
    // in this function must degrade to that, never to a dead button.
    for (const bad of [null, undefined, 'click', 42, true]) {
      assert.equal(shouldIntercept(bad), false, `${String(bad)} was intercepted`);
    }
  });

  it('never throws on junk', () => {
    for (const bad of JUNK) assert.doesNotThrow(() => shouldIntercept(bad));
  });
});

describe('filenameFromDisposition', () => {
  const FB = 'secvault-download.csv';

  it('reads the quoted form the export route actually emits', () => {
    // app/api/logs/export/route.js: `attachment; filename="${out.filename}"`
    assert.equal(
      filenameFromDisposition('attachment; filename="secvault-logs-20260924.csv"', FB),
      'secvault-logs-20260924.csv'
    );
  });

  it('reads the unquoted form', () => {
    assert.equal(filenameFromDisposition('attachment; filename=report.pdf', FB), 'report.pdf');
  });

  it('reads RFC 5987 filename* and percent-decodes it', () => {
    assert.equal(
      filenameFromDisposition("attachment; filename*=UTF-8''secvault%20logs.csv", FB),
      'secvault logs.csv'
    );
  });

  it('prefers filename* when both are present', () => {
    // ⛔ A server emits both when the real name is not ASCII: an ASCII-safe
    // `filename` for old clients, the true name in `filename*`. Preferring the
    // plain one silently downgrades every non-ASCII export to the placeholder.
    const h = `attachment; filename="ascii-fallback.csv"; filename*=UTF-8''real-%E6%97%A5.csv`;
    assert.equal(filenameFromDisposition(h, FB), 'real-日.csv');
  });

  it('tolerates a filename* with no charset/language section', () => {
    assert.equal(filenameFromDisposition("attachment; filename*=plain%20name.csv", FB), 'plain name.csv');
  });

  it('is case-insensitive about the parameter name', () => {
    assert.equal(filenameFromDisposition('attachment; FileName="x.csv"', FB), 'x.csv');
  });

  describe('sanitising — the header is untrusted input', () => {
    it('strips a traversal down to the basename', () => {
      assert.equal(filenameFromDisposition('attachment; filename="../../etc/passwd"', FB), 'passwd');
    });

    it('strips a traversal that arrived percent-encoded in filename*', () => {
      assert.equal(
        filenameFromDisposition("attachment; filename*=UTF-8''..%2F..%2Fetc%2Fpasswd", FB),
        'passwd'
      );
    });

    it('strips a Windows path', () => {
      const out = filenameFromDisposition('attachment; filename="C:\\Windows\\Temp\\evil.csv"', FB);
      assert.equal(out, 'evil.csv');
      assert.ok(!out.includes('\\'));
      assert.ok(!out.includes(':'), 'a drive letter colon survived');
    });

    it('strips an NTFS alternate-data-stream suffix', () => {
      // Windows is the only platform this product ships on. `file.csv:stream`
      // is not a legal filename there anyway, so nothing legitimate is lost.
      const out = filenameFromDisposition('attachment; filename="report.csv:hidden"', FB);
      assert.ok(!out.includes(':'));
    });

    it('strips control characters, including the NUL used to truncate a name', () => {
      const out = filenameFromDisposition('attachment; filename="safe.csv\u0000.exe"', FB);
      assert.ok(!/[\u0000-\u001F\u007F]/.test(out), 'a control character survived');
    });

    it('falls back when sanitising leaves nothing', () => {
      // ⛔ The "we could not read this" case. An empty name would hand the
      // browser a blank save dialog, which reads as a broken download rather
      // than as a header we refused.
      assert.equal(filenameFromDisposition('attachment; filename=".."', FB), FB);
      assert.equal(filenameFromDisposition("attachment; filename*=UTF-8''..", FB), FB);
      // ⛔ REGRESSION, found by this test on its first run: for both of these
      // the quoted parser correctly produced an empty name and the UNQUOTED
      // parser then re-read the same parameter, handing back the literal `""`
      // and `"` as filenames. An empty name a server explicitly stated is still
      // a statement; the answer is our fallback, not the punctuation around it.
      assert.equal(filenameFromDisposition('attachment; filename=""', FB), FB);
      assert.equal(filenameFromDisposition('attachment; filename="/"', FB), FB);
      assert.equal(filenameFromDisposition('attachment; filename="\\\\"', FB), FB);
    });
  });

  describe('when the header says nothing usable', () => {
    it('falls back on a missing, empty or unparseable header', () => {
      assert.equal(filenameFromDisposition(undefined, FB), FB);
      assert.equal(filenameFromDisposition(null, FB), FB);
      assert.equal(filenameFromDisposition('', FB), FB);
      assert.equal(filenameFromDisposition('   ', FB), FB);
      assert.equal(filenameFromDisposition('attachment', FB), FB);
      assert.equal(filenameFromDisposition('inline; charset=utf-8', FB), FB);
    });

    it('falls back on a non-string header rather than coercing it', () => {
      for (const bad of [42, true, [], {}, () => {}]) {
        assert.equal(filenameFromDisposition(bad, FB), FB);
      }
    });

    it('recovers from a bad percent escape by using the plain filename', () => {
      // ⛔ A malformed filename* is not a reason to fail the download. The file
      // is the point; its name is not.
      const h = `attachment; filename="good.csv"; filename*=UTF-8''%E0%A4%A`;
      assert.equal(filenameFromDisposition(h, FB), 'good.csv');
    });

    it('falls back when a bad percent escape is all there is', () => {
      assert.equal(filenameFromDisposition("attachment; filename*=UTF-8''%ZZ%", FB), FB);
    });

    it('returns the fallback verbatim, without sanitising it', () => {
      // ⛔ The fallback comes from our own call site, not the wire. Quietly
      // rewriting it would hide a bad literal from whoever wrote it.
      assert.equal(filenameFromDisposition('', '../weird-but-ours.csv'), '../weird-but-ours.csv');
    });

    it('never throws', () => {
      for (const bad of JUNK) assert.doesNotThrow(() => filenameFromDisposition(bad, FB));
    });
  });
});

describe('describeFailure', () => {
  it('prefers the server\'s own explanation verbatim', () => {
    // ⛔ `/api/logs/export` answers a refusal with a detail that already names
    // the remedy. Paraphrasing it from a status code throws away the only part
    // of the message that says what to do differently.
    const detail = 'The export stopped at the row cap after 6 hours of the requested 24.';
    assert.equal(describeFailure({ status: 504, reason: 'row_cap', detail }), detail);
  });

  it('gives the server\'s explanation a full stop when it lacks one', () => {
    const out = describeFailure({ detail: 'The export stopped at the row cap' });
    assert.equal(out, 'The export stopped at the row cap.');
  });

  it('does not double the punctuation the server already wrote', () => {
    assert.equal(describeFailure({ detail: 'Narrow the window!' }), 'Narrow the window!');
    assert.equal(describeFailure({ detail: 'Why did this fail?' }), 'Why did this fail?');
  });

  it('ignores a blank detail and falls through to the status', () => {
    const out = describeFailure({ status: 403, detail: '   ' });
    assert.match(out, /not permitted/i);
  });

  describe('the status map', () => {
    it('401 and 403 say the operator is not permitted', () => {
      for (const status of [401, 403]) {
        assert.match(describeFailure({ status }), /not permitted/i);
      }
    });

    it('413 names the size and the remedy', () => {
      const out = describeFailure({ status: 413 });
      assert.match(out, /too large/i);
      assert.match(out, /narrow/i, 'a size refusal with no remedy is not actionable');
    });

    it('504 names the timeout and the remedy', () => {
      const out = describeFailure({ status: 504 });
      assert.match(out, /too long/i);
      assert.match(out, /narrow/i);
    });

    it('504 is NOT swallowed by the general 5xx branch', () => {
      // A timeout has a remedy the operator can apply; "the server could not
      // produce the file" does not. Ordering is what keeps them apart.
      assert.notEqual(describeFailure({ status: 504 }), describeFailure({ status: 500 }));
    });

    it('other 5xx say the server could not produce the file', () => {
      for (const status of [500, 502, 503, 599]) {
        assert.match(describeFailure({ status }), /server could not produce/i);
      }
    });

    it('an unmapped status is named by its code', () => {
      // ⛔ The number is the only durable fact we hold about a case nobody
      // anticipated — it is the difference between a diagnosable ticket and
      // "the download button is broken".
      assert.match(describeFailure({ status: 418 }), /418/);
      assert.match(describeFailure({ status: 404 }), /404/);
    });

    it('accepts a numeric string status, as a header or param would give it', () => {
      assert.equal(describeFailure({ status: '403' }), describeFailure({ status: 403 }));
    });
  });

  describe('when the failure itself carries nothing we can read', () => {
    it('a missing status is "the server never answered", not "HTTP undefined"', () => {
      // ⛔ `Number(null)` is 0 and 0 is finite — the same trap CLAUDE.md records
      // against `maxDevices`. Printing "HTTP 0" or "HTTP undefined" looks like a
      // server verdict and sends the operator hunting a code that does not exist.
      for (const f of [{}, { status: null }, { status: undefined }, { status: '' }, { status: 'abc' }, { status: NaN }]) {
        const out = describeFailure(f);
        assert.match(out, /before the server answered/i, `bad sentence for ${JSON.stringify(f)}`);
        assert.ok(!/undefined|null|NaN|HTTP 0/.test(out), `leaked a raw value: ${out}`);
      }
    });

    it('status 0 is treated as no answer, not as HTTP 0', () => {
      assert.match(describeFailure({ status: 0 }), /before the server answered/i);
      assert.ok(!describeFailure({ status: 0 }).includes('HTTP 0'));
    });

    it('carries a machine reason code in parentheses when there is no detail', () => {
      // Not a sentence, so never shown alone — but worth quoting in a ticket.
      const out = describeFailure({ status: 504, reason: 'row_cap' });
      assert.match(out, /\(row_cap\)\.$/);
    });

    it('does not append the reason when the server wrote a detail', () => {
      assert.equal(describeFailure({ detail: 'Already explained.', reason: 'row_cap' }), 'Already explained.');
    });
  });

  describe('the invariant the whole function exists for', () => {
    // ⛔ The bug being fixed is the browser's own "Something went wrong".
    // Returning '' or 'undefined' here would be the identical defect with our
    // name on it, so this is asserted over a MATRIX rather than a few picks.
    const CASES = [
      undefined, null, {}, [], 'oops', 42,
      { status: 0 }, { status: -1 }, { status: 200 }, { status: 418 },
      { status: 401 }, { status: 413 }, { status: 500 }, { status: 504 },
      { status: null, reason: null, detail: null },
      { status: undefined, reason: undefined, detail: undefined },
      { detail: '' }, { detail: '   ' }, { reason: '' },
      { status: 'not-a-number' }, { status: {} }, { detail: 123 },
    ];

    it('always returns a non-empty sentence ending in a full stop', () => {
      for (const c of CASES) {
        const out = describeFailure(c);
        assert.equal(typeof out, 'string', `not a string for ${JSON.stringify(c)}`);
        assert.ok(out.trim().length > 0, `empty sentence for ${JSON.stringify(c)}`);
        assert.match(out, /[.!?]$/, `no terminal punctuation for ${JSON.stringify(c)}: ${out}`);
      }
    });

    it('never leaks "undefined", "null" or "NaN" into the operator\'s sentence', () => {
      for (const c of CASES) {
        const out = describeFailure(c);
        assert.ok(!/\b(undefined|null|NaN)\b/.test(out), `leaked for ${JSON.stringify(c)}: ${out}`);
      }
    });

    it('never throws', () => {
      for (const c of [...CASES, ...JUNK]) assert.doesNotThrow(() => describeFailure(c));
    });
  });
});

describe('coverageNote', () => {
  // Both shapes are real: the component holds a live `Response.headers`, while
  // a test or a server-side caller has a plain object. A helper that understood
  // only one would be pinned by a path production never takes.
  const FROM = '2026-09-23T10:00:00.000Z';
  const TO = '2026-09-23T16:00:00.000Z';

  function asHeaders(obj) {
    const h = new Headers();
    for (const [k, v] of Object.entries(obj)) h.set(k, v);
    return h;
  }

  const SHORTENED = {
    'x-secvault-window-shortened': 'true',
    'x-secvault-covered-from': FROM,
    'x-secvault-covered-to': TO,
  };

  it('says nothing when the response makes no claim', () => {
    assert.equal(coverageNote({}), null);
    assert.equal(coverageNote(asHeaders({})), null);
  });

  it('says nothing when the window was NOT shortened', () => {
    // The route emits the literal 'false' on every complete export. Treating it
    // as a warning would paint one on every download and teach operators to
    // ignore the one that matters.
    const full = { ...SHORTENED, 'x-secvault-window-shortened': 'false' };
    assert.equal(coverageNote(full), null);
    assert.equal(coverageNote(asHeaders(full)), null);
  });

  it('reports a shortened window from a plain object', () => {
    const note = coverageNote(SHORTENED);
    assert.ok(note, 'a shortened window produced no note');
    assert.match(note, /shorter/i);
    assert.ok(note.includes(FROM) && note.includes(TO), 'the covered range is not named');
  });

  it('reports a shortened window from a real Headers, case-insensitively', () => {
    const note = coverageNote(asHeaders({
      'X-SecVault-Window-Shortened': 'true',
      'X-SecVault-Covered-From': FROM,
      'X-SecVault-Covered-To': TO,
    }));
    assert.ok(note);
    assert.ok(note.includes(FROM) && note.includes(TO));
  });

  it('reads a mixed-case plain object too, so a hand-built one cannot go silent', () => {
    const note = coverageNote({
      'X-SecVault-Window-Shortened': 'true',
      'X-SecVault-Covered-From': FROM,
      'X-SecVault-Covered-To': TO,
    });
    assert.ok(note, 'a mixed-case plain object lost the coverage warning entirely');
  });

  it('says the file is COMPLETE for what it covers', () => {
    // ⛔ The export truncates the WINDOW, never the rows inside it. Wording this
    // as a failure would push an operator to discard usable evidence.
    assert.match(coverageNote(SHORTENED), /complete/i);
  });

  describe('when the claim is there but the range is not', () => {
    it('names the gap instead of rendering "undefined to undefined"', () => {
      // ⛔ The "we could not read this" case, twice over: dropping the note
      // would hide a STATED limitation because a second header went missing,
      // and printing the raw undefined would make the product look broken at
      // precisely the moment it is being careful.
      for (const missing of ['x-secvault-covered-from', 'x-secvault-covered-to']) {
        const partial = { ...SHORTENED };
        delete partial[missing];
        const note = coverageNote(partial);
        assert.ok(note, `no note at all when ${missing} was absent`);
        assert.match(note, /did not state which range/i);
        assert.ok(!/undefined|null/.test(note), `leaked a raw value: ${note}`);
      }
    });

    it('does the same when both bounds are absent', () => {
      const note = coverageNote({ 'x-secvault-window-shortened': 'true' });
      assert.match(note, /did not state which range/i);
    });

    it('treats an empty bound as absent rather than printing a blank range', () => {
      const note = coverageNote({ ...SHORTENED, 'x-secvault-covered-from': '' });
      assert.match(note, /did not state which range/i);
    });
  });

  describe('what does NOT count as a claim', () => {
    it('reads "true" in any case, and nothing else, as the claim', () => {
      // ⛔ THE ASYMMETRY IS THE WHOLE ARGUMENT. Only the word `true` can match
      // in any case, so accepting case variants cannot manufacture a false
      // warning — while an exact match would MISS a real one the day a
      // producer or a proxy changes the case, and a missed warning means an
      // operator reads a six-hour file as a twenty-four-hour one. Written in
      // the direction whose failure mode is harmless.
      for (const v of ['True', 'TRUE', ' true ']) {
        assert.ok(
          coverageNote({ ...SHORTENED, 'x-secvault-window-shortened': v }),
          `"${v}" was not read as a shortened-window claim`
        );
      }
      for (const v of ['1', 'yes', 'shortened', ' ', 'false', 'truthy']) {
        assert.equal(
          coverageNote({ ...SHORTENED, 'x-secvault-window-shortened': v }),
          null,
          `"${v}" was read as a shortened-window claim`
        );
      }
    });

    it('tolerates the optional whitespace HTTP permits around a field value', () => {
      assert.ok(coverageNote({ ...SHORTENED, 'x-secvault-window-shortened': ' true ' }));
    });

    it('ignores a non-string header value rather than coercing it', () => {
      assert.equal(coverageNote({ ...SHORTENED, 'x-secvault-window-shortened': true }), null);
    });
  });

  it('survives a headers-like object whose get() throws', () => {
    // An unreadable header is treated exactly like an absent one, rather than
    // being allowed to take down the download the operator is waiting for.
    const hostile = { get() { throw new Error('nope'); } };
    assert.doesNotThrow(() => coverageNote(hostile));
    assert.equal(coverageNote(hostile), null);
  });

  it('never throws on junk', () => {
    for (const bad of JUNK) {
      assert.doesNotThrow(() => coverageNote(bad));
      assert.equal(coverageNote(bad), null);
    }
  });
});

describe('⛔ fileResponseRefusal — never save a page as a file', () => {
  it('accepts the content types a real export is served as', () => {
    for (const ct of FILE_CONTENT_TYPES) {
      assert.equal(
        fileResponseRefusal({ contentType: ct, redirected: false }),
        null,
        `${ct} was refused, so a legitimate export would fail to save`
      );
    }
  });

  it('tolerates parameters and casing on the content type', () => {
    assert.equal(fileResponseRefusal({ contentType: 'text/csv; charset=utf-8' }), null);
    assert.equal(fileResponseRefusal({ contentType: 'TEXT/CSV' }), null);
    assert.equal(fileResponseRefusal({ contentType: '  text/csv  ' }), null);
  });

  it('refuses an HTML page', () => {
    const r = fileResponseRefusal({ contentType: 'text/html; charset=utf-8' });
    assert.ok(r, 'an HTML page was accepted as a file');
    assert.equal(r.reason, 'text/html');
    assert.match(r.detail, /did not return a file/);
  });

  it('refuses a type nobody thought to name', () => {
    // ⛔ THE DENYLIST'S BLIND SPOT. The first version asked
    // `ctype.includes('text/html')`, so every one of these was SAVED AS A FILE.
    for (const ct of ['application/xhtml+xml', 'text/xml', 'image/png', 'text/html-sandboxed']) {
      assert.ok(fileResponseRefusal({ contentType: ct }), `${ct} was accepted as a file`);
    }
  });

  it('refuses a response with NO content type at all', () => {
    // ⛔ `(res.headers.get('content-type') || '')` turned a missing header into
    // an empty string, which does not contain 'text/html', which passed. An
    // absent type is not evidence that a file was sent.
    for (const missing of [undefined, null, '', '   ']) {
      const r = fileResponseRefusal({ contentType: missing });
      assert.ok(r, `a missing content-type (${JSON.stringify(missing)}) was accepted as a file`);
      assert.equal(r.reason, 'no-content-type');
    }
  });

  it('refuses a REDIRECTED response even when it looks like a file', () => {
    // ⛔ THE CASE THAT ACTUALLY HAPPENS. /api/logs/export answers a refusal
    // with a 303 to /logs; fetch follows it and the final response is an
    // ordinary 200 from a different route. Nothing but `redirected` records
    // that a refusal took place.
    const r = fileResponseRefusal({ contentType: 'text/csv', redirected: true });
    assert.ok(r, 'a followed redirect was accepted as a file');
    assert.equal(r.reason, 'redirected');
    assert.match(r.detail, /somewhere else/);
  });

  it('never throws on junk', () => {
    for (const bad of JUNK) {
      assert.doesNotThrow(() => fileResponseRefusal(bad));
    }
    assert.doesNotThrow(() => fileResponseRefusal());
  });
});

describe('⛔ a thrown fetch reaches describeFailure’s no-response branch', () => {
  // ⛔ THAT BRANCH WAS UNREACHABLE FROM THE ONLY CALLER. DownloadButton's catch
  // passed the browser's own string as `detail`, and describeFailure gives
  // `detail` absolute priority — correct for a refusal the ROUTE worded, wrong
  // for a throw that has no server words at all. So the function short-circuited
  // on its first line and the operator was shown the raw "Failed to fetch."
  // A guard that cannot fire, in the error path.
  it('status 0 produces the connection sentence, not a bare HTTP code', () => {
    const s = describeFailure({ status: 0, reason: 'Failed to fetch' });
    assert.match(s, /before the server answered/);
    assert.doesNotMatch(s, /HTTP 0/);
  });

  it('carries the browser’s raw message parenthesised, for a ticket', () => {
    assert.match(describeFailure({ status: 0, reason: 'Failed to fetch' }), /\(Failed to fetch\)/);
  });

  it('does not let the raw message become the whole sentence', () => {
    const s = describeFailure({ status: 0, reason: 'Failed to fetch' });
    assert.notEqual(s, 'Failed to fetch.');
    assert.ok(s.length > 40, `the operator was shown a bare browser string: ${s}`);
  });

  it('still lets a REAL server detail win, which is the rule this preserves', () => {
    assert.equal(
      describeFailure({ status: 400, detail: 'Stopped at the row cap; narrow the window.' }),
      'Stopped at the row cap; narrow the window.'
    );
  });
});
