'use strict';
// Pins the syslog frame parser.
//
// This runs against ~93 million events a day, so a wrong DEFAULT here does not
// produce an error anyone notices — it produces a large, confident, wrong
// dataset. Every test below that asserts `null` is asserting the same rule
// CLAUDE.md now states outright: a failed read is not a measurement.
//
// The load-bearing case is the RFC 3164 timestamp, which carries no year and
// no timezone. Getting the year wrong at a December/January boundary puts
// events 12 months away, where every "last 7 days" query silently misses them.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  parseSyslogLine,
  decodePri,
  resolveBsdTimestamp,
  MAX_PRI,
} = require('../lib/syslog/syslogParser');

// A fixed "now" so no test depends on the wall clock.
const RECV = new Date(2026, 8, 8, 12, 0, 0); // 8 Sep 2026 12:00:00 local

describe('syslogParser: PRI decoding', () => {
  it('splits a PRI into facility and severity', () => {
    assert.deepEqual(decodePri('134'), { facility: 16, severity: 6 }); // local0.info
    assert.deepEqual(decodePri('0'), { facility: 0, severity: 0 });
    assert.deepEqual(decodePri(String(MAX_PRI)), { facility: 23, severity: 7 });
  });

  it('returns null/null for an out-of-range PRI rather than a plausible facility', () => {
    // 192 is one past the maximum. Clamping it would invent facility 24.
    for (const bad of ['192', '999', '-1', 'abc', '']) {
      assert.deepEqual(
        decodePri(bad),
        { facility: null, severity: null },
        `PRI ${JSON.stringify(bad)} is malformed, not facility 23`
      );
    }
  });
});

describe('syslogParser: RFC 3164 (BSD)', () => {
  const line = '<134>Sep  8 11:59:58 FGT-EDGE date=2026-09-08 devname="FGT-EDGE" action=deny';

  it('extracts facility, severity, hostname and message', () => {
    const e = parseSyslogLine(line, RECV);
    assert.equal(e.format, 'rfc3164');
    assert.equal(e.facility, 16);
    assert.equal(e.severity, 6);
    assert.equal(e.severityName, 'info');
    assert.equal(e.hostname, 'FGT-EDGE');
    assert.match(e.message, /^date=2026-09-08/);
  });

  it('resolves the missing year to the one nearest the receive time', () => {
    const e = parseSyslogLine(line, RECV);
    assert.ok(e.eventAt instanceof Date);
    assert.equal(e.eventAt.getFullYear(), 2026);
    assert.equal(e.eventAt.getMonth(), 8); // September
    assert.equal(e.eventAt.getDate(), 8);
  });

  it('⛔ resolves a Dec 31 event received on Jan 1 to the PREVIOUS year', () => {
    // The whole reason the year logic exists. Naively stamping the receive
    // year puts this event 12 months in the future.
    const recv = new Date(2027, 0, 1, 0, 0, 1);
    const e = parseSyslogLine('<134>Dec 31 23:59:58 fw last-of-year', recv);
    assert.equal(e.eventAt.getFullYear(), 2026, 'must roll back, not forward');
    assert.equal(e.eventAt.getMonth(), 11);
  });

  it('⛔ resolves a Jan 1 event received on Dec 31 to the NEXT year (clock skew)', () => {
    const recv = new Date(2026, 11, 31, 23, 59, 55);
    const e = parseSyslogLine('<134>Jan  1 00:00:02 fw first-of-year', recv);
    assert.equal(e.eventAt.getFullYear(), 2027);
  });

  it('flags that the timezone was ASSUMED, since the format carries none', () => {
    const e = parseSyslogLine(line, RECV);
    assert.equal(e.tzAssumed, true, 'callers must be able to surface this as an assumption');
  });

  it('returns eventAt null — not a guess — when the date is implausibly distant', () => {
    // A device with a badly wrong clock. Any year we pick is >45 days out.
    const e = parseSyslogLine('<134>Mar 15 00:00:00 fw skewed', RECV);
    assert.equal(e.eventAt, null, 'better no timestamp than a confident wrong one');
    assert.equal(e.parseComplete, false);
  });

  it('rejects Feb 29 in a non-leap year instead of sliding it to Mar 1', () => {
    const recv = new Date(2027, 1, 28, 12, 0, 0); // 2027 is not a leap year
    const e = parseSyslogLine('<134>Feb 29 12:00:00 fw nonexistent-day', recv);
    assert.equal(e.eventAt, null, 'Feb 29 2027 does not exist; do not store Mar 1');
  });

  it('parses a tag with and without a PID', () => {
    const withPid = parseSyslogLine('<38>Sep  8 11:00:00 host sshd[1234]: bad login', RECV);
    assert.equal(withPid.program, 'sshd');
    assert.equal(withPid.procId, '1234');
    assert.equal(withPid.message, 'bad login');

    const noPid = parseSyslogLine('<38>Sep  8 11:00:00 host kernel: oom', RECV);
    assert.equal(noPid.program, 'kernel');
    assert.equal(noPid.procId, null, 'absent PID is null, not 0');
  });

  it('does not mistake the start of a message for a hostname', () => {
    // No hostname token; the payload begins immediately.
    const e = parseSyslogLine('<134>Sep  8 11:00:00 devname=FGT action=accept', RECV);
    assert.match(e.message, /devname=FGT/);
  });
});

describe('syslogParser: RFC 5424', () => {
  const line =
    '<165>1 2026-09-08T11:59:58.123+07:00 fw01 PAN-OS 4321 TRAFFIC ' +
    '[meta seq="12"] src=10.0.0.1 dst=8.8.8.8';

  it('extracts every header field', () => {
    const e = parseSyslogLine(line, RECV);
    assert.equal(e.format, 'rfc5424');
    assert.equal(e.facility, 20);
    assert.equal(e.severity, 5);
    assert.equal(e.hostname, 'fw01');
    assert.equal(e.program, 'PAN-OS');
    assert.equal(e.procId, '4321');
    assert.equal(e.msgId, 'TRAFFIC');
    assert.equal(e.structuredData, '[meta seq="12"]');
    assert.equal(e.message, 'src=10.0.0.1 dst=8.8.8.8');
  });

  it('uses the offset in the timestamp, assuming nothing', () => {
    const e = parseSyslogLine(line, RECV);
    assert.equal(e.eventAt.toISOString(), '2026-09-08T04:59:58.123Z');
    assert.equal(e.tzAssumed, false, 'RFC 5424 carries its own offset');
    assert.equal(e.parseComplete, true);
  });

  it('maps NILVALUE "-" to null, not to the literal dash', () => {
    const e = parseSyslogLine('<165>1 2026-09-08T11:00:00Z - - - - - hello', RECV);
    assert.equal(e.hostname, null);
    assert.equal(e.program, null);
    assert.equal(e.procId, null);
    assert.equal(e.msgId, null);
    assert.equal(e.structuredData, null);
    assert.equal(e.message, 'hello');
  });

  it('does not end structured data on a "]" inside a quoted value', () => {
    const e = parseSyslogLine(
      '<165>1 2026-09-08T11:00:00Z h a - - [x k="a]b"] real message',
      RECV
    );
    assert.equal(e.structuredData, '[x k="a]b"]');
    assert.equal(e.message, 'real message');
  });
});

describe('syslogParser: malformed input is kept, never invented', () => {
  it('keeps a line with no PRI as a raw message with null facility/severity', () => {
    const e = parseSyslogLine('just some text with no priority', RECV);
    assert.equal(e.format, 'raw');
    assert.equal(e.facility, null);
    assert.equal(e.severity, null, 'must not default to 6/info');
    assert.equal(e.eventAt, null);
    assert.equal(e.message, 'just some text with no priority');
  });

  it('handles a PRI with no timestamp (common from firewalls)', () => {
    const e = parseSyslogLine('<134>devname=FGT action=deny srcip=1.2.3.4', RECV);
    assert.equal(e.format, 'pri-only');
    assert.equal(e.severity, 6);
    assert.equal(e.eventAt, null, 'no timestamp in the frame means no timestamp');
    assert.equal(e.message, 'devname=FGT action=deny srcip=1.2.3.4');
  });

  it('never throws, whatever it is handed', () => {
    for (const junk of [null, undefined, 42, {}, [], '', '<', '<>', '<999>', '\0\0']) {
      assert.doesNotThrow(() => parseSyslogLine(junk, RECV), `input ${JSON.stringify(junk)}`);
      const e = parseSyslogLine(junk, RECV);
      assert.equal(typeof e.message, 'string', 'message is always a string');
    }
  });

  it('strips trailing NULs and newlines that senders pad with', () => {
    const e = parseSyslogLine('<134>Sep  8 11:00:00 host tail-padding\0\0\n', RECV);
    assert.doesNotMatch(e.message, /\0/);
    assert.doesNotMatch(e.message, /\n/);
  });

  it('returns eventAt null when receivedAt is unusable, rather than guessing a year', () => {
    for (const bad of [undefined, null, 'nope', new Date('nope')]) {
      const e = parseSyslogLine('<134>Sep  8 11:00:00 host x', bad);
      assert.equal(e.eventAt, null, 'no reference time means no year can be resolved');
    }
  });
});

describe('syslogParser: resolveBsdTimestamp directly', () => {
  it('returns null without a usable reference time', () => {
    assert.equal(resolveBsdTimestamp(8, 8, 11, 0, 0, null), null);
    assert.equal(resolveBsdTimestamp(8, 8, 11, 0, 0, new Date('nope')), null);
  });

  it('picks the candidate year closest to the reference', () => {
    const d = resolveBsdTimestamp(8, 8, 11, 0, 0, RECV);
    assert.equal(d.getFullYear(), 2026);
  });
});
