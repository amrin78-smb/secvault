import Link from 'next/link';
import { IconChevronDown } from '../icons';
import Card, { CardBody } from '../ui/Card';
import Badge from '../ui/Badge';
import AnswerHeader from '../ui/AnswerHeader';
import Disclosure from '../ui/Disclosure';
import EmptyState from '../ui/EmptyState';
// ⛔ THE SHARED RAMP, NOT A LOCAL ONE. This file briefly declared its own
// {critical:danger, high:warning, medium:info...} map and tests/designSystemRamp
// caught it: `info` is BLUE, and blue is the brand hue, deliberately kept out
// of the severity ramp so that --primary stays unambiguous (see the Design
// System note in CLAUDE.md — dropping blue out of severity is what makes the
// whole separation hold). Never re-declare this locally.
import { SEVERITY_BADGE_COLOR } from '../analysis/severityRamp';

// THE WORK QUEUE, drawn. One ranked list across every engine in the product.
//
// ⛔ SERVER component — the page hands it an already-computed result. Every
// judgement is made in lib/engines/workQueue.js; this file only decides how to
// draw it.
//
// ⛔ ═══ THE THREE BANDS ARE RENDERED AS THREE SECTIONS, ALWAYS ═══════════
// `verify` is NOT a collapsed footer and NOT the tail of `scheduled`. It is the
// band that holds everything SecVault could not measure — a licence expiry it
// could not parse, a firewall it could not read — and those are precisely the
// items that vanish from every other product's dashboard. A firewall SecVault
// cannot collect from produces no CVEs, no failing checks and no rule findings,
// which on every other screen in this product makes it look like the healthiest
// device on the fleet. This band is where that is said out loud.
//
// ⛔ `verify` CARRIES NO HUE. Same rule as ui/NotMeasured and CoverageBar: a
// gap in what SecVault can see is neither good news nor bad news, and giving it
// a severity colour would claim one or the other.

const BANDS = [
  {
    key: 'act_now',
    title: 'Act now',
    blurb: 'Measured evidence that something is exposed or broken right now.',
    dot: 'var(--sev-crit)',
  },
  {
    key: 'scheduled',
    title: 'Scheduled',
    blurb: 'Confirmed and real, but it does not need to happen today.',
    dot: 'var(--sev-med)',
  },
  {
    key: 'verify',
    title: 'Needs a human',
    blurb:
      'SecVault cannot measure these. They are not lower priority — they are unverifiable, '
      + 'which is a different thing, and they are listed rather than dropped for exactly that reason.',
    // ⛔ Hueless. Never a severity colour.
    dot: 'var(--unmeasured)',
  },
];

const TYPE_LABEL = {
  cve: 'Vulnerability',
  compliance: 'Compliance',
  config_diff: 'Config change',
  licence: 'Licence',
  licence_unknown: 'Licence',
  rule_cleanup: 'Rule hygiene',
  tunnel: 'VPN tunnel',
  collection_gap: 'Collection',
  segmentation: 'Segmentation',
  ingest_drop: 'Log ingest',
};


const LABEL = {
  fontSize: 'var(--text-xs)',
  textTransform: 'uppercase',
  letterSpacing: '0.04em',
  color: 'var(--text-muted)',
  fontWeight: 600,
};

// The four questions every item must answer. ⛔ "How will I know it is done" is
// the one that separates this from a findings list — CLAUDE.md's rule-cleanup
// section makes the same point: listing unused rules is what the competition
// already does; stating whether the change actually went is what it cannot.
function Field({ label, children }) {
  if (!children) return null;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      <span style={LABEL}>{label}</span>
      <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
        {children}
      </span>
    </div>
  );
}

/**
 * One item. Native <details>, so this stays a SERVER component — no client JS,
 * no state, no hydration, and it survives AutoRefresh's router.refresh().
 *
 * ⛔ COLLAPSED IS NOT TRUNCATED. The obvious alternative — render only the top
 * five — was rejected: it hides the rest behind nothing, so an operator reaches
 * the bottom of a short list and believes they are finished. That is precisely
 * the lie the truncation banner on this page exists to prevent, and it would be
 * worse, because nothing would disclose it. Collapsing removes no item, no
 * count and no band total.
 *
 * ⛔ WHAT STAYS VISIBLE IS THE IDENTITY, and it is chosen by the same test used
 * for the tunnel-page disclosure: could a reader who never expands this draw a
 * WRONG conclusion? Type, count, title, affected firewalls and the
 * "not measurable" marker all stay out — they are what the item IS. The four
 * explanatory fields go behind the click, because not knowing WHY yet is not
 * the same as being misled.
 *
 * @param {boolean} defaultOpen  the first item of each band opens by default,
 *   so the depth is discoverable rather than hidden behind a row that looks
 *   inert. A page of uniformly closed rows teaches nobody that there is
 *   anything underneath them.
 */
function WorkItem({ item, defaultOpen = false }) {
  const unmeasured = item.evidence === 'unmeasured';
  return (
    <details
      className="wq-item"
      open={defaultOpen}
      style={{
        border: '1px solid var(--border)',
        borderLeft: `3px solid ${unmeasured ? 'var(--unmeasured)' : 'var(--border)'}`,
        borderRadius: 'var(--radius)',
        background: 'var(--bg-card)',
      }}
    >
      <summary>
        <Badge color={SEVERITY_BADGE_COLOR[item.severity] || 'neutral'}>
          {TYPE_LABEL[item.type] || item.type}
        </Badge>
        {item.count > 1 ? (
          <span style={{ ...LABEL, color: 'var(--text-secondary)', flex: 'none' }}>×{item.count}</span>
        ) : null}

        <span
          style={{
            fontSize: 'var(--text-base)',
            fontWeight: 600,
            color: 'var(--text-primary)',
            minWidth: 0,
          }}
        >
          {item.title}
        </span>

        {/* ⛔ Says what KIND of claim this is, and stays on the collapsed row —
            a reader scanning without expanding must still see that this one is
            not a measurement. */}
        {unmeasured ? (
          <span
            className="badge"
            style={{
              flex: 'none',
              background: 'var(--surface-subtle)',
              color: 'var(--unmeasured)',
              border: '1px solid var(--border)',
            }}
            title="SecVault could not measure this. It is listed so that the gap is visible, not because it was observed."
          >
            not measurable
          </span>
        ) : null}

        {/* The scope, on the closed row. Which firewalls are involved is how an
            operator decides whether this is theirs before opening anything. */}
        {item.affects && item.affects.length ? (
          <span
            style={{
              fontSize: 'var(--text-xs)',
              color: 'var(--text-muted)',
              marginLeft: 'auto',
              textAlign: 'right',
              flex: '0 1 auto',
              minWidth: 0,
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
          >
            {item.affects.join(', ')}
          </span>
        ) : null}

        <IconChevronDown className="wq-chevron" width={16} height={16} aria-hidden="true" />
      </summary>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
          gap: 'var(--s3) var(--s4)',
          padding: 'var(--s3) var(--s4) var(--s4)',
        }}
      >
        <Field label="Why it is here">{item.why}</Field>
        <Field label="What to do">{item.action}</Field>
        <Field label="How you will know it is done">{item.done}</Field>
        {item.affects && item.affects.length ? (
          <Field label="Affects">{item.affects.join(', ')}</Field>
        ) : null}

        {item.href ? (
          <div>
            <Link href={item.href} className="btn btn-secondary" style={{ fontSize: 'var(--text-sm)' }}>
              Open
            </Link>
          </div>
        ) : null}
      </div>
    </details>
  );
}

function Band({ band, items }) {
  if (items.length === 0) return null;
  return (
    <Card>
      <CardBody>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
          <div>
            <h2
              style={{
                margin: 0,
                fontSize: 'var(--text-lg)',
                fontWeight: 600,
                display: 'flex',
                alignItems: 'center',
                gap: 'var(--s2)',
              }}
            >
              <span
                aria-hidden="true"
                style={{ width: 8, height: 8, borderRadius: '50%', background: band.dot, flex: 'none' }}
              />
              {band.title}
              <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>({items.length})</span>
            </h2>
            <p
              style={{
                margin: 'var(--s1) 0 0',
                fontSize: 'var(--text-sm)',
                color: 'var(--text-secondary)',
                maxWidth: '95ch',
              }}
            >
              {band.blurb}
            </p>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
            {items.map((it, i) => (
              <WorkItem key={it.key} item={it} defaultOpen={i === 0} />
            ))}
          </div>
        </div>
      </CardBody>
    </Card>
  );
}

export default function WorkQueueBoard({ result }) {
  const { items, summary, answer, sources } = result;
  const byBand = (key) => items.filter((i) => i.band === key);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
      <Card>
        <CardBody>
          <AnswerHeader
            answer={answer}
            context={
              `Across ${summary.sourcesTotal} engines · `
              + `${summary.deviceCount} firewall${summary.deviceCount === 1 ? '' : 's'} involved`
            }
          />
        </CardBody>
      </Card>

      {/* ⛔ A FAILED SOURCE IS A BANNER, NOT A FOOTNOTE. The queue is shorter
          than the truth whenever this shows, and a shorter queue reads as good
          news. It is drawn hueless rather than red: the sources did not find a
          problem, they failed to answer. */}
      {summary.sourcesFailed > 0 ? (
        <Card>
          <CardBody>
            <div
              style={{
                borderLeft: '3px solid var(--unmeasured)',
                paddingLeft: 'var(--s3)',
                fontSize: 'var(--text-sm)',
                color: 'var(--text-secondary)',
              }}
            >
              <strong>This queue is incomplete.</strong>{' '}
              {summary.sourcesFailed} of {summary.sourcesTotal} sources could not be read, so work
              they would have contributed is missing from every band below.
              <ul style={{ margin: 'var(--s2) 0 0', paddingLeft: 'var(--s4)' }}>
                {summary.failedSources.map((f) => (
                  <li key={f.key}>
                    <code>{f.key}</code> — {f.error}
                  </li>
                ))}
              </ul>
            </div>
          </CardBody>
        </Card>
      ) : null}

      {/* ⛔ A CAP THAT BIT IS THE SECOND WAY THIS LIST IS SHORTER THAN THE
          TRUTH, and it is the more insidious one: a failed source at least
          announces itself, whereas a truncated list looks complete. An operator
          works to the bottom of it and believes they are finished. */}
      {summary.sourcesTruncated > 0 ? (
        <Card>
          <CardBody>
            <div
              style={{
                borderLeft: '3px solid var(--unmeasured)',
                paddingLeft: 'var(--s3)',
                fontSize: 'var(--text-sm)',
                color: 'var(--text-secondary)',
              }}
            >
              <strong>Not everything is listed.</strong> A per-source cap keeps one noisy engine
              from drowning the queue, and it bit here — so reaching the bottom of a band below is
              not the same as being finished.
              <ul style={{ margin: 'var(--s2) 0 0', paddingLeft: 'var(--s4)' }}>
                {summary.truncatedSources.map((t) => (
                  <li key={t.key}>
                    <code>{t.key}</code> — showing {t.shown} of{' '}
                    {t.of === 'unknown' ? 'an unknown total' : t.of}
                  </li>
                ))}
              </ul>
            </div>
          </CardBody>
        </Card>
      ) : null}

      {items.length === 0 && summary.sourcesFailed === 0 ? (
        <Card>
          <CardBody>
            <EmptyState
              message={
                'Nothing is outstanding across any engine, and every source was readable. '
                + 'This is an all-clear that SecVault is prepared to stand behind.'
              }
            />
          </CardBody>
        </Card>
      ) : null}

      {BANDS.map((band) => (
        <Band key={band.key} band={band} items={byBand(band.key)} />
      ))}

      <Card>
        <CardBody>
          <Disclosure summary="How this queue is built, and what it deliberately leaves out">
            <p style={{ margin: 0 }}>
              Every item is computed at read time from facts other engines already collected. There
              is no stored queue and no scheduled job behind this page — a saved to-do list would go
              stale against the data it indexes, and a stale to-do list is worse than none because
              people work it.
            </p>
            <p style={{ margin: 0 }}>
              <strong>An item is a decision, not a finding.</strong> This fleet holds over a thousand
              rule-analysis findings; they appear here as one item per firewall, linking to the tab
              where that work is actually done. The count travels with the item so the aggregation is
              visible rather than hidden.
            </p>
            <p style={{ margin: 0 }}>
              <strong>Deliberately excluded:</strong> compliance checks with a <code>warning</code>{' '}
              or <code>na</code> status, and CVEs banded <code>scheduled</code> or{' '}
              <code>monitor</code>. Neither is a confirmed piece of work a person can action, and
              padding the queue with items whose first step is &ldquo;find out whether this is even a
              problem&rdquo; is how a queue stops being used.
            </p>
            <p style={{ margin: 0 }}>
              <strong>Nothing here is acknowledged by ticking a box.</strong> Each item states how
              SecVault will independently observe that it is done — a re-assessed version, a
              re-collected ruleset, a re-evaluated check. The one exception is the unreviewed config
              change, where acknowledgement is the action.
            </p>
            <p style={{ margin: 0 }}>
              Sources read this time:{' '}
              {sources.map((s) => `${s.key} (${s.ok ? s.count : 'failed'})`).join(', ')}.
            </p>
          </Disclosure>
        </CardBody>
      </Card>
    </div>
  );
}
