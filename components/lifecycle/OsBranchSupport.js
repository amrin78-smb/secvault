import Link from 'next/link';
import Card, { CardBody } from '../ui/Card';
import Table from '../ui/Table';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';

// OS BRANCH SUPPORT — is the operating-system branch each firewall runs still
// one the vendor commits to fixing?
//
// ⛔ PRESENTATION ONLY. Every verdict, sentence and date comes from
// lib/osBranch.js via lib/osBranchData.js; this file re-derives nothing. The
// page it mounts on already states that rule for the four sections above it,
// and it is the reason this one cannot drift from the work-queue item built
// from the same verdicts.
//
// ⛔ FOUR STATES GET FOUR TREATMENTS, AND `unknown` IS HUELESS. A gap in OUR
// reach is not a severity of the customer's — the rule the whole design system
// runs on — so an uncovered vendor, an unreadable version and an absent branch
// are drawn in --unmeasured, never in the severity ramp and never in a
// reassuring grey that reads as fine.
//
// ⛔ `extended_only` HAS ITS OWN TINT AND ITS OWN WORDS, and may never share
// either with `supported` or with `eol`. It is the state the whole feature
// exists to make visible: the branch still receives fixes, but only for a
// customer holding an extended-support contract. Rendered as supported it hides
// a contract the customer may not have; rendered as eol it is wrong for the
// customers who do.

const STATE = {
  supported: { tone: 'success', label: 'Supported' },
  extended_only: { tone: 'orange', label: 'Extended only' },
  eol: { tone: 'danger', label: 'Past support' },
  unknown: { tone: 'muted', label: 'Unknown' },
};

const MUTED = { color: 'var(--text-muted)' };
const UNMEASURED = { color: 'var(--unmeasured)' };

// ⛔ A DASH, NOT A ZERO AND NOT A BLANK. An empty cell reads as "nothing to
// report"; this is "the vendor states no such date", which for a branch with no
// extended support is a real and different fact.
function dateCell(value) {
  if (!value) return <span style={MUTED}>—</span>;
  return <span style={{ fontVariantNumeric: 'tabular-nums' }}>{value}</span>;
}

export default function OsBranchSupport({ support }) {
  if (!support) return null;
  const devices = Array.isArray(support.devices) ? support.devices : [];
  const corpus = support.corpus || {};
  const counts = (support.summary && support.summary.counts) || {};
  const byReason = (support.summary && support.summary.unknownByReason) || {};

  // ⛔ ORDERED WORST FIRST, AND `unknown` IS NOT THE BOTTOM. It sits above
  // `supported` because an unknown branch is an open question about a firewall
  // and a supported one is a closed one — sorting our own blind spots below
  // every settled answer is how they stop being looked at.
  const rank = { eol: 0, extended_only: 1, unknown: 2, supported: 3 };
  const rows = [...devices].sort((a, b) => {
    const d = (rank[a.state] ?? 9) - (rank[b.state] ?? 9);
    if (d !== 0) return d;
    return String(a.deviceName || '').localeCompare(String(b.deviceName || ''));
  });

  return (
    <Card>
      <CardBody>
        <div
          style={{
            fontSize: 'var(--text-lg)',
            fontWeight: 700,
            color: 'var(--text-primary)',
            marginBottom: 4,
          }}
        >
          OS Branch Support
        </div>
        <p style={{ margin: '0 0 14px', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
          Whether the OS branch each firewall runs is still one its vendor commits to fixing. A
          branch past that date is remediated by an upgrade, not by a patch — so an advisory
          against a firewall here needs a different plan from one on a supported branch.
        </p>

        {/* ⛔ A FAILED READ SAYS SO. Rendering an empty table here would be
            indistinguishable from a fleet with nothing on a dead branch — the
            house bug, on the section built to report it. The page's other four
            sections cannot hit this because their reads are in one Promise.all
            that fails the page; this one is isolated so a pre-migration deploy
            costs the section, not the page. */}
        {support.readError ? (
          <EmptyState
            message={`Branch support could not be read: ${support.readError}. This is a fault, not `
              + 'a statement that every firewall is on a supported branch.'}
          />
        ) : devices.length === 0 ? (
          <EmptyState message="No active firewall has a collected version to match against the branch lifecycle corpus." />
        ) : (
          <>
            <Table>
              <colgroup>
                <col style={{ width: '20%' }} />
                <col style={{ width: '18%' }} />
                <col style={{ width: '15%' }} />
                <col style={{ width: '14%' }} />
                <col style={{ width: '14%' }} />
                <col style={{ width: '19%' }} />
              </colgroup>
              <thead>
                <tr>
                  <th>Device</th>
                  <th>Branch</th>
                  <th>Support</th>
                  <th>Standard ends</th>
                  <th>Extended ends</th>
                  <th>Date source</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((d) => {
                  const st = STATE[d.state] || STATE.unknown;
                  const unknown = d.state === 'unknown';
                  return (
                    <tr key={d.deviceId}>
                      <td title={d.deviceName}>
                        <Link href={`/devices/${d.deviceId}`}>{d.deviceName}</Link>
                      </td>
                      <td style={unknown ? UNMEASURED : undefined} title={d.version || ''}>
                        {d.branch ? `${d.product} ${d.branch}` : <span style={UNMEASURED}>—</span>}
                      </td>
                      <td>
                        {/* ⛔ The sentence rides in `title`, but the BADGE WORD is
                            what carries the state — never the tint alone. */}
                        <Badge color={st.tone} title={d.sentence}>{st.label}</Badge>
                      </td>
                      <td>{dateCell(d.supportEnd)}</td>
                      <td>{dateCell(d.extendedEnd)}</td>
                      <td style={{ fontSize: 'var(--text-sm)' }}>
                        {unknown ? (
                          // ⛔ THE REASON, NOT A BARE "unknown". Five different
                          // causes send an operator to five different places;
                          // the sentence names which one this is.
                          <span style={UNMEASURED}>{d.sentence}</span>
                        ) : d.vendorConfirmed ? (
                          <span style={MUTED}>Vendor</span>
                        ) : (
                          // ⛔ AN AGGREGATOR DATE SAYS SO IN WORDS, on every row,
                          // and links the official page it cites. A low-confidence
                          // date rendered like a vendor-confirmed one is this
                          // codebase's signature bug with an upgrade budget
                          // attached.
                          <span style={UNMEASURED}>
                            Aggregator{' '}
                            {d.vendorLink ? (
                              <a href={d.vendorLink} target="_blank" rel="noopener noreferrer">
                                (check vendor)
                              </a>
                            ) : null}
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </Table>

            {/* ⛔ THE FIVE UNKNOWN CAUSES ARE NAMED AND NEVER SUMMED into one
                "N unknown" figure — fix collection, fix the parser, accept that
                a vendor is not covered, or ask the publisher for a branch are
                four different next steps. */}
            <p style={{ margin: '12px 0 0', fontSize: 'var(--text-sm)', ...UNMEASURED }}>
              {counts.unknown > 0 ? (
                <>
                  <span aria-hidden="true">⚠</span>{' '}
                  Branch support is unknown for <strong style={UNMEASURED}>{counts.unknown}</strong>{' '}
                  firewall{counts.unknown === 1 ? '' : 's'}:{' '}
                  {[
                    byReason.product_not_covered
                      ? `${byReason.product_not_covered} on an OS the corpus does not cover`
                      : null,
                    byReason.branch_absent
                      ? `${byReason.branch_absent} on a branch that is not in the corpus`
                      : null,
                    byReason.no_version
                      ? `${byReason.no_version} with no collected version`
                      : null,
                    byReason.unreadable_version
                      ? `${byReason.unreadable_version} whose version could not be read`
                      : null,
                    byReason.cycle_unreadable
                      ? `${byReason.cycle_unreadable} whose corpus row states no usable date`
                      : null,
                  ].filter(Boolean).join(' · ')}
                  . Unknown is not supported and not end-of-life.
                </>
              ) : (
                <>Every active firewall matched a branch in the lifecycle corpus.</>
              )}
            </p>

            {/* ⛔ THE CORPUS STATES ITS OWN REACH. Without this a reader cannot
                tell "nothing is end-of-life" from "nothing has been checked" —
                and before the feed's first sync those render identically. */}
            <p style={{ margin: '6px 0 0', fontSize: 'var(--text-sm)', ...MUTED }}>
              {corpus.neverSynced
                ? 'The branch lifecycle feed has not applied a corpus yet, so every firewall above '
                  + 'reads as unknown.'
                : `Corpus: ${corpus.total} branch${corpus.total === 1 ? '' : 'es'}`
                  + `${corpus.feedVersion ? ` (feed ${corpus.feedVersion})` : ''}`
                  + `${Array.isArray(corpus.byProduct) && corpus.byProduct.length
                    ? ` — ${corpus.byProduct.map((p) => `${p.product} ${p.n}`).join(', ')}`
                    : ''}.`}
            </p>
          </>
        )}
      </CardBody>
    </Card>
  );
}
