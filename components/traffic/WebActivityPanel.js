import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import IconChip from '../ui/IconChip';
import { IconGrid } from '../icons';
// ⛔ EVERY SENTENCE THIS PANEL PRINTS IS BUILT BY A PURE MODULE, NOT INLINE.
// The bars are almost incapable of being wrong; the claims beside them are the
// feature, and JSX cannot be unit-tested by `node:test` (there is no transform
// in this repo, deliberately). Same split as every engine here.
import {
  fmtBytes, volumeAttributionSentence, categoryCaveatSentence, coverageSentence, noVolumeReason,
} from '../../lib/syslog/webActivityText';

// components/traffic/WebActivityPanel.js
//
// "What are people actually using?" — the question management asks, rendered
// the way the rest of this product renders a measurement.
//
// ⛔ ONE COMPONENT, BOTH TABS. The fleet Traffic tab and each firewall's own
// Traffic tab show the SAME panel over the same `getWebActivity` shape. Two
// implementations of a chart whose whole value is a claim boundary would drift,
// and the one that drifted would be the one someone screenshotted.
//
// ⛔ IT IS NOT TITLED "TOP WEBSITES", AND THAT IS A CLAIM BOUNDARY RATHER THAN
// WORD CHOICE. What the firewalls report is their own APPLICATION identity —
// `youtube-base`, `facebook-base` — not the hostname that was visited. SecVault
// does hold `url_hostname` on raw events, but it is populated on a small
// minority of them (measured 2026-09-21: 1.3% of a 20-minute fleet sample, with
// several firewalls reporting none at all) and has no rollup, so it dies with
// the 30-day partitions. A "top websites" ranking built from it would describe
// a fortieth of the traffic under a heading claiming the estate. Closing that
// gap needs hostname logging enabled on the firewalls AND a rollup to retain it
// — a change with an ingestion cost, not a relabelled query.
//
// ⛔ THREE THINGS ARE ALWAYS SHOWN TOGETHER AND MUST NOT BE SEPARATED:
//   1. what was identified, ranked by volume;
//   2. how much could NOT be identified (usually the larger number — `ssl` and
//      `quic-base` alone outweigh every named application on this fleet);
//   3. which firewalls can answer the question at all.
// Showing 1 without 2 turns a floor into a total. Showing 1 without 3 turns a
// statement about six firewalls into a statement about sixteen.

const titleStyle = { display: 'flex', alignItems: 'center', gap: 8 };

// ⛔ Em dash, never 0 — the same rule as every other figure in this product.
function Measure({ text }) {
  if (text === null || text === undefined) {
    return <span style={{ color: 'var(--unmeasured)' }}>—</span>;
  }
  return <span style={{ fontVariantNumeric: 'tabular-nums' }}>{text}</span>;
}

function Bars({ rows, labelOf, valueOf, displayOf, color }) {
  const max = rows.reduce((n, r) => Math.max(n, valueOf(r) || 0), 0);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
      {rows.map((r) => (
        <div key={labelOf(r)}>
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 2 }}>
            <span style={{
              fontSize: 'var(--text-sm)',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}>
              {labelOf(r)}
            </span>
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', flexShrink: 0 }}>
              <Measure text={displayOf(r)} />
            </span>
          </div>
          <div style={{ height: 6, background: 'var(--surface-subtle)', borderRadius: 3, overflow: 'hidden' }}>
            <div style={{
              width: `${max > 0 ? Math.max(2, Math.round((valueOf(r) / max) * 100)) : 0}%`,
              height: '100%',
              background: color,
            }} />
          </div>
        </div>
      ))}
    </div>
  );
}

function Note({ tone, children }) {
  return (
    <div style={{
      marginTop: 10,
      padding: '8px 10px',
      borderRadius: 'var(--radius-sm)',
      background: tone === 'bad' ? 'var(--tint-danger)' : (tone === 'warn' ? 'var(--tint-warn)' : 'var(--surface-subtle)'),
      color: tone === 'bad' ? 'var(--tint-danger-fg)' : (tone === 'warn' ? 'var(--tint-warn-fg)' : 'var(--text-muted)'),
      fontSize: 'var(--text-xs)',
      lineHeight: 1.5,
    }}>
      {children}
    </div>
  );
}

/**
 * @param {object}  web       a `getWebActivity()` result
 * @param {boolean} perDevice true on a single firewall's tab, which changes the
 *                            wording only — never which facts are shown
 */
export default function WebActivityPanel({ web, perDevice = false }) {
  if (!web) return null;

  const { identified, categories, bytesCapable, hours } = web;

  const noVolume = noVolumeReason(web, perDevice);
  const attribution = volumeAttributionSentence(web);
  const catCaveat = categoryCaveatSentence(categories, perDevice);

  return (
    <Card>
      <CardHeader>
        <CardTitle style={titleStyle}>
          <IconChip icon={IconGrid} color="var(--tint-teal-fg)" bg="var(--tint-teal)" />
          Web &amp; application activity ({hours}h)
        </CardTitle>
      </CardHeader>
      <CardBody>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 20 }}>
          <div>
            <div style={{
              fontSize: 'var(--text-xs)',
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
              color: 'var(--text-muted)',
              marginBottom: 8,
            }}>
              By volume
            </div>
            {noVolume ? (
              // ⛔ NOT AN EMPTY LIST. FortiOS re-logs a session with a running
              // cumulative counter, so its byte columns cannot be added without
              // counting the same bytes repeatedly. "We may not sum this" and
              // "there was no traffic" are opposite facts and a blank panel
              // renders them the same way.
              <div style={{ fontSize: 'var(--text-sm)', color: 'var(--unmeasured)', lineHeight: 1.6 }}>
                {noVolume}
              </div>
            ) : identified.length === 0 ? (
              <div style={{ fontSize: 'var(--text-sm)', color: 'var(--unmeasured)', lineHeight: 1.6 }}>
                Nothing was attributed to a named application in this window.
              </div>
            ) : (
              <>
                <Bars
                  rows={identified}
                  labelOf={(r) => r.application}
                  valueOf={(r) => r.bytes}
                  displayOf={(r) => fmtBytes(r.bytes)}
                  color="var(--primary)"
                />
                {attribution ? <Note>{attribution}</Note> : null}
              </>
            )}
          </div>

          <div>
            <div style={{
              fontSize: 'var(--text-xs)',
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
              color: 'var(--text-muted)',
              marginBottom: 8,
            }}>
              Web categories
            </div>
            {categories.classified.length === 0 ? (
              <div style={{ fontSize: 'var(--text-sm)', color: 'var(--unmeasured)', lineHeight: 1.6 }}>
                {perDevice
                  ? 'This firewall returned no URL category in this window.'
                  : 'No firewall returned a URL category in this window.'}
              </div>
            ) : (
              <Bars
                rows={categories.classified}
                labelOf={(r) => r.category}
                valueOf={(r) => r.events}
                displayOf={(r) => Number(r.events).toLocaleString()}
                color="var(--accent-teal)"
              />
            )}
            {/* ⛔ THE UNCLASSIFIED TOTAL IS NEVER RANKED WITH THE CATEGORIES.
                Live it is the largest value by an order of magnitude — `any`,
                `unscanned` and `license-expired` together dwarf every real
                category — so sorting them into the same list would put "we did
                not look" at the top of a list of what staff browse. */}
            {catCaveat ? (
              <Note tone={categories.licenceLapsed ? 'bad' : 'warn'}>{catCaveat}</Note>
            ) : null}
          </div>
        </div>

        {/* ⛔ COVERAGE LAST BUT NEVER ABSENT. Application identity comes from a
            licensed inspection feature, so it is wildly uneven across a real
            fleet: measured here every PAN-OS firewall names 100% of its
            sessions while four of five FortiGates name under half, and one
            names 3%. Without this the panel reads as a statement about the
            estate when it is a statement about whichever firewalls inspect. */}
        <div style={{
          marginTop: 16,
          paddingTop: 12,
          borderTop: '1px solid var(--border-light)',
          fontSize: 'var(--text-xs)',
          color: 'var(--text-muted)',
          lineHeight: 1.6,
        }}>
          {coverageSentence(web, perDevice)}
        </div>
      </CardBody>
    </Card>
  );
}
