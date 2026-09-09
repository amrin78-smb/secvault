'use client';

import { useState } from 'react';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Card, { CardBody } from '../ui/Card';
import NotMeasured from '../ui/NotMeasured';

// Fleet-wide "Path Query" tool — type a source/destination IP (optional
// protocol/port) and see the multi-hop path that traffic takes ACROSS the
// whole managed firewall fleet, not just one device's own ruleset. This is
// the fleet-scoped successor to components/analysis/AccessPathTab.js (which
// stays single-device, config-object-resolving) — deliberately mirrors that
// component's form/fetch/error-handling shape for visual and behavioral
// consistency between the two sibling tools, but renders a CHAIN of hops
// instead of one device's decided rule. Backed by lib/engines/topology.js via
// POST /api/topology/path-query.

const VERDICT_BADGE_COLOR = { allow: 'success', deny: 'danger' };
const VERDICT_LABEL = { allow: 'Allow', deny: 'Deny', unspecified: 'Unspecified' };

// ⛔ `unspecified` IS NOT A THIRD OUTCOME, IT IS THE ABSENCE OF ONE. No rule on
// that device decided this traffic, and SecVault holds no default/implicit-
// policy data for ANY vendor (lib/engines/topology.js is explicit that it must
// never be upgraded to 'deny'). A muted Badge put it in the same visual family
// as Allow and Deny, one shade quieter — so the reader saw a verdict. It is
// hueless with a reason instead: the firewall's real behaviour here is unknown
// to this tool, and the operator must go and look.
const UNSPECIFIED_REASON =
  'No rule on this device decided this traffic, and SecVault holds no default/implicit-policy data for any vendor. This is not "denied" and not "allowed" — it is unknown.';

// ⛔ A CAVEAT IS UNCERTAINTY, NOT SEVERITY. This was a `warning` Badge, which
// borrows the amber of a risk finding to say "one address/service object in the
// matched rule could not be resolved" — a limitation of what SecVault could
// read, exactly the state NotMeasured exists to render hueless.
const CAVEAT_REASON =
  'The rule that matched involved an object SecVault could not fully resolve (an FQDN address, or a name with no matching object), so this hop is a best-effort match rather than a certain one.';

const FIELD_LABEL_STYLE = {
  marginBottom: 4,
  display: 'block',
  fontSize: 'var(--text-xs)',
  textTransform: 'uppercase',
  letterSpacing: '0.06em',
  color: 'var(--text-muted)',
};

const INPUT_STYLE = {
  width: '100%',
  padding: '6px 10px',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius)',
  background: 'var(--bg-primary)',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-sm)',
};

// Verdict chip, shared by the per-hop card and the overall result. Module top
// level (never define a component inside another, per CLAUDE.md's #1 rule).
function VerdictChip({ verdict }) {
  if (verdict === 'allow' || verdict === 'deny') {
    return <Badge color={VERDICT_BADGE_COLOR[verdict]}>{VERDICT_LABEL[verdict]}</Badge>;
  }
  return <NotMeasured text={VERDICT_LABEL[verdict] || verdict || 'Unspecified'} reason={UNSPECIFIED_REASON} />;
}

// One hop card in the horizontal chain — top-level component (never define a
// component inside another, per CLAUDE.md's #1 critical rule).
function HopCard({ hop }) {
  return (
    <div
      style={{
        flex: '0 0 auto',
        minWidth: 220,
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        padding: 12,
        background: 'var(--bg-primary)',
        display: 'flex',
        flexDirection: 'column',
        gap: 6,
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
        <strong style={{ fontSize: 'var(--text-sm)' }}>{hop.deviceName}</strong>
        <VerdictChip verdict={hop.verdict} />
      </div>
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
        {hop.matchedRule ? (
          hop.matchedRule.ruleName || hop.matchedRule.ruleIdVendor || '(unnamed rule)'
        ) : (
          <NotMeasured text="No deciding rule" reason={UNSPECIFIED_REASON} />
        )}
      </div>
      {(hop.natApplied || hop.hasCaveat) && (
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 'var(--s1)' }}>
          {hop.natApplied && (
            <Badge color="info">NAT{hop.natRuleName ? `: ${hop.natRuleName}` : ''}</Badge>
          )}
          {/* ⛔ Hueless, with the reason — see CAVEAT_REASON above. */}
          {hop.hasCaveat && <NotMeasured text="Unresolved object" reason={CAVEAT_REASON} />}
        </div>
      )}
    </div>
  );
}

// initialSrcIp: pre-filled Source IP, passed from the Fleet Map's node
// click-through (?srcIp=... query param, read server-side by
// app/(dashboard)/topology/page.js) — editable, never auto-submitted.
export default function PathQueryTab({ initialSrcIp = '' }) {
  const [srcIp, setSrcIp] = useState(initialSrcIp);
  const [dstIp, setDstIp] = useState('');
  const [protocol, setProtocol] = useState('');
  const [port, setPort] = useState('');
  const [querying, setQuerying] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  async function handleQuery(e) {
    e.preventDefault();
    if (querying) return;
    if (!srcIp.trim() || !dstIp.trim()) {
      setError('Source and destination IP are both required.');
      return;
    }
    setQuerying(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch('/api/topology/path-query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          srcIp: srcIp.trim(),
          dstIp: dstIp.trim(),
          protocol: protocol || undefined,
          port: port ? Number(port) : undefined,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.error || 'Path query failed');
      }
      setResult(data);
    } catch (err) {
      setError(err.message || 'Path query failed');
    } finally {
      setQuerying(false);
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', margin: 0 }}>
        Fleet-wide — this walks traffic ACROSS every managed firewall a path might cross, unlike the per-device
        Access Path tool on each device&apos;s Rule Analysis page (which only resolves that device&apos;s own
        ruleset). It depends on routing/interface data that, as of this build, is only collected for Palo Alto and
        Fortinet devices — a device pair not covered by either vendor simply won&apos;t chain together in the
        adjacency graph, and the path may end early as a result.
      </p>

      <Card>
        <CardBody>
          <form onSubmit={handleQuery} style={{ display: 'flex', flexWrap: 'wrap', gap: 12, alignItems: 'flex-end' }}>
            <div style={{ minWidth: 160 }}>
              <label style={FIELD_LABEL_STYLE} htmlFor="topology-path-src">
                Source IP
              </label>
              <input
                id="topology-path-src"
                style={INPUT_STYLE}
                value={srcIp}
                onChange={(e) => setSrcIp(e.target.value)}
                placeholder="10.1.2.3"
              />
            </div>
            <div style={{ minWidth: 160 }}>
              <label style={FIELD_LABEL_STYLE} htmlFor="topology-path-dst">
                Destination IP
              </label>
              <input
                id="topology-path-dst"
                style={INPUT_STYLE}
                value={dstIp}
                onChange={(e) => setDstIp(e.target.value)}
                placeholder="10.5.0.10"
              />
            </div>
            <div style={{ minWidth: 120 }}>
              <label style={FIELD_LABEL_STYLE} htmlFor="topology-path-protocol">
                Protocol
              </label>
              <select
                id="topology-path-protocol"
                style={INPUT_STYLE}
                value={protocol}
                onChange={(e) => setProtocol(e.target.value)}
              >
                <option value="">Any</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="icmp">ICMP</option>
              </select>
            </div>
            <div style={{ minWidth: 100 }}>
              <label style={FIELD_LABEL_STYLE} htmlFor="topology-path-port">
                Port
              </label>
              <input
                id="topology-path-port"
                style={INPUT_STYLE}
                type="number"
                min="0"
                max="65535"
                value={port}
                onChange={(e) => setPort(e.target.value)}
                placeholder="443"
              />
            </div>
            <Button type="submit" disabled={querying}>
              {querying ? 'Querying…' : 'Query'}
            </Button>
          </form>
          {/* ⛔ An error is not a verdict. Say that the query did not RUN, so a
              reader cannot carry away "nothing was found" from a request that
              never completed. */}
          {error && (
            <div
              style={{
                marginTop: 'var(--s3)',
                padding: 'var(--s2) var(--s3)',
                borderRadius: 'var(--radius-sm)',
                background: 'var(--tint-danger)',
                color: 'var(--tint-danger-fg)',
                fontSize: 'var(--text-sm)',
              }}
              role="alert"
            >
              <strong>The path query did not run.</strong> {error}
            </div>
          )}
        </CardBody>
      </Card>

      {/* Loading state: the result panel is replaced, not left showing a stale
          answer next to a spinning button. */}
      {querying && (
        <Card>
          <CardBody>
            <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', margin: 0 }}>
              Walking the path across every managed firewall the traffic might cross…
            </p>
          </CardBody>
        </Card>
      )}

      {result && !querying && (
        <Card>
          <CardBody>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
                  Overall verdict
                </span>
                <VerdictChip verdict={result.finalVerdict} />
              </div>

              {result.note && (
                <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', margin: 0 }}>{result.note}</p>
              )}

              {Array.isArray(result.hops) && result.hops.length > 0 ? (
                <div style={{ overflowX: 'auto' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '4px 2px' }}>
                    {result.hops.map((hop, i) => (
                      <div key={hop.deviceId || i} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        {i > 0 && (
                          <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-lg)' }}>&rarr;</span>
                        )}
                        <HopCard hop={hop} />
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                // ⛔ Zero hops is a COVERAGE result, not a network result. The
                // verdict above already renders hueless for `unspecified`; this
                // says why, so nobody reads an empty chain as "nothing is in
                // the way".
                <p style={{ fontSize: 'var(--text-sm)', color: 'var(--unmeasured)', margin: 0 }}>
                  No hops resolved — neither the source nor the destination address landed on a device this
                  tool has routing/interface data for (collected today for Palo Alto and Fortinet only). SecVault
                  did not evaluate a single rule for this traffic; this says nothing about whether it is allowed.
                </p>
              )}
            </div>
          </CardBody>
        </Card>
      )}
    </div>
  );
}
