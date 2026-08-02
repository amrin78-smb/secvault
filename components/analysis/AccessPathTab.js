'use client';

import { useState } from 'react';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Card, { CardBody } from '../ui/Card';

// Per-device "Access Path Query" tab — type a source/destination IP
// (optional protocol/port) and see which of this device's own rules would
// decide that traffic, walking the ruleset the same way the firewall does
// (sequence order, first non-excluded rule wins). Unlike ReachabilityTab.js
// (zone-name level, server-rendered), this resolves real address/service
// OBJECTS via lib/engines/objectResolver.js — a client component since it
// needs live user input, modeled on components/config/ConditionsManager.js's
// local-state form -> fetch -> typed-result render shape (see that file for
// the established pattern this one follows).
//
// Deliberately single-device, config-only — same scope limit
// reachabilityMatrix.js's header comment already states: no cross-device
// topology data exists anywhere in this codebase.

const VERDICT_BADGE_COLOR = { allow: 'success', deny: 'danger', unspecified: 'muted' };
const VERDICT_LABEL = { allow: 'Allow', deny: 'Deny', unspecified: 'Unspecified' };

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

function formatField(value) {
  if (value === null || value === undefined) return 'any';
  if (Array.isArray(value)) return value.length === 0 ? 'any' : value.join(', ');
  return String(value);
}

function ResultRowLabel({ result }) {
  const map = {
    match: { color: 'success', label: 'Match' },
    'no-match': { color: 'muted', label: 'No match' },
    unresolved: { color: 'warning', label: 'Unresolved' },
  };
  const { color, label } = map[result] || map.unresolved;
  return <Badge color={color}>{label}</Badge>;
}

function WalkRow({ entry }) {
  const r = entry.rule;
  return (
    <div
      style={{
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        padding: 10,
        background: entry.decided ? 'var(--tint-info)' : 'var(--bg-primary)',
        display: 'flex',
        flexDirection: 'column',
        gap: 6,
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
        <strong style={{ fontSize: 'var(--text-sm)' }}>{r.ruleName || r.ruleIdVendor || '(unnamed rule)'}</strong>
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          {r.action} {entry.decided ? '— decided' : '— did not exclude, but not decisive'}
        </span>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '4px 10px', fontSize: 'var(--text-xs)' }}>
        <span style={{ color: 'var(--text-muted)' }}>Source</span>
        <span>
          <ResultRowLabel result={entry.srcResult} /> {formatField(r.srcAddresses)}
        </span>
        <span style={{ color: 'var(--text-muted)' }}>Destination</span>
        <span>
          <ResultRowLabel result={entry.dstResult} /> {formatField(r.dstAddresses)}
        </span>
        <span style={{ color: 'var(--text-muted)' }}>Service</span>
        <span>
          <ResultRowLabel result={entry.svcResult} /> {formatField(r.services)}
        </span>
      </div>
    </div>
  );
}

export default function AccessPathTab({ deviceId }) {
  const [srcIp, setSrcIp] = useState('');
  const [dstIp, setDstIp] = useState('');
  const [protocol, setProtocol] = useState('');
  const [port, setPort] = useState('');
  const [querying, setQuerying] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [showWalk, setShowWalk] = useState(false);

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
    setShowWalk(false);
    try {
      const res = await fetch(`/api/devices/${deviceId}/access-path`, {
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
        throw new Error(data.error || 'Access path query failed');
      }
      setResult(data);
    } catch (err) {
      setError(err.message || 'Access path query failed');
    } finally {
      setQuerying(false);
    }
  }

  const precedingWalk = result ? result.walk.filter((w) => !w.decided) : [];
  const decidedWalk = result ? result.walk.find((w) => w.decided) : null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', margin: 0 }}>
        Resolves real address/service objects (not just zone names — see the Reachability tab for that) against this
        device&apos;s own ruleset only. Never answers cross-device or multi-hop paths — SecVault has no network
        topology model.
      </p>

      <Card>
        <CardBody>
          <form onSubmit={handleQuery} style={{ display: 'flex', flexWrap: 'wrap', gap: 12, alignItems: 'flex-end' }}>
            <div style={{ minWidth: 160 }}>
              <label style={FIELD_LABEL_STYLE} htmlFor="access-path-src">
                Source IP
              </label>
              <input
                id="access-path-src"
                style={INPUT_STYLE}
                value={srcIp}
                onChange={(e) => setSrcIp(e.target.value)}
                placeholder="10.1.2.3"
              />
            </div>
            <div style={{ minWidth: 160 }}>
              <label style={FIELD_LABEL_STYLE} htmlFor="access-path-dst">
                Destination IP
              </label>
              <input
                id="access-path-dst"
                style={INPUT_STYLE}
                value={dstIp}
                onChange={(e) => setDstIp(e.target.value)}
                placeholder="10.5.0.10"
              />
            </div>
            <div style={{ minWidth: 120 }}>
              <label style={FIELD_LABEL_STYLE} htmlFor="access-path-protocol">
                Protocol
              </label>
              <select
                id="access-path-protocol"
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
              <label style={FIELD_LABEL_STYLE} htmlFor="access-path-port">
                Port
              </label>
              <input
                id="access-path-port"
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
          {error && (
            <p style={{ color: 'var(--red)', fontSize: 'var(--text-sm)', marginTop: 10, marginBottom: 0 }}>{error}</p>
          )}
        </CardBody>
      </Card>

      {result && (
        <Card>
          <CardBody>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <Badge color={VERDICT_BADGE_COLOR[result.verdict] || 'muted'}>
                {VERDICT_LABEL[result.verdict] || result.verdict}
              </Badge>
              {result.hasCaveat && (
                <Badge color="warning">Uncertain — an unresolved object affected this result</Badge>
              )}
            </div>

            {result.note && (
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', margin: 0 }}>{result.note}</p>
            )}

            {decidedWalk ? (
              <div>
                <div style={FIELD_LABEL_STYLE}>Deciding rule</div>
                <WalkRow entry={decidedWalk} />
              </div>
            ) : (
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', margin: 0 }}>
                No rule matched this traffic — this device has no explicit rule for it (unspecified, not necessarily
                denied; SecVault does not model this vendor&apos;s default policy).
              </p>
            )}

            {precedingWalk.length > 0 && (
              <div>
                <button
                  type="button"
                  onClick={() => setShowWalk((v) => !v)}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'var(--primary)',
                    cursor: 'pointer',
                    fontSize: 'var(--text-sm)',
                    padding: 0,
                  }}
                >
                  {showWalk ? 'Hide' : 'Show'} {precedingWalk.length} earlier rule{precedingWalk.length === 1 ? '' : 's'}{' '}
                  that partially matched but were excluded
                </button>
                {showWalk && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 8 }}>
                    {precedingWalk.map((entry) => (
                      <WalkRow key={entry.rule.id} entry={entry} />
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
          </CardBody>
        </Card>
      )}
    </div>
  );
}
