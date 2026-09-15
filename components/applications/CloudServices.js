import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';

// What the fleet's rulebase reaches, named against the published cloud
// catalogue. A SERVER component — it is pure display with no interactivity, so
// nothing crosses a client boundary and there is nothing to serialise.
//
// ⛔ THE CATALOGUE'S STATE IS PART OF EVERY ANSWER HERE. On an install with no
// outbound access — this product's target customer, not an edge case — the
// catalogue is empty and stays empty, and this section must read as "nothing to
// check against" rather than showing an empty table that looks like a clean
// result. That distinction is the whole reason `unavailable` and `no_match` are
// separate states in the engine.

const LABEL = {
  fontSize: 'var(--text-xs)',
  textTransform: 'uppercase',
  letterSpacing: '0.04em',
  color: 'var(--text-muted)',
  fontWeight: 600,
};

const HATCH = {
  backgroundImage: 'var(--hatch)',
  backgroundColor: 'var(--surface-subtle)',
  border: '1px dashed var(--border)',
  borderRadius: 'var(--radius)',
  padding: 'var(--s4)',
  color: 'var(--unmeasured)',
  fontSize: 'var(--text-sm)',
  lineHeight: 1.55,
};

function StatusLine({ status }) {
  // ⛔ Only a FRESH, POPULATED catalogue gets ordinary text. Empty, stale and
  // unreadable are all drawn hueless — none of them is a failure of the
  // customer's network, and none of them may read as a clean result either.
  const plain = status.state === 'ok';
  return (
    <div
      style={{
        fontSize: 'var(--text-xs)',
        color: plain ? 'var(--text-muted)' : 'var(--unmeasured)',
        marginTop: 'var(--s2)',
      }}
    >
      {status.message}
    </div>
  );
}

export default function CloudServices({ summary }) {
  if (!summary) return null;
  const { status, services, hardcoded, totals } = summary;

  // ── Nothing to check against ────────────────────────────────────────────
  if (!status.usable) {
    return (
      <Card>
        <CardHeader><CardTitle>Cloud services in your rules</CardTitle></CardHeader>
        <CardBody>
          <div style={HATCH}>
            <strong style={{ color: 'var(--unmeasured)' }}>
              {status.state === 'error'
                ? 'The cloud catalogue could not be read.'
                : 'No cloud catalogue has been fetched on this install.'}
            </strong>
            <div style={{ marginTop: 'var(--s2)' }}>{status.message}</div>
            <div style={{ marginTop: 'var(--s3)' }}>
              {/* ⛔ The sentence that stops an empty table being read as an answer. */}
              Nothing here should be read as &ldquo;no cloud services are in use&rdquo; — SecVault has
              no published list to compare your rules against, so it has not checked.
            </div>
          </div>
        </CardBody>
      </Card>
    );
  }

  const distinctHardcoded = new Set(hardcoded.map((h) => h.value)).size;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Cloud services in your rules</CardTitle>
      </CardHeader>
      <CardBody style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>

        <div>
          <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.55, maxWidth: '82ch' }}>
            Hostnames and addresses in your rulebase, matched against each provider&rsquo;s own
            {/* ⛔ NO STOP-SIGN GLYPH IN BODY PROSE. This paragraph shipped with
                one mid-sentence and it read as an error icon attached to text
                that is merely explaining something.

                It is NOT banned product-wide, and a repo-wide test asserting
                that was written and then deleted on the evidence: lib/evidence.js
                carries 38 of them inside the drawer's monospace FORMULA block
                (`<code>{payload.rule}</code>`), where it reads as a marginal note
                in a technical listing rather than as an icon. That is deliberate
                and established. The distinction is prose versus formula, which is
                a judgement a mechanical guard cannot make — so this is a comment,
                not a test. */}
            published list. A match names the <strong>provider and the service they publish</strong>
            {' '}— never an application. An address inside AWS&rsquo;s ranges is AWS, not whatever runs there.
          </p>
          <StatusLine status={status} />
        </div>

        {/* ── Named services ─────────────────────────────────────────────── */}
        {services.length === 0 ? (
          <div style={HATCH}>
            None of the {totals.fqdnObjects} hostname objects in your rulebase appear in the published
            lists. That means these publishers do not list them — not that the objects are unused.
          </div>
        ) : (
          <section>
            <h3 style={{ ...LABEL, margin: '0 0 var(--s2)' }}>What your rules reference</h3>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', tableLayout: 'fixed', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
                <colgroup>
                  <col style={{ width: '46%' }} />
                  <col style={{ width: '14%' }} />
                  <col style={{ width: '16%' }} />
                  <col style={{ width: '24%' }} />
                </colgroup>
                <thead>
                  <tr>
                    <th style={{ ...LABEL, textAlign: 'left', padding: 'var(--s2) var(--s3)', borderBottom: '1px solid var(--border)' }}>Service</th>
                    <th style={{ ...LABEL, textAlign: 'right', padding: 'var(--s2) var(--s3)', borderBottom: '1px solid var(--border)' }}>Hostnames</th>
                    <th style={{ ...LABEL, textAlign: 'right', padding: 'var(--s2) var(--s3)', borderBottom: '1px solid var(--border)' }}>Firewalls</th>
                    <th style={{ ...LABEL, textAlign: 'left', padding: 'var(--s2) var(--s3)', borderBottom: '1px solid var(--border)' }}>Reached by rules</th>
                  </tr>
                </thead>
                <tbody>
                  {services.map((s) => (
                    <tr key={s.label}>
                      <td style={{ padding: 'var(--s3)', borderBottom: '1px solid var(--border-light)', color: 'var(--text-primary)' }}>
                        {s.label}
                      </td>
                      <td style={{ padding: 'var(--s3)', borderBottom: '1px solid var(--border-light)', textAlign: 'right', fontVariantNumeric: 'tabular-nums' }}>
                        {s.hostCount}
                      </td>
                      <td style={{ padding: 'var(--s3)', borderBottom: '1px solid var(--border-light)', textAlign: 'right', fontVariantNumeric: 'tabular-nums' }}>
                        {s.deviceCount}
                      </td>
                      <td style={{ padding: 'var(--s3)', borderBottom: '1px solid var(--border-light)' }}>
                        {/* ⛔ ZERO HERE IS A STATEMENT ABOUT THE OBJECTS, NOT ABOUT THE
                            SERVICE. The objects are defined on the firewall but no enabled
                            rule reaches them. It does NOT mean the service is blocked —
                            traffic to it may well be permitted by a broader rule that
                            names no hostname at all. */}
                        {s.ruleCount > 0 ? (
                          <span style={{ fontVariantNumeric: 'tabular-nums' }}>
                            {s.ruleCount} rule{s.ruleCount === 1 ? '' : 's'}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--unmeasured)' }}>
                            defined, not referenced
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p style={{ margin: 'var(--s3) 0 0', fontSize: 'var(--text-xs)', color: 'var(--text-muted)', lineHeight: 1.55, maxWidth: '82ch' }}>
              &ldquo;Defined, not referenced&rdquo; means the objects exist on the firewall but no
              enabled rule names them, directly or through a group. It does <strong>not</strong> mean
              the service is blocked — traffic to it may be permitted by a broader rule that names no
              hostname at all.
            </p>
          </section>
        )}

        {/* ── The finding ────────────────────────────────────────────────── */}
        {hardcoded.length > 0 ? (
          <section>
            <h3 style={{ ...LABEL, margin: '0 0 var(--s2)' }}>
              Addresses pinned to a provider&rsquo;s range
            </h3>
            <div
              style={{
                border: '1px solid var(--border)',
                borderLeft: '3px solid var(--sev-med)',
                borderRadius: 'var(--radius)',
                padding: 'var(--s4)',
                fontSize: 'var(--text-sm)',
                color: 'var(--text-secondary)',
                lineHeight: 1.55,
              }}
            >
              <strong style={{ color: 'var(--text-primary)' }}>
                {distinctHardcoded} address{distinctHardcoded === 1 ? '' : 'es'} in your rulebase
                {distinctHardcoded === 1 ? ' sits' : ' sit'} inside space a cloud provider publishes
                {hardcoded.length !== distinctHardcoded ? ` (${hardcoded.length} objects across the fleet)` : ''}.
              </strong>
              <div style={{ marginTop: 'var(--s2)' }}>
                These work until the provider moves that range, and then they stop — without anyone
                touching the firewall, and without any alert, because nothing on the device changed.
                Providers publish hostnames precisely so this does not have to be pinned.
              </div>
            </div>

            <details style={{ marginTop: 'var(--s3)' }}>
              <summary style={{ cursor: 'pointer', fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
                Show the addresses
              </summary>
              <div style={{ overflowX: 'auto', marginTop: 'var(--s3)' }}>
                <table style={{ width: '100%', tableLayout: 'fixed', borderCollapse: 'collapse', fontSize: 'var(--text-sm)' }}>
                  <colgroup>
                    <col style={{ width: '22%' }} />
                    <col style={{ width: '18%' }} />
                    <col style={{ width: '24%' }} />
                    <col style={{ width: '36%' }} />
                  </colgroup>
                  <thead>
                    <tr>
                      <th style={{ ...LABEL, textAlign: 'left', padding: 'var(--s2) var(--s3)', borderBottom: '1px solid var(--border)' }}>Address</th>
                      <th style={{ ...LABEL, textAlign: 'left', padding: 'var(--s2) var(--s3)', borderBottom: '1px solid var(--border)' }}>Firewall</th>
                      <th style={{ ...LABEL, textAlign: 'left', padding: 'var(--s2) var(--s3)', borderBottom: '1px solid var(--border)' }}>Object</th>
                      <th style={{ ...LABEL, textAlign: 'left', padding: 'var(--s2) var(--s3)', borderBottom: '1px solid var(--border)' }}>Published as</th>
                    </tr>
                  </thead>
                  <tbody>
                    {hardcoded.slice(0, 200).map((h, i) => (
                      <tr key={`${h.deviceId}-${h.value}-${i}`}>
                        <td style={{ padding: 'var(--s2) var(--s3)', borderBottom: '1px solid var(--border-light)', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
                          {h.value}
                        </td>
                        <td style={{ padding: 'var(--s2) var(--s3)', borderBottom: '1px solid var(--border-light)' }}>{h.device}</td>
                        <td style={{ padding: 'var(--s2) var(--s3)', borderBottom: '1px solid var(--border-light)', color: 'var(--text-secondary)', wordBreak: 'break-word' }}>
                          {h.objectName}
                        </td>
                        <td style={{ padding: 'var(--s2) var(--s3)', borderBottom: '1px solid var(--border-light)', color: 'var(--text-secondary)' }}>
                          {h.label}{' '}
                          <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
                            {h.range}
                          </span>
                          {/* ⛔ Two publishers claiming the same space is disclosed, not hidden. */}
                          {h.ambiguous ? (
                            <span style={{ color: 'var(--unmeasured)' }}> · also claimed by another provider</span>
                          ) : null}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {hardcoded.length > 200 ? (
                // ⛔ A truncated list must say it is truncated. A reader who
                // works to the bottom of a capped table believes they are done.
                <p style={{ margin: 'var(--s3) 0 0', fontSize: 'var(--text-xs)', color: 'var(--unmeasured)' }}>
                  Showing the first 200 of {hardcoded.length}.
                </p>
              ) : null}
            </details>
          </section>
        ) : null}

        {/* ── What was not looked at ─────────────────────────────────────── */}
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', lineHeight: 1.6, borderTop: '1px solid var(--border-light)', paddingTop: 'var(--s3)' }}>
          {/* ⛔ COVERAGE, STATED. A naming feature that shows its hits and hides
              its misses reads as far more complete than it is. */}
          Checked {totals.fqdnObjects} hostname and {totals.ipObjects} address objects across the
          fleet; named {totals.namedObjects}.{' '}
          {totals.unnamedObjects > 0 ? (
            <>{totals.unnamedObjects} hostname objects are not in any published list. </>
          ) : null}
          {totals.unclassifiedObjects > 0 ? (
            <>
              {totals.unclassifiedObjects} further objects use an address shape SecVault does not
              read (mostly <code>start-end</code> ranges) and were not checked at all.
            </>
          ) : null}
        </div>
      </CardBody>
    </Card>
  );
}
