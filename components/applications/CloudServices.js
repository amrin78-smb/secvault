import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import DeclareCloudApp from './DeclareCloudApp';
import { pool } from '../../lib/db';
import { buildPlans, loadDeclarationCatalogue } from '../../app/api/applications/from-cloud/derive';

// What the fleet's rulebase reaches, named against the published cloud
// catalogue. Still a SERVER component: the only interactive part is the
// per-service Declare control, which is its own small client island. Everything
// else — the tables, the coverage footer, the finding — renders on the server
// exactly as before.
//
// ⛔ THE DECLARE PLAN IS BUILT HERE, ON THE SERVER, by the same module the POST
// handler uses. That is what lets each button state how many flows it will
// create BEFORE it is clicked, on first paint, with no fetch-on-mount and no
// second version of the derivation to drift against what actually gets written.
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

/**
 * provider + service -> the declaration plan for that pair.
 *
 * ⛔ KEYED ON (provider, service), NOT ON THE DISPLAY LABEL. The label is built
 * identically in both places today, but keying a lookup on a presentation
 * string is how a future wording change silently removes every Declare button
 * with nothing failing anywhere.
 */
function planKey(provider, service) {
  return `${String(provider || '').toLowerCase()}::${String(service || '').trim().toLowerCase()}`;
}

async function loadPlans() {
  try {
    const catalogue = await loadDeclarationCatalogue(pool);
    const map = new Map();
    for (const plan of buildPlans(catalogue)) {
      map.set(planKey(plan.provider, plan.service), plan);
    }
    return map;
  } catch (_err) {
    // ⛔ The SECTION is not taken down by this. Naming what the rulebase reaches
    // is the primary job here and it has already been done; the Declare control
    // is an extra. Returning null omits the buttons and leaves a stated reason,
    // rather than rendering a control that would fail on click.
    return null;
  }
}

export default async function CloudServices({ summary, declaredNames = [] }) {
  if (!summary) return null;
  // ⛔ WHAT IS ALREADY DECLARED IS AN INPUT, NOT SOMETHING THE BUTTON DISCOVERS
  // BY FAILING. Offering "Declare with 49 flows" for a service that already
  // exists, and answering the click with a 409, teaches an operator the control
  // is unreliable — the page knew the answer before they pressed it. Matched on
  // the exact name the route composes, so this cannot drift from what a second
  // click would actually collide with.
  const declaredSet = new Set(
    (declaredNames || []).map((x) => String(x).trim().toLowerCase())
  );
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
  const plans = await loadPlans();

  return (
    <Card>
      <CardHeader>
        <CardTitle>Cloud services in your rules</CardTitle>
      </CardHeader>
      <CardBody style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>

        <div>
          <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.55, maxWidth: '82ch' }}>
            {/* ⛔ THE COMMENT LIVES ABOVE THIS SENTENCE, NOT INSIDE IT. It was
                between "own" and "published list", and JSX strips a comment
                WITHOUT leaving whitespace — so two text nodes were welded into
                "ownpublished" on screen. A comment is invisible in source and
                load-bearing in output; never put one mid-sentence.

                (What it said, and still applies: no stop-sign glyph in body
                prose. It is a comment convention, not UI language — mid-sentence
                it reads as an error icon on text that is merely explaining
                something. It is NOT banned product-wide: lib/evidence.js carries
                38 inside the drawer's monospace FORMULA block, which is
                deliberate. A repo-wide test asserting otherwise was written and
                deleted on that evidence.) */}
            Hostnames and addresses in your rulebase, matched against each provider&rsquo;s own
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
                  <col style={{ width: '28%' }} />
                  <col style={{ width: '11%' }} />
                  <col style={{ width: '11%' }} />
                  <col style={{ width: '18%' }} />
                  <col style={{ width: '32%' }} />
                </colgroup>
                <thead>
                  <tr>
                    <th style={{ ...LABEL, textAlign: 'left', padding: 'var(--s2) var(--s3)', borderBottom: '1px solid var(--border)' }}>Service</th>
                    <th style={{ ...LABEL, textAlign: 'right', padding: 'var(--s2) var(--s3)', borderBottom: '1px solid var(--border)' }}>Hostnames</th>
                    <th style={{ ...LABEL, textAlign: 'right', padding: 'var(--s2) var(--s3)', borderBottom: '1px solid var(--border)' }}>Firewalls</th>
                    <th style={{ ...LABEL, textAlign: 'left', padding: 'var(--s2) var(--s3)', borderBottom: '1px solid var(--border)' }}>Reached by rules</th>
                    <th style={{ ...LABEL, textAlign: 'left', padding: 'var(--s2) var(--s3)', borderBottom: '1px solid var(--border)' }}>Declare as an application</th>
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
                      <td style={{ padding: 'var(--s3)', borderBottom: '1px solid var(--border-light)' }}>
                        {/* ⛔ The control states its effect before it is clicked,
                            from a plan built on the server by the same module
                            that will do the writing. Where the plan is missing
                            the button is omitted rather than offering an action
                            the route would refuse. */}
                        {plans ? (
                          <DeclareCloudApp
                            provider={s.provider}
                            service={s.service}
                            label={s.label}
                            plan={(plans.get(planKey(s.provider, s.service)) || {}).derivation || null}
                            alreadyDeclared={declaredSet.has(String(s.label || '').trim().toLowerCase())}
                          />
                        ) : (
                          <span style={{ color: 'var(--unmeasured)', fontSize: 'var(--text-xs)' }}>
                            unavailable — the catalogue could not be re-read
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
            {/* ⛔ WHAT DECLARING DOES, AND WHAT IT DOES NOT. Stated once here so
                every button below it is read correctly: a declaration built
                from a publisher's list is destination-and-port only. The source
                is a placeholder on every flow, because no publisher knows —
                and SecVault cannot know — which of your networks reaches the
                service. */}
            <p style={{ margin: 'var(--s2) 0 0', fontSize: 'var(--text-xs)', color: 'var(--text-muted)', lineHeight: 1.55, maxWidth: '82ch' }}>
              Declaring builds flows <strong>only from what the provider publishes</strong> — their IP
              ranges and, where they state them, their ports. No port is invented, and where a provider
              lists a service by hostname only the application is created with no flows, which is the
              correct answer rather than a failure. Every created flow&rsquo;s source is a{' '}
              <strong>placeholder</strong> you need to narrow: only you know which of your networks
              reaches the service.
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
