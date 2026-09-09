import Link from 'next/link';
import { pool } from '../../lib/db';
import Card, { CardBody } from '../ui/Card';
import { PRODUCT_NAME } from '../../lib/branding';

export const dynamic = 'force-dynamic';

// First-run guidance, shown INSTEAD of the dashboard when no firewall has been
// added yet.
//
// ⛔ WHY THIS EXISTS. A fresh install rendered the full dashboard against an
// empty database: a grid of zeros, em-dashes and "no data" panels. That is the
// first thing a new operator — or an evaluator — ever sees, and it reads as
// BROKEN rather than as EMPTY. The product looked like it had failed to load
// when in fact it was working perfectly and had simply never been given a
// device.
//
// ⛔ It replaces the dashboard only while `devices` is genuinely empty. The
// moment one firewall exists, the real dashboard takes over, zeros and all —
// because from that point a zero is a MEASUREMENT ("no critical CVEs on your
// one device") rather than an absence of input. Keeping the wizard around
// after that would hide real data behind a tutorial.
//
// ⛔ Every step's state is READ FROM THE DATABASE, never stored as "wizard
// progress". A checklist that remembers being ticked can disagree with
// reality — someone deletes the only device and the wizard still says step 1
// is done. Each step asks its own question every time it renders, which is the
// same instinct as computing device health at read time rather than storing a
// verdict.

async function getFirstRunState() {
  // One round trip. Each subquery answers one step, and each is a question
  // about the DATA, not about a remembered click.
  const { rows } = await pool.query(`
    SELECT
      (SELECT count(*) FROM devices)::int                                   AS devices,
      (SELECT count(*) FROM devices WHERE active)::int                      AS active_devices,
      (SELECT count(*) FROM device_versions)::int                           AS versions,
      (SELECT count(*) FROM firewall_rules)::int                            AS rules,
      (SELECT count(*) FROM advisories)::int                                AS advisories,
      (SELECT count(*) FROM audit_findings)::int                            AS findings,
      (SELECT count(*) FROM feed_sync_log WHERE status = 'success')::int    AS feed_syncs
  `);
  return rows[0];
}

function Step({ n, done, title, body, action, href }) {
  return (
    <li
      style={{
        display: 'flex',
        gap: 'var(--s4)',
        padding: 'var(--s4) 0',
        borderTop: n === 1 ? 'none' : '1px solid var(--border-light)',
      }}
    >
      <span
        aria-hidden="true"
        style={{
          flex: 'none',
          width: 26,
          height: 26,
          borderRadius: '50%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: 'var(--text-sm)',
          fontWeight: 600,
          background: done ? 'var(--tint-success)' : 'var(--surface-subtle)',
          color: done ? 'var(--tint-success-fg)' : 'var(--text-muted)',
          border: done ? '1px solid transparent' : '1px solid var(--border)',
        }}
      >
        {done ? '✓' : n}
      </span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{title}</div>
        <p style={{ margin: '2px 0 0', fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
          {body}
        </p>
        {action && href && !done && (
          <Link
            href={href}
            className="btn btn-primary"
            style={{ display: 'inline-block', marginTop: 'var(--s3)', fontSize: 'var(--text-sm)' }}
          >
            {action}
          </Link>
        )}
      </div>
      <span
        style={{
          flex: 'none',
          alignSelf: 'flex-start',
          fontSize: 'var(--text-xs)',
          color: done ? 'var(--tint-success-fg)' : 'var(--text-muted)',
        }}
      >
        {done ? 'Done' : 'Not yet'}
      </span>
    </li>
  );
}

/**
 * Returns null when the fleet is non-empty, so the caller can render it
 * unconditionally and let it decide.
 */
export default async function FirstRun() {
  const s = await getFirstRunState();
  if (s.devices > 0) return null;

  return (
    <Card>
      <CardBody>
        <h2 style={{ margin: 0, fontSize: 'var(--text-xl)', color: 'var(--text-primary)' }}>
          Welcome to {PRODUCT_NAME}
        </h2>
        <p
          style={{
            margin: 'var(--s2) 0 var(--s4)',
            fontSize: 'var(--text-md)',
            color: 'var(--text-secondary)',
            maxWidth: '62ch',
          }}
        >
          {/* ⛔ Says plainly that the emptiness is expected. The screen this
              replaced showed zeros everywhere, and a zero on a security
              dashboard is a claim — "no critical CVEs" — that this install has
              not earned yet. */}
          No firewalls have been added yet, so there is nothing to report on. That is expected on a
          new install — the figures below the dashboard would otherwise read as
          &ldquo;nothing is wrong&rdquo;, when the truth is that nothing has been looked at.
        </p>

        <ol style={{ listStyle: 'none', margin: 0, padding: 0 }}>
          <Step
            n={1}
            done={s.devices > 0}
            title="Add your first firewall"
            body="Its vendor, management address and credentials. Credentials are encrypted before they are stored and are never written to a log."
            action="Add a firewall"
            href="/devices/new"
          />
          <Step
            n={2}
            done={s.versions > 0 || s.rules > 0}
            title="Collect from it"
            body="Test connectivity, then run a collection. This pulls the software version and the ruleset — the two facts almost everything else is derived from."
            action="Go to firewalls"
            href="/devices"
          />
          <Step
            n={3}
            done={s.feed_syncs > 0 && s.advisories > 0}
            title="Let the CVE feeds sync"
            body="The engine fetches NVD, vendor PSIRT advisories and the CISA KEV catalogue on its own schedule, then matches them against the versions it collected. Nothing to do here but wait for the first run."
            action="Check feed status"
            href="/settings"
          />
          <Step
            n={4}
            done={s.findings > 0}
            title="Run a compliance audit"
            body="Scores the collected configuration against PCI DSS, ISO 27001, CIS v8, NIST and SANS. Needs step 2 to have succeeded first."
            action="Open compliance"
            href="/compliance"
          />
        </ol>

        <p
          style={{
            margin: 'var(--s4) 0 0',
            paddingTop: 'var(--s3)',
            borderTop: '1px solid var(--border-light)',
            fontSize: 'var(--text-sm)',
            color: 'var(--text-muted)',
          }}
        >
          This page is replaced by the dashboard as soon as one firewall exists.
        </p>
      </CardBody>
    </Card>
  );
}
