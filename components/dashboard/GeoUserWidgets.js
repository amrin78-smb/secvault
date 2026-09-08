import Link from 'next/link';
import { pool } from '../../lib/db';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import IconChip from '../ui/IconChip';
import { IconTopology, IconUser, IconGrid } from '../icons';
import { getTopCountries, getTopUsers, getTopUrlCategories } from '../../lib/syslog/trafficStats';

export const dynamic = 'force-dynamic';

// Geographic, per-user and URL-category reporting — three Firewall Analyzer
// report families the decommission review listed as missing and which turned
// out to need no new collection at all: Palo Alto and FortiOS both put country,
// user and URL category in logs SecVault was already receiving and discarding.
//
// ⛔ No GeoIP database is involved anywhere. The country is the firewall's own
// answer. That also means it is only as good as the vendor's own geo feed, and
// a device that does not populate it simply contributes to `unreported` rather
// than being silently excluded.

const titleStyle = { display: 'flex', alignItems: 'center', gap: 8 };
const rowLabel = {
  fontSize: 'var(--text-base)',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
};

function Num({ value }) {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) {
    return <span style={{ color: 'var(--text-muted)' }}>—</span>;
  }
  return <span style={{ fontVariantNumeric: 'tabular-nums' }}>{Number(value).toLocaleString()}</span>;
}

function Bar({ pct, tone }) {
  return (
    <div aria-hidden="true" style={{ height: 5, borderRadius: 3, background: 'var(--border)', overflow: 'hidden' }}>
      <div style={{ width: `${Math.max(0, Math.min(100, pct))}%`, height: '100%', background: tone }} />
    </div>
  );
}

function Empty({ children }) {
  return <div style={{ fontSize: 'var(--text-base)', color: 'var(--text-muted)' }}>{children}</div>;
}

function logsHref(params) {
  return `/logs?${new URLSearchParams(params).toString()}`;
}

// ---------------------------------------------------------------------------

export async function TopCountriesWidget() {
  const { countries, internal, unreported } = await getTopCountries(pool, 24, 8);
  const max = countries.reduce((n, c) => Math.max(n, c.events), 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle style={titleStyle}>
          <IconChip icon={IconTopology} color="#2dd4bf" bg="rgba(45,212,191,0.20)" />
          Top Destination Countries (24h)
        </CardTitle>
      </CardHeader>
      <CardBody>
        {countries.length === 0 ? (
          <Empty>
            No external destinations recorded. Country comes from the firewall&apos;s own
            geo lookup, so an empty list here means the devices are not reporting it.
          </Empty>
        ) : (
          <>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
              {countries.map((c) => (
                <div key={c.country}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 2 }}>
                    <span style={rowLabel}>
                      <Link
                        href={logsHref({ dstCountry: c.country, limit: '250' })}
                        style={{ color: 'var(--text-primary)' }}
                      >
                        {c.country}
                      </Link>
                      {c.denied > 0 ? (
                        <span style={{ marginLeft: 6, fontSize: 'var(--text-sm)', color: 'var(--red)' }}>
                          {c.denied.toLocaleString()} denied
                        </span>
                      ) : null}
                    </span>
                    <span style={{ fontSize: 'var(--text-base)' }}><Num value={c.events} /></span>
                  </div>
                  <Bar pct={max > 0 ? (c.events / max) * 100 : 0} tone="#2dd4bf" />
                </div>
              ))}
            </div>
            {/* ⛔ Internal and unreported traffic is stated, not dropped.
                Excluded silently, the ranking above would read as the whole
                picture while covering a fraction of it. */}
            <div style={{ marginTop: 8, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
              Excludes {internal.toLocaleString()} internal event
              {internal === 1 ? '' : 's'} (private address space, which both vendors
              label rather than geolocate)
              {unreported > 0
                ? `, and ${unreported.toLocaleString()} with no country reported.`
                : '.'}
            </div>
          </>
        )}
      </CardBody>
    </Card>
  );
}

export async function TopUsersWidget() {
  const { users, coveragePct, attributed } = await getTopUsers(pool, 24, 8);
  const max = users.reduce((n, u) => Math.max(n, u.events), 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle style={titleStyle}>
          <IconChip icon={IconUser} color="#818cf8" bg="rgba(129,140,248,0.20)" />
          Top Users (24h)
        </CardTitle>
      </CardHeader>
      <CardBody>
        {users.length === 0 ? (
          <Empty>
            No traffic could be attributed to a user. Identity comes from PAN-OS
            User-ID or an authenticated FortiOS session — without one of those the
            firewall reports no username, and SecVault does not guess one.
          </Empty>
        ) : (
          <>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
              {users.map((u) => (
                <div key={u.user}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 2 }}>
                    <span style={rowLabel}>
                      <Link
                        href={logsHref({ srcUser: u.user, limit: '250' })}
                        style={{ color: 'var(--text-primary)' }}
                      >
                        {u.user}
                      </Link>
                      {u.denied > 0 ? (
                        <span style={{ marginLeft: 6, fontSize: 'var(--text-sm)', color: 'var(--red)' }}>
                          {u.denied.toLocaleString()} denied
                        </span>
                      ) : null}
                    </span>
                    <span style={{ fontSize: 'var(--text-base)' }}><Num value={u.events} /></span>
                  </div>
                  <Bar pct={max > 0 ? (u.events / max) * 100 : 0} tone="#818cf8" />
                </div>
              ))}
            </div>
            {/* ⛔ Coverage is stated. A top-users chart that does not say what
                share of traffic it can attribute invites the reader to assume
                the listed users are the only ones active. */}
            <div style={{ marginTop: 8, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
              {coveragePct === null
                ? 'No traffic in this window to attribute.'
                : `Covers ${coveragePct}% of events (${attributed.toLocaleString()} with an identified user). ` +
                  'The rest carried no username from the firewall.'}
            </div>
          </>
        )}
      </CardBody>
    </Card>
  );
}

export async function UrlCategoriesWidget() {
  const rows = await getTopUrlCategories(pool, 24, 10);
  const max = rows.reduce((n, r) => Math.max(n, r.events), 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle style={titleStyle}>
          <IconChip icon={IconGrid} color="#f472b6" bg="rgba(244,114,182,0.20)" />
          Web / Application Categories (24h)
        </CardTitle>
      </CardHeader>
      <CardBody>
        {rows.length === 0 ? (
          <Empty>
            No categorised traffic. Categories come from the firewall&apos;s URL-filtering
            and application-control engines.
          </Empty>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
            {rows.map((r) => (
              <div key={r.category}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 2 }}>
                  <span style={rowLabel}>
                    <Link
                      href={logsHref({ urlCategory: r.category, limit: '250' })}
                      style={{ color: 'var(--text-primary)' }}
                    >
                      {r.category}
                    </Link>
                    {r.denied > 0 ? (
                      <span style={{ marginLeft: 6, fontSize: 'var(--text-sm)', color: 'var(--red)' }}>
                        {r.denied.toLocaleString()} blocked
                      </span>
                    ) : null}
                  </span>
                  <span style={{ fontSize: 'var(--text-base)' }}><Num value={r.events} /></span>
                </div>
                <Bar pct={max > 0 ? (r.events / max) * 100 : 0} tone="#f472b6" />
              </div>
            ))}
          </div>
        )}
      </CardBody>
    </Card>
  );
}
