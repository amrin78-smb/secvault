import { getServerSession } from 'next-auth';
import { authOptions } from '../../api/auth/[...nextauth]/route';
import { can, roleOf, VIEW_LOG_SEARCH } from '../../../lib/rbac';
import NoAccess from '../../../components/ui/NoAccess';
import PageHeader from '../../../components/ui/PageHeader';
import LogSearchForm from '../../../components/logs/LogSearchForm';
import LogResults from '../../../components/logs/LogResults';
import { pool } from '../../../lib/db';
import { searchEvents, getFilterOptions, MAX_WINDOW_DAYS } from '../../../lib/syslog/logSearch';

export const dynamic = 'force-dynamic';

// Raw log search — the forensic view. This is the capability ManageEngine
// Firewall Analyzer was the tool of record for, and the single largest gap
// found in the decommission review: before this page, "what did 10.248.65.4 do
// at 03:00 last Tuesday" had no answer anywhere in SecVault.
//
// Server-rendered from the URL's own query string, so a search is linkable,
// pasteable into a ticket, and survives a refresh. Only ONE filter is ever
// implicit: the time window, which is mandatory and bounded server-side
// (lib/syslog/logSearch.js explains why an unbounded search here would be an
// outage for the ingest rather than a slow page).

function first(v) {
  return Array.isArray(v) ? v[0] : v;
}

// ⛔ A CAPABILITY-GATED READ, which is new in this codebase. Every other GET
// in this app is ungated, on the documented principle that read access is not
// where the risk is. Raw log search is the deliberate exception: it returns
// unredacted syslog, which carries usernames, internal addresses and URLs —
// the most personally identifying data SecVault holds. The Operator role does
// not include it.
//
// ⛔ The guard is HERE, not only in the sidebar. Hiding the nav entry stops
// discovery; it does nothing about a bookmark, a pasted link, or a URL typed
// from memory.
export default async function LogsPage({ searchParams }) {
  const session = await getServerSession(authOptions);
  if (!can(session, VIEW_LOG_SEARCH)) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <PageHeader title="Log search" />
        <NoAccess
          role={roleOf(session)}
          what="Log search"
          detail="Raw log search returns unredacted syslog, including usernames, internal addresses and visited URLs. It is limited to Admin and Super Admin."
        />
      </div>
    );
  }
  const sp = searchParams || {};
  const params = {};
  for (const k of [
    'from', 'to', 'limit', 'deviceId', 'vendor', 'action', 'logClass', 'logSubtype',
    'protocol', 'application', 'ruleName', 'srcUser', 'srcCountry', 'dstCountry',
    'threatName', 'urlCategory', 'urlHostname', 'sourceIp', 'srcIp', 'dstIp',
    'authOutcome',
    'srcPort', 'dstPort', 'q', 'page',
  ]) {
    const v = first(sp[k]);
    if (v !== undefined && v !== null && String(v) !== '') params[k] = String(v);
  }

  // Filter dropdowns are populated from what this fleet ACTUALLY sends rather
  // than a hardcoded list, so an action or class no device produces never
  // appears as a choice that silently returns nothing.
  let devices = [];
  let options = { vendors: [], actions: [], logClasses: [] };
  try {
    const [d, o] = await Promise.all([
      pool.query('SELECT id, name FROM devices WHERE active ORDER BY name'),
      getFilterOptions(pool, 24),
    ]);
    devices = d.rows;
    options = o;
  } catch {
    // A failed lookup degrades the dropdowns to free text; it must not stop
    // the search itself from working.
  }

  const deviceNames = {};
  for (const d of devices) deviceNames[d.id] = d.name;

  // Only run a search once the operator has actually asked for one. Landing on
  // /logs with no parameters shows the form, not an arbitrary slice of the
  // last hour presented as if it were a result.
  const hasQuery = Object.keys(params).length > 0;
  let result = null;
  if (hasQuery) {
    try {
      result = await searchEvents(pool, params);
    } catch (err) {
      result = { error: err.message };
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <PageHeader
        title="Log search"
        subtitle={
          `Search raw firewall logs for investigation. Raw events are kept for a ` +
          `few days; searches are limited to ${MAX_WINDOW_DAYS} days and always ` +
          `cover a bounded time window.`
        }
      />
      <LogSearchForm params={params} devices={devices} options={options} />
      {hasQuery ? (
        <LogResults result={result} deviceNames={deviceNames} searchParams={params} />
      ) : (
        <div style={{ fontSize: 'var(--text-base)', color: 'var(--text-muted)', padding: '4px 2px' }}>
          Choose a filter and search. With nothing set, the window defaults to the last hour.
        </div>
      )}
    </div>
  );
}
