import { pool } from '../../lib/db';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import IconChip from '../ui/IconChip';
import { IconDevices, IconChart, IconActivity, IconShield, IconGrid } from '../icons';
import { getServerHealth, diskState, BYTES_IN_GB } from '../../lib/serverHealth';

export const dynamic = 'force-dynamic';

// The health of the SERVER, not of the firewalls.
//
// ⛔ EVERY FIGURE IS NULLABLE AND NULL RENDERS AS AN EM-DASH, NEVER ZERO. On
// this tab that rule is not cosmetic: "0 GB free" is an emergency and "we could
// not read the volume" is a gap in our own instrumentation, and the two must
// never look alike. Same reason `hit_count` is tri-state.

const titleStyle = { display: 'flex', alignItems: 'center', gap: 8 };

function gb(bytes) {
  if (bytes === null || bytes === undefined || !Number.isFinite(Number(bytes))) {
    return <span style={{ color: 'var(--unmeasured)' }}>—</span>;
  }
  const v = Number(bytes) / BYTES_IN_GB;
  // Below a gigabyte, "0.0 GB" is indistinguishable from nothing at all.
  if (v < 1) return <>{Math.max(1, Math.round(Number(bytes) / (1024 ** 2)))} MB</>;
  return <>{v >= 100 ? v.toFixed(0) : v.toFixed(1)} GB</>;
}

function num(v) {
  if (v === null || v === undefined || !Number.isFinite(Number(v))) {
    return <span style={{ color: 'var(--unmeasured)' }}>—</span>;
  }
  return <>{Number(v).toLocaleString()}</>;
}

function ago(seconds) {
  if (seconds === null || seconds === undefined) return <span style={{ color: 'var(--unmeasured)' }}>never</span>;
  if (seconds < 90) return <>{seconds}s ago</>;
  if (seconds < 5400) return <>{Math.round(seconds / 60)} min ago</>;
  return <>{Math.round(seconds / 3600)}h ago</>;
}

function Panel({ icon, tint, tintBg, title, children }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle style={titleStyle}>
          <IconChip icon={icon} color={tint} bg={tintBg} />
          {title}
        </CardTitle>
      </CardHeader>
      <CardBody>{children}</CardBody>
    </Card>
  );
}

const STATE_COLOR = { ok: 'var(--green)', warning: 'var(--yellow)', critical: 'var(--red)' };

function Row({ label, value, sub }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, padding: '5px 0' }}>
      <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
        {label}
        {sub ? (
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{sub}</div>
        ) : null}
      </span>
      <span style={{ fontSize: 'var(--text-sm)', fontWeight: 600, textAlign: 'right' }}>{value}</span>
    </div>
  );
}

export default async function ServerHealthWidgets() {
  const h = await getServerHealth(pool);

  return (
    <>
      <Panel icon={IconDevices} tint="var(--tint-info-fg)" tintBg="var(--tint-info)" title="Disk">
        {h.disks.map((d) => {
          const state = diskState(d);
          return (
            <div key={d.volume} style={{ marginBottom: 'var(--s4)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 4 }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{d.volume}</span>
                <span style={{ fontSize: 'var(--text-sm)' }}>
                  {gb(d.freeBytes)} free of {gb(d.totalBytes)}
                </span>
              </div>
              {/* ⛔ NO BAR WHEN THERE IS NO MEASUREMENT. A zero-width bar reads
                  as an empty disk and a full-width one as a full disk; both are
                  claims we cannot make. The hatch is this product's hueless
                  not-measured state. */}
              {d.totalBytes === null ? (
                <div
                  style={{
                    height: 8, borderRadius: 4, background: 'var(--hatch)',
                    border: '1px dashed var(--border)',
                  }}
                  title="not measured"
                />
              ) : (
                <div style={{ height: 8, background: 'var(--surface-subtle)', borderRadius: 4, overflow: 'hidden' }}>
                  <div
                    style={{
                      width: `${Math.min(100, Math.max(1, d.usedPct))}%`,
                      height: '100%',
                      background: STATE_COLOR[state] || 'var(--unmeasured)',
                    }}
                  />
                </div>
              )}
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 3 }}>
                {d.error ? (
                  <span style={{ color: 'var(--yellow)' }}>not measured — {d.error}</span>
                ) : (
                  <>{d.usedPct}% used · {d.roles.join(', ')}</>
                )}
              </div>
            </div>
          );
        })}
        {/* ⛔ SAYS WHAT WAS MEASURED, NOT WHAT WE WISH WE KNEW. The PostgreSQL
            data directory cannot be read by the application's database role
            (SHOW data_directory is superuser-only), so it is never claimed to be
            covered — it is only covered when it happens to share a volume with a
            path listed above. */}
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 'var(--s3)', lineHeight: 1.6 }}>
          Volumes are measured from the directories SecVault writes to. The PostgreSQL data
          directory is not listed separately — the database role cannot read its location — so it is
          only represented here when it shares a volume with one of these paths.
        </div>
      </Panel>

      <Panel icon={IconChart} tint="var(--tint-purple-fg)" tintBg="var(--tint-purple)" title="Database">
        <div style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, marginBottom: 'var(--s3)' }}>
          {gb(h.database.totalBytes)}
        </div>
        {h.database.error ? (
          <div style={{ color: 'var(--yellow)', fontSize: 'var(--text-sm)' }}>
            not measured — {h.database.error}
          </div>
        ) : null}
        {h.database.tablesError ? (
          <div style={{ color: 'var(--yellow)', fontSize: 'var(--text-sm)' }}>
            Largest relations not measured — {h.database.tablesError}
          </div>
        ) : null}
        {(h.database.tables || []).slice(0, 5).map((t) => (
          <Row key={t.name} label={<span style={{ fontFamily: 'var(--font-mono)' }}>{t.name}</span>} value={gb(t.bytes)} />
        ))}
        {/* A FAILED READ IS NOT AN ALL-CLEAR. This block used to render only when
            the array was non-empty, and the array was [] on failure — so a
            permission-denied pg_stat_user_tables was pixel-identical to "no table
            has significant dead tuples". */}
        {h.database.deadTuplesError ? (
          <div style={{ color: 'var(--yellow)', fontSize: 'var(--text-sm)', marginTop: 'var(--s3)' }}>
            Dead-tuple pressure not measured — {h.database.deadTuplesError}
          </div>
        ) : null}
        {h.database.deadTuples && h.database.deadTuples.length > 0 ? (
          <div style={{ marginTop: 'var(--s3)', paddingTop: 'var(--s3)', borderTop: '1px solid var(--border)' }}>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 4 }}>
              {/* ⛔ Dead tuples are a real signal on this product, not trivia: a
                  backfill once rewrote 302 advisory rows to identical values on
                  every deploy and left that table 18.6% dead. */}
              Dead tuples — space held by deleted or updated rows, reclaimed by autovacuum
            </div>
            {(h.database.deadTuples || []).map((t) => (
              <Row
                key={t.name}
                label={<span style={{ fontFamily: 'var(--font-mono)' }}>{t.name}</span>}
                value={<>{num(t.dead)} {t.pct !== null ? <span style={{ color: 'var(--text-muted)' }}>({t.pct}%)</span> : null}</>}
              />
            ))}
          </div>
        ) : null}
      </Panel>

      <Panel icon={IconGrid} tint="var(--tint-teal-fg)" tintBg="var(--tint-teal)" title="Raw syslog retention">
        {h.retention.error ? (
          <div style={{ color: 'var(--yellow)', fontSize: 'var(--text-sm)', marginBottom: 'var(--s3)' }}>
            Partition catalogue not measured — {h.retention.error}
          </div>
        ) : null}
        <Row label="Daily partitions" value={num(h.retention.partitions)} />
        <Row label="Oldest day retained" value={h.retention.oldestDay || <span style={{ color: 'var(--unmeasured)' }}>—</span>} />
        <Row label="Newest day" value={h.retention.newestDay || <span style={{ color: 'var(--unmeasured)' }}>—</span>} />
        <Row label="Raw event storage" value={gb(h.retention.bytes)} />
        <Row
          label="Configured retention"
          value={h.retention.retentionDays ? <>{h.retention.retentionDays} days</> : <span style={{ color: 'var(--unmeasured)' }}>—</span>}
          sub="SYSLOG_RETENTION_DAYS"
        />
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 'var(--s3)', lineHeight: 1.6 }}>
          {/* ⛔ Counted from the partitions, never from a row count: SELECT
              count(*) over this table is a full scan of ~28M rows per day. */}
          Counted from the partition catalogue, not by counting rows. Raw events age out by dropping
          a whole partition, which is why this figure moves in day-sized steps.
        </div>
      </Panel>

      <Panel icon={IconActivity} tint="var(--tint-warn-fg)" tintBg="var(--tint-warn)" title={`Ingest (last ${h.ingest.windowMinutes} min)`}>
        {/* THE PANEL WHOSE JOB IS TO SAY INGEST IS BROKEN MUST SAY SO. Its error
            was never rendered at all, and because the error shape omitted
            `flushes`, the "no flushes recorded" banner below was ALSO suppressed
            (undefined === 0 is false) — so a database failure produced five
            em-dashes and no explanation whatsoever. */}
        {h.ingest.error ? (
          <div style={{ color: 'var(--yellow)', fontSize: 'var(--text-sm)', marginBottom: 'var(--s3)' }}>
            Ingest statistics could not be read — {h.ingest.error}. These figures are NOT MEASURED,
            not zero.
          </div>
        ) : null}
        <Row label="Events received" value={num(h.ingest.received)} />
        <Row label="Rate" value={h.ingest.eventsPerSec === null ? num(null) : <>{num(h.ingest.eventsPerSec)}/sec</>} />
        <Row
          label="Dropped"
          value={
            <span style={{ color: h.ingest.dropped > 0 ? 'var(--red)' : undefined }}>
              {num(h.ingest.dropped)}
            </span>
          }
          sub="overflow is counted, never hidden"
        />
        <Row
          label="Spool backlog"
          value={
            <span style={{ color: h.ingest.backlog > 0 ? 'var(--yellow)' : undefined }}>
              {num(h.ingest.backlog)}
            </span>
          }
          sub="files written but not yet inserted"
        />
        <Row label="Flushes in window" value={num(h.ingest.flushes)} />
        {h.ingest.flushes === 0 ? (
          /* ⛔ NO FLUSHES IS NOT ZERO DROPS. An absent collector would otherwise
             render as a clean ingest — the most reassuring possible way to show
             that nothing is being collected at all. */
          <div style={{ color: 'var(--yellow)', fontSize: 'var(--text-sm)', marginTop: 'var(--s3)' }}>
            The collector recorded no flushes in this window, so these figures are NOT MEASURED
            rather than zero. Check that SecVault-Collector is running.
          </div>
        ) : null}
      </Panel>

      <Panel icon={IconShield} tint="var(--tint-success-fg)" tintBg="var(--tint-success)" title="Services">
        {/* ⛔ INFERRED FROM WHAT EACH SERVICE WRITES, not from sc.exe. NSSM
            reports a crash-looping process as Running, so the service state
            would be LESS truthful than the evidence — and asking Windows would
            mean spawning a process from a web request. */}
        <Row label="App (this page)" value={<span style={{ color: 'var(--green)' }}>responding</span>} sub={`node ${h.process.nodeVersion}, up ${Math.round(h.process.uptimeSeconds / 60)} min`} />
        {h.services.map((s) => (
          <Row
            key={s.name}
            label={s.name}
            // "NEVER" IS A FACT; A FAILED READ IS NOT. Both produced ageSeconds
            // null and the value column printed "never" for both - asserting, on
            // the panel that decides whether the engine is alive, something
            // manufactured from a read that did not happen.
            value={
              s.error
                ? <span style={{ color: 'var(--unmeasured)' }}>not measured</span>
                : <span style={{ color: s.ageSeconds === null ? 'var(--unmeasured)' : undefined }}>{ago(s.ageSeconds)}</span>
            }
            sub={s.error ? `could not read its table — ${s.error}` : 'last write to its own tables'}
          />
        ))}
        <Row label="App memory (RSS)" value={gb(h.process.rssBytes)} />
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 'var(--s3)', lineHeight: 1.6 }}>
          Liveness is inferred from each service&apos;s own most recent database write, not from the
          Windows service state — a crash-looping process still reports as Running.
        </div>
      </Panel>
    </>
  );
}
