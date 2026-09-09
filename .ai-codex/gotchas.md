# gotchas.md — Footguns a fresh session would get wrong

One line each. Distilled from CLAUDE.md's extensive documented incident history, cross-checked
against current code. This is NOT a substitute for CLAUDE.md — it's a fast pre-check; if you're
about to touch something listed here, go read the full CLAUDE.md section before acting.

## React / UI
- Never define a React component inside another component's function body — full remount on every
  keystroke, loses input focus. Verified clean as of 2026-07-23 (see components.md's Violations
  section) — re-check this every time you add a new component.
- **`var(--primary)`/`var(--red)` is NOT the default link color for identity/navigation links**
  (device names, CVE IDs, rule names) — as of the 2026-07-23 UI audit, use `className="link-quiet"`
  (globals.css) instead: plain `--text-primary` at rest, `--primary` + underline only on hover.
  Red/primary as a resting link color dilutes red's meaning as a genuine severity signal elsewhere
  on the same page — reserve it for real danger/critical states, brand buttons, and the active-nav
  accent bar. Breadcrumbs, "Back to X"/"View all →" action-prose links, and badges/pills were
  deliberately left alone in that pass (not considered "identity links") — don't retroactively
  "fix" those without a reason.
- If you set an inline `style={{ color: 'inherit' }}` (or any resting color) on the SAME element as
  a CSS class with a `:hover` rule (like `.link-quiet`), the inline style still wins for the RESTING
  state (inline beats an external class at equal/lower specificity) — but the class's `:hover` rule
  still applies on hover, since inline styles have no way to express pseudo-classes. Net effect: the
  hover color still works, but the resting color silently stays whatever the inline style said,
  which is very easy to miss when applying `.link-quiet` to an element that has its own inline
  `color`/`linkCellStyle`-style spread — check for and remove any inline resting-color override,
  don't just add the className alongside it. (Confirmed live during the 2026-07-23 audit fix in
  `components/cve/CVETable.js`.)
- A count that CAN legitimately be zero and represents "how many bad things exist" (Patch Now,
  Critical findings, etc.) should render zero in `var(--text-muted)`, not the severity color — the
  severity color should only appear once the count is actually non-zero. Don't apply this to a
  count where zero isn't inherently good (a total count, a "Denied Rules"/"NAT Enabled" count, a
  category/vendor-distribution count) — those keep their fixed color regardless of value.
- `tableLayout: 'fixed'` is required with percentage column widths, or columns collapse
  unpredictably on overflow. `components/ui/Table.js` already enforces this internally.
- `tableLayout: 'fixed'` only fixes column WIDTHS — it does NOT clip overflowing cell content on its
  own. Found live 2026-07-23: `app/globals.css`'s base `td` rule has `overflow: hidden; text-overflow:
  ellipsis;` but the base `th` rule never did (`white-space: nowrap` only) — a `<colgroup>` column
  narrower than its header text (the Rules table's `rules/page.js` had Schedule at 3% and Hits at 2%)
  rendered the header text spilling visibly into the NEXT column's header ("SCHEDULE"+"LOG" merging
  into "SCHEDULLOG"), not truncating. Fixed globally by adding `overflow: hidden; text-overflow:
  ellipsis;` to the base `th` rule (matching `td`) — every other table in the app already uses ≥6%
  columns and was unaffected; only `rules/page.js`'s colgroup also needed rebalancing (Schedule
  3%→6%, Hits 2%→4%, borrowed from the wider address/comment columns) since 2-3% is too narrow to
  show anything useful even once clipped. When adding a new narrow `<col>` percentage, sanity-check
  it can fit its header's shortest reasonable ellipsis form, not just that the percentages sum to 100.
- A CSS Grid item's default `min-width: auto` lets one pathologically long unbroken string (e.g. a
  corrupted config-diff summary) blow an entire grid column to tens of thousands of px, pushing
  siblings off-screen. `.dashboard-widget-grid > * { min-width: 0; }` fixes this generically —
  don't re-litigate per-widget.
- Settings page uses client-side `useState` for its active tab, NOT the `?tab=` query-param
  server-driven pattern every other tabbed page in this app uses — deliberate, copied from
  netvault's own Settings page. Don't "fix" this to match the other pages.

## The shell is dark in BOTH themes, so `--tint-*-fg` is wrong on it (2026-09-09)

The header and sidebar use `--navy` in light mode and in dark mode. Everything else in the app sits
on `--bg-card`/`--bg-primary`, which flip.

⛔ So the usual rule — "any tinted surface behind text uses a `--tint-*`/`--tint-*-fg` pair" — is
**inverted on the shell**. A `-fg` token flips with the theme; on a bar that does not flip, the
light-mode value is a dark colour on a dark ground, i.e. invisible. This is easy to introduce and
hard to notice, because whoever adds it is almost certainly looking at dark mode at the time.

Text and icons drawn on `--navy` use `--shell-fg`, `--shell-fg-ok`, `--shell-fg-bad`, which are
defined once on `:root` and are NOT redefined in the dark block. `components/layout/Header.js`'s
sync pill is the reference case: it previously hardcoded `#86efac`/`#fca5a5` for exactly this
reason, and the hardcoding was correct in effect even though it bypassed the token layer.

Related, same file: `.sv-nav a.active .sv-nav-chip` is now always the brand accent. Each nav entry
used to carry its own hue, but only the ACTIVE chip was ever coloured, so the "you are here" signal
was a different colour on every page — and on `/vulnerability` it was a red sitting beside severity
badges that use red to mean critically exposed. ⛔ The per-item wayfinding cue is the GLYPH, and
every sidebar entry must keep a distinct one; the old comments in `Sidebar.js` claimed the colour
was that cue, which was never true.

## Services / process model
- NEVER use PowerShell service cmdlets (`Start-Service`/`Stop-Service`/`Get-Service` for
  state-changing calls) — they silently disconnect WinRM sessions. Use `sc.exe`. Read-only
  `Get-Service ... .Status` polling is fine, the state-CHANGING cmdlets are the actual rule.
- NEVER `npm install` in any script — always `npm ci`.
- `SecVault-Engine` (NSSM service) runs as `LocalSystem`, not a logged-in AD user — a firewall rule
  scoped to a user/group (User-ID mapping on an NGFW) will not match its outbound traffic even if
  the host/port part of the rule is correct. Relevant if diagnosing "we opened the firewall but it's
  still blocked" for anything the engine process calls out to.
- `AppEnvironmentExtra` path casing in NSSM must match the actual filesystem case exactly — wrong
  casing causes duplicate React instances and silent rendering failures.
- Never point NSSM `AppParameters` at `node_modules\.bin\next` — that's npm's POSIX shell wrapper,
  not JS; `node` crashes trying to parse it, `sc.exe start` still reports success. Use
  `node_modules\next\dist\bin\next` instead.
- `analyzeRules()`'s O(n²) pairwise loop yields to the event loop every 25 iterations
  (`yieldToEventLoop`) so Collect Now doesn't freeze the whole app — but this REOPENED a
  concurrency race between two independent callers of `runAnalysisForDevice()` for the same device;
  fixed with `pg_advisory_xact_lock(hashtext(device_id))`. A future "make this faster/more async"
  change to any DELETE+reinsert engine needs the same lock, not just a naive await.

## Deploy / update pipeline
- `core.sshCommand` (used by the in-app updater's git transport) is ALWAYS shell-interpreted by
  git's own bundled MSYS2 shell, regardless of which account invokes git or which ssh binary is
  named. Any Windows path fed into it MUST use forward slashes — a bare backslash silently
  vanishes before ssh ever sees it. Don't debug this by testing `ssh -v` interactively — that
  bypasses the shell-interpretation layer entirely and will look fixed when it isn't.
- The SSH deploy key needs to exist at a MACHINE-WIDE path
  (`C:\ProgramData\SecVault\ssh\secvault_deploy`), not just an interactive admin's own profile —
  the in-app "Update Now" button runs as a SYSTEM-scheduled task with a different profile/PATH than
  whoever ran `Install-SecVault.ps1` interactively.
- `Update-SecVault.ps1` gates `sc.exe start SecVault-App` on BOTH `npm run build` succeeding AND
  `node lib\migrate.js` succeeding — never let the app restart against a broken build or an
  incomplete schema migration.
- A bare `CREATE INDEX`/`ALTER TABLE` in `schema.sql` for a column that only a JS migration adds
  (not `schema.sql`'s own `CREATE TABLE` body) breaks every upgrading server, because `schema.sql`
  always runs before any JS migration in `migrate.js`'s `main()`. Any DDL for a JS-migration-added
  column belongs IN that JS migration, issued after the column-adding step, never in `schema.sql`.
- Windows Server tool paths are fixed, not on `PATH` by default: `psql.exe` at
  `C:\Program Files\PostgreSQL\16\bin\psql.exe`, `git.exe` at `C:\Program Files\Git\cmd\git.exe`,
  `nssm.exe` at `C:\Windows\System32\nssm.exe`. PowerShell script paths must use `\`, not `/`.
- `psql` invoked from PowerShell/WinRM can return exit code `-1` even when the command actually
  succeeded (output went to stderr, not a real failure) — accept `-1` as success for schema
  migration steps. Set `$env:PGPASSWORD` before calling `psql` for unattended execution.

## Syslog archive (lib/syslog/archive.js)

⛔ **The archive is CONCATENATED GZIP MEMBERS — one per flush — and not every reader handles that.**
The gzip spec defines a stream as a *sequence* of members, so appending independent members keeps
the file valid. GNU `gunzip`/`zcat`/`zgrep` and Node's `zlib.gunzipSync` read all of them.
**.NET Framework's `System.IO.Compression.GZipStream` reads only the FIRST member and stops** —
which is what PowerShell 5.1 gives you. Verifying a 15.5 MB archive with PowerShell returned 1,146
lines and a "0.1x ratio"; the same file through Node returned 231,567 lines and 11.1x. The archive
was correct and the *verifier* was wrong, which is the dangerous shape of this bug: it reports
catastrophic data loss that has not happened, and would just as happily hide real loss.
Use `node -e` or GNU tools to read these files. .NET Core 3.0+ handles multi-member; Framework 4.x does not.

⛔ **Archiving happens BEFORE the DB insert**, while the spool file is still on disk. So the archive
legitimately runs slightly AHEAD of the database (measured 0.33% — the in-flight flush), never
behind. When checking completeness, archive-ahead-of-DB is correct and DB-ahead-of-archive is a bug.

⛔ **PostgreSQL does not compress `message` and cannot be made to compete here.** Measured: 748 bytes
of text stored in 752 bytes. TOAST only compresses once a tuple exceeds ~2 KB and these rows are
~1 KB. Even forced, per-row compression is 2-3x, because the 11x comes from compressing ACROSS
lines. This is why the archive is a file and not a column.

## `node --check` does NOT validate JSX (found 2026-09-08)

⛔ `node --check` exits **0** on a component containing broken JSX. Verified: appending
`export function Broken() { return <div><span>oops</div>; }` to `components/ui/Badge.js` still
passes. It parses the file as ESM and never reaches the JSX, so an unclosed tag, a stray brace
inside a `{...}` expression, or a mismatched fragment all sail through.

CLAUDE.md's pre-commit checklist is CORRECT as written — it scopes `node --check` to
`lib/**`, `services/**` and `app/api/**`, which are non-JSX. ⛔ **Do not widen that glob to
`components/**` or `app/(dashboard)/**` thinking it adds a check.** It would add only a false
green. For those files the real gate is `npm run build`.

Confusingly, `node --check` DOES catch some errors in the same files — an unclosed *paren*
breaks the CommonJS fallback parse and is reported. So it fails loudly on some corruption and
silently on JSX corruption, which is worse than failing consistently: it looks like a working
check. A JSX-aware alternative is `next/dist/build/swc`'s `parse(src, {filename, syntax:
'ecmascript', jsx: true, isModule: true})`, which does catch it. **As of 2026-09-09 that alternative is wired up as `tests/jsxSyntax.test.js`**, which parses every .js file in the repo in ~1.5s and is verified to catch exactly the case above. So `npm test` now covers JSX syntax and `npm run build` is no longer the only gate — which matters most when several agents are editing JSX in parallel and a build cannot safely run.

## A wrong COLUMN NAME passes every gate (found 2026-09-09, production down)

⛔ The dashboard home page (`/`) returned "Application error: a server-side exception has
occurred", digest `539791548`, **for every user on every load**, from the moment the
feed-freshness strip landed until v2.86.1. Cause:

```
error: column "completed_at" does not exist   (SQLSTATE 42703)
  at .next/server/app/(dashboard)/page.js
```

`feed_sync_log`'s column is `finished_at`; it has never been called `completed_at`. The same
wrong name was in `lib/formatDisplay.js`'s `newestFeedAt()`.

**Why nothing caught it — all three gates are structurally blind to it:**

| gate | why it passed |
|---|---|
| `node --check` | a SQL string is an opaque string literal to the JS parser |
| `npm test` | the engine tests take STUB pools; nothing here touches a schema |
| `npm run build` | a `force-dynamic` page's query is never executed at build time |

So the only real gate was loading the page — and the page that broke is the one route you never
click while verifying a feature, because you are already sitting on it. ⛔ **After any change
that adds or edits SQL, load the actual page, including `/`.** A wrong column name is the
cheapest available way to take this app down.

`tests/sqlColumns.test.js` now checks every SQL identifier in the repo against `lib/schema.sql`
(no DB — it parses the same file `lib/migrate.js` runs). It was verified to catch this exact
bug by re-injecting it. Two parsing details that matter if you touch it: a partitioned table
ends `) PARTITION BY RANGE (received_at);`, so the CREATE TABLE terminator is `\n)` + anything
+ `;` — the stricter `\n);` silently swallows the NEXT table's columns into `syslog_events`;
and a column added by `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` is not in any CREATE body, so
the ALTERs are parsed too.

A one-off audit against the LIVE database at the time of the fix found no other bad column name
anywhere in the repo — the 51 other flagged identifiers were all table aliases (`dca`, `rar`,
`caa`), the `xmax` system column, and one temp table.

## PAN-OS positional indices differ per SUBTYPE, not just per TYPE (2026-09-08)

⛔ CLAUDE.md warns that PAN-OS CSV positions differ per log TYPE. They also differ in MEANING per
THREAT SUBTYPE, and that cost real signal for a day.

`PAN_THREAT.threatName` was mapped to index **33**, which is the CATEGORY. The signature name is
index **32**. The map had been "verified" against a URL-FILTERING row, where index 32 is a bare
`(9999)` placeholder and 33 (`block-Deny Web-O365`) looked like a plausible name — both readings
fit that one subtype. On a real IPS row they do not: index 32 held
`Phishing:bailliede.ru(109010001)` and `ISF SNMP Authentication Attempt(96504)` while 33 held
`any`.

**The cost:** every phishing, malware and cryptomining detection on the fleet was stored as its URL
category, so Top Threats showed `any` where it should have named the malware. Nothing errored.

⛔ Two follow-on rules from the same investigation:
- A bare `(9999)` names nothing and must resolve to NULL, or it becomes the most common "threat
  name" on the fleet.
- Index 30 is the ACTION on threat rows too, not only traffic rows. It was gated on `isTraffic`,
  leaving every threat row with `action = null` — so the dashboards could not distinguish a threat
  that was BLOCKED (`drop`) from one merely OBSERVED (`alert`).

**Lesson:** one captured sample of one subtype cannot validate a positional map. Both a
url-filtering row AND a real IPS row are now fixtures in `tests/vendorFields.test.js`.

## A range-based text edit silently deletes whatever sits inside the range (2026-09-09)

⛔ The v2.88.0 chart-grammar merge collapsed two modules by cutting text BETWEEN TWO MARKERS
(`cut(src, 'export const TOOLTIP_SURFACE', '// Hover affordance')`). A constant that happened to
live inside one of those ranges — `TOOLTIP_LABEL_STYLE` — went with it, and the dashboard threw

```
ReferenceError: TOOLTIP_LABEL_STYLE is not defined
```

the moment a chart tooltip rendered on `/?tab=security`.

**Every static gate passed.** `npm run build` compiled cleanly, `jsxSyntax.test.js` parsed every
file, `importIntegrity.test.js` was satisfied, `sqlColumns.test.js` was satisfied. A reference to a
deleted MODULE-SCOPE identifier inside a component body is invisible to all of them, because it is
only evaluated when that component actually renders. Same shape as the `completed_at` outage the
same day: a wrong column name is invisible until the query runs.

⛔ **Prefer replacing an exact known block over cutting a range.** A range edit cannot tell you what
it removed. If a range really is necessary, print or diff the removed text and read it.

⛔ **A general "no-undef" lint was attempted and DELIBERATELY NOT SHIPPED.** A narrow version keyed
on SCREAMING_SNAKE identifiers in code positions produced **187 false positives** across the repo —
acronyms in JSX prose (`CVSS`, `NAT`, `PCI_DSS`), plus real corruption from trying to strip JSX text
with a `>...<` range (in a plain `.js` file `>` and `<` are operators, so that strip deletes code and
invents undefined names). A lint that noisy gets switched off, which costs more than the coverage it
buys. Doing it properly needs real scope analysis over the swc AST, which is ESLint's job. Until
then the gate for this class is **loading the page**.

The one-off scanner used to find the damage is worth re-creating ad hoc after any shared-module
refactor: strip comments and strings, collect `const|let|var|function|class NAME` plus imports and
destructures, then report SCREAMING_SNAKE names used in `={NAME}` / `...NAME` / `NAME.` positions
that are not declared. Run it over the changed files only — repo-wide it is unusable.

## A parser that speculatively probes can misdiagnose its own input (2026-09-09)

⛔ `app-error.log` carried 253 instances of

```
[cidrUtils] "24" looks like an IPv4 literal/CIDR but failed to parse ...
[cidrUtils] "1"  ... same
```

The obvious reading — single digits reaching an IPv4 parser means something upstream is SPLITTING an
address into fragments — was wrong, and cost time. Nothing upstream fragments anything.

`objectResolver.resolveAddressEntry()` deliberately tries a literal parse BEFORE falling back to an
object-name lookup. `parseIpRange()` splits any value on the first `-` and probes both halves. Palo
Alto address OBJECT NAMES routinely contain dashes — `SERVER-24`, `WIFI-23`, `PAM-1`,
`172.16.12.0-24` — so the half `24` reached the warning path, and `IP_SHAPED` used `(\.[0-9]+)*`,
which allows ZERO dots. A bare integer was therefore judged "a malformed IP" instead of "not an IP".

⛔ **No comparison was ever skipped, and that was PROVEN rather than argued**: resolution output over
all 1,716 rules of all 16 devices hashed identically before and after the fix, warnings 253 -> 0.
Those names resolve one step later through the object lookup.

Two separate changes, and keeping them separate matters:
1. **The cause** — `parseIpRange()` parses its halves with a silent core and judges shapedness on the
   WHOLE string. A genuinely malformed range still warns, once, naming the whole value.
2. **Belt and braces, separately justified** — `IP_SHAPED` now requires at least one dot. A lone `24`
   is not an IPv4 literal by any reading. ⛔ This narrows WHAT WARNS, never what parses; the strict
   4-octet validation is untouched.

⛔ The general lesson: when a parser is used as a TEST ("is this thing an IP?") rather than as a
converter ("turn this into an IP"), a failure is an ordinary answer and must not be logged as a
defect. Diagnostics belong where the value's meaning is known, not inside a speculative probe.

Pinned by `tests/cidrUtils.test.js`, which uses the real object names from the fleet and fails 11 of
16 against the pre-fix parser.

## Schema
- `CREATE TABLE IF NOT EXISTS` is a no-op on a table that already exists — adding a column to an
  EXISTING table needs a companion `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` too, or already-deployed
  servers silently never get it. This has caused at least 2 real production incidents (device_versions
  serial column; audit_findings.matched_rule_ids). Always add both forms.
- `finding_acknowledgements` is keyed on `(device_id, rule_id_vendor, finding_type)`, NOT a UUID —
  `firewall_rules`/`rule_analysis_results` are fully DELETE+reinserted on every collect, so any UUID
  PK would be a fresh random value on the very next pull and silently lose every acknowledgement.
- `zone_classifications` is per-device, not global — a global design shipped first and was rebuilt
  within hours after being reported unusable (real zone names in this fleet are per-device VPN
  tunnel/site identifiers, not shared role names).
- `credential_profiles` has NO foreign key to `devices`/`device_credentials` — applying a profile
  COPIES its decrypted plaintext into the device's own row at that moment; renaming/rotating/deleting
  the profile afterward never touches any device that already used it.

## Vendor adapters (see connectors.md for the full per-vendor detail)
- `getRules()` MUST throw on a genuine retrieval failure, never return `[]` — `collectAndStore()`
  DELETEs the existing ruleset before reinserting, so a failed pull returning `[]` silently wipes
  real data and reports success. `[]` is only valid for a confirmed, honestly-empty ruleset.
- Fortinet REST/SSH: VDOM collection needs an explicit `vdom=`/`edit <vdom>` — omitting it silently
  returns only the default VDOM, looking like a complete pull.
- Check Point: `packages[0]` (positional package pick) was a real, fixed bug — gateway/policy
  resolution must be identity-based (name/IP match), with a hard throw naming candidates on
  ambiguity, never a silent first-match guess, on a multi-gateway management server.
- Palo Alto SSH parses the PAN-OS brace tree, NOT `set`-format output, despite running
  `set cli config-output-format set` first (that command's effect turned out not to matter — three
  rounds of live debugging established this; don't re-attempt the `set`-format theory).
- Palo Alto: a fully Panorama-managed device can have ZERO rulebase content in its LOCAL config
  tree at all (every rule is Panorama-pushed) — `getRules()` falls back to the effective/merged
  security policy in that case, on BOTH transports. Known permanent gaps in that fallback: no
  disabled-rule visibility, no real logging state, no hit counts, no NAT. Both
  transports are now live-verified. ⛔ The XML/API transport's original (2026-07-23) version was
  live-verified on 2026-08-25 to be **WRONG**: `show running security-policy` returns the CLI's
  brace text wrapped in one `<member>` element, not structured XML, so that fallback returned
  `null` on every device and was dead code — and because `collectAndStore` DELETEs before
  reinserting, PAKFood's 33 real rules were wiped. It now tries `pushed-shared-policy` (structured
  XML, best data) first, then the `<member>` text through the SSH transport's proven text parser.
  See `connectors.md` item 4 for the full three-tier order and the live counts.
- Sangfor has no live device, no documentation trail — every field mapping is doc-derived and
  explicitly marked low-confidence; `getObjects()` deliberately returns an empty stub rather than
  guess at unverified block syntax.
- **`hit_count` is TRI-STATE: a real count, `0` = the device genuinely reported zero, `NULL` = NOT
  MEASURED.** Fortinet/Sangfor over SSH, and Palo Alto's SSH transport, report NULL on every rule
  (by design). Until 2026-08-25 they reported `0` and the column was `NOT NULL DEFAULT 0`, so
  Phase 5 flagged every one of those rules `unused` -- findings fabricated entirely from missing
  data. `ruleAnalysis.js` now emits `unused` only for a MEASURED zero. Never coerce NULL to 0 in a
  query, a renderer, or an engine; sort with `NULLS LAST` (Postgres puts NULLs first in DESC).
- ⛔ **Palo Alto hit counts were broken on every device until 2026-08-25**, and the shape of the
  bug is worth remembering: `buildRuleHitCountCmd()` omitted the `<vsys>` wrapper, so PAN-OS
  rejected the command outright ("show -> rule-hit-count -> vsys-name unexpected here"). The
  enrichment's catch swallowed it -- correctly, since a hit count is additive -- and every rule
  kept the default 0. A total failure to read was therefore stored as an affirmative measurement.
  Tolerating a failure is right; recording it as a fact is not. With the wrapper corrected the
  response matches 100% of stored rules on all 10 API-transport devices (1,503 rules, 1,094 with a
  nonzero count); the 2 extra entries per device are PAN-OS's implicit intrazone/interzone
  defaults, which are not part of the config rulebase.

## CVE pipeline (see cve-pipeline.md for the full flow)
- NVD wildcard CPE queries need `virtualMatchString`, never `cpeName` — `cpeName` 404s on wildcard
  strings despite being the documented parameter.
- `versionEndIncluding` = vulnerable UP TO AND INCLUDING; `versionEndExcluding` = UP TO BUT NOT
  INCLUDING (that version is already fixed). Swapping these marks patched devices as vulnerable.
- A CPE `criteria` version segment can itself carry a wildcard (`"10.0.*"`), not just the whole-field
  sentinels `*`/`-` — treating it as one exact pinned version collapses a whole branch's range to a
  single point and silently stops matching every other build in that branch. Fixed 2026-07-23
  (`extractVersionFromCriteria`/`branchRangeFromWildcardCriteria` in `lib/feeds/nvd.js`).
- NVD (`services.nvd.nist.gov`/`nvd.nist.gov`) is currently blocked at this deployment's own network
  perimeter (confirmed 2026-07-23 via `Test-NetConnection` failing at the TCP level) — CIRCL is the
  real, operating fallback right now, not a theoretical one. Deliberately parked, not being actively
  chased — don't re-flag this as a fresh discovery.
- `device_cve_assessments` gets DELETE+rewritten under a `pg_advisory_xact_lock` from 3 independent
  trigger paths (scheduled sync, config-change-triggered re-match, manual "Assess Now") — the lock
  exists because an overlapping run computed from stale data could otherwise resurrect a
  since-patched CVE's row after a newer, correct run already removed it.
- A code fix to CVE version-range extraction does NOT retroactively repair rows already persisted
  before the fix — see `backfillPaloAltoVersionRanges()`/`cleanupVolatileConfigDiffs()` and every
  other `lib/migrate.js` backfill for the established remediation pattern.

## RBAC / auth
- Middleware only checks session PRESENCE, not role — every mutating (POST/PUT/DELETE/PATCH) route
  needs its OWN explicit `isAdmin(session)` check via `lib/rbac.js`. A route sitting under a
  differently-named path from its sibling (e.g. `/api/analysis/run` vs
  `/api/devices/[id]/analysis`) is easy to miss when auditing RBAC coverage by directory structure —
  grep every exported POST/PUT/DELETE/PATCH handler directly instead.
- The JWT re-checks a local-provider user's role from the DB on EVERY request (not just at sign-in)
  so a role change/deletion takes effect on the very next request, not after a 30-day token expiry —
  LDAP-authenticated tokens are deliberately exempt (no `users` table row to check against; LDAP
  role is always hardcoded `admin` in `authorize()`, a known, unfixed gap).
- UI-level hiding of admin-only controls (buttons/tabs) is cosmetic only — the real enforcement is
  always the route's own server-side `isAdmin()` check. Never treat a hidden button as sufficient
  security.

## Compliance / applicability engine
- `config_applies`/predicate results are TRI-STATE (`yes`/`no`/`unknown`) and `unknown` must NEVER
  collapse to `no` — an empty/failed config pull defaulting to `no` would silently downgrade a
  KEV-listed, actively-exploited CVE from `patch_now` to `monitor`. Same discipline applies to
  compliance checks (`na` when nothing is measurable, never a guessed `pass`/`fail`).
- `getLatestConfigParsed()` normalizes the config root (`normalizeConfigParsedRoot`) before ANY
  predicate sees it — Palo Alto SSH's real tree lives under a `.tree` wrapper key, and XML/API's
  `deviceconfig` is nested under `devices.entry.deviceconfig`; skipping normalization silently makes
  every `deviceconfig.*`-path predicate resolve to a false `no`/fail regardless of the device's real
  configuration. This was a real, confirmed production bug (2026-07-18) affecting every Palo Alto
  device on both transports.
- A zone-dependent compliance check (`rule-no-external-to-internal-access`) must resolve to `na` when
  zone classification data doesn't exist yet, NOT a false `pass` — reusing the generic `rule_scan`
  shape (which treats zero matches as an unconditional pass) here would silently misreport 100%
  compliance before any admin has classified a single zone.

## Rule analysis engine
- `redundant` only fires when the exact-duplicate rule ISN'T the first covering match `shadow`'s own
  loop lands on — two exactly-duplicate same-action rules are always reported as `shadow`, never
  `redundant`, in a simple 2-rule case. Pre-existing engine behavior, not a bug.
- `generalization` deliberately excludes the case where two rules' fields are FULLY equal (already
  covered by `redundant`) — otherwise an exact-duplicate pair would double-report under two finding
  types simultaneously.
- Any new finding type MUST be added to `app/api/devices/[id]/acknowledgements/route.js`'s
  `FINDING_TYPES` allow-list, or acknowledging it permanently 400s. This has been missed twice
  already (`correlation`, then `external_exposure`/`generalization` follow-ups) — check this file
  every time a new `rule_analysis_results.finding_type` value is introduced.
- Shadow/redundant/reorder analysis is O(n²) and skipped entirely above 1000 rules (warning logged,
  not silently truncated).
- Shadow/redundant/correlation/generalization/reorder_candidate analysis is VDOM-aware as of
  2026-07-30 — `firewall_rules.vdom` (new column, Fortinet-only, both transports) plus
  `isStrictlyEarlier()` treating any pair with differing `vdom` values as never comparable, closing
  the false-positive-across-VDOMs bug this used to have. `network_objects` has NO equivalent fix —
  an identically-named object collected from two different VDOMs on the same device still silently
  collapses to whichever was inserted last; a real, separate, still-open gap.
- `riskScore.js`'s `computeRiskScoreFromCounts()` caps each severity tier's contribution
  INDEPENDENTLY before summing (critical 40/high 30/medium 20/info 10) — do NOT revert this to a
  single "sum everything then clamp the total to 100" formula. That was the actual shipped
  behavior until 2026-07-23 and it saturated at "Critical (100)" for 13 of 14 real fleet devices,
  because medium-severity findings (7 of 12 finding types, `unused` especially) commonly run into
  the hundreds and `2 * medium` alone exceeds 100 long before critical/high are even considered.
  If you ever need to add a new severity tier or change a weight, cap it independently too.
- `device_risk_history` only stores `(device_id, score, band, recorded_at)` — never the underlying
  severity counts. Any future change to the risk-scoring formula can NEVER retroactively correct
  historical trend rows, only new snapshots going forward. Don't promise a backfill for this table;
  it isn't possible without also storing the raw counts (which it doesn't).

---

## Redaction rules

Every field/pattern that MUST be stripped or masked before it reaches `device_configs`,
`config_backups`, `config_diffs`, `firewall_rules.raw_rule`, or a log line. This is a security
product — `device_configs`/`config_backups`/`config_diffs` are `GRANT SELECT`'d to
`claude_readonly`/`nocvault_readonly`, so anything NOT redacted here is readable by those roles.

**Universal keyword pattern** (independently duplicated per adapter/file — NOT a shared module, by
this codebase's own convention; keep every copy in step if you widen one):
`secret | password | passwd | psk | pre[-_]?shared | private[-_]?key | phash | community | credential | token | api[-_]?key | keytab`
— current canonical copies, all now in step as of 2026-07-30: `lib/adapters/forcepoint/parser.js`,
`lib/adapters/checkpoint/parser.js` (widened 2026-07-30 — used to be the one narrower, out-of-step
copy, missing `phash`/`pre-shared`/`keytab`), and `lib/engines/configDiff.js`'s
`SECRET_PATH_PATTERN`. Widen ALL copies together whenever any one changes.

**Specific known secret-bearing fields, by vendor/format**:
- **Palo Alto XML/API** (`lib/adapters/paloalto/parser.js` `SECRET_TAGS`): `phash`, `password`,
  `passwd`, plus IKE/IPsec pre-shared-key and SNMPv3 auth/priv password tag names. Redacts BOTH
  `<tag>value</tag>` element form and `tag="value"` attribute form, in the RAW XML text, before
  `parseConfig()` ever builds the parsed tree.
- **Palo Alto SSH** (`lib/adapters/paloalto/sshParser.js` `SECRET_TOKENS`): `phash` (admin user
  password hash, `mgt-config users <u> phash`), `password`, `passwd`, `password-hash`, plus IKE PSK
  and SNMPv3 secret tokens. Quote-span-aware — redacts only the matched token's VALUE, preserving
  the brace/quote structure around it (a 2026-07-20 fix; the earlier version could corrupt the
  brace tree when a legitimate free-text field merely CONTAINED the word "password").
- **Fortinet** (`lib/adapters/fortinet/cliParser.js` `isSecretKey`/`SECRET_SET_KEYS`): any key
  matching `pass(wd|word|phrase)`, plus SNMP community strings (context-sensitive — only redacted
  inside an `snmp` block, since "community" as a bare word can appear elsewhere), PSK values,
  `ENC`-prefixed FortiOS-obfuscated values (catch-all). Multi-line quoted values are tracked
  generically (any `set key "..."` value, not just already-recognized-secret keys) so a later
  genuinely-secret line can't be misjudged as outside its quoted context.
- **Cisco ASA** (`lib/adapters/cisco_asa/parser.js` `REDACTION_RULES`, 17 rules): `enable password`,
  `passwd` (telnet/SSH login), AAA `key`/`radius-common-pw` (both single-line and multi-line
  sub-mode forms), SNMPv3 user secrets (two-secret form: auth AND priv passwords on one line).
- **Check Point** (`lib/adapters/checkpoint/parser.js` `redactSecrets`): keyword-based recursive
  walk over the gateway/api_versions config object — the only adapter, historically, with NO
  redaction pass at all until fixed; verify this stays true for any new Check Point config surface.
- **Forcepoint** (`lib/adapters/forcepoint/parser.js` `redactEngineElement`): recursive, bounded to
  depth 12, fail-closed (an error during redaction drops that subtree to a placeholder rather than
  risk returning it unredacted).
- **Sangfor** (`lib/adapters/sangfor/parser.js` `redactConfig`): keyword-triggered rest-of-line
  redaction PLUS a dedicated PEM private-key BLOCK redaction (multi-line `-----BEGIN...-----END-----`
  bodies, which a single-line keyword match can't catch).

**Database-level exclusions (not code redaction — access control)**:
- `device_credentials`, `credential_profiles` — NEVER granted to `claude_readonly`/
  `nocvault_readonly`, no readonly view either (the whole row is credential-adjacent, no safe
  subset worth a view).
- `settings` — base table `REVOKE`d from readonly roles; a `settings_readonly` VIEW (excluding the
  `key='admin_password_hash'` row) is granted instead. `app/api/settings/route.js`'s own
  `HIDDEN_KEYS = new Set(['admin_password_hash'])` filter ONLY hides it from the HTTP GET response —
  it does nothing for raw SQL access, which is exactly why the view+REVOKE exists.
- `users` — base table `REVOKE`d; a `users_readonly` VIEW (excluding `password_hash`) granted
  instead.
- Any FUTURE secret-bearing row added to `settings` (or a new table generally) needs this same
  treatment — a view excluding the secret column, not a bare table grant. This has already been
  gotten wrong once (a blanket `GRANT SELECT ON TABLE settings` shipped before this fix).

**Config-diff defense-in-depth** (`lib/engines/configDiff.js`): `device_configs.config_parsed` is
SUPPOSED to already be redacted by the adapter before it ever reaches this layer — this exists
anyway, defensively, because a real incident proved the assumption alone wasn't enough:
`deepRedactSecrets()` recurses into a one-sided added/removed diff entry's carried VALUE (not just
its top-level PATH — a whole new object landing as one opaque entry could hide a nested secret key
that the path-only check would miss). `isRegisteredSubtreeRoot()` decomposes a whole-subtree
add/remove of a volatile root into per-leaf diff entries so the noise-filter still applies correctly
even when an entire section appears/disappears as one entry instead of field-by-field.

**Array diffing was purely positional until 2026-07-30 — a real bug, not a hypothetical one.**
`diffValue()`'s array branch used to compare `oldArr[i]` vs `newArr[i]` by INDEX only — removing one
entry from the middle of a plain-value array (e.g. a VPN group's username list) shifted every
later entry down one slot, and each shift was reported as a separate "modified" entry (a real
production report: one real removal showed up as a dozen-plus fake modifications). Fixed via
`diffPrimitiveArrayLCS()` — an LCS-based diff used ONLY when every element on both sides is a plain
primitive (string/number/boolean/null). Same `isVolatilePath()` filtering applies to LCS-produced
entries as every other push site.

**Object arrays got the same treatment 2026-07-31 (v2.30.0)** — arrays of OBJECTS were still positional
until this, which is what produced the Palo Alto XML/API rulebase shift cascade (one rule inserted near the
top → every later rule diffed against a different rule → dozens/hundreds of fake "modified" fields; a real
report showed 37 added / 38 removed / 152 modified for one small change). `diffValue`'s `bothArrays` branch
now, BEFORE the positional fallback, aligns arrays of objects by a shared UNIQUE identity key
(`ARRAY_IDENTITY_KEYS = ['@_name','name']` — `@_name` = every XML/API `<entry name>` array, `name` = the
flat Fortinet/Check Point/Forcepoint admin arrays) via `chooseArrayIdentityKey()`/
`diffObjectArrayByIdentity()`. Matched elements diff field-by-field (a pure REORDER with no field change now
produces NO entry at all — deliberate; ordering concerns belong to rule-analysis's `reorder_candidate`, not
config-diff), an element only on one side is a real add/remove. Emits the SAME positional `entry[N]` paths as
before (matched/added → new index, removed → old index) so classifyPath/redaction/truncation/DiffViewer
grouping are all unchanged — only the PAIRING changed. Gated hard: falls back to positional unless EVERY
element on BOTH sides is a plain object with a usable, unique identity value at the chosen key (a missing key
or a duplicate identity → positional). **Forward-only** — like every diff fix here, it can't retroactively
un-cascade already-persisted `config_diffs` rows (the two source snapshots are gone); only new pulls are
clean. No backfill is possible for this, same as `device_risk_history`'s documented limitation.

**`friendlyDescription` (added 2026-07-30, extended same day)**: `classifyDiff()` entries carry an
extra `friendlyDescription: string|null` field — a plain-English one-line description (e.g. `Local
user "satish" was removed`) for these recognized shapes:
- `local-user-database.user(-group)` and `address`/`address-group`/`service`/`service-group` object
  leaves (the original two).
- VPN config: Fortinet's flat `ssl_vpn` dict, Palo Alto's GlobalProtect config (detected via the
  same `/global.?protect/i` deep-scan `vpnSummary.js` already uses — its exact nesting varies, so
  only a shallow field is ever named, deeper nesting gets a generic-but-accurate "GlobalProtect
  configuration was changed"), and Forcepoint's top-level tri-state `smc_vpn_gateway_configured`
  (never describes the `null`/"undetected" state confidently).
- Admin accounts: Fortinet `admins[]`, Palo Alto `mgt-config.users` (SSH transport resolves the
  username; XML/API's opaque `entry[N]`/`@_name` array returns `null`, same gap as below), Cisco ASA
  `usernames[]`, Check Point `administrators[]`, Forcepoint `smc_administrators[]`. **Known gap,
  accepted, not a bug**: a FIELD-LEVEL modify to an EXISTING admin on the three array-of-objects
  vendors (Fortinet/Check Point/Forcepoint) always resolves `null` — the diff entry only carries the
  changed leaf's old/new value, never the sibling `name` needed to say WHICH admin changed; only a
  whole admin record added/removed (where the full record IS the value) gets a description. Fixing
  this would need entry-level friendlyDescription computation to see the surrounding array, not just
  one entry — a bigger change, not done.
- Rule Changes table (`pushRuleChange()`'s separate `ruleChanges[]`, not a `classifyDiff()` section):
  a whole PAN-OS rule added/removed (SSH transport only — see below) gets a full sentence built from
  its raw brace-attrs fields (`action`/`from`/`to` always named; `source`/`destination`/`service`/
  `application`/`category` named only when present and not the PAN-OS `"any"` no-op default). Each
  rule-table row also gained a separate `fieldLabel: string|null` (humanized raw field name, e.g.
  `log-end` → `log end`, for the Field column) — a DIFFERENT field from `friendlyDescription`, both
  always present, `null` when not applicable.

Computed against the entry's REAL untruncated path/value before `truncatePathForDisplay()` runs —
classifying against an already-truncated path/value would silently misfire. Never names a
secret-shaped or `<redacted>` field in a sentence (reuses `SECRET_PATH_PATTERN`/
`SECRET_PATH_EXCEPTIONS` — confirmed `must_change_password` false-positives this pattern and is
correctly never named). `null` for everything else, including every Fortinet path under this
feature's first two shapes (Fortinet's config_parsed has no `local-user-database`/`address`/etc.
segment — structural no-op there, not a vendor check) and the XML/API transport's `entry[N]`/
`@_name`-shaped object arrays throughout (rule table, admin accounts) — same "can't resolve without
the live tree" gap `classifyPath()`'s rule-name resolution already documents; the raw-rule sentence
is therefore only ever reachable via the SSH transport. `components/config/DiffViewer.js` renders
`friendlyDescription` as the primary label (raw path moved to a hover tooltip) and `fieldLabel` in
place of the raw field name in the Rule Changes table's Field column — falls back to exactly
today's raw rendering wherever either is `null`.

**Separately found, NOT fixed here (out of scope for this feature)**: Check Point's adapter-level
`redactSecrets()` already masks `administrators[].must_change_password`'s VALUE to `'<redacted>'` —
an over-redaction of a plain boolean field that happens to contain the word "password" in its name,
not an actual secret. Harmless (the field is simply never usefully displayable anywhere, including
here), but worth a narrower fix in `lib/adapters/checkpoint/parser.js` if this field ever needs to
be shown.

**`friendlyDescription` extended further, same day**: also covers NAT Rules (Palo Alto SSH only,
same brace-attrs treatment as security rules — `from`/`to` always named, translation sub-shape
described when cleanly resolvable, e.g. `dynamic-ip-and-port`/`static-ip`, omitted otherwise), PBF
Rules (same treatment, forwarding action named when resolvable), Zones (reuses
`friendlyDescriptionForNetworkObject()` directly rather than a parallel copy), Fortinet's remaining
flat settings sections (`snmp`/`ntp`/`dns`/`log_syslogd`/`password_policy`/`fortiguard`/
`autoupdate_schedule` — field names grounded in `lib/auditChecksSeed.js`'s own live compliance
predicates, e.g. `ntp.ntpsync`, `dns.primary`, `log_syslogd.status`), and `system_info` (gated by the
existing `MEANINGFUL_SUBTREE_FIELDS_BY_VENDOR` allowlist — `sw-version` → "Firmware version was
changed", the field that also triggers the CVE re-match hook; `hostname` → "Device was renamed").
`deviceconfig` and `network.*` interface entries were deliberately left `null` — no clean, confidently
groundable single-field pattern found for either.

**Volatile-subtree filtering (`MEANINGFUL_SUBTREE_FIELDS_BY_VENDOR`) gained `content-preview` and a
segment-scan rewrite (2026-07-30)**: `shared.content-preview` is PAN-OS's own staging area for a
pending New/Modified App-ID content update (confirmed via Palo Alto's community/docs, not assumed)
— cleared automatically once the update installs or is discarded, never an admin decision. A real
user report showed it firing "1 removed"/"1 added" config-diff alerts across many unrelated devices
at similar times — the exact noise signature `system_info` filtering already existed for. Registered
with an EMPTY allowlist (`new Set([])`), unlike `system_info`'s curated one — there is no
admin-meaningful field inside this node at all, so every field under it is excluded, not just an
unlisted subset. Required a real mechanism change, not just a new entry: `isVolatilePath()`/
`isRegisteredSubtreeRoot()` used to require the volatile root to be an EXACT PREFIX from the start of
`path` (works for `system_info`, which both parsers merge in at the top of `config_parsed` directly),
but `content-preview` sits nested (`tree.shared.content-preview` on SSH, differently on XML/API) —
`findSubtreeRootIndex()` now scans for the root as a segment ANYWHERE in the path instead. Verified
this is a safe broadening for `system_info` too (it never appears nested elsewhere) and does NOT
suppress a real sibling change under the same `shared` node (e.g. an address object edit) — only the
registered root segment itself and its own descendants are affected.

**⛔ Real bug found and fixed while verifying the above**: `SECTION_LABELS` used to include
`rulebase`/`pre-rulebase`/`post-rulebase` as ordinary entries in the same flat array as `nat`/`pbf`/
etc. `sectionLabelFor()` scans PATH SEGMENTS in order and returns on the first match anywhere in
`SECTION_LABELS` — a NAT rule's path is `...rulebase.nat.rules.<name>...`, so the `rulebase` segment
(appearing before `nat`) always won first, meaning every NAT/PBF change was mislabeled "Rules (detail
unavailable for this device)" and never reached the correct "NAT Rules"/"Policy-Based Forwarding
Rules" label. Fixed by moving `rulebase`/`pre-rulebase`/`post-rulebase` into a separate
`FALLBACK_RULEBASE_LABELS` map, checked only after the main `SECTION_LABELS` scan finds nothing —
preserves the original intent (an unresolvable-index XML/API security-rule path still gets that
label) without letting it shadow more specific labels further down the same path.

**Rule Changes table gets a real detail table, not just a sentence (added 2026-07-30)**: a whole PAN-OS
security rule added/removed (the raw brace-attrs `change.value`, SSH transport only) is now converted
via `lib/adapters/paloalto/sshParser.js`'s existing `ruleFromBraceEntry()` (newly exported — it
wasn't before) into the same NormalizedRule shape the fleet Rules page already renders, and shown as a
small "Field | Value" table (same column labels: Name/Enabled/Action/Src Zone/Dst Zone/Src Address/
Dst Address/Services/Comment/Applications/Schedule/Log) INSTEAD of the raw JSON blob — the
`friendlyDescription` sentence still renders above it. Falls back to exactly the old raw-JSON
rendering on any doubt (`ruleFromBraceEntry()` throwing, a malformed `change.value`, or a
suspiciously-empty-looking result) — `components/config/DiffViewer.js`'s `looksLikeRealRule()`/
`tryBuildRuleFromChange()` guard this. Only ever reachable via the SSH transport (same
XML/API-unresolvable-index gap as everywhere else in this feature).

**Generic flat-object table for every OTHER whole-object change (added 2026-07-30)**: unlike PAN-OS
rules, address/service objects, zones, VPN records, and admin records have no existing per-domain
normalizer to reuse — `components/config/DiffViewer.js`'s `isFlatObject()` gate (conservative: any
nested object or array-of-objects anywhere inside disqualifies it, falls back to raw JSON) decides
whether an added/removed/modified object value gets a generic "Field | Value" table
(`FlatObjectTable`) or, for a modified pair where BOTH sides are flat, a three-column "Field | Old |
New" comparison table (`FlatObjectDiffTable`, changed cells colored red/green) instead of two stacked
raw-JSON blobs. Field labels are a local, purely mechanical Title Case transform (`titleCaseField()`)
— deliberately NOT the same helper as `configDiff.js`'s sentence-casing one, different casing need.

**Indexed-rule grouping — Palo Alto XML/API "Security Rules" (added 2026-07-31, v2.29.0).** The XML/API
transport stores each rulebase (security/nat/pbf) as an array of `<entry name="…">` objects, so a diff
path is `…rulebase.security.rules.entry[N].<field>` — `entry[N]` is an opaque positional index and the
rule NAME is a sibling `@_name`, unresolvable from one diff entry (same gap `classifyPath()`/
`isUnresolvableIndex` already documents). These used to render as a flat wall of `entry[5].log-end: yes`
rows + raw JSON under the section then labelled "Rules (detail unavailable for this device)". Fix is
PRESENTATION-ONLY — the diff algorithm/counts are unchanged: `classifyDiff()` now tags each such section
entry with `ruleIndex`/`ruleField` (via `extractIndexedRuleEntry()`, computed against the REAL untruncated
path; both `null` for every other shape), and `components/config/DiffViewer.js` regroups entries sharing an
index into one Field/Change/Value table per rule (labelled "Rule #N" by position, or the real name when a
whole-rule add/remove carries `@_name`). Section renamed "Security Rules" — a stable classification key,
also in `OverviewConfigChangesCard.js`'s `HIGH_IMPACT_LABELS`, change both together. **Root-cause shift
cascade FIXED 2026-07-31 (v2.30.0):** `diffValue`'s `bothArrays` branch now aligns arrays of objects by a
shared unique identity key (`@_name`/`name`) instead of by position (`chooseArrayIdentityKey`/
`diffObjectArrayByIdentity`), so inserting/removing one rule no longer cascades into false "modified" fields
down the rulebase — see the "Array diffing" note below. Grouping still needed for readability; the two are
complementary. Paths keep the positional `entry[N]` grammar (matched/added → new index, removed → old
index), so name-in-path fragility was avoided entirely.

**Vendor-agnostic noise leaves (`UNIVERSAL_VOLATILE_LEAF_FIELDS`, added v2.31.1).** Separate from the
per-vendor `MEANINGFUL_SUBTREE_FIELDS_BY_VENDOR` allowlists: a small set of derived/computed summary leaf
fields filtered by LEAF NAME on EVERY vendor (and the no-vendor `diffConfigs` call). Currently just
`security_rules_count` — Palo Alto's parser derives it (rulebase size), it moves on every rule add/remove and
duplicates the per-rule change table. `isVolatilePath()` checks this FIRST, before the per-vendor subtree
lookup. Add a new always-noise leaf here (not to a per-vendor allowlist) when it's a computed value no admin
edits directly. Cleaned from historical rows by the same `cleanupVolatileConfigDiffs` migration.

**Whole-subtree-root volatile entries need DECOMPOSITION in the cleanup path, not just `isVolatilePath` (added 2026-07-31, v2.31.0).** `isVolatilePath()` only matches a nested LEAF under a registered root, never the bare root captured as one object (`{path:'tree.shared.content-preview', value:{…}}`). At compute time `diffValue`'s `isRegisteredSubtreeRoot` branch decomposes those, but `filterDiffForCurrentRules()` (the `cleanupVolatileConfigDiffs` migration) only ran the leaf filter — so a HISTORICAL whole-`content-preview`-object add (recorded before decomposition existed, or when vendor was unknown) rendered as a permanent "1 added" noise row. `filterDiffForCurrentRules()` now re-runs `diffValue({}, e.value, …)`/`diffValue(e.value, {}, …)` on any added/removed registered-root entry so the current allowlist applies per-leaf: `content-preview` (empty allowlist) drops entirely; `system_info` keeps only allowlisted fields and sheds embedded clock/uptime telemetry. Runs on every migrate, idempotent.

**Display-layer truncation is a SEPARATE concern from redaction — don't conflate them.** A corrupted
(not secret, just malformed/oversized) path or value needs `truncatePathForDisplay()`/
`CollapsibleString`, not a redaction pass — but a rendering surface added for `config_diffs` data has
THREE independent places a path/value can render (`change_summary`'s cached one-liner,
`classifyDiff()`'s section-entry paths, `classifyDiff()`'s rule-change table cells) — fixing display
truncation in one does not fix the other two; check all three for any new consumer of diff data.

**Never log**: the constructed PAN-OS keygen URL (`?type=keygen&user=...&password=...` — the
password travels as a literal query parameter, inherent to PAN-OS's own auth flow) — SecVault's own
`redactSecrets()`/`scrubUrlSecretParams()` in `lib/adapters/paloalto/api.js` strips this from any
error string by parameter NAME (survives re-encoding), and the keygen response body is never echoed
into any error at all.

## A failed read persisted as an affirmative empty (system-info read failure)

Added 2026-08-25, v2.59.0. Both Palo Alto transports fetch `show system info`
BEST-EFFORT when building a config snapshot: on failure they log and pass `null`,
and their `parseConfig()` turns that into `system_info: {}` plus null
`hostname`/`model`/`sw_version`. `configDiff` then correctly reported ~12
REMOVALS against the previous populated snapshot, and ~12 ADDITIONS when the next
read succeeded — false config-change alerts on a security product.

Confirmed on TUG: `config_raw` was byte-identical (151063 bytes) on both the
"removed" and "added" day. The device changed nothing; only the READ alternated.

⛔ Fixed in ONE place — `preserveSystemInfoOnReadFailure()` in
`lib/adapters/index.js`, not per-adapter — so it covers both PA transports and any
future adapter merging a best-effort `system_info`. On an empty/absent value it
carries the PREVIOUS snapshot forward and pushes a `result.errors` note, the same
"previous values kept" discipline as `getLicenses`/`getDiskUsage`. A POPULATED
system_info is never touched, so a genuine model/serial/version change still diffs.

⛔ When writing an adapter: OMIT a key you could not read. Never write `{}` — an
empty object is an assertion that the device reported nothing, which is a
different claim from "we failed to ask".

Historical rows are repaired by `cleanupSystemInfoReadFailureDiffs()` (run from
`migrate.js`). Deliberately narrow after the type-coercion cleanup precedent:
a modified entry qualifies ONLY when exactly one side is blank — both sides
populated is a real change and survives. Live dry-run before shipping: 3 rows
deleted, 0 updated, 106 of 109 untouched.

## ⛔ `ON DELETE SET NULL` + `UNIQUE NULLS NOT DISTINCT` are mutually incompatible (found 2026-09-09)

Device delete was **permanently broken** for any device with syslog history — not slow, impossible.
From `app-error.log`:

```
code:   23505  (unique_violation)
where:  UPDATE ONLY "syslog_rollup_hourly" SET "device_id" = NULL WHERE $1 = "device_id"
detail: Key (bucket_hour, source_ip, device_id, vendor, action, severity, log_class)
        = (2026-09-09 10:00, 10.204.6.1, null, fortinet, blocked, 4, utm) already exists
```

Two deliberate decisions collided. The FK is `ON DELETE SET NULL`; the constraint is
`UNIQUE NULLS NOT DISTINCT` — the choice CLAUDE.md documents so grouping keys can stay honestly
nullable instead of using `'unknown'` sentinel strings. A `device_id = NULL` row for the same bucket
already exists (events that arrived before the sender was matched), so NULLing collides.

⛔ **`syslog_rollup_hourly` is the ONLY table with this combination** — proven by a lint test over
`lib/schema.sql`, not by inspection, and confirmed against production. The other SET NULL FKs are
safe for distinguishable reasons: `syslog_events` has no unique constraint beyond its PK,
`discovered_devices` is unique on `source_ip` alone, and `background_jobs`' partial unique index is
plain NULLS DISTINCT. A second lint asserts the deletion engine's `ROLLUP_TABLES` covers every
`syslog_*_hourly` table in the schema, so a NEW rollup cannot silently reintroduce this.

⛔ **Rollup rows are DELETED, never NULLed.** Beyond fixing 23505 it is correct on the merits: they
are derived aggregates, and NULLing would merge a deleted device's traffic into the *unmatched
sender* bucket — the exact population `discovered_devices` reads — so a deleted device would
resurface as a phantom unmanaged firewall.

## ⛔ Deleting a device blocks syslog INGESTION, not just the UI

The delete holds an exclusive row lock on `devices`; the collector needs a KEY SHARE lock on that
same row to INSERT any event for the device. Verified in `pg_locks` on 2026-09-09:
`INSERT INTO syslog_events` waiting on the DELETE, with 3.35M rows still to rewrite.

That is why deletion is staged and batched OUTSIDE the `devices` lock, and why the final statement
holds it for milliseconds: `SELECT … FOR UPDATE` (which conflicts with the `FOR KEY SHARE` any new
referencing write must take) → mop up any rollup row that landed in the gap → `DELETE FROM devices`.
Ten of the eleven rollup tables are `ON DELETE CASCADE` and would clean themselves up at that
statement — they are swept beforehand anyway, because a cascade deleting 256,000 rows *while holding
that lock* is the same outage in a different costume.

## ⛔ An exact `COUNT(*)` on `syslog_events` for one device is NOT affordable

Measured 2026-09-09: for the busiest device it does not complete in 8 seconds, even with the
`(device_id, received_at)` index. The delete-confirmation dialog therefore estimates from the hourly
rollups and LABELS the figure approximate; a count that fails renders "not counted", never `0`.
Never put a bare `COUNT(*)` over `syslog_events` on a page load.

## ⛔ An unreadable optional capability is NOT an unreachable device (2026-09-09)

The Devices table said **"Failing 0% of polls succeeding"** about OKF(F2) — a FortiGate that had
just been collected in full, was answering its metric and test polls, and was reachable over SSH.
Three bugs stacked to produce that one sentence:

1. **`'vpn'` was missing from `VALID_SOURCES`.** `recordConnectivity` falls back to `'collect'` for
   an unrecognised source, so every VPN-poll observation — added 2026-08-25 *specifically* so a
   failing VPN poll would stop reading as healthy — was filed under `collect`. The tooltip then
   showed `collect 0/14` for a device whose collect had just succeeded. ⛔ Any new poller MUST be
   added to that set; the fallback stops an observation being lost, but pays for it by
   misattributing it, which is worse when nobody checks.
2. **A capability failure was recorded as unreachable.** `get vpn ssl monitor` returned output the
   parser did not recognise (almost certainly because SSL-VPN is simply not configured), the adapter
   correctly refused to guess a session count and threw — and the poller wrote `reachable: false`.
   "This feature is not present" became "this device is down".
3. **The note printed a bare percentage.** `worstRate` is the MINIMUM across sources by design (a
   device is as broken as its most broken collector), so without naming the source it reads as
   "nothing about this device works".

**The fix.** `CapabilityUnavailableError` in `lib/adapters/interface.js`, thrown only when the
transport genuinely succeeded, plus `isCapabilityUnavailable(err)`. The VPN poller records
`reachable: true` for it — the device demonstrably WAS reached — and keeps the capability gap in the
message, which is a different fact from reachability and does not belong in the same boolean.

⛔ **Throw it ONLY when the transport succeeded.** If the connect, the login or the API call failed,
throw a normal Error: that IS reachability evidence and must keep counting against the device. The
detection is by FLAG (`err.deviceWasReached`), not `instanceof` — adapters and engines load through
several paths here and an instanceof across two module instances of the same file silently returns
false.

⛔ **The 3-day window means history persists.** A device carries its pre-fix failures until they age
out. That is correct — the failures were real — but do not read it as the fix not working.

## ⛔ `getRules()` returning `[]` from a FAILED read — four more instances (found 2026-09-09)

CLAUDE.md's adapter contract says `getRules()` must THROW on a retrieval failure, because
`collectAndStore` DELETEs a device's `firewall_rules` before reinserting — so `[]` from a failed
pull silently wipes the real ruleset. This is the mechanism that wiped PAKFood's 33 rules in August.
A whole-app sweep found the contract violated in **four** adapters:

- **`paloalto/index.js` — LIVE, 10 devices.** Two paths, not one. The any-vsys catch returned `[]`
  AND short-circuited all three Panorama tiers; the final fall-through returned `[]` outright; and
  a tier that answered with a non-null EMPTY array was accepted as a successful collection.
- **`checkpoint/parser.js`** — a `null` page was skipped WITHOUT being counted, so `malformedPages`
  stayed 0 and the warning never fired. `api.js` returns `parsed = null` for any HTTP-200 with an
  empty or non-JSON body (a proxy or captive-portal page), which is the likeliest real shape.
- **`forcepoint/index.js`** — only the `throw` branch was guarded; `smc.getPolicy()` resolving to
  `null` fell through to `parsePolicy(null)` → warn → `[]`.
- **`sangfor/index.js`** — `if (output.trim().length > 0)` accepted a CLI REJECTION BANNER as the
  config, and short-circuited the remaining `CONFIG_COMMANDS`, defeating the dialect fallback.
  Downstream `hasUsableConfig()` then returned TRUE for the banner, so compliance scored every
  predicate `fail` instead of `na`.

⛔ **The distinguishing evidence is KEY PRESENCE, not length.** PAN-OS answers a config-get whose
xpath resolved to nothing with `<result/>` — no `rules` key; a real-but-empty rulebase answers
`<result><rules/></result>` — key present, empty value. "The xpath found nothing" and "the rulebase
is empty" are different statements and only the second may be stored. Forcepoint's `parsePolicy`
already made this distinction and is the pattern the others now follow.

⛔ **A PARTIAL page set must throw too.** Returning the readable pages silently truncates a real
ruleset, because the caller DELETEs first — the same rule as Fortinet's "collect every VDOM or fail".

⛔ **Plain `Error`, never `CapabilityUnavailableError`, for a rules failure.** That class means the
transport succeeded and only an OPTIONAL capability was unreadable, and it deliberately stops the
poller counting the device as unreachable. A rulebase is not optional — every firewall has one — so
a device that cannot show SecVault its rules genuinely is one SecVault cannot manage, and it must
keep counting against reachability. Using the capability class here would re-create the bug it was
written to prevent, pointed the other way: a real management failure rendered as healthy.

## ⛔ Check Point: never take `layers[0]` either (fixed 2026-09-09)

Same class as the already-documented `packages[0]` bug. `checkpoint/index.js` warned about multiple
access layers and then stored **layer 1 only** as if it were the whole rulebase. R80+ Ordered Layers
are a normal configuration. `getRules()` now walks every layer in the package's declared order.
⛔ Check Point restarts `rule-number` at 1 PER LAYER, so `sequence_number` is renumbered continuously
across layers — otherwise several rules sit at position 1 and every ordering analysis (shadow,
reorder) is meaningless. Provenance kept as `raw_rule._secvault_access_layer`.
⛔ Unverified against real R80+ hardware — the ordering semantics are reasoned, not observed.
