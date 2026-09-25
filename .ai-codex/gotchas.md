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

## ⛔ `node --check` IS A NO-OP ON ANY FILE WITH A TOP-LEVEL `import` (found 2026-09-19)

**It is not "JSX-blind". It is blind.** The section below (written 2026-09-08) concluded that
CLAUDE.md's checklist was "CORRECT as written" because it scopes `node --check` to non-JSX
directories. That conclusion was wrong, and it was wrong in the reassuring direction: every file in
`app/api/**` is ESM, and `node --check` reports **nothing at all** for an ESM file.

Measured 2026-09-19, four different syntax errors, each written twice — once after a top-level
`import`, once without:

| error | in an ESM file | in a CJS file |
|---|---|---|
| `const x = 'un'terminated';` | **exit 0** | exit 1 |
| `const x = (1 + 2;` | **exit 0** | exit 1 |
| `const x = {a: 1,,};` | **exit 0** | exit 1 |
| `function f( { return 1; }` | **exit 0** | exit 1 |

So the "unclosed paren IS caught" consolation below holds only for CommonJS — `lib/**` and
`services/**`, which is where it still earns its place.

⛔ **HOW IT WAS FOUND: it passed a genuinely broken file that shipped to `main`.** A release-notes
string in `app/api/system/update-status/route.js` contained an unescaped apostrophe
(`the vendor's score`), which ends the string early and is a plain syntax error — nothing to do
with JSX. `node --check` exited 0. The file would have failed `npm run build` on the production
server, mid-deploy. What caught it was `tests/jsxSyntax.test.js`, which uses SWC and parses
everything; **`npm test` is the real syntax gate for this repo, not `node --check`.**

⛔ The deeper lesson is the one this file keeps recording: the 2026-09-08 entry below stopped at
the first explanation that fit the evidence it had (JSX), certified the checklist on that basis,
and the certification outlived the reasoning. A gate blessed by a comment is the hardest kind to
re-examine.

## `node --check` does NOT validate JSX (found 2026-09-08 — see the correction above)

⛔ `node --check` exits **0** on a component containing broken JSX. Verified: appending
`export function Broken() { return <div><span>oops</div>; }` to `components/ui/Badge.js` still
passes. It parses the file as ESM and never reaches the JSX, so an unclosed tag, a stray brace
inside a `{...}` expression, or a mismatched fragment all sail through.

⛔ **CORRECTED 2026-09-19 — this paragraph used to certify the checklist and was wrong.** It
said: "CLAUDE.md's pre-commit checklist is CORRECT as written — it scopes `node --check` to
`lib/**`, `services/**` and `app/api/**`, which are non-JSX." The `app/api/**` half is false:
those files are ESM, and `node --check` reports nothing whatsoever for an ESM file (table at the
top of this section). It is a real check for `lib/**` and `services/**` only.
⛔ **Do not widen the glob to `components/**` or `app/(dashboard)/**` thinking it adds a check** —
that part stands, and for the same reason it should never have been trusted on `app/api/**`.

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

## ⛔ A NAME IS NOT A PATH: dots and spaces are legal in PAN-OS names (2026-09-22)

Two separate defects, one root cause — treating punctuation as structure.

- `classifyPath()` split on `.` and called the first segment the rule, so
  `Allow_URL_tfcc.fisheries.go.th` was displayed as `Allow_URL_tfcc`. **47 of 1,780 live
  rules carry a dot.** Naming a rule that does not exist is worse than naming none.
- `PATH_SHAPE_VIOLATION` treated ANY whitespace as proof of a corrupted capture, so
  `65.32 allow all` and `Batch Scan for 27.254.123.18` rendered as
  "(unreadable path — see full diff for details)" — in the rule-name column.

⛔ **The second is this repo's signature bug running BACKWARDS.** Usually a failed read is
recorded as a fact; here a perfectly good fact was recorded as a failed read. Both destroy the
operator's ability to trust the page, and the second is harder to notice because it looks
like the system being careful. When you write a guard that declares data unreadable, check
what it calls unreadable on the LIVE fleet before shipping it.

Anchor on a known FIELD TOKEN at the end, never on the separator. Pinned by
`tests/configDiffRuleNames.test.js`.

## ⛔ The Panorama origin marker is UNOBSERVABLE over SSH, and the check now says so (2026-09-22)

`undecidable_when_key: '@_panorama'` is an XML attribute the API transport produces.
`lib/adapters/paloalto/sshParser.js` builds `raw_rule` from brace-parsed attributes and emits
no `@_*` key at all — while still collecting pre/post-rulebase, i.e. Panorama-pushed rules
arrive over SSH carrying no origin marker. Same firewall, same rules: `mgmt_method: 'api'`
gives `warning`, `'ssh'` gives `fail` naming those rules.

⛔ **It is not fixable by reasoning over stored rows**, and a parser change would not repair
rows already collected. So `configAuditor` detects the absence of the marker's whole
NAMESPACE (`@_*`), not of `@_panorama` itself — a firewall with genuinely no pushed rules is
a normal state and must not be caveated — and discloses the limitation in the finding
(`originMarkerUnobservable`), calling the count an upper bound. ⛔ The `fail` and its rule
names are KEPT: a real absence on a real rule is a real finding, and burying it is the
mistake `undecidableNote` already refuses. A `pass` carries no caveat — presence was observed.

## ⛔ `log_class='vpn'` IS NOT "a VPN login", and no SUBTYPE fixes it (2026-09-24)

Measured on the live fleet over two hours: of **19,600** `log_class='vpn'` rows only **4,871** are
authentications. The rest are `portal-prelogin` (the bot hitting the portal page before it tries a
password), HIP checks, tunnel-latency, getconfig, register, logout.

| vendor | what the subtype says |
|---|---|
| `paloalto` | `portal-auth` / `gateway-auth` for logins, a dozen other subtypes for the rest |
| `fortinet` | **`vpn` for every row** — auth and non-auth alike |

⛔ **So a `log_subtype` filter works for Palo Alto and silently returns nothing for Fortinet**,
which on a forensics page reads as "this user did nothing" rather than "this filter cannot express
your question". The ONLY column that separates them is `auth_outcome`, which is exactly why
`lib/syslog/rollups.js` builds `syslog_vpn_auth_hourly` on `auth_outcome IS NOT NULL` and why
`logSearch.js` grew an `authOutcome=any` enum rather than reusing `logSubtype`.

⛔ **Class alone is ~70% noise, and that is worse than it sounds.** `/logs` orders by
`received_at DESC` and pages at 50, so the first screen of a class-only VPN search can contain NO
authentication at all — and the reader concludes the finding that linked them there has nothing
behind it. A filter that is merely imprecise becomes a confident wrong answer once a page size is
applied to it.

## ⛔ A SEARCH PARAM WITH NO FORM FIELD IS DROPPED BY THE FIRST RE-SUBMIT (2026-09-24)

`components/logs/LogSearchForm.js` is a plain GET `<form>` with **no hidden inputs** — the URL is
the query. So any param `app/(dashboard)/logs/page.js` accepts but the form cannot render
disappears the moment the operator presses Search. The search does not error and does not narrow:
it **widens**, and the wider result looks like the same query.

`srcCountry` sat in the page whitelist with no control at all until v2.178.0. It went unnoticed
because nothing linked to it; the VPN detection links do. When adding a filter, add the control in
the same commit — `tests/logSearch.test.js` asserts that every param those links emit is on the
`FILTERS` whitelist, but only a control keeps it there across a re-submit.
## ⛔ A CSV FORMULA GUARD THAT COULD NOT FIRE, PINNED BY A TEST THAT NAMED IT (2026-09-24)

`csvEscape` neutralises spreadsheet formula injection by prefixing an apostrophe to a cell
beginning `=`, `+`, `-` or `@`. Its comment said, correctly, that Excel strips a leading tab or CR
and *then* re-reads the leading character, so a naive check on index 0 is defeated by `"	=cmd..."`.

The code then did exactly that:

```js
s = s.replace(/[
	]+/g, ' ');   // 	 becomes a SPACE
if (/^[=+\-@]/.test(s)) s = `'${s}`;  // ...so index 0 is ' ', and this never fires
```

⛔ **The case the comment named was the one case not covered.** And
`tests/ruleChangeRequestReport.test.js` asserted the broken output —
`assert.equal(csvEscape('
=1+1'), '" =1+1"')` — under a test called *"newlines and tabs are folded
so they cannot hide a leading character"*. The name stated the property; the assertion pinned its
opposite. Found only because the log export wrote a fresh test for the behaviour the comment
described rather than for the behaviour the code had.

⛔ **When a comment describes a defence, test the defence, not the code.** A test written by
reading the implementation agrees with the implementation by construction, including where it is
wrong — and then makes the bug look deliberate to everyone after.

Fixed to `/^\s*[=+\-@]/`, keeping the whitespace: the apostrophe is what neutralises the value, and
deleting leading characters from an attacker-controlled log line would tidy the evidence rather
than protect the reader.

## ⛔ A ROW CEILING MADE THE QUERY SLOW, NOT SAFE (2026-09-24)

The CSV export ran the same query `/logs` runs, with `LIMIT 50001` instead of `LIMIT 51`. The page
answers in **12ms**; the export was cancelled at the 10s statement timeout. Same filters, same
window.

`ORDER BY received_at DESC LIMIT n` **only exits early if enough rows MATCH.** A result set smaller
than the ceiling therefore forces a full scan of the window — so the bound that existed to keep the
work small was the thing that made it large, for every query the operator was most likely to run.

Measured on one source address with `log_class='vpn'`:

| window | rows | time |
|---|---|---|
| 1 hour | 123 | **0.25s** |
| 23 hours | 2,254 | **97s** |

Superlinear: recent partitions are hot in the buffer cache, older ones come off the disk the
collector is writing to. ⛔ **Raising the timeout was not the fix** — the scan needs ~100s, and
`syslog_events` has no `src_ip` index by deliberate design. The window is now walked in one-hour
slices, newest first, each its own bounded statement.

⛔ **A bound is not automatically a protection. Ask what it makes the planner do.**

## ⛔ `<a download>` SWALLOWS EVERY SERVER-SIDE REFUSAL (2026-09-24)

The export answered a refusal with JSON and a 4xx/5xx, carrying a carefully worded reason and the
remedy. With the `download` attribute the browser owns the response and never renders it: Edge
showed **"export.json — Couldn't download. Something went wrong."** and nothing else. The operator
cannot tell a refusal from a broken button, and the reason reaches nobody.

⛔ **A message the user cannot see is the same as no message.** Drop the attribute and let the
browser NAVIGATE: a success still downloads and leaves the page in place (`Content-Disposition`
decides that, not the attribute), while a refusal answers **303** back to the page and renders as a
banner. Content negotiation keeps the JSON answer for an `Accept: application/json` caller, so the
route stays usable as an API.

## ⛔ `request.nextUrl.origin` IS `localhost:3000` UNDER server.js (2026-09-24)

SecVault serves TLS through `server.js`, which wraps the Next request handler rather than running
`next start`. Under that wrapper `request.nextUrl.origin` resolves to Next's internal default —
**`https://localhost:3000`** — not the host the request arrived on. Measured live on the reference
deployment, which answers on `:3010`.

`/api/logs/export` built its 303 refusal redirect from it, so a refusal on the no-JS path pointed
the browser at an address that does not exist. The banner it redirects to was never reached, and
the failure was a dead page instead of an explanation — worse than the JSON it replaced.

⛔ **Never build an absolute redirect URL from a derived origin.** A RELATIVE `Location` is legal
(RFC 7231 §7.1.2), is resolved by the browser against the URL it actually used, and cannot be wrong
about a host because it never names one. `Response.redirect()` requires an absolute URL, so a
relative one needs `new Response(null, {status: 303, headers: {Location: '/path'}})`.

⛔ **The console address is configurable at runtime** (Settings -> Certificate -> Console
address, `NEXTAUTH_URL`), so there is no compile-time origin to fall back to either. Anything that
needs the real one must read it from `NEXTAUTH_URL` or the `Host` header — and then it is one more
thing that can be misconfigured. A relative URL avoids the question entirely.

## ⛔ A COVERAGE RATIO OVER A WINDOW LONGER THAN YOUR DATA MEASURES *YOU* (2026-09-25)

`ruleHitCorrelation.getDeviceLogCoverage()` certified a log-derived "this rule saw no traffic" only
when the device logged through >= 90% of the window. Measured on the live fleet:

| | |
|---|---|
| rollup history (collector shipped 2026-09-08) | **413 hours** |
| default window | 30 days = **720 hours** |
| every device's ratio | **0.572 — FAIL** |
| hours those devices actually missed | **0** |

Every firewall was logging **100% of every hour it was possible to log**, and all 15 were reported
`no-coverage` — a phrase that names the DEVICE. The gate was measuring SecVault's own install date.
1,444 rules carried that attribution.

⛔ **NOBODY NOTICED BECAUSE THE EFFECT WAS CONSERVATIVE.** The whole log-derived measured-zero
path had never armed once, so there was no wrong number on screen to investigate — only a feature
silently doing nothing.

⛔ **AND IT WOULD HAVE ARMED ITSELF, FLEET-WIDE, ON A DATE NOBODY WROTE DOWN.** At ~100% logging
density the trailing 720-hour window crosses the 0.9 ratio around **2026-10-05** purely by the
passage of time — no deploy, no review. Log-derived `unused` findings would have begun appearing
across the fleet, including NAME-grade ones on every Palo Alto (see the grading note below). A guard
that flips from "never fires" to "fires everywhere" by calendar is not a guard.

The fix separates the two questions and gives the second its own state:

```js
// history is OURS; the ratio is the DEVICE'S. Test history FIRST -- a young
// rollup also produces a low ratio, so a ratio-first order reports the wrong
// cause and the real one never surfaces.
covered: sufficientHistory && hours >= MIN_WINDOW_HOURS && ratio >= MIN_COVERAGE_RATIO
```

`insufficient-history` is now distinct from `no-coverage`, which is the same `na`-vs-`warning`
distinction this codebase already draws for compliance: **an uncertainty that is ours must not be
recorded as a negative fact about the device.** An unreadable history is `null` — never 0, never
"assume plenty" — and denies.

⛔ **The history comes from an UNCORRELATED SCALAR SUBQUERY in the same statement**
(`(SELECT min(bucket_hour) FROM syslog_rollup_hourly) AS first_bucket`), not a second round trip.
A separate query also breaks every caller's stub pool in a way that looks like the guard is broken
rather than new — which is exactly what happened on the first attempt, across five test files.

---

## ⛔ A RULE NAME IS NOT A RULE ID, AND AN ABSENCE IS ONLY AS STRONG AS WHAT YOU SEARCHED BY (2026-09-25)

`syslog_rule_hits_hourly` identifies rules differently per vendor, and the split is **total**:

| vendor | rows | with `rule_id` | with `rule_name` |
|---|---|---|---|
| Fortinet | 61,835 | **all of them** (44 distinct) | 48,061 |
| Palo Alto | 80,203 | **NONE — NULL on every row** | all (223 distinct) |

`enrichRulesWithLogEvidence` matched by id, fell back to name, and labelled both `logEvidence:
'hits'`. Two different qualities of evidence, indistinguishable downstream.

⛔ **THE MATCH DIRECTION IS SAFE; THE ABSENCE DIRECTION IS NOT.** A match says "in use", which
only ever REFUSES a deletion. An ABSENCE says "unused", which is what `ruleAnalysis.js` turns into
an `unused` finding and a cleanup candidate — and a rule **renamed** during the window is absent
under its new name while passing traffic under its old one. On a name-only vendor that is a live
rule proposed for deletion, from a rename.

So `usageGrade` (`device` / `log-id` / `log-name` / `null`) and `deletionEvidence` (true only for
the first two). ⛔ `logEvidence` KEPT its existing values rather than splitting `'hits'` into
`'hits-id'`/`'hits-name'`: `ruleAnalysis.js` compares `logEvidence === 'hits'` to decide a
device-reported zero is CONTRADICTED by observed traffic, and moving the string would have silently
disarmed it.

⛔ **AND "NO ROWS" IS NOT "ROWS THAT NAME NOTHING".** The first guard written here refused to
certify whenever both hit maps were empty — which is also what a genuinely idle firewall looks
like, so it would have made an honestly quiet ruleset permanently unanswerable. The format case has
its own signature: the device DID produce rule-hit rows and not one carried an id or a name
(`rowsSeen > 0` with empty maps). Live example: PAKFood's single rollup row carries neither.

---

## ⛔ `Number.isFinite(Number(v))` IS NOT A "DID WE READ THIS?" GUARD (2026-09-25)

`Number(null)` is **0**, and 0 is finite. So is `Number('')`, `Number([])` and `Number(false)`.
The idiom that looks like it separates a real measurement from an unreadable one:

```js
const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : null; };  // ⛔ WRONG
```

…converts **every** unreadable input into a MEASURED ZERO — this codebase's signature bug, inside
the helper written to prevent it. CLAUDE.md already documents the exact trap for `maxDevices`
("`Number(null)` is 0 and 0 is finite, so a bare `Number.isFinite` guard on `maxDevices` would turn
'this licence does not state a count' into 'this licence covers no firewalls'"), and it recurred
anyway, in `lib/engines/coverageRegister.js`, hours after that paragraph was read.

The form that works — accept a number, or a non-empty numeric STRING (which is how `pg` returns
`count(*)`), and nothing else:

```js
const num = (v) => {
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (typeof v === 'string' && v.trim() !== '') {
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }
  return null;
};
```

⛔ **WHAT CAUGHT IT WAS THE MANDATED TEST CASE, NOT REVIEW.** CLAUDE.md's Testing section requires
every new test to include the "we could not measure this" case, not just pass and fail. Reading the
helper did not reveal it — it looks correct, and every pass/fail fixture went green. `withCap()` in
`workQueueData.js` has carried the correct form (and a comment explaining why) since it was
written; copy from there rather than re-deriving it.

## ⛔ `.env.local` GREW TO 2.2 GB AND TOOK THE CONSOLE TO PLAINTEXT (2026-09-24)

**Symptom:** a deploy reported `completed WITH ERRORS` — both verification steps failed with
*"Insufficient memory to continue the execution of the program"*. Services reported RUNNING.
`https://…:3010` refused every connection; the port WAS listening and accepted the TCP connection,
which is what made it look like a TLS fault.

**Actual state:** the console was serving **plain HTTP on 3010** with no `CREDENTIAL_KEY` and no
`NEXTAUTH_SECRET`. `app-error.log` had the only honest line:

```
Failed to load env from .env.local Error: Cannot create a string longer than 0x1fffffe8 characters
  code: ERR_STRING_TOO_LONG
```

**Cause:** PowerShell 5.1 `Get-Content` decodes with the ANSI codepage. The installer read
`.env.local` that way and wrote it back as UTF-8, so every non-ASCII character roughly doubled per
deploy. An em-dash inside a COMMENT seeded from `.env.local.example` became one 2,209,122,508-byte
line. Nothing ever read that comment.

**Recovery, if it recurs** — the `KEY=VALUE` lines survive intact at the head and tail; only the
corrupt line is huge:
1. ⛔ Do NOT delete `.env.local`. It holds `CREDENTIAL_KEY`, which exists nowhere else, and
   `.env.local.bak-*` files sit beside it.
2. Stream it with node, keeping every line under ~8 KB and discarding the rest. PowerShell byte
   loops are far too slow at this size — one took >10 minutes and had to be killed, and it held a
   LOCK that then blocked the repair.
3. Verify before swapping: compare the key SET and per-value hashes against the newest
   `.env.local.bak-*`. Print fingerprints, never values.
4. Rename the corrupt file aside rather than deleting; restart `SecVault-App`; confirm `app.log`
   says `TLS: ACTIVE` and that `https://127.0.0.1:3010/login` answers 200.

⛔ **The deploy's own verification is what caught it**, by failing. Had those two steps been
skipped, the banner would have read "completed successfully" over a console serving plaintext.

### ⛔ THE FIRST FIX ONLY CORRECTED THE READ, AND THE WRITE WAS STILL ANSI (found the same day)

`-Encoding UTF8` went onto every `Get-Content` of an env file, and the test written to hold it
filtered on `/Get-Content/` and asserted **nothing about any write**. So
`Set-Content -Path $envLocalPath -Value $envContent -NoNewline` in `Install-SecVault.ps1` — the
script that CREATES the file, nine lines above a read that had just been corrected — passed the new
guard cleanly. Measured in a PS 5.1.26100 harness: that write emits an em-dash as the single ANSI
byte `0x97`, which `Get-Content -Encoding UTF8` then reads back as `U+FFFD`.

**The same disagreement as the outage, running the other way.** It bites on a RE-RUN over a server
built before the ASCII template landed: a value containing a non-ASCII character (an `LDAP_BASE_DN`
with an accented OU, a localised `SYSLOG_ARCHIVE_DIR`) is corrupted irreversibly, and a character
with no cp1252 mapping silently becomes `?`. The read-back verification only asserts `^KEY=\S`, so a
mangled value passes it.

⛔ **AN ENCODING IS A ROUND TRIP, AND SO IS ITS TEST.** Fixing one half and testing only that half
is what left this. Writes now go through
`[System.IO.File]::WriteAllText(path, text, (New-Object System.Text.UTF8Encoding($false)))`
(no BOM, matching `Set-SecVaultEnvLine`), and `tests/installerEnvEncoding.test.js` scans READS and
WRITES separately, over `Get-Content`/`Select-String`/`switch -File` and
`Set-Content`/`Add-Content`/`Out-File`, matching env-path variables by CASE-INSENSITIVE PREFIX —
the near-miss spellings `$envLocal` and `$envLocalForScheme` are already in `Update-SecVault.ps1`
and the original fixed-string list matched neither.

⛔ **The 1 MB tripwire was also on only ONE of the two read-modify-write paths.** It lived in
`SecVault-Tls.ps1`'s `Set-SecVaultEnvLine`; `Install-SecVault.ps1` step 10 had none, so on the 2.2 GB
file it exists to catch it first made a **2.2 GB `Copy-Item` backup**, then died inside
`Get-Content -Raw` with an opaque .NET `OutOfMemoryException` instead of printing the recovery
instructions above. Both writers now carry it, and the test asserts both.

## ⛔ THE PRODUCT COULD NOT BE INSTALLED FROM SCRATCH (found 2026-09-24)

The first genuine fresh-install test of the packaged installer failed at
`node lib\migrate.js` with:

```
relation "advisories" does not exist            (SQLSTATE 42P01)
```

and, once that was fixed, again with:

```
relation "snmp_metric_snapshots" does not exist (SQLSTATE 42P01)
```

`lib/schema.sql` had a foreign key 430 lines before its target table, and two
`ALTER TABLE ... ADD COLUMN IF NOT EXISTS` 140 lines before theirs. `migrate.js` sends the file as
ONE batch, so each aborted the whole migration and the installer stopped `[FATAL]`.

⛔ **NEITHER COULD EVER HAVE BEEN SEEN ON A RUNNING SERVER.** Both statements are legal and
succeed wherever the table already exists — which is every install that has ever migrated. The file
ran on every deploy for months. `npm run dbcheck` executes real SQL and did not catch it either,
because it runs against an ESTABLISHED database.

⛔ **`IF NOT EXISTS` IS NOT AN ORDERING GUARANTEE.** `CREATE TABLE IF NOT EXISTS` guards creation;
`ADD COLUMN IF NOT EXISTS` guards the COLUMN, not the TABLE. Both read as defensive and neither is.

⛔ **AND THE FIRST GUARD WRITTEN FOR THIS WAS TOO NARROW.** It checked `REFERENCES` only, passed,
and the next live migration failed on the `ALTER`. A guard covering one shape of a defect reports
clean about the others, and the green is then read as coverage. `tests/schemaOrder.test.js` checks
REFERENCES / CREATE INDEX / ALTER TABLE / CREATE TRIGGER / COMMENT ON / INSERT INTO — widen that
list rather than narrow it.

⛔ **The lesson beyond the schema: an install path that is never run is not tested.** Everything
else about the installer had been verified statically — parse checks, AST checks, package contents,
the deploy key authenticating for real, the zip round-tripping. All of it passed. The product still
could not be installed.

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

## ⛔ `unused` fired against SecVault's own logs (fixed 2026-09-09)

`ruleAnalysis.js`'s `loggedZero` correctly required `logEvidence === 'measured-zero'`, but
`zeroFromDevice` looked only at `hit_count === 0` — while the rule object already carried
`loggedHits`/`logEvidence` from `correlateDeviceRules`. A device-reported zero that syslog directly
contradicted still produced an `unused` finding.

Live: **6 stored `unused` findings on TSR_EKC** sat on rules with `hit_count = 0` and up to
**127,069 logged hits** in 30 days. Both branches now require
`!(logEvidence === 'hits' && loggedHits > 0)`.

⛔ **Only POSITIVE log evidence contradicts.** `no-coverage`, `window-too-short`,
`rule-logging-disabled` and absent enrichment all still leave a device-measured zero reportable —
otherwise a device with no log coverage would lose every `unused` finding it legitimately has, which
is the tri-state collapsing in the other direction.

⛔ Those particular 6 rows are ALSO a stale-data problem (TSR_EKC last collected 2026-08-06, before
the `hit_count` tri-state fix) — two independent causes with one symptom. `lib/migrate.js`'s
`backfillUnmeasurableFacts()` handles the data half; this handles the code half, which a Palo Alto
counter reset with live logged traffic would reproduce on fresh data.

## ⛔ A not-measured bar segment must use `--hatch`, never a hued hatch (fixed 2026-09-09)

`/exposure`'s proportion bar drew its **unmeasured** segment as a 45° hatch in `--yellow` — the
MEDIUM step of the severity ramp — sitting between a red measured-reached and a grey measured-quiet.
So "we could not look at this" rendered as a medium-severity finding. The design system reserves
`--unmeasured` for text and `--hatch` (hueless) for a bar segment or swatch, precisely so this state
carries no severity reading. The KIND distinction the bar relies on is unaffected: hatched-vs-solid
is what carries it, and it still works in greyscale.

## Two findings from the sweep that did NOT reproduce — do not re-chase

- **`catch (_err) { throw err }`**, reported by two independent sweeps at specific lines in
  `paloalto/index.js`, `paloalto/ssh.js` and `fortinet/ssh.js`, said to throw a `ReferenceError`
  instead of the real parse error. A scan of every `catch` block in `lib/` and `services/` for an
  out-of-scope `err` reference finds **none**.
- **`VpnLoginLocations.js` showing 5 sources with no "of N"** — already correct at HEAD; both country
  lists carry `Showing 5 of N` footers and the sources table says `Busiest sources (15 of 21)`. The
  reported line number was stale.

### `clampInt` and the empty string (found live 2026-09-10)

`Number('')` is `0`, which is FINITE — so a clamp written as
`Number(String(value ?? '').trim())` turns an OMITTED parameter into `0`, which then clamps to the
MINIMUM rather than falling back to the default. Live symptom: the VPN traffic panel drew **one**
user while the total beside it said 62. Nothing threw, nothing logged, and the page looked
deliberate. Any `clampInt`-shaped helper must treat empty/whitespace as ABSENT before `Number()`.
Pinned by a test in `tests/vpnTrafficAttribution.test.js`.

### FortiOS `tunnel-up` is TWO different events, and `user=` is not always a person

⛔ **A gateway is not a person.** FortiOS emits `action="tunnel-up"` both for a real SSL-VPN
tunnel-mode login (`tunneltype="ssl-web"`/`"ssl-tunnel"`) and for a **site-to-site IPsec tunnel**
completing phase 2 (`tunneltype="ipsec"`, logid `0101037138`, logdesc *"IPsec connection status
changed"*). `tunnel-up` sat in `FORTINET_SUCCESS_ACTIONS` unconditionally, so every IPsec tunnel
coming up was recorded as a successful VPN login.

⛔ **`user=` holds the PEER GATEWAY ADDRESS on IPsec events** — the "user" of a site-to-site tunnel
with no XAuth is the peer itself, which is why those rows also carry `xauthuser="N/A"`. An address is
NOT a NULL-shaped placeholder, so `meaningful()` could never catch it: it is a real string carrying
the WRONG FACT. `xauthuser` is the genuine account when the tunnel does authenticate one.

⛔ **DO NOT "fix" this by removing `tunnel-up` from the success set.** Measured live 2026-09-10 over
36h: 15 IPsec tunnel-ups against 3 `ssl-web` + 2 `ssl-tunnel`. Those 5 are REAL logins — three rollup
rows belong to a named employee who genuinely logged in over SSL-VPN. Deleting the verb would have
erased a real person's login history to remove fake gateways. **`tunneltype` is the discriminator**,
and an absent/unrecognised tunnel type resolves to `null`, never success.

Blast radius before the repair: 14 fabricated success events, 11 fabricated rows in the PERMANENT
`syslog_vpn_auth_hourly`, ~4,000 rows in 12h carrying an address in `src_user`, and **13 fake "users"
holding ~14,000 events in the PERMANENT `syslog_user_hourly`** — the same failure this file already
recorded for the literal `"N/A"` becoming the 5th busiest user.

⛔ **The code fix only affects NEW events** — `auth_outcome`/`src_user` are computed at INGEST and
stored. `lib/migrate.js`'s `repairFortinetIpsecAuthMisclassification()` corrects the persisted rows,
and it must fix `syslog_events` as well as the rollups: `syslog_user_hourly` re-aggregates a 24h
lookback, so deleting its rows without fixing the events re-creates them within a day.

### ⛔ Next's SWC compressor silently DELETES text from concatenated template literals

Found 2026-09-10 by a browser sweep, in production, on `/vpn?vtab=detections`. The page read:

> "...where the user has at least **3least 7.**"

The source was correct. **37 characters were deleted by the minifier.**

**The trigger:** two template literals joined by `+` where the interpolations CONSTANT-FOLD. The
trailing static text of the left-hand literal is dropped.

```js
`a ${A} TAIL ` + `least ${B}.`          // const A=3, B=7  ->  "a 3least 7."
`p ${a} T1 ` + `q ${b} T2 ` + `r ${c}.` // all const       ->  "p 3q 7r 9."  (both tails gone)
```

With opaque runtime values it merges correctly, which is why this is rare and why the codebase is
full of safe-looking `\`...\` + \`...\`` (32 files). In `vpnDetections.js` it fired because
`NEW_COUNTRY_MIN_USER_DAYS = 3` and `NEW_COUNTRY_MIN_BASELINE_DAYS = 7` are module-level literals.

⛔ **RE-SPLITTING THE LITERALS DOES NOT FIX IT — it only moves which tail is eaten.** Verified: the
first rewrite rendered `"at least 3and the fleet has at least 7."` instead. The fix is to stop
using adjacent template literals: use **plain quoted strings with `+`**, or one literal, or
`[...].join('')`.

⛔ **INVISIBLE to every check this repo runs** — `node --check`, `npm test`, `jsxSyntax.test.js` and
reading the source all pass. Only the BUILT BUNDLE shows it. To check a suspect file:

```js
const { minify } = require('next/dist/build/swc');
minify(require('fs').readFileSync(f, 'utf8'), { compress: true, mangle: false })
  .then((r) => console.log((typeof r === 'string' ? r : r.code)));
```

A whole-repo scan found this as the only user-visible loss, but the hazard is live wherever a
module-level numeric const is interpolated into concatenated template literals.

### ⛔ A new step in Update-SecVault.ps1 does not run on the deploy that adds it

Found 2026-09-12. `lib/pg-server-settings.sql` and its installer step were committed, pushed and
deployed; the deploy log showed the file arriving in the `git pull`, and the DEPLOYED script
contained the step — but only the older `schema-grants` step executed, and `log_lock_waits` stayed
`off`.

The reason: **`Update-SecVault.ps1` updates itself.** PowerShell has already parsed the running
script by the time step 3 (`git pull`) replaces it on disk, so a newly added step first executes on
the NEXT deploy. A second, no-op deploy applied it (`ALTER SYSTEM` in the log, setting `on`).

⛔ So when adding a step to the update script, expect to deploy TWICE, and verify the step's EFFECT
rather than the deploy's exit code — this one reported "completed successfully" both times. The same
trap applies to any change in the update script itself: new service handling, changed ordering, a
new migration invocation.

### ⛔ Raising a CODE DEFAULT does nothing when the deployed `.env.local` sets that key

Found 2026-09-12, immediately after the entry above, and by the same class of mistake: a fix that
was committed, deployed, and WRONG in production while every check said otherwise.

`SYSLOG_MAX_BUFFER`'s default was raised 200000 -> 400000 in `services/collector.js`, and
`.env.local.example` was updated to match. Both correct, both useless: the deployed
`C:AppsSecVault.env.local` carried an explicit `SYSLOG_MAX_BUFFER=200000`, which wins. The
collector kept running with the old buffer across the deploy that "raised" it.

⛔ **`.env.local.example` IS NOT THE DEPLOYED FILE.** It is a template, gitignored-sibling
documentation, and nothing reads it at runtime. `Update-SecVault.ps1` never copies it over a live
`.env.local` (correctly -- that would destroy `CREDENTIAL_KEY` and orphan every stored
credential). So for any key ALREADY PRESENT in a deployment's `.env.local`, changing the code
default changes nothing there, forever.

What caught it was a startup banner line, added in the same commit, that reports the value the
process actually resolved:

```
[collector] buffer    : 400,000 datagrams; wide rollup sweeps defer above 100,000
```

⛔ **This is why an effective-configuration banner is worth the four lines it costs.** Without it
the deploy log, the service state, the version number and the test suite were all green and the
fix was simply absent. A config value is not applied because you changed its default -- it is
applied when the running process says it resolved to the new one.

Same shape as the self-update trap above, and the same rule: **verify the EFFECT, never the
deploy.**

Measured on the reference deployment 2026-09-12, its `.env.local` sets 13 `SYSLOG_*` keys, and
they fall into three groups worth telling apart before changing any default:

- **Genuinely divergent** — `SYSLOG_ARCHIVE_RETENTION_DAYS=45` against a code default of 60
  (⛔ and against the 60 this repo's own env list documents). Changing the default here is a
  no-op on this box, and the documented number is not the number running.
- **Present but IDENTICAL to the default** — `SYSLOG_UDP_PORT`/`SYSLOG_TCP_PORT` (`514,1514`),
  `SYSLOG_FLUSH_MS`, `SYSLOG_RETENTION_DAYS`, `SYSLOG_RAW_MESSAGE`, the three rollup keys.
  ⛔ These are the dangerous ones: they behave exactly like an unset key TODAY, so nothing hints
  they are pinned, and a future default change silently does not apply. `SYSLOG_MAX_BUFFER` was
  in this group until it was edited.
- **Absent, so the code default genuinely governs** — `SYSLOG_DETAIL_RETENTION_DAYS`,
  `SYSLOG_SPOOL_RETRY_MINUTES`. Only for these does editing the default change production.

So: before "raising a default" as a fix, read the deployed `.env.local` for that key. If it is
present at all — even at the same value — the default is decoration and the file is what runs.

⚠️ Fixing it means editing a production file that holds `CREDENTIAL_KEY`, `NEXTAUTH_SECRET` and
`PG_ADMIN_PASSWORD`: back it up first, edit the ONE line by anchored regex (never rewrite the
file), never print its contents, and confirm the other keys survived by COUNT. The collector then
needs a restart, which costs whatever UDP arrives while it is down -- the spool protects what was
already received, not what is still in flight.

### ⛔ The TLS step: three self-inflicted failures in one PowerShell block (2026-09-14)

v2.112.0 shipped a working TLS implementation that did not turn on, three
deploys running. Each failure was a different shape and all three are worth
knowing, because none of them produced an error that named the real cause.

**1. `2>&1` on a native executable.** OpenSSL writes key-generation progress
(`+++++...`) to stderr. With `$ErrorActionPreference = 'Stop'` — which
`Update-SecVault.ps1` sets deliberately — PS 5.1 wraps each stderr line in an
ErrorRecord, so a *successful* keygen threw and was reported as
"OpenSSL failed: +++++...". ⛔ This is documented in CLAUDE.md's PowerShell
section AND in this script's own header comment, which explains the trap at
length; the script even carries an `Invoke-Native` helper built to avoid it. A
shared helper dot-sourced by both installers cannot use that helper, so it
relaxes the preference itself and judges success by EXIT CODE and files on disk.

**2. A step that reported success while doing nothing.** `Invoke-Step` logs
"succeeded" when the block does not THROW, and every failure path inside the TLS
step returns early with a `[WARN]`. The log therefore read `[WARN] OpenSSL
failed` immediately followed by `Step succeeded: Enable TLS`. ⛔ A step whose
failure modes are early returns must state its own outcome — it now logs
`TLS: ENABLED` or `TLS: NOT ENABLED` explicitly.

**3. An undefined variable that looked like a syntax error.** `$NssmExe` was
never defined in this script (it exists in `Install-SecVault.ps1`). PowerShell
reported *"The expression after '&' in a pipeline element produced an object
that was not valid"*, which reads as a parsing problem rather than "that
variable does not exist". ⛔ Before shipping a block that touches variables from
elsewhere in a long script, grep that every one is actually DEFINED there — a
ten-second check that would have saved two deploy cycles.

⛔ **And the helper was dot-sourced BEFORE `git pull`**, so a fix to it could
never take effect on the deploy that delivered it. It is re-sourced after the
pull now. The update script itself still self-updates and needs two deploys,
which is unavoidable — it is already parsed and running.

⛔ **`schtasks /run` on an already-running task is a SILENT NO-OP.** Firing the
"second" deploy while the first was still going did nothing at all, and the
logs made it look like both had run. Wait for the task to leave `Running` before
triggering it again — and wait for it to ENTER `Running` before concluding it
has finished, or the check returns instantly against the previous run.

### ⛔ A custom Next server must load .env.local ITSELF (2026-09-14, caused an outage)

`next start` calls `loadEnvConfig()` for you. A CUSTOM server does not get that
for free, and `server.js` reads `TLS_CERT_PATH` at its top level — before
`next()` is even constructed.

On the server those paths live in `.env.local`, so `resolveTlsConfig()` saw an
empty `process.env`, reported **"TLS: not configured"**, and served plain HTTP.
Everything else worked, because Next loads the env for the APP's code — only
this file's own top-level read was empty, which is what made it hard to see.

The consequence was not a quiet mis-report. The updater's HTTPS probe correctly
found nothing listening on TLS, fired its rollback, and the rollback then wrote
a corrupt `AppParameters` (see below) — so the console went DOWN. A missing
`require('@next/env').loadEnvConfig(process.cwd())` cost a production outage.

⛔ **AND IT IS WHY THE LOCAL TEST PASSED.** The local run exported `TLS_CERT_PATH`
in the shell, so `process.env` already held it and the missing load was
invisible. **A local test that supplies configuration differently from
production is not testing the path production takes.** Re-run with the values in
`.env.local` and nothing exported — that reproduced it immediately.

### ⛔ `nssm get` returns UTF-16 with NULs — never round-trip it into `nssm set`

The TLS rollback captured the old entry point with `& $NssmExe get SecVault-App
AppParameters` and wrote it back on failure. That output carries embedded NULs,
so `nssm set` truncated it to **`n`**: the service could not start at all, and
the SAFETY NET became the outage it existed to prevent.

Strip NULs on capture (`-replace "`0", ''`), and — more importantly — never
trust the captured value: if it does not look like the real entry point, write
the documented literal instead. A rollback is the one path that must not fail.

### ⛔ `ServerCertificateValidationCallback = { $true }` DOES NOT WORK in PS 5.1 (2026-09-14, two outages)

This is the answer in every search result for "PowerShell ignore self-signed
certificate", and in Windows PowerShell 5.1 it is wrong. .NET invokes that
delegate on a BACKGROUND THREAD with no PowerShell runspace, so the scriptblock
throws:

    There is no Runspace available to run scripts in this thread.
    The script block you attempted to invoke was:  $true

…and the request dies with the far less helpful *"The underlying connection was
closed: An unexpected error occurred on a send."* The inner exception is the
only place the real reason appears.

⛔ **WHAT IT COST.** `Update-SecVault.ps1` probes the console over HTTPS after
enabling TLS and rolls back if it does not answer. The probe could never
succeed, so it returned a FALSE NEGATIVE every time — the app log read
`[secvault] TLS: ACTIVE … listening on https://0.0.0.0:3010` at the exact moment
the updater concluded the console was dead and tore a working deployment down.
Twice.

**A false negative in a health check is worse than having no health check**, because
it actively destroys a good deployment. Two separate bugs were blamed and fixed
before the probe itself was suspected — it was the one component never tested,
precisely because it was the thing doing the testing.

Use `ICertificatePolicy` instead: a real .NET type whose method runs on the
calling thread.

    if (-not ('SecVaultTrustAllCerts' -as [type])) { Add-Type -TypeDefinition @'
    using System.Net; using System.Security.Cryptography.X509Certificates;
    public class SecVaultTrustAllCerts : ICertificatePolicy {
      public bool CheckValidationResult(ServicePoint sp, X509Certificate c, WebRequest r, int p) { return true; }
    }
    '@ }
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object SecVaultTrustAllCerts

⛔ **TEST THE TEST.** Verify a health check returns TRUE against a known-good
server before trusting it to condemn one — and check it still returns FALSE for a
genuinely dead port, or "fixing" it by making it always true is the next bug.

## Git-for-Windows OpenSSL has NO legacy provider (v2.118.0)

⛔ `pfxToPem`'s `-legacy` retry masked the real error. The bundled OpenSSL has no legacy provider
module, so `-legacy` ALWAYS dies with `unable to load provider legacy` — and the retry read only
the SECOND stderr, overwriting the first attempt's `Mac verify error: invalid password?`. A
mistyped .pfx password therefore produced a vague catch-all. Both stderrs are now scanned,
password failures detected first, and a genuinely legacy-encrypted .pfx gets a message saying the
password is NOT the problem.

## Install-SecVault.ps1 now wires TLS (v2.118.0)

It previously had NO TLS wiring at all, while `SecVault-Tls.ps1` claimed to be "dot-sourced by
BOTH installer scripts" and `Update-SecVault.ps1` claimed "fresh installs set this" — both false.
A new customer got plaintext with no path to HTTPS. New step 14b mints the cert, sets the env keys
and registers `server.js`; new `-EnableTls` / `-HttpRedirectPort` params. ⛔ Its rollback restores a
LITERAL entry point and never reads `nssm get` back, so the UTF-16/NUL corruption cannot recur there.

## ACLs on the private key use well-known SIDs, not English names (v2.118.0)

⛔ `SetAccessRuleProtection($true,$false)` followed by grants to the STRINGS "SYSTEM"/"Administrators"
does not resolve on a non-English Windows: inheritance is stripped and then no grant is added,
leaving the private key with an EMPTY ACL and only a friendly note in the log. Now `S-1-5-18` /
`S-1-5-32-544`.


## ⛔ "Top websites" is NOT buildable from `url_hostname` — do not try (measured 2026-09-21)

Management asks for it by name ("can we see traffic to YouTube, Facebook"), the column exists, and
a query against it returns rows. All three are true and it is still the wrong feature.

`syslog_events.url_hostname` measured over a 20-minute live window: **18,723 of ~1,405,000 events
(1.3%)**, and five Palo Altos — SMT, TUM(TUTH1), TUG, ITC-SLY, IDC FW — reported **zero**. It also
has **no rollup**, so whatever is there dies with the 30-day partitions, and `syslog_events` may
never be scanned for a ranking (no `src_ip`/hostname index, ~28M rows/day; the whole reason
`logSearch.js` needs three bounds).

So a "Top websites" table would describe a fortieth of the traffic under a heading claiming the
estate — and, worse, would look complete. **The answerable question is the APPLICATION**
(`youtube-base`, `facebook-base`, `tiktok-base`), which IS rolled up hourly with byte counts and
retained: live 24h, facebook-base 33.9 GB / tiktok-base 24.1 GB / youtube-base 4.8 GB. Both the
Traffic Activity PDF and `WebActivityPanel` say out loud why there is no hostname list, because an
unexplained absence reads as an oversight and invites the next session to add it from exactly this
data.

Closing it needs URL-filtering log profiles enabled on the firewalls AND a `syslog_url_hourly`
rollup argued on measured cardinality — an ingestion-cost decision, not a query change.

## ⛔ A chart is the one claim nobody checks (v2.157.0)

A wrong number in a table gets queried by the person who knows what it should be. A wrong bar just
looks like a bar. Every honesty rule this codebase applies to a figure applies to its picture, and
the failure modes are listed with their fixes under `lib.md`'s chassis-charts section. The two that
were NOT hypothetical, both found by rendering the real PDF against live data and looking at it:

1. **A chart sliced to 15 by its caller rendered 10** and looked complete — `drawBarChart`'s `max`
   defaults to 10 and truncates silently. Every call site now spells `max` out.
2. **Two palette entries were grey and near-black**, so `ms-ds-smbv3` rendered in the exact grey
   this product reserves for "not measured". Colour that means something elsewhere cannot be
   borrowed for decoration here.

⛔ AND THE PROCESS POINT: neither was visible to any unit test, and both were obvious in one
screenshot. Rasterise the PDF and LOOK at it (`pymupdf`, `get_pixmap`) before committing a report
change — the same lesson as the cover-chips bug one version earlier, which also only surfaced
against real data.


## ⛔ `firewall_rules.hit_count` IS A LIFETIME COUNTER, NOT A WINDOW (measured 2026-09-21)

The column is tri-state and every rule about NULL still holds — but the NUMBER, when present, is
the firewall's own counter since IT last reset, on a date SecVault does not know and which differs
per device. It is NOT "hits in the last N days", and `ruleHitCorrelation.js`'s `effectiveHitCount`
prefers it over log-derived hits.

That preference is CORRECT for `unused` (a device-reported zero is the strongest evidence
available) and WRONG for anything windowed. Measured against the same rules' 30-day logged hits:

| rule | device counter | logged 30d | ratio |
|---|---|---|---|
| `Allow-M365-MDE-Intune` (TUM) | 4,183,915,499 | 3,886,420 | 1,076x |
| `Private2LAN` (SMT) | 4,085,493,504 | 24,519,895 | 167x |
| `PRIVATE TO DMZ1` (IDC FW) | 4,000,924,982 | **0** | — |

⛔ So a fleet-wide ranking built on it compares numbers that were never comparable, and the last
row is the proof: 4 billion lifetime hits beside nothing at all in the window. Any report or widget
answering "in the last N days" must rank on `loggedHits` from `syslog_rule_hits_hourly`. Keep the
counter if it is useful — label it lifetime, never sum it, never compare it between rows.

## ⛔ A 30-DAY WINDOW CANNOT BE COVERED ON THIS FLEET YET

`ruleHitCorrelation.getDeviceLogCoverage` calls a device covered only at `MIN_COVERAGE_RATIO` 0.9
of the window. The collector started 2026-09-08, so ~313 hours exist: at 7 days all 15 logging
devices are covered (ratio 1.01) and at 30 days **none** is (ratio 0.43).

⛔ The consequence is not a smaller number, it is a DIFFERENT KIND OF ANSWER: with no device
covered, nothing is ever `measured-zero`, so every "this rule carried no traffic" list is empty.
Empty because unmeasurable, which reads exactly like empty because clean. Any feature defaulting to
30 days over rule-hit evidence inherits this — default to 7 and say which window was used.


## ⛔ What the six-agent sweep of 2026-09-21 found, and the one pattern behind it

Nine P0 fixes in v2.160.0 and seven more in v2.161.0. Four were in code already
running on the reference deployment. The individual defects are documented at
their sites; what is worth carrying forward is that **almost every one shipped
past a test that asserted the SHAPE of the code rather than its BEHAVIOUR.**

The clearest case: the login page's open-redirect guard was covered by
`assert.match(src, /startsWith\('\/\/'\)/)` — a regex proving a string existed
in a file. Replacing the entire function with `raw => raw` left the suite green.
The guard was bypassable with an embedded tab and shipped anyway.

⛔ **A test that reads source text can only prove a line exists. It cannot prove
the line runs, that it runs before the thing it guards, or that it is correct.**
Where a behavioural test is impossible because the function lives in a client
component, that is a signal to MOVE THE FUNCTION, not to settle for a regex —
which is why `lib/returnPath.js` exists as its own pure module.

Second pattern, three independent instances: **a function whose empty case had a
different TYPE from its full case.** `windowAppBytes` returned `[]` on its early
exits and an object otherwise, and every per-firewall report on a Fortinet was a
500. Same class as `getRules()` returning `[]`, and it will not be the last.

Third: **`bool_or()` on the outer side of a LEFT JOIN returns `false`, never
`NULL`**, because `x IS NOT NULL` never evaluates to NULL. Any tri-state built
that way is silently a two-state. Use `FILTER (WHERE <joined>.id IS NOT NULL)`
so the aggregate sees zero rows and returns NULL.

Fourth: **`sum(...) FILTER (...)` returns NULL when no row matches the filter**,
which is NOT the same as "the column was never populated". Distinguishing them
needs a second aggregate counting rows that carry the column at all.

## ⛔ CSV EXPORTS: EIGHT FILES HAND-ROLLED THE ESCAPING, SEVEN STILL DO (found 2026-09-25)

`lib/csv.js` is the shared, correct implementation. It ALWAYS quotes (conditional quoting means
deciding per value whether it contains a separator, and one wrong call shifts every column after
it), folds newlines/CRs/tabs to a space, doubles internal quotes, and **neutralises a leading
formula character** with `/^\s*[=+\-@]/` -> prefix `'`. The `^\s*` is deliberate: an earlier version
folded whitespace to a space BEFORE testing `^[=+\-@]`, so the guard could never fire.

**Why it matters:** a cell beginning `=`, `+`, `-` or `@` is executed as a formula when the file is
opened in Excel or LibreOffice. These exports carry values that originate OUTSIDE SecVault — device
names, rule names, firewall rule COMMENTS an administrator typed, compliance finding reasons.

**RESOLVED 2026-09-25 (v2.185.0 + v2.185.1): ALL EIGHT ARE MIGRATED.** `lib/csv.js` is now the
only CSV escape in the repo.

⛔ **THE SHARPEST FORM OF THE DEFECT, worth keeping because it explains why nobody noticed:** the old
test was `/[",

]/`, and the canonical payload `=cmd|'/c calc'!A1` contains no comma, no quote
and no newline. So the most dangerous value in the export was not "quoted but un-neutralised" — it
was written out **RAW AND UNQUOTED**. `@SUM(1,1)` got quoted only by the luck of its comma, and was
still a live formula.

⛔ **THE MIGRATION TRAP, hit in three of the eight:** `csvEscape` does a bare `String(value)`. Several
routes ran `typeof value === 'object' ? JSON.stringify(value) : String(value)` BEFORE escaping, and
that transformation is load-bearing — `devices/[id]/rules` has **six JSONB columns** (src/dst
addresses, services, applications, src/dst zones) which node-postgres hands back as real arrays, and
`vpn/fleet` + `devices/[id]/vpn` export `TIMESTAMPTZ` as JS `Date` objects. Dropping the branch turns
an address list into `[object Object]` and silently rewrites every timestamp to the server's local
zone. Each migration kept it at the CALL SITE so a string reaches `csvRow`.
⛔ And the null guard must stay AHEAD of the object test: `typeof null === 'object'`, so the wrong
order writes the literal text `null` into cells that were always empty.

⛔ `tests/csvInjection.test.js` is now an ABSOLUTE invariant rather than a tolerance list: no file
outside `lib/csv.js` may define a CSV escape at all, each of the eight routes is pinned BY NAME (a
revert fails saying which, and naming the cells at risk), and a separate case asserts the scan
actually walked >400 files — the previous version's second assertion looped over a list that emptied
itself as the work completed, which is this file's own "a scan over nothing passes" trap.

⛔ **TWO PRE-EXISTING GAPS FOUND AND DELIBERATELY NOT FIXED** (an encoding commit is not the place):
1. `compliance/[deviceId]`'s Matched Rules does `.map(id => ruleNamesById.get(id)).filter(Boolean)`,
   and `firewall_rules` is DELETE+reinserted every pull — so "matched rules we can no longer name"
   exports IDENTICALLY to "matched no rules", in the evidence column of a compliance export.
2. Timestamp formats disagree between siblings: `vpn/fleet` and `devices/[id]/vpn` emit a JSON date
   literal (quotes and all), `devices/[id]/snmp` emits the server-local `Date#toString`. Caused by
   one family having the object branch and the other not.

⛔ Not defects: `lib/syslog/actions.js`'s `sqlList` `.join(',')` builds a SQL fragment from module
constants, and the other `join(',')` hits are query-string or SQL builders, not CSV.
