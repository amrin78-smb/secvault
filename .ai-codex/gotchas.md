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
  disabled-rule visibility, no real logging state, no hit counts, no NAT. **The SSH transport's
  version is live-verified (33/33 rules confirmed); the XML/API transport's version (added
  2026-07-23) is NOT yet live-verified** — its request construction is proven, but the response
  shape is doc-derived. Don't assume the API-transport fallback is trustworthy until checked
  against a real device's `[PaloAlto Debug] effective security-policy raw response` log line.
- Sangfor has no live device, no documentation trail — every field mapping is doc-derived and
  explicitly marked low-confidence; `getObjects()` deliberately returns an empty stub rather than
  guess at unverified block syntax.

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
— current canonical copies: `lib/adapters/forcepoint/parser.js` (`SECRET_KEY_PATTERN`),
`lib/engines/configDiff.js` (`SECRET_PATH_PATTERN`, the widened/fixed version — includes `phash` and
`pre[-_]?shared`, which a narrower `private[-_]?key`-only check does NOT match). Widen ALL copies
together — `lib/adapters/checkpoint/parser.js`'s own `SECRET_KEY_PATTERN` is the OLDER, narrower
form (missing `phash`/`pre-shared`/`keytab`) and should be checked against this list whenever any
sibling copy changes.

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
