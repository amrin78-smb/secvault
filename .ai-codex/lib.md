# lib/ — Library Export Index

Every export from `lib/`, grouped by file. `[SENSITIVE]` = touches credentials, encryption,
device auth, or config/secret storage — treat any change to these with extra care.

Part 1: `lib/*.js` (root) + `lib/engines/**`. Part 2: `lib/adapters/**` + `lib/feeds/**`.

---

## lib/db.js

`pool` -> `pg.Pool` — singleton PostgreSQL connection pool (`connectionString: DATABASE_URL`); has an `error` listener registered to prevent unhandled-rejection crashes on idle-client errors.

## lib/activityLog.js

`logActivity(pool, {actor, action, deviceId, detail})` -> `Promise<void>` — inserts one `activity_log` audit row; NEVER throws (catches and console.warns on failure).

## lib/apiUtils.js

`isValidUuid(value)` -> `boolean` — regex-checks a string looks like a UUID (8-4-4-4-12 hex), used to guard path params before hitting a UUID-typed SQL column.

## lib/theme.js
(ES module, `'use client'` — exports via `export`, not `module.exports`; only top-level `lib/*.js` file that isn't CommonJS)

`THEME_KEY` -> `string` — `'secvault-theme'`, the localStorage key.
`getTheme()` -> `'light'|'dark'` — reads current `data-theme` attribute off `<html>`.
`applyTheme(theme)` -> `void` — sets/removes `data-theme="dark"` on `<html>`, persists to localStorage, dispatches `secvault:theme` CustomEvent.
`toggleTheme()` -> `'light'|'dark'` — flips current theme via `applyTheme`, returns the new value.
`THEME_INIT_SCRIPT` -> `string` — inline `<script>` body (no-flash theme pre-paint init), injected into `app/layout.js`'s `<head>`.

## lib/credStore.js
[SENSITIVE] — entire file (AES-256-GCM credential encryption)

`encrypt(plaintext)` -> `{encrypted: string, iv: string}` — AES-256-GCM encrypt; `encrypted` = `hex(ciphertext):hex(authTag)`, `iv` = hex. Key from `CREDENTIAL_KEY` env (32-byte hex). [SENSITIVE]
`decrypt(encrypted, iv)` -> `string` (plaintext) — inverse of `encrypt`. [SENSITIVE]
`getCredential(deviceId, credentialType, pool)` -> `Promise<string|null>` — fetches+decrypts latest `device_credentials` row for `(deviceId, credentialType)`. Requires `pool`. [SENSITIVE]
`setCredential(deviceId, credentialType, plaintext, pool)` -> `Promise<void>` — encrypts + `INSERT ... ON CONFLICT (device_id, credential_type) DO UPDATE` (atomic upsert, relies on `UNIQUE(device_id, credential_type)`). Requires `pool`. [SENSITIVE]

## lib/feedStatus.js

`getLastSyncs(pool)` -> `Promise<object[]>` — up to 10 most recent `feed_sync_log` rows (`feed_name, status, started_at, finished_at`).
`getSyncPillStatus(pool)` -> `Promise<{ok: boolean, label: string, lastSyncs: object[]}>` — condensed header-pill status across `nvd`/`paloalto_psirt`/`fortinet_psirt`/`kev`; `label` is `'NO SYNC YET'|'FEEDS OK'|'FEED ERROR'`.

## lib/formatDisplay.js

Added v2.83.0 during the raw-text UI sweep; indexed 2026-09-09. Pure, no DB, CommonJS — the shared
home for "a stored value, in words". Server and client components both import it.

`timeAgo(value)` -> `string|null` — `'4 min ago'` / `'in 2 h'`; `null` (not `'—'`, not `'never'`) when the value is absent or unparseable, so the CALLER decides what absence reads as.
`absoluteUtc(value)` -> `string|null` — `'2026-09-09 08:41 UTC'`. Always paired with `timeAgo` on a `title=`, because a relative time alone cannot be cross-referenced against a device log.
`titleCase(v)` -> `string` — `snake_case`/`kebab-case` enum to `'Snake Case'`. For vendor action words and status enums with no curated label.
`FEED_LABELS` -> `object` — feed slug to product name (`nvd` -> `'NVD'`, `kev` -> `'CISA KEV'`).
`feedStatusRank(status)` -> `number` — sort order for feed status. ⛔ An UNKNOWN status ranks as bad (`1`), not good — a status this app has never seen is not evidence things are fine.
`newestFeedAt(rows)` -> `Date|null` — newest `finished_at || started_at` across feed rows. ⛔ The column is `finished_at`; asking for `completed_at` here and on the dashboard is what took `/` down on 2026-09-09 (gotchas.md).
`STANDARD_LABELS` / `standardLabel(key)` -> `string` — compliance standard DB key to its real name (`PCI_DSS` -> `'PCI DSS'`). Unrecognised keys fall through to `titleCase`, never to a guess.

## lib/density.js

Client module. Table density, stamped as `data-density` on `<html>`. Structural mirror of lib/corners.js and lib/theme.js — same storage/attribute/event/no-flash-script shape, so there is one pattern for all three.

`DENSITIES` -> `string[]` — `['comfortable','compact','dense']`; the default is first, and a value not in this list is ignored rather than guessed at.
`DENSITY_LABELS` -> `object` — display names.
`getDensity()` / `applyDensity(d)` / `DENSITY_INIT_SCRIPT` — read, set (+persist +`secvault:density` event), and the pre-paint inline script.
⛔ Works ONLY because table padding/font resolve through `--row-pad-y`/`--row-pad-x`/`--row-font`. A hardcoded cell padding opts itself out silently.
⛔ Density changes ROW GEOMETRY ONLY — it must never hide a column, truncate a value or drop a badge. A denser table shows the same facts in less space, not fewer facts.

## lib/savedViews.js

Named filter/column/sort states per user per table (`saved_views`). All functions take `pool`.

`listSavedViews(pool, userId, scope)` -> own views plus anyone’s shared ones; own sort first.
`saveView(pool, userId, {scope,name,query,shared,isDefault})` -> upsert on (user_id, scope, name). ⛔ Clears the previous default INSIDE the transaction BEFORE inserting — `uq_saved_views_one_default` is a real partial unique index, so the other order fails the insert instead of moving the default (same rule as `device_configs.is_baseline`).
`deleteSavedView(pool, userId, id)` -> ⛔ owner scoping lives in the SQL WHERE clause, not the route, so no future caller can forget it.
`getDefaultView(pool, userId, scope)`.
`normalizeScope/Name/Query` — ⛔ the stored query string is REPLAYED into the address bar, so it is untrusted input: leading `?` stripped, length capped, anything with whitespace, quotes, a scheme or a path separator rejected.

## lib/evidence.js

(v2.107.0) Pure, dependency-free CommonJS builders that turn data a caller ALREADY HAS into a
serializable evidence descriptor `{title, claim, formula, inputs[], unmeasured[], source, rule?}`
for components/ui/Evidence.js. Runs no queries and imports no pool, which is what lets a React
SERVER component build one and pass it to the client drawer as a prop.

Exports: `isRenderableEvidence` (the guard — a mark never renders without it),
`deviceCountEvidence`, `securityScoreEvidence`, `patchNowEvidence`, `highRiskEvidence`,
`rulesEvidence`, `complianceScoreEvidence`, `cveCoverageGap`, (v2.108.0)
`cvePostureEvidence`, `deviceComplianceEvidence`, `ruleHygieneEvidence`, and (v2.109.0)
`lifecycleEvidence`, `deviceInventoryEvidence`, `exposureEvidence`.

⛔ `source` and `rule` are CUSTOMER-FACING PROSE rendered verbatim in the drawer footer: a
PRODUCT name ("CVE prioritisation engine") and a SecVault POLICY name, never a source path and
never CLAUDE.md. Pinned by `tests/noInternalRefs.test.js`.

⛔ `cvePostureEvidence` shows BOTH units side by side and labels them — `*_cves` is
COUNT(DISTINCT advisory_id), `*_count` is device-CVE PAIRS. They never sum together, and the
dashboard shipped that exact conflation once (v2.107.0: "3 vulnerabilities" for one CVE on three
firewalls). ⛔ `ruleHygieneEvidence` renders hit_count's three buckets explicitly (with-hits /
measured-zero / NOT MEASURED) and states that unmeasured rules are REFUSED from cleanup requests
server-side, not merely flagged.

⛔ `unmeasured: []` IS A CLAIM — the drawer renders it as "everything this number depends on was
measured". Never leave it empty to mean "I did not look". ⛔ Never fabricate an input: if the caller
does not have the number, the row does not appear and the builder returns null, because a plausible
0 inside an evidence panel is worse than the same 0 on a tile — the panel is where the operator went
specifically to check. ⛔ `securityScoreEvidence` DERIVES its formula from the components the engine
returned rather than restating 40/30/30, so a weight change in securityScore.js cannot leave the
drawer confidently explaining arithmetic that no longer runs. Pinned by tests/evidence.test.js.

## lib/answers.js

(v2.107.0) `buildFleetAnswer(headline)` -> `{sentence, lead, tone, coverage}`. The one-sentence
plain-English answer above the dashboard grid. Pure CommonJS.

(v2.108.0) also `buildCveAnswer`, `buildDeviceComplianceAnswer`, `buildRuleHygieneAnswer`, and
(v2.109.0) `buildLifecycleAnswer`, `buildDeviceInventoryAnswer`, `buildExposureAnswer` — one per
wired page, each with its OWN coverage question: unassessed devices / `na` checks / rules with no
usage data / an unparseable licence expiry / never-probed devices / never-watched exposure paths.

⛔ FOUR tones, not three: `critical`/`warn`/`ok`/`unknown`. An ALL-CLEAR IS FORBIDDEN WHILE COVERAGE
IS INCOMPLETE — "nothing outstanding" over a fleet where three firewalls were never assessed returns
`unknown` (hueless), never `ok` (green). That is the failed-read-as-a-fact rule in prose, and it is
the whole reason this is a module with tests rather than a template string in a component. ⛔ The
coverage caveat SURVIVES the critical branch too: a gap does not stop mattering because something
worse was found — the real number may be higher than the one displayed.

## lib/totp.js

(v2.111.0) Pure RFC 6238 TOTP + RFC 4648 base32 on node `crypto`. Zero dependencies. Exports
`generateSecret`, `generateCode`, `verifyCode` (returns `{valid, counter}` so the caller can
enforce single use), `buildOtpauthUri`, `base32Encode/Decode`, `hotp`, `counterFor`.
⛔ HMAC-SHA1 is the RFC default and what every authenticator implements — not a defect.
⛔ ±1 step window only; each extra step widens the replay window by 30s.
Pinned against RFC 6238's published vectors in `tests/mfa.test.js`.

## lib/mfa.js

(v2.111.0) Stateful MFA over `lib/totp.js`: `startEnrolment`, `confirmEnrolment`,
`verifyForLogin`, `getStatus`, `isEnabledFor`, `resetFor`, `setRequired`. Secret encrypted with
credStore's AES-256-GCM; recovery codes bcrypt-hashed.
⛔ `verifyForLogin` enforces SINGLE USE via `last_counter` (`<=`, not `!==`) and consumes a used
recovery code by deleting it. ⛔ A short code never reaches the bcrypt loop — otherwise every
failed 6-digit attempt runs ten compares and the form becomes a CPU-exhaustion target.
⛔ `getStatus` never returns the secret or the hashes. ⛔ A placeholder row created by
`setRequired` is NOT an enrolment (`enrolled` checks for a secret).

## lib/mfa-reset.js

(v2.111.0) Offline CLI: `node lib/mfa-reset.js <username>` / `--list`. The third lockout path.
⛔ Guarded by `require.main === module` — without it, merely requiring the file runs `main()` and
sets a non-zero exit code, which is exactly what `tests/moduleLoad.test.js` caught.

## lib/tlsConfig.js

(v2.112.0) `resolveTlsConfig(env, fsImpl)` -> THREE states: `active` / `disabled` / `failed`.
⛔ `failed` (certs configured but unreadable, or half-configured — one path set alone) must
never be reported as `disabled`. Also `describeTlsStatus`, `nextAuthUrlMismatch` (catches the
scheme mismatch that breaks sign-in silently) and `portFrom` (junk never yields NaN or 0 — a
port of 0 binds a RANDOM port and presents as "started but unreachable").

## lib/certValidate.js

(v2.112.0) `validateCertificatePair(certPem, keyPem, now)` and `describeCertificate(certPem)`.
⛔ The pair check uses `X509Certificate.checkPrivateKey()` — a mismatched certificate and key
both parse fine and fail only at the TLS handshake, i.e. at the next restart. Refuses an
expired certificate and one with no SANs (browsers ignore the CN). ⛔ `describeCertificate` is
separate because `validateCertificatePair` refuses a missing key BEFORE parsing anything.

## lib/engines/segmentation.js

(v2.113.0) PURE. `evaluateIntent(intent, rules, ctx)` -> a verdict; `summarise`, `zoneListMatches`,
`trafficEvidence`, `isAllowAction`/`isDenyAction`, `VERDICTS`.
⛔ `any` and an EMPTY zone list are both WILDCARDS — matching literally understates reachability,
which on a segmentation report is a false assurance. ⛔ `trafficEvidence` is tri-state and `null`
WINS OVER `false`: one unmeasured permitting rule makes the pair UNKNOWN, because that rule might
be the one carrying the traffic. ⛔ CAN means "an enabled allow rule matches", NOT "a packet would
pass" — addresses/services/rule order are deliberately not modelled.

## lib/engines/segmentationData.js

(v2.113.0) The pool half: `listFleetZones` (derived from rules, never typed), `listIntents`,
`loadFleetRulesWithEvidence`, `evaluateSegmentation`, `upsertIntent`, `deleteIntent`.
⛔ Traffic evidence is NOT re-derived — it reuses `ruleHitCorrelation.js` unchanged, because two
implementations of measured-zero vs no-coverage would eventually disagree and the wrong one would
be recommending rule deletions. ⛔ Returns `rulesCollected:false` so an uncollected fleet reports
UNKNOWN instead of a perfect score built from missing data.

## lib/engines/applicationView.js

(v2.124.0) PURE. The application view's judgement: `normaliseFlow`, `evaluateFlowOnDevice`,
`aggregateFlow`, `usedVerdict`, `flowFinding`, plus the box algebra (`makeBox`/`intersectBox`/
`subtractBox`/`boxVolume`) and `parseCidr`/`rangeToString`. `VERDICTS` =
`permitted`/`partially_permitted`/`blocked`/`unspecified`; `USED` =
`rule-active`/`rule-idle`/`unknown`.
⛔ **It does NOT reuse `queryAccessPath()`, and cannot.** That function requires src/dst to be
SINGLE /32 ADDRESSES and throws otherwise; a declared flow is almost never a point. Sampling one
address out of a /24 and reporting the answer for the whole range is the fabricated-measurement bug.
The hard part — group expansion, FQDNs, vendor service grammars — IS reused unchanged
(`resolveAddressField`/`resolveServiceField`/`buildObjectMap` from `objectResolver.js`); only the
RANGE comparison is new.
⛔ **Exact decomposition, not "weakest dimension".** Rules are walked in `sequence_number` order
against a set of undecided (src x dst x port) boxes that split as rules claim parts of them, so the
permitted/blocked/unspecified VOLUMES are exact. Comparing dimensions separately reports a flow whose
254 of 255 addresses are permitted as BLOCKED — a hole reported as closed, the dangerous direction.
⛔ `MAX_UNDECIDED_BOXES` (4000) makes a pathological rulebase `unverified`, never a partial answer
dressed as a whole one. ⛔ The action vocabulary is BORROWED from `segmentation.js`; an unrecognised
action decides nothing and is counted. ⛔ A NULL `sequence_number` sorts LAST, same as
`queryAccessPath` — a rule whose position is unknown must not be assumed to sit at the top.
⛔ `aggregateFlow` takes the BEST SINGLE DEVICE's answer: **volumes are never unioned across
devices**, because two firewalls each permitting half a flow does not add up to a permitted flow.
⛔ `usedVerdict` speaks about the permitting RULES, never about the flow, and one rule with no
usable hit count makes the whole answer `unknown`. ⛔ `unspecified` is NEVER rendered as denied —
there is no implicit-policy data in this codebase for any vendor.

## lib/engines/applicationViewData.js

(v2.124.0) The pool half: CRUD (`listApplications`/`getApplication`/`createApplication`/
`updateApplication`/`deleteApplication`/`addFlow`/`updateFlow`/`deleteFlow`), `loadFleet`,
`evaluateFlow`, `summariseFlows`, `evaluateApplication`, `orphanCoverage`,
`evaluateAllApplications`.
⛔ Nothing is cached and NO VERDICT IS STORED — a verdict is a function of the current rulebase and
traffic window, and a stored one goes stale and is then read as fact. ⛔ Traffic evidence is NOT
re-derived: `ruleHitCorrelation.js` unchanged, same as `segmentationData.js`. ⛔ `loadFleet` builds
each device's object maps ONCE and passes them into every flow evaluation — rebuilding them per flow
per device (10,044 `network_objects` rows fleet-wide) was the dominant cost. ⛔ A device with no
collected rules is NAMED in `devicesWithoutRules`, never omitted, and its presence makes every flow
`unverified` rather than "blocked". ⛔ `addFlow`/`updateFlow` validate with the SAME
`normaliseFlow` that will later evaluate the row, so an unanswerable flow is never stored.
⛔ `orphanCoverage()` is a **COVERAGE figure, not a finding** (`isCoverageNotFinding:true`): with
nothing declared it reports ~1,095 unclaimed allow rules, which is accurate and useless. And
"unclaimed" is NEVER "unused" — `unused` is `ruleAnalysis.js`'s word and requires a MEASURED zero.
⛔ `evaluateAllApplications` isolates each stage and returns `errors[]` INSTEAD of throwing; every
caller must re-raise or banner them (see `gatherApplications`).
⛔ Per-flow traffic usage is NOT ANSWERABLE at all — no rollup carries both flow endpoints — so only
rule-level usage is reported, in weaker words.

## lib/engines/workQueue.js

(v2.115.0) PURE. `bandFor` / `rankItems` / `summarise` / `WORK_BANDS`. ⛔ `evidence` decides the
BAND: `unmeasured` can never reach `act_now`, and an unknown value fails CLOSED to `verify`.
⛔ `rankItems` is STABLE (band -> severity -> count -> title) — a queue that reorders between
refreshes destroys the one thing a queue is for. ⛔ `summarise` reports `sourcesFailed` AND
`sourcesTruncated`; both block the all-clear in `buildWorkQueueAnswer`.

## lib/engines/workQueueData.js

(v2.115.0, tenth gather v2.124.0) TEN gathers, each isolated in `runSource` so a throw reports `{ok:false,error}` rather
than contributing zero items. ⛔ The ack join in `gatherRuleCleanup` MUST go through
`firewall_rules` — `rule_analysis_results.rule_id` is a UUID FK, `finding_acknowledgements.
rule_id_vendor` is the vendor text id; joining them directly is `text = uuid` and Postgres
refuses it. ⛔ `groupBy` collapses CVE and compliance to ONE ITEM PER PROBLEM (not per device) — devices survive
as `affects`/`deviceIds`. ⛔ Grouping sources fetch `ROW_FETCH_LIMIT` rows and cap AFTER grouping:
capping rows first would silently drop devices from an item that still looked complete, a truncation
the truncation banner itself could not see. ⛔ `withCap` discloses shown-of-total when `PER_SOURCE_CAP` bites, at the cost of one
COUNT only in that case. ⛔ Licences produce TWO item kinds: a parsed expiry (`reported`) and an
UNPARSEABLE one (`unmeasured` -> verify band) — `expires_at IS NULL` with raw `Never` is
perpetual and is NOT listed.
⛔ `gatherApplications` (v2.124.0) emits **ONE ITEM PER APPLICATION**, never per flow — a
declaration is exhaustive, so an item per flow would grow the queue with the SIZE OF THE DECLARATION.
Work states are `violation`/`broken`/`partial`/`invalid`; `unspecified` and `ok_unverified` are
deliberately EXCLUDED (not confirmed work), and the orphan COVERAGE figure is never an item.
⛔ ONE unverified flow makes the whole item `unmeasured` -> `verify`; a fully-verified violation is
`reported` AT MOST, never `measured` — SecVault read the rulebase, it did not observe a packet.
⛔ It is the only gather that RUNS AN ENGINE rather than a query, so its cost is guarded twice: an
already-computed `opts.applications` is used as-is (the `opts.segmentation` pattern), otherwise a
single COUNT on `application_flows` decides whether the whole-fleet load happens at all. ⛔ That
probe FAILS OPEN — an unreadable count falls through to the evaluation, because "we could not read
the count" is not "nothing is declared".

## lib/rbac.js

⛔ REWRITTEN v2.110.0 — three roles (`super_admin`/`admin`/`operator`) behind a capability layer.
Exports `can(session, cap)` (the one check), `capabilitiesOf`, `roleOf`, `isSuperAdmin`,
`isAssignableRole`, `ASSIGNABLE_ROLES`/`ROLE_LABELS`/`ROLE_DESCRIPTIONS`, the eight capability
constants, and `forbiddenResponse(cap)` which names the missing authority. `isAdmin()` remains as
a legacy alias for `manage_devices` so un-migrated routes deny operators by default. Fails closed
on every malformed input including an unrecognised capability string. Matrix pinned exhaustively
by `tests/rbac.test.js`, which also scans every route file for a missing guard.

[SENSITIVE] — entire file (auth/authorization guard)

`ADMIN_ROLE` -> `string` — `'admin'`. [SENSITIVE]
`VIEWER_ROLE` -> `string` — `'viewer'`. [SENSITIVE]
`isAdmin(session)` -> `boolean` — true iff `session.user.role === 'admin'`. [SENSITIVE]
`forbiddenResponse()` -> `Response` — standard 403 JSON `{error: 'Forbidden — admin role required'}`. [SENSITIVE]

## lib/updateCheck.js

`findGitRoot(start)` -> `string` — walks up from `start` looking for `.git` (max 6 levels).
`localCommitHash(repoRoot)` -> `string|null` — `git rev-parse HEAD` short SHA (7 chars) for the local checkout; null on failure.
`remoteCommitHash(repoRoot)` -> `Promise<string|null>` — `git ls-remote origin main` short SHA via git transport (not GitHub REST API); uses SSH deploy-key override. [SENSITIVE] (touches deploy SSH key path resolution)
`remoteVersion(repoRoot)` -> `Promise<string>` — reads `package.json` version from `FETCH_HEAD` after `git fetch`; falls back to local `pkg.version` on failure.
`pkg` -> `object` — the loaded root `package.json`.
(internal, not exported: SSH command string is built with forward slashes only — git's bundled MSYS2 shell mangles backslashes in `core.sshCommand`. Resolves the deploy key path: `C:\ProgramData\SecVault\ssh\secvault_deploy` then repo-relative fallback.) [SENSITIVE]

## lib/auditChecksSeed.js

`CHECKS` -> `object[]` — curated array of compliance check definitions (`checkId, name, description, standards, vendor, severity, predicateConfig, remediationGuidance`); predicate types include `config_key_exists`/`config_value_equals`/`config_value_matches`/`feature_enabled`/`admin_access_from_zone`/`not_evaluable_from_config`/`rule_scan`/`ruleset_property`. ⛔ `not_evaluable_from_config` resolves `na` (excluded from the score denominator), NOT `warning`, since 2026-08-25 — `configAuditor.evaluateCheck()` short-circuits it before the `pass_when` guard. Current count (45) matches CLAUDE.md's Compliance Engine section — recount via `grep -c "checkId:"` if this file changes. Full mechanics: `.ai-codex/compliance-pipeline.md`.
`seedAuditChecks(pool)` -> `Promise<{count: number}>` — idempotent `INSERT ... ON CONFLICT (check_id) DO UPDATE` seed/refresh of `audit_checks` from `CHECKS`.

## lib/credentialProfiles.js
[SENSITIVE] — entire file (reusable credential bundles: device auth, SSH, API keys, SNMP creds)

`deriveDisplayUsername(plaintext)` -> `string|null` — best-effort extracts a non-secret `username` field from a JSON-shaped credential plaintext, for display only; never throws. [SENSITIVE]
`buildProfilePlaintext(credentialType, {authMode, secret, username, password, enablePassword, snmpVersion, authProtocol, authPassword, privProtocol, privPassword})` -> `string|null` — builds the stored plaintext JSON/raw-string shape per `credentialType` (`smc_api|rest_api|ssh|snmp`); returns null if fields insufficient. [SENSITIVE]
`listProfiles(pool)` -> `Promise<object[]>` — metadata-only rows (`id, name, credential_type, username, created_at, updated_at`) — safe for HTTP response.
`getProfileMeta(id, pool)` -> `Promise<object|null>` — metadata-only single profile row.
`getProfilePlaintext(id, pool)` -> `Promise<{credentialType: string, plaintext: string}|null>` — decrypts profile secret; SERVER-SIDE USE ONLY, must never leave the process. [SENSITIVE]
`createProfile({name, credentialType, plaintext}, pool)` -> `Promise<object>` — encrypts + inserts a new profile, returns metadata row. [SENSITIVE]
`updateProfile(id, {name, plaintext}, pool)` -> `Promise<object|null>` — rename and/or rotate-secret (either omittable); `credential_type` immutable. [SENSITIVE]
`deleteProfile(id, pool)` -> `Promise<void>` — deletes a credential profile row.

## lib/notificationChannels.js
[SENSITIVE] — entire file (outbound notification channels: webhook URLs, SMTP passwords). Added 2026-08-01, mirrors lib/credentialProfiles.js's shape exactly.

`NOTIFICATION_CHANNEL_TYPES` -> `string[]` — `['slack_webhook','teams_webhook','email','generic_webhook']`.
`ALERT_TYPES` -> `string[]` — `['patch_now_cve','compliance_critical','config_diff','compliance_report']` (4th value added 2026-08-02, email-only — see `components/settings/NotificationsPanel.js`'s `EMAIL_ONLY_ALERT_TYPES` gate and `lib/engines/complianceReport.js`).
`buildChannelPlaintext(channelType, {webhookUrl, smtpPassword})` -> `string|null` — the three webhook types store the raw URL as the whole secret; `email` stores the SMTP password only (host/port/from/to live in the non-secret `config` JSONB). [SENSITIVE]
`listChannels(pool)` -> `Promise<object[]>` — metadata-only rows, safe for HTTP response.
`getChannelMeta(id, pool)` -> `Promise<object|null>` — metadata-only single channel row.
`getChannelPlaintext(id, pool)` -> `Promise<{id, name, channelType, alertTypes, config, plaintext}|null>` — decrypts one channel; SERVER-SIDE USE ONLY (the test-send route). [SENSITIVE]
`listEnabledChannelsWithSecrets(pool)` -> `Promise<object[]>` — decrypts every ENABLED channel in one query; used by lib/engines/notificationDispatch.js's poll job. SERVER-SIDE USE ONLY. [SENSITIVE]
`createChannel({name, channelType, alertTypes, config, plaintext}, pool)` -> `Promise<object>` — encrypts + inserts, returns metadata row. [SENSITIVE]
`updateChannel(id, {name, enabled, alertTypes, config, plaintext}, pool)` -> `Promise<object|null>` — partial update (each field omittable); `channel_type` immutable. [SENSITIVE]
`deleteChannel(id, pool)` -> `Promise<void>`.
`recordChannelSuccess(id, pool)` / `recordChannelError(id, message, pool)` -> `Promise<void>` — updates `last_success_at`/`last_error`/`last_error_at`, called by lib/notify.js's callers after every dispatch attempt.

## lib/notify.js
Added 2026-08-01. CommonJS, no DB access — pure dispatch, callers pass an already-decrypted channel object.

`dispatchNotification(channel, message)` -> `Promise<void>` — single entry point, routes to the per-`channel_type` sender ({alertType, title, summary, url, deviceName, attachments?} message shape); throws on failure. `NOTIFY_TIMEOUT_MS = 8000` (shorter than every other outbound timeout in this codebase — fire-and-forget inside a poll loop over N channels x M items). Teams payload (Adaptive Card via a `message` envelope, the current Power Automate Workflows webhook shape) logs its raw response once on first live send (`loggedFirstTeamsResponse`) — live-verification risk, not a settled spec, same `loggedFirst*` convention as the vendor adapters. `email` uses `nodemailer` (new dependency, 2026-08-01 — none existed in this codebase before); `message.attachments` (added 2026-08-02, nodemailer-native `[{filename, content: Buffer, contentType}]`) passes straight through to `sendMail()` — used by `lib/engines/complianceReport.js` for the PDF report, ignored by every webhook sender.

## lib/snmpClient.js
[SENSITIVE] — entire file (SNMP session/credential handling)

`createSession(credential, host, port, timeoutMs)` -> `net-snmp.Session` — builds a v1/v2c or v3 SNMP session from a parsed credential (see `lib/adapters/snmpCredential.js`). Throws if no credential/host. [SENSITIVE]
`getMetrics(session, oidMap, timeoutMs, host)` -> `Promise<Object<string,string|null>>` — GETs a flat map of named scalar OIDs; per-OID error resolves to `null`, not a thrown error; wrapped in an outer hard-timeout race.
`walkSubtree(session, baseOid, timeoutMs, host)` -> `Promise<Array<{oid:string,value:*}>>` — SNMP WALK a subtree (table-indexed metrics); per-row errors skipped.
`closeSession(session)` -> `void` — best-effort session close.
`DEFAULT_TIMEOUT_MS` -> `number` — `8000`.

## lib/migrate.js

`runSchema(pool)` -> `Promise<void>` — executes `lib/schema.sql` verbatim against the DB.
`seedUsers(pool)` -> `Promise<{migrated: boolean, seeded: boolean, username?: string}>` — guarded on `users` table being empty: migrates legacy `settings.admin_username/admin_password_hash` into `users`, or seeds default `admin/changeme`. [SENSITIVE] (touches password hash migration)
`main()` -> `Promise<void>` (not exported, run via `require.main === module`) — orchestrates: runSchema → seedUsers → seedAuditChecks (NOT best-effort, throws loud) → backfillVulnerabilityCategories (best-effort) → cleanupVolatileConfigDiffs (best-effort) → regenerateOversizedChangeSummaries (best-effort) → migrateZoneClassificationsToPerDevice (best-effort) → backfillPaloAltoVersionRanges (best-effort) → backfillNvdNativeVersionRanges (best-effort, added 2026-07-31, the other five vendors).
(internal, not exported: `loadEnvLocal()`; `migrateZoneClassificationsToPerDevice(pool)` -> `Promise<{discardedGlobalRows: number}>` — migrates `zone_classifications` from global to per-device schema shape, adds `device_id` column/constraint/index — the index creation lives HERE not in schema.sql, see schema.md's "Known schema debt".)

---

## lib/engines/prioritization.js

`computePriority(assessment, device, cvssScore)` -> `'patch_now'|'scheduled'|'monitor'` — pure priority-band decision tree (KEV → log_hit → CVSS≥9 → CVSS≥7 → unknown-applicability → default), then asset-criticality bump-one-band modifier. Order is fixed per CLAUDE.md, do not reorder.
`updatePrioritiesForDevice(deviceId, pool)` -> `Promise<void>` — recomputes+persists `priority_band` for every `device_cve_assessments` row of a device.

## lib/engines/versionMatcher.js

`matchDeviceToAdvisories(device, deviceVersionTuple, advisories, recommendedReleases, applicability=null)` -> `object[]` (pure) — matches one device against pre-filtered advisories, computing `version_affected`, `config_applies` (tri-state via applicability engine), `kev_listed`, `fixed_in`, `is_fixed_recommended`. Only emits rows where `version_affected===true`.
`runMatchForAllDevices(pool)` -> `Promise<{assessed: number, matched_cves: number, errors: object[]}>` — full engine run over all active devices; per-device `pg_advisory_xact_lock` guards concurrent DELETE+UPSERT+prioritization against 3 independent call sites. **This is where `device_cve_assessments` gets cleared/rewritten** — see cve-pipeline.md stage on assessment clearing.

## lib/engines/adminAccountSummary.js

`summarizeAdminAccounts(vendor, configParsed)` -> `{supported: boolean, accounts: {username, privilege, twoFactorEnabled, sourceRestricted}[], totalCount: number, superuserCount: number, error?: boolean}` — vendor-dispatched (fortinet/paloalto/cisco_asa) interpretation of already-collected config for "who can log in"; never throws, degrades to `error:true` on parse failure. [SENSITIVE] (reads admin account identity/privilege from device config, though not passwords)

## lib/engines/applicability.js

`evaluatePredicate(predicateType, predicateConfig, configParsed)` -> `'yes'|'no'|'unknown'` (pure, never throws) — evaluates one CVE-applicability predicate (`config_key_exists|config_value_equals|config_value_matches|feature_enabled|port_exposed|admin_access_from_zone`) against parsed config.
`computeConfigApplies(conditions, configParsed)` -> `'yes'|'no'|'unknown'` — AND-combines a list of predicate conditions; empty/no-usable-config always → `'unknown'`, never `'no'`.
`evaluateConditionsDetailed(conditions, configParsed)` -> `{config_applies, per_condition: {id, condition_description, predicate_type, result}[]}` — per-condition breakdown for the admin "test predicate" UI.
`getLatestConfigParsed(deviceId, pool)` -> `Promise<object|null>` — latest `device_configs.config_parsed`, normalized via `normalizeConfigParsedRoot` (fixes Palo Alto SSH `.tree` wrapper / XML `devices.entry.deviceconfig` nesting).
`loadConditionsByAdvisory(pool, vendor)` -> `Promise<Map<string, object[]>>` — all `advisory_conditions` for a vendor, grouped by `advisory_id`.
`getConfigAppliesForDevice(deviceId, advisoryId, pool)` -> `Promise<'yes'|'no'|'unknown'>` — single device×advisory applicability lookup.
`hasUsableConfig(configParsed)` -> `boolean` — true only for a non-empty interrogatable object (guards `{}`/null/array).
`normalizeConfigParsedRoot(configParsed)` -> `object` — hoists Palo Alto SSH `.tree` / XML `deviceconfig` to top level; no-op for other vendors.

## lib/engines/cidrUtils.js

`parseCidrOrIp(str)` -> `{network: number, prefixLen: number}|null` — parses IPv4 literal/CIDR into masked network + prefix; `null` for anything non-IPv4-shaped (IPv6, object names, "any").
`cidrContains(outerStr, innerStr)` -> `boolean|null` — true if outer CIDR range contains inner; `null` if either isn't parseable (never coerced to `false`).
`cidrEquals(aStr, bStr)` -> `boolean|null` — true if both denote the same masked range; `null` if either isn't parseable.
`parseIpRange(str)` -> `{start,end}|null` (added 2026-08-02, for `objectResolver.js`) — parses a literal `"start-end"` IPv4 range (both sides bare `/32`s); `null` for anything else.
`rangeContains(outer, inner)` / `rangeOverlaps(a, b)` -> `boolean` — numeric `{start,end}` containment/overlap, uniform across CIDR and range shapes.
`cidrToRange(cidr)` -> `{start,end}` — widens a parsed CIDR to a `{start,end}` range. ⛔ `/32` needs a special case (`0xffffffff >>> 32` is a no-op in JS, same mod-32 footgun `maskForPrefixLen()` already guards for `/0` — get this backwards and every single-host CIDR silently widens to the whole address space).

## lib/engines/configDiff.js

`diffConfigs(oldParsed, newParsed, vendor?)` -> `{added, removed, modified}` (pure) — deep recursive diff of two parsed config trees; applies vendor-specific volatile-path filtering + defense-in-depth secret redaction; caps at 500 entries. Arrays are aligned by VALUE not position: all-primitive arrays via LCS (`diffPrimitiveArrayLCS`), all-object arrays sharing a unique `@_name`/`name` key via identity alignment (`diffObjectArrayByIdentity`, added 2026-07-31 — kills the Palo Alto XML/API rulebase shift cascade); everything else falls back to positional. Forward-only, no backfill for existing rows.
`summarizeDiff(diff)` -> `string` — human one-liner (`"N added, M removed — e.g. path1, path2"`), with sanitized/truncated example paths.
`isEmptyDiff(diff)` -> `boolean` — true if added/removed/modified are all empty.
`detectAndStoreDiff(deviceId, pool, vendor?)` -> `Promise<{changed: boolean, diffId: string|null, summary: string|null}>` — diffs the 2 latest `device_configs` snapshots and inserts a `config_diffs` row if changed.
`createBackup(deviceId, label, pool)` -> `Promise<{backupId: string|null}>` — copies latest `config_raw` into `config_backups` (`label` ∈ auto/manual/pre-change).
`filterDiffForCurrentRules(diff, vendor)` -> `object` — re-applies current volatile-path filter + secret redaction to an already-computed diff object; also DECOMPOSES a whole registered-volatile-subtree-root entry (`content-preview`/`system_info` captured as one object) back through `diffValue` so the current per-leaf allowlist applies (drops content-preview entirely, keeps only system_info's allowlisted fields) — added 2026-07-31 to clean historical whole-block noise rows the leaf-only filter missed. [SENSITIVE] (secret-redaction pass over stored config diffs)
`cleanupVolatileConfigDiffs(pool)` -> `Promise<{checked, deleted, updated}>` — retroactive migration: deletes/updates existing `config_diffs` rows per current noise/secret rules. [SENSITIVE]
`classifyDiff(diff)` -> `{ruleChanges: object[], sections: object[]}` — presentation-layer grouping of a diff into a rule-change table + labeled sections; pure, read-time only. Section entries also carry `friendlyDescription` and (added 2026-07-31) `ruleIndex`/`ruleField` — the positional index + in-rule field of a Palo Alto XML/API `...rulebase.<sec|nat|pbf>.rules.entry[N].<field>` path (both `null` for any other shape), so `DiffViewer.js` can regroup the flat per-field rows of the (renamed) "Security Rules" section into one table per rule. `extractIndexedRuleEntry(path)` is the pure `{index, field}` extractor. The label `Security Rules` (was `Rules (detail unavailable for this device)` pre-2.29.0) is a stable classification key — `components/devices/OverviewConfigChangesCard.js`'s `HIGH_IMPACT_LABELS` keys off it, change both together.
`regenerateOversizedChangeSummaries(pool)` -> `Promise<{checked, updated}>` — backfill: re-derives `change_summary` for any oversized (>500 char) stored row.
`collapsePrimitiveArrayShifts(diff)` -> `diff` (pure) — collapses a primitive-array positional-shift cascade (a set-like membership list where the OLD positional diff reported a 1-element insert/remove as N "modified" + a mis-named tail add/remove) back to the true added/removed via LCS reconstruction of the changed region. Gated: ≥3 primitive modified entries at one array path + contiguous indices. Uses `lcsPrimitiveDiff`.
`collapseHistoricalArrayShiftCascades(pool)` -> `Promise<{checked, updated}>` — migration applying the above to every stored `config_diffs` row + re-deriving `change_summary`; idempotent, best-effort. Wired into migrate.js. Fixes the historical "246 modified" membership-list rows (new diffs never produce them — their array branch already uses LCS).

## lib/engines/vpnSessions.js

`storeVpnSessions(deviceId, sessions, pool)` -> `Promise<{count}>` — DELETE+reinsert (one transaction) the LIVE per-user active-session set into `vpn_active_sessions`. Engine-worker calls it only after a SUCCESSFUL poll (a failed pull never wipes; an empty array clears — nobody connected). Session objects: `{username, tunnel_type, source_ip, assigned_ip, login_time, duration_seconds, bytes_in, bytes_out, client, gateway, raw}` (any field nullable). Added 2026-07-31.
`getVpnSessions(deviceId, pool)` -> `Promise<object[]>` — current active-session rows for the per-device VPN page.

## lib/engines/vpnTunnels.js

`storeVpnTunnels(deviceId, tunnels, pool)` / `getVpnTunnels(deviceId, pool)` — same live-snapshot DELETE+reinsert + read pattern as vpnSessions.js, for `vpn_ipsec_tunnels`. Tunnel shape: `{name, peer, status, ike_version, bytes_in, bytes_out, raw}`. Fed by the adapters' optional `getVpnTunnels()` (PAN-OS `show vpn ipsec-sa`, Fortinet `diagnose vpn tunnel list`, Cisco `show vpn-sessiondb l2l`), stored by the engine-worker VPN poll in its own try/catch (a tunnel-pull failure never fails the session poll). Added 2026-07-31.

## lib/engines/dashboardSnapshot.js

`computeAndStoreDashboardSnapshot(pool, { ifAbsent })` — `ifAbsent:true` switches the upsert from
`ON CONFLICT DO UPDATE` to `DO NOTHING` and returns `{stored}` reporting honestly whether a row was
written. ⛔ Used by the STARTUP catch-up; the 00:10 cron still uses the default DO UPDATE.

⛔ There used to be TWO startup paths that cancelled each other: an unconditional run in `main()`
and a guarded `runDashboardSnapshotIfMissing()` in `scheduleJobs()`, which is called AFTER it. The
guard always found the row the unconditional run had just written, so it was a permanent no-op —
and because the write was DO UPDATE, every deploy restart REPLACED that day’s snapshot with
mid-day numbers. A day’s trend point was whatever the last restart happened to see.

⛔ The catch-up leans on the existing `UNIQUE (snapshot_date)` constraint, not on a read-then-write
check, so two racing startups cannot both conclude the row is missing.

⛔ It writes `CURRENT_DATE` as a SQL literal and never as a parameter, so the engine has no way to
express any other date. Past gaps are permanent by design: those days’ CVE bands, compliance
findings and rule analysis no longer exist, and writing today’s numbers under an old date would
fabricate history.


`computeFleetCveSeverity(pool)` -> `Promise<{critical, high, medium, low}>` — fleet-wide (active devices) CVE counts by CVSS bucket; unscored CVEs excluded from all buckets.
`computeFleetComplianceScores(pool)` -> `Promise<{overall: number|null, byStandard: Record<string, number|null>, byStandardCounts: Record<string, {pass,fail,warning}>}>` — fleet-wide pass/(pass+fail+warning) scores per standard + overall; `null` when unmeasurable. `byStandardCounts` (added 2026-08-02, additive — `computeAndStoreDashboardSnapshot` below ignores it) is the raw counts behind each percentage, for `lib/engines/complianceReport.js`'s fleet summary section.
`computeAndStoreDashboardSnapshot(pool)` -> `Promise<{cve, compliance}>` — computes + `UPSERT`s today's `fleet_dashboard_snapshots` row (idempotent per calendar day).

## lib/engines/objectUsage.js

`analyzeObjectUsage(objects, rules)` -> `{object_id, finding_type: 'unused'|'duplicate', detail, related_object_ids}[]` (pure) — namespace-partitioned (address vs service) unused/duplicate object detection with transitive group-membership closure.
`storeObjects(deviceId, objects, pool)` -> `Promise<{count: number}>` — DELETE+reinsert `network_objects` from an adapter's `getObjects()` result.
`runObjectUsageAnalysisForDevice(deviceId, pool)` -> `Promise<{findings: object[]}>` — loads objects+rules, analyzes, DELETE+reinsert `object_analysis_results` in one transaction.

## lib/syslog/eventStore.js

`buildPartitionSql(date)` / `partitionNameFor(date)` — daily partition DDL, **UTC** so a boundary is the same instant everywhere and does not move under DST. Range is `[day, day+1)`; an off-by-one here leaves a whole day of events with nowhere to land.
`buildInsertSql(rowCount)` / `flattenRow(event)` / `chunk(arr, size)` — multi-row parameterized INSERT. ⛔ 35 columns x `MAX_ROWS_PER_INSERT` (500) = 17,500 binds, kept well under PostgreSQL's 65535-parameter cap; a test asserts this, because exceeding it fails under load rather than in review. `COLUMNS.length` and `flattenRow()`'s array length must stay equal — they are positional, and a mismatch shifts every value one column left.
`ensurePartitions(pool, now)` — creates yesterday/today/tomorrow. Yesterday matters: an event can arrive just after a UTC midnight rollover and without the partition the INSERT fails outright.
`dropOldPartitions(pool, retentionDays, now)` — ⛔ DROPs partitions, never DELETEs rows, and only ever names matching `^syslog_events_\d{8}# lib/ — Library Export Index

Every export from `lib/`, grouped by file. `[SENSITIVE]` = touches credentials, encryption,
device auth, or config/secret storage — treat any change to these with extra care.

Part 1: `lib/*.js` (root) + `lib/engines/**`. Part 2: `lib/adapters/**` + `lib/feeds/**`.

---

## lib/db.js

`pool` -> `pg.Pool` — singleton PostgreSQL connection pool (`connectionString: DATABASE_URL`); has an `error` listener registered to prevent unhandled-rejection crashes on idle-client errors.

## lib/activityLog.js

`logActivity(pool, {actor, action, deviceId, detail})` -> `Promise<void>` — inserts one `activity_log` audit row; NEVER throws (catches and console.warns on failure).

## lib/apiUtils.js

`isValidUuid(value)` -> `boolean` — regex-checks a string looks like a UUID (8-4-4-4-12 hex), used to guard path params before hitting a UUID-typed SQL column.

## lib/theme.js
(ES module, `'use client'` — exports via `export`, not `module.exports`; only top-level `lib/*.js` file that isn't CommonJS)

`THEME_KEY` -> `string` — `'secvault-theme'`, the localStorage key.
`getTheme()` -> `'light'|'dark'` — reads current `data-theme` attribute off `<html>`.
`applyTheme(theme)` -> `void` — sets/removes `data-theme="dark"` on `<html>`, persists to localStorage, dispatches `secvault:theme` CustomEvent.
`toggleTheme()` -> `'light'|'dark'` — flips current theme via `applyTheme`, returns the new value.
`THEME_INIT_SCRIPT` -> `string` — inline `<script>` body (no-flash theme pre-paint init), injected into `app/layout.js`'s `<head>`.

## lib/credStore.js
[SENSITIVE] — entire file (AES-256-GCM credential encryption)

`encrypt(plaintext)` -> `{encrypted: string, iv: string}` — AES-256-GCM encrypt; `encrypted` = `hex(ciphertext):hex(authTag)`, `iv` = hex. Key from `CREDENTIAL_KEY` env (32-byte hex). [SENSITIVE]
`decrypt(encrypted, iv)` -> `string` (plaintext) — inverse of `encrypt`. [SENSITIVE]
`getCredential(deviceId, credentialType, pool)` -> `Promise<string|null>` — fetches+decrypts latest `device_credentials` row for `(deviceId, credentialType)`. Requires `pool`. [SENSITIVE]
`setCredential(deviceId, credentialType, plaintext, pool)` -> `Promise<void>` — encrypts + `INSERT ... ON CONFLICT (device_id, credential_type) DO UPDATE` (atomic upsert, relies on `UNIQUE(device_id, credential_type)`). Requires `pool`. [SENSITIVE]

## lib/feedStatus.js

`getLastSyncs(pool)` -> `Promise<object[]>` — up to 10 most recent `feed_sync_log` rows (`feed_name, status, started_at, finished_at`).
`getSyncPillStatus(pool)` -> `Promise<{ok: boolean, label: string, lastSyncs: object[]}>` — condensed header-pill status across `nvd`/`paloalto_psirt`/`fortinet_psirt`/`kev`; `label` is `'NO SYNC YET'|'FEEDS OK'|'FEED ERROR'`.

## lib/density.js

Client module. Table density, stamped as `data-density` on `<html>`. Structural mirror of lib/corners.js and lib/theme.js — same storage/attribute/event/no-flash-script shape, so there is one pattern for all three.

`DENSITIES` -> `string[]` — `['comfortable','compact','dense']`; the default is first, and a value not in this list is ignored rather than guessed at.
`DENSITY_LABELS` -> `object` — display names.
`getDensity()` / `applyDensity(d)` / `DENSITY_INIT_SCRIPT` — read, set (+persist +`secvault:density` event), and the pre-paint inline script.
⛔ Works ONLY because table padding/font resolve through `--row-pad-y`/`--row-pad-x`/`--row-font`. A hardcoded cell padding opts itself out silently.
⛔ Density changes ROW GEOMETRY ONLY — it must never hide a column, truncate a value or drop a badge. A denser table shows the same facts in less space, not fewer facts.

## lib/savedViews.js

Named filter/column/sort states per user per table (`saved_views`). All functions take `pool`.

`listSavedViews(pool, userId, scope)` -> own views plus anyone’s shared ones; own sort first.
`saveView(pool, userId, {scope,name,query,shared,isDefault})` -> upsert on (user_id, scope, name). ⛔ Clears the previous default INSIDE the transaction BEFORE inserting — `uq_saved_views_one_default` is a real partial unique index, so the other order fails the insert instead of moving the default (same rule as `device_configs.is_baseline`).
`deleteSavedView(pool, userId, id)` -> ⛔ owner scoping lives in the SQL WHERE clause, not the route, so no future caller can forget it.
`getDefaultView(pool, userId, scope)`.
`normalizeScope/Name/Query` — ⛔ the stored query string is REPLAYED into the address bar, so it is untrusted input: leading `?` stripped, length capped, anything with whitespace, quotes, a scheme or a path separator rejected.

## lib/rbac.js
[SENSITIVE] — entire file (auth/authorization guard)

`ADMIN_ROLE` -> `string` — `'admin'`. [SENSITIVE]
`VIEWER_ROLE` -> `string` — `'viewer'`. [SENSITIVE]
`isAdmin(session)` -> `boolean` — true iff `session.user.role === 'admin'`. [SENSITIVE]
`forbiddenResponse()` -> `Response` — standard 403 JSON `{error: 'Forbidden — admin role required'}`. [SENSITIVE]

## lib/updateCheck.js

`findGitRoot(start)` -> `string` — walks up from `start` looking for `.git` (max 6 levels).
`localCommitHash(repoRoot)` -> `string|null` — `git rev-parse HEAD` short SHA (7 chars) for the local checkout; null on failure.
`remoteCommitHash(repoRoot)` -> `Promise<string|null>` — `git ls-remote origin main` short SHA via git transport (not GitHub REST API); uses SSH deploy-key override. [SENSITIVE] (touches deploy SSH key path resolution)
`remoteVersion(repoRoot)` -> `Promise<string>` — reads `package.json` version from `FETCH_HEAD` after `git fetch`; falls back to local `pkg.version` on failure.
`pkg` -> `object` — the loaded root `package.json`.
(internal, not exported: SSH command string is built with forward slashes only — git's bundled MSYS2 shell mangles backslashes in `core.sshCommand`. Resolves the deploy key path: `C:\ProgramData\SecVault\ssh\secvault_deploy` then repo-relative fallback.) [SENSITIVE]

## lib/auditChecksSeed.js

`CHECKS` -> `object[]` — curated array of compliance check definitions (`checkId, name, description, standards, vendor, severity, predicateConfig, remediationGuidance`); predicate types include `config_key_exists`/`config_value_equals`/`config_value_matches`/`feature_enabled`/`admin_access_from_zone`/`not_evaluable_from_config`/`rule_scan`/`ruleset_property`. ⛔ `not_evaluable_from_config` resolves `na` (excluded from the score denominator), NOT `warning`, since 2026-08-25 — `configAuditor.evaluateCheck()` short-circuits it before the `pass_when` guard. Current count (45) matches CLAUDE.md's Compliance Engine section — recount via `grep -c "checkId:"` if this file changes. Full mechanics: `.ai-codex/compliance-pipeline.md`.
`seedAuditChecks(pool)` -> `Promise<{count: number}>` — idempotent `INSERT ... ON CONFLICT (check_id) DO UPDATE` seed/refresh of `audit_checks` from `CHECKS`.

## lib/credentialProfiles.js
[SENSITIVE] — entire file (reusable credential bundles: device auth, SSH, API keys, SNMP creds)

`deriveDisplayUsername(plaintext)` -> `string|null` — best-effort extracts a non-secret `username` field from a JSON-shaped credential plaintext, for display only; never throws. [SENSITIVE]
`buildProfilePlaintext(credentialType, {authMode, secret, username, password, enablePassword, snmpVersion, authProtocol, authPassword, privProtocol, privPassword})` -> `string|null` — builds the stored plaintext JSON/raw-string shape per `credentialType` (`smc_api|rest_api|ssh|snmp`); returns null if fields insufficient. [SENSITIVE]
`listProfiles(pool)` -> `Promise<object[]>` — metadata-only rows (`id, name, credential_type, username, created_at, updated_at`) — safe for HTTP response.
`getProfileMeta(id, pool)` -> `Promise<object|null>` — metadata-only single profile row.
`getProfilePlaintext(id, pool)` -> `Promise<{credentialType: string, plaintext: string}|null>` — decrypts profile secret; SERVER-SIDE USE ONLY, must never leave the process. [SENSITIVE]
`createProfile({name, credentialType, plaintext}, pool)` -> `Promise<object>` — encrypts + inserts a new profile, returns metadata row. [SENSITIVE]
`updateProfile(id, {name, plaintext}, pool)` -> `Promise<object|null>` — rename and/or rotate-secret (either omittable); `credential_type` immutable. [SENSITIVE]
`deleteProfile(id, pool)` -> `Promise<void>` — deletes a credential profile row.

## lib/notificationChannels.js
[SENSITIVE] — entire file (outbound notification channels: webhook URLs, SMTP passwords). Added 2026-08-01, mirrors lib/credentialProfiles.js's shape exactly.

`NOTIFICATION_CHANNEL_TYPES` -> `string[]` — `['slack_webhook','teams_webhook','email','generic_webhook']`.
`ALERT_TYPES` -> `string[]` — `['patch_now_cve','compliance_critical','config_diff','compliance_report']` (4th value added 2026-08-02, email-only — see `components/settings/NotificationsPanel.js`'s `EMAIL_ONLY_ALERT_TYPES` gate and `lib/engines/complianceReport.js`).
`buildChannelPlaintext(channelType, {webhookUrl, smtpPassword})` -> `string|null` — the three webhook types store the raw URL as the whole secret; `email` stores the SMTP password only (host/port/from/to live in the non-secret `config` JSONB). [SENSITIVE]
`listChannels(pool)` -> `Promise<object[]>` — metadata-only rows, safe for HTTP response.
`getChannelMeta(id, pool)` -> `Promise<object|null>` — metadata-only single channel row.
`getChannelPlaintext(id, pool)` -> `Promise<{id, name, channelType, alertTypes, config, plaintext}|null>` — decrypts one channel; SERVER-SIDE USE ONLY (the test-send route). [SENSITIVE]
`listEnabledChannelsWithSecrets(pool)` -> `Promise<object[]>` — decrypts every ENABLED channel in one query; used by lib/engines/notificationDispatch.js's poll job. SERVER-SIDE USE ONLY. [SENSITIVE]
`createChannel({name, channelType, alertTypes, config, plaintext}, pool)` -> `Promise<object>` — encrypts + inserts, returns metadata row. [SENSITIVE]
`updateChannel(id, {name, enabled, alertTypes, config, plaintext}, pool)` -> `Promise<object|null>` — partial update (each field omittable); `channel_type` immutable. [SENSITIVE]
`deleteChannel(id, pool)` -> `Promise<void>`.
`recordChannelSuccess(id, pool)` / `recordChannelError(id, message, pool)` -> `Promise<void>` — updates `last_success_at`/`last_error`/`last_error_at`, called by lib/notify.js's callers after every dispatch attempt.

## lib/notify.js
Added 2026-08-01. CommonJS, no DB access — pure dispatch, callers pass an already-decrypted channel object.

`dispatchNotification(channel, message)` -> `Promise<void>` — single entry point, routes to the per-`channel_type` sender ({alertType, title, summary, url, deviceName, attachments?} message shape); throws on failure. `NOTIFY_TIMEOUT_MS = 8000` (shorter than every other outbound timeout in this codebase — fire-and-forget inside a poll loop over N channels x M items). Teams payload (Adaptive Card via a `message` envelope, the current Power Automate Workflows webhook shape) logs its raw response once on first live send (`loggedFirstTeamsResponse`) — live-verification risk, not a settled spec, same `loggedFirst*` convention as the vendor adapters. `email` uses `nodemailer` (new dependency, 2026-08-01 — none existed in this codebase before); `message.attachments` (added 2026-08-02, nodemailer-native `[{filename, content: Buffer, contentType}]`) passes straight through to `sendMail()` — used by `lib/engines/complianceReport.js` for the PDF report, ignored by every webhook sender.

## lib/snmpClient.js
[SENSITIVE] — entire file (SNMP session/credential handling)

`createSession(credential, host, port, timeoutMs)` -> `net-snmp.Session` — builds a v1/v2c or v3 SNMP session from a parsed credential (see `lib/adapters/snmpCredential.js`). Throws if no credential/host. [SENSITIVE]
`getMetrics(session, oidMap, timeoutMs, host)` -> `Promise<Object<string,string|null>>` — GETs a flat map of named scalar OIDs; per-OID error resolves to `null`, not a thrown error; wrapped in an outer hard-timeout race.
`walkSubtree(session, baseOid, timeoutMs, host)` -> `Promise<Array<{oid:string,value:*}>>` — SNMP WALK a subtree (table-indexed metrics); per-row errors skipped.
`closeSession(session)` -> `void` — best-effort session close.
`DEFAULT_TIMEOUT_MS` -> `number` — `8000`.

## lib/migrate.js

`runSchema(pool)` -> `Promise<void>` — executes `lib/schema.sql` verbatim against the DB.
`seedUsers(pool)` -> `Promise<{migrated: boolean, seeded: boolean, username?: string}>` — guarded on `users` table being empty: migrates legacy `settings.admin_username/admin_password_hash` into `users`, or seeds default `admin/changeme`. [SENSITIVE] (touches password hash migration)
`main()` -> `Promise<void>` (not exported, run via `require.main === module`) — orchestrates: runSchema → seedUsers → seedAuditChecks (NOT best-effort, throws loud) → backfillVulnerabilityCategories (best-effort) → cleanupVolatileConfigDiffs (best-effort) → regenerateOversizedChangeSummaries (best-effort) → migrateZoneClassificationsToPerDevice (best-effort) → backfillPaloAltoVersionRanges (best-effort) → backfillNvdNativeVersionRanges (best-effort, added 2026-07-31, the other five vendors).
(internal, not exported: `loadEnvLocal()`; `migrateZoneClassificationsToPerDevice(pool)` -> `Promise<{discardedGlobalRows: number}>` — migrates `zone_classifications` from global to per-device schema shape, adds `device_id` column/constraint/index — the index creation lives HERE not in schema.sql, see schema.md's "Known schema debt".)

---

## lib/engines/prioritization.js

`computePriority(assessment, device, cvssScore)` -> `'patch_now'|'scheduled'|'monitor'` — pure priority-band decision tree (KEV → log_hit → CVSS≥9 → CVSS≥7 → unknown-applicability → default), then asset-criticality bump-one-band modifier. Order is fixed per CLAUDE.md, do not reorder.
`updatePrioritiesForDevice(deviceId, pool)` -> `Promise<void>` — recomputes+persists `priority_band` for every `device_cve_assessments` row of a device.

## lib/engines/versionMatcher.js

`matchDeviceToAdvisories(device, deviceVersionTuple, advisories, recommendedReleases, applicability=null)` -> `object[]` (pure) — matches one device against pre-filtered advisories, computing `version_affected`, `config_applies` (tri-state via applicability engine), `kev_listed`, `fixed_in`, `is_fixed_recommended`. Only emits rows where `version_affected===true`.
`runMatchForAllDevices(pool)` -> `Promise<{assessed: number, matched_cves: number, errors: object[]}>` — full engine run over all active devices; per-device `pg_advisory_xact_lock` guards concurrent DELETE+UPSERT+prioritization against 3 independent call sites. **This is where `device_cve_assessments` gets cleared/rewritten** — see cve-pipeline.md stage on assessment clearing.

## lib/engines/adminAccountSummary.js

`summarizeAdminAccounts(vendor, configParsed)` -> `{supported: boolean, accounts: {username, privilege, twoFactorEnabled, sourceRestricted}[], totalCount: number, superuserCount: number, error?: boolean}` — vendor-dispatched (fortinet/paloalto/cisco_asa) interpretation of already-collected config for "who can log in"; never throws, degrades to `error:true` on parse failure. [SENSITIVE] (reads admin account identity/privilege from device config, though not passwords)

## lib/engines/applicability.js

`evaluatePredicate(predicateType, predicateConfig, configParsed)` -> `'yes'|'no'|'unknown'` (pure, never throws) — evaluates one CVE-applicability predicate (`config_key_exists|config_value_equals|config_value_matches|feature_enabled|port_exposed|admin_access_from_zone`) against parsed config.
`computeConfigApplies(conditions, configParsed)` -> `'yes'|'no'|'unknown'` — AND-combines a list of predicate conditions; empty/no-usable-config always → `'unknown'`, never `'no'`.
`evaluateConditionsDetailed(conditions, configParsed)` -> `{config_applies, per_condition: {id, condition_description, predicate_type, result}[]}` — per-condition breakdown for the admin "test predicate" UI.
`getLatestConfigParsed(deviceId, pool)` -> `Promise<object|null>` — latest `device_configs.config_parsed`, normalized via `normalizeConfigParsedRoot` (fixes Palo Alto SSH `.tree` wrapper / XML `devices.entry.deviceconfig` nesting).
`loadConditionsByAdvisory(pool, vendor)` -> `Promise<Map<string, object[]>>` — all `advisory_conditions` for a vendor, grouped by `advisory_id`.
`getConfigAppliesForDevice(deviceId, advisoryId, pool)` -> `Promise<'yes'|'no'|'unknown'>` — single device×advisory applicability lookup.
`hasUsableConfig(configParsed)` -> `boolean` — true only for a non-empty interrogatable object (guards `{}`/null/array).
`normalizeConfigParsedRoot(configParsed)` -> `object` — hoists Palo Alto SSH `.tree` / XML `deviceconfig` to top level; no-op for other vendors.

## lib/engines/cidrUtils.js

`parseCidrOrIp(str)` -> `{network: number, prefixLen: number}|null` — parses IPv4 literal/CIDR into masked network + prefix; `null` for anything non-IPv4-shaped (IPv6, object names, "any").
`cidrContains(outerStr, innerStr)` -> `boolean|null` — true if outer CIDR range contains inner; `null` if either isn't parseable (never coerced to `false`).
`cidrEquals(aStr, bStr)` -> `boolean|null` — true if both denote the same masked range; `null` if either isn't parseable.
`parseIpRange(str)` -> `{start,end}|null` (added 2026-08-02, for `objectResolver.js`) — parses a literal `"start-end"` IPv4 range (both sides bare `/32`s); `null` for anything else.
`rangeContains(outer, inner)` / `rangeOverlaps(a, b)` -> `boolean` — numeric `{start,end}` containment/overlap, uniform across CIDR and range shapes.
`cidrToRange(cidr)` -> `{start,end}` — widens a parsed CIDR to a `{start,end}` range. ⛔ `/32` needs a special case (`0xffffffff >>> 32` is a no-op in JS, same mod-32 footgun `maskForPrefixLen()` already guards for `/0` — get this backwards and every single-host CIDR silently widens to the whole address space).

## lib/engines/configDiff.js

`diffConfigs(oldParsed, newParsed, vendor?)` -> `{added, removed, modified}` (pure) — deep recursive diff of two parsed config trees; applies vendor-specific volatile-path filtering + defense-in-depth secret redaction; caps at 500 entries. Arrays are aligned by VALUE not position: all-primitive arrays via LCS (`diffPrimitiveArrayLCS`), all-object arrays sharing a unique `@_name`/`name` key via identity alignment (`diffObjectArrayByIdentity`, added 2026-07-31 — kills the Palo Alto XML/API rulebase shift cascade); everything else falls back to positional. Forward-only, no backfill for existing rows.
`summarizeDiff(diff)` -> `string` — human one-liner (`"N added, M removed — e.g. path1, path2"`), with sanitized/truncated example paths.
`isEmptyDiff(diff)` -> `boolean` — true if added/removed/modified are all empty.
`detectAndStoreDiff(deviceId, pool, vendor?)` -> `Promise<{changed: boolean, diffId: string|null, summary: string|null}>` — diffs the 2 latest `device_configs` snapshots and inserts a `config_diffs` row if changed.
`createBackup(deviceId, label, pool)` -> `Promise<{backupId: string|null}>` — copies latest `config_raw` into `config_backups` (`label` ∈ auto/manual/pre-change).
`filterDiffForCurrentRules(diff, vendor)` -> `object` — re-applies current volatile-path filter + secret redaction to an already-computed diff object; also DECOMPOSES a whole registered-volatile-subtree-root entry (`content-preview`/`system_info` captured as one object) back through `diffValue` so the current per-leaf allowlist applies (drops content-preview entirely, keeps only system_info's allowlisted fields) — added 2026-07-31 to clean historical whole-block noise rows the leaf-only filter missed. [SENSITIVE] (secret-redaction pass over stored config diffs)
`cleanupVolatileConfigDiffs(pool)` -> `Promise<{checked, deleted, updated}>` — retroactive migration: deletes/updates existing `config_diffs` rows per current noise/secret rules. [SENSITIVE]
`classifyDiff(diff)` -> `{ruleChanges: object[], sections: object[]}` — presentation-layer grouping of a diff into a rule-change table + labeled sections; pure, read-time only. Section entries also carry `friendlyDescription` and (added 2026-07-31) `ruleIndex`/`ruleField` — the positional index + in-rule field of a Palo Alto XML/API `...rulebase.<sec|nat|pbf>.rules.entry[N].<field>` path (both `null` for any other shape), so `DiffViewer.js` can regroup the flat per-field rows of the (renamed) "Security Rules" section into one table per rule. `extractIndexedRuleEntry(path)` is the pure `{index, field}` extractor. The label `Security Rules` (was `Rules (detail unavailable for this device)` pre-2.29.0) is a stable classification key — `components/devices/OverviewConfigChangesCard.js`'s `HIGH_IMPACT_LABELS` keys off it, change both together.
`regenerateOversizedChangeSummaries(pool)` -> `Promise<{checked, updated}>` — backfill: re-derives `change_summary` for any oversized (>500 char) stored row.
`collapsePrimitiveArrayShifts(diff)` -> `diff` (pure) — collapses a primitive-array positional-shift cascade (a set-like membership list where the OLD positional diff reported a 1-element insert/remove as N "modified" + a mis-named tail add/remove) back to the true added/removed via LCS reconstruction of the changed region. Gated: ≥3 primitive modified entries at one array path + contiguous indices. Uses `lcsPrimitiveDiff`.
`collapseHistoricalArrayShiftCascades(pool)` -> `Promise<{checked, updated}>` — migration applying the above to every stored `config_diffs` row + re-deriving `change_summary`; idempotent, best-effort. Wired into migrate.js. Fixes the historical "246 modified" membership-list rows (new diffs never produce them — their array branch already uses LCS).

## lib/engines/vpnSessions.js

`storeVpnSessions(deviceId, sessions, pool)` -> `Promise<{count}>` — DELETE+reinsert (one transaction) the LIVE per-user active-session set into `vpn_active_sessions`. Engine-worker calls it only after a SUCCESSFUL poll (a failed pull never wipes; an empty array clears — nobody connected). Session objects: `{username, tunnel_type, source_ip, assigned_ip, login_time, duration_seconds, bytes_in, bytes_out, client, gateway, raw}` (any field nullable). Added 2026-07-31.
`getVpnSessions(deviceId, pool)` -> `Promise<object[]>` — current active-session rows for the per-device VPN page.

## lib/engines/vpnTunnels.js

`storeVpnTunnels(deviceId, tunnels, pool)` / `getVpnTunnels(deviceId, pool)` — same live-snapshot DELETE+reinsert + read pattern as vpnSessions.js, for `vpn_ipsec_tunnels`. Tunnel shape: `{name, peer, status, ike_version, bytes_in, bytes_out, raw}`. Fed by the adapters' optional `getVpnTunnels()` (PAN-OS `show vpn ipsec-sa`, Fortinet `diagnose vpn tunnel list`, Cisco `show vpn-sessiondb l2l`), stored by the engine-worker VPN poll in its own try/catch (a tunnel-pull failure never fails the session poll). Added 2026-07-31.

## lib/engines/dashboardSnapshot.js

`computeAndStoreDashboardSnapshot(pool, { ifAbsent })` — `ifAbsent:true` switches the upsert from
`ON CONFLICT DO UPDATE` to `DO NOTHING` and returns `{stored}` reporting honestly whether a row was
written. ⛔ Used by the STARTUP catch-up; the 00:10 cron still uses the default DO UPDATE.

⛔ There used to be TWO startup paths that cancelled each other: an unconditional run in `main()`
and a guarded `runDashboardSnapshotIfMissing()` in `scheduleJobs()`, which is called AFTER it. The
guard always found the row the unconditional run had just written, so it was a permanent no-op —
and because the write was DO UPDATE, every deploy restart REPLACED that day’s snapshot with
mid-day numbers. A day’s trend point was whatever the last restart happened to see.

⛔ The catch-up leans on the existing `UNIQUE (snapshot_date)` constraint, not on a read-then-write
check, so two racing startups cannot both conclude the row is missing.

⛔ It writes `CURRENT_DATE` as a SQL literal and never as a parameter, so the engine has no way to
express any other date. Past gaps are permanent by design: those days’ CVE bands, compliance
findings and rule analysis no longer exist, and writing today’s numbers under an old date would
fabricate history.


`computeFleetCveSeverity(pool)` -> `Promise<{critical, high, medium, low}>` — fleet-wide (active devices) CVE counts by CVSS bucket; unscored CVEs excluded from all buckets.
`computeFleetComplianceScores(pool)` -> `Promise<{overall: number|null, byStandard: Record<string, number|null>, byStandardCounts: Record<string, {pass,fail,warning}>}>` — fleet-wide pass/(pass+fail+warning) scores per standard + overall; `null` when unmeasurable. `byStandardCounts` (added 2026-08-02, additive — `computeAndStoreDashboardSnapshot` below ignores it) is the raw counts behind each percentage, for `lib/engines/complianceReport.js`'s fleet summary section.
`computeAndStoreDashboardSnapshot(pool)` -> `Promise<{cve, compliance}>` — computes + `UPSERT`s today's `fleet_dashboard_snapshots` row (idempotent per calendar day).

## lib/engines/objectUsage.js

`analyzeObjectUsage(objects, rules)` -> `{object_id, finding_type: 'unused'|'duplicate', detail, related_object_ids}[]` (pure) — namespace-partitioned (address vs service) unused/duplicate object detection with transitive group-membership closure.
`storeObjects(deviceId, objects, pool)` -> `Promise<{count: number}>` — DELETE+reinsert `network_objects` from an adapter's `getObjects()` result.
`runObjectUsageAnalysisForDevice(deviceId, pool)` -> `Promise<{findings: object[]}>` — loads objects+rules, analyzes, DELETE+reinsert `object_analysis_results` in one transaction.

. A partition name is an identifier and cannot be a bind parameter, so it is generated then re-validated before interpolation.
`insertEvents(pool, events)` -> `{stored, failedChunks}` — one bad chunk does not sink the flush, and the caller keeps the spool file whenever `failedChunks > 0` so nothing is silently discarded.
`toInetOrNull` / `toPortOrNull` / `toIntOrNull` / `toTextOrNull` — ⛔ all return NULL rather than a substitute. An INET column rejects malformed input and would abort the WHOLE batch, so a firewall logging a hostname where an IP belongs must yield NULL, never `0.0.0.0`.

## lib/syslog/syslogParser.js

`parseSyslogLine(line, receivedAt)` -> normalized frame — RFC 3164 (BSD) + RFC 5424. Pure, never throws, and REQUIRES `receivedAt` because RFC 3164 year resolution is meaningless without a reference time. Every field is nullable and stays null when the frame does not carry it. Returns `format` (`rfc3164|rfc5424|pri-only|raw|unknown`) and `parseComplete`.
⛔ `tzAssumed` is part of the contract: RFC 3164 has no timezone, so the collector's local zone is assumed and the flag says so. RFC 5424 carries its own offset and sets it false.
⛔ Year resolution picks the candidate year closest to `receivedAt` and returns null beyond ~45 days. A Dec 31 event received Jan 1 must resolve BACKWARD; stamping the receive year puts it 12 months in the future where every "last 7 days" query misses it. Feb 29 in a non-leap year is rejected, not slid to Mar 1.
`decodePri(priText)` -> `{facility, severity}`, both null when malformed. Validates the STRING before `Number()` — `Number('')` is 0, which previously decoded a blank PRI to facility 0 / severity 0, i.e. a kernel EMERGENCY invented from an empty string (found by its own test).

## lib/syslog/vendorParsers.js

`detectVendor(message)` -> slug | `null`. ⛔ NO "generic" fallback: a guessed vendor mis-parses every field after it, so an unrecognised payload is stored raw and unattributed.
`parseVendorPayload(message)` -> normalized event | `null`. `parseFortinet` / `parsePaloAlto` / `parseKeyValue` / `splitCsv` exported for reuse and testing.
⛔ **Every field position/name here was read off REAL CAPTURED LOGS** from this fleet's preserved FWA archive (2026-09-08), never from vendor docs — CLAUDE.md's "documentation lies" rule. The captured lines are the fixtures in `tests/vendorParsers.test.js`, so the evidence sits next to the code.
Fortinet: space-separated key=value; `eventtime` is a NANOSECOND epoch (19 digits) paired with `tz`, preferred over the date/time pair. Carries `policyid` AND `poluuid` — the rule linkage that will let log evidence produce real hit counts for the SSH transport, which cannot report them via the API at all.
Palo Alto: POSITIONAL CSV. Rule NAME at index 11, action at index 30, and PAN-OS carries no rule id/uuid in the log at all. ⛔ Positions differ per log TYPE — `PAN_COMMON` + `PAN_TRAFFIC` + `PAN_THREAT` are three separate maps and each row is read only through the map for ITS type; a THREAT row leaves traffic-only fields null rather than borrowing the wrong column.

**Fields added 2026-09-08** — `logSubtype`, `srcUser`, `srcCountry`, `dstCountry`, `urlCategory`, `urlHostname`, `threatName`, `threatSeverity`. Every one was ALREADY arriving in logs both vendors send and was being discarded; none needs a new device command, a GeoIP database or an AD integration. This is what makes geographic, per-user, URL and attack reporting possible without new collection.
⛔ **PAN-OS puts COUNTRY at different indices per log type**: TRAFFIC 41/42, THREAT 38/39. Crossing the maps returns a real, plausible, WRONG value — traffic index 39 is a sequence number and would render as a country name. Pinned by `tests/vendorFields.test.js` using real captured lines from both types.
⛔ FortiOS reports `srccountry="Reserved"` for RFC1918 addresses. That is the device's own answer and is kept verbatim — not rewritten to null (which would discard a real answer) nor to "Private" (which would invent a word the device never said).
⛔ Fortinet's `threatName` accepts only `attack` or `virus`, never `eventtype` — on an app-ctrl row `eventtype` reads "signature", which names nothing and would top every Top Threats report.
`threatSeverityRank(raw)` -> `0-5 | null` — maps PAN-OS (`informational`..`critical`) and FortiOS (`debug`..`emergency`) onto ONE ordered scale so a severity chart does not split a level across two vendor words. ⛔ Returns null for an unrecognized word, never a default level: a threat filed under a guessed severity silently changes where it sorts in a prioritized list.

## lib/syslog/threatStats.js

`getTopAttackers` / `getTopTargets` / `getTopThreats` / `getThreatsBySeverity` / `getThreatTimeline` / `getDeviceThreatSummary` — the Security-tab reports, i.e. Firewall Analyzer's Attack, Virus and Security report families.
⛔ **These read `syslog_events` DIRECTLY while every traffic widget reads a rollup**, and that split is deliberate: threat events are 1.31% of the stream (~70k/hour measured) and are covered by the PARTIAL `idx_syslog_events_class`, so a raw read is cheap AND keeps the per-event attacker/target/signature detail an aggregate destroys. "Which host attacked which host" is the question being asked.
⛔ `getThreatsBySeverity` merges PAN-OS and FortiOS severity vocabularies via `threatSeverityRank()` and returns `unranked` (word not recognized) and `unreported` (no severity at all) as SEPARATE counts — never folded into a level, because a threat filed under a guessed severity silently changes where it sorts. Each level also reports the vendor words that landed on it, so a merge is visibly a merge.
⛔ Rows with no `threat_name` are excluded from `getTopThreats`, not bucketed under a synthetic label that would top the chart.

## lib/syslog/logSearch.js

`buildSearchQuery(filters, now)` -> `{sql, params, from, to, clamped, limit, applied, rejected}` · `searchEvents(pool, filters, now)` · `getFilterOptions(pool, hours)` · `clampPage` / `MAX_PAGE` (200).
⛔ **NO COUNT(*), EVER.** Measured on the live fleet: an exact count of a ONE-HOUR window took **43 SECONDS** (1,657,462 rows). Paging works without a total — `limit + 1` reveals whether a next page exists and `<Pagination hasMore>` renders "Page 3" rather than a "of 47" nobody verified. Paging itself is cheap: the PK is `(received_at, id)`, exactly the sort order (measured 5ms page 1, 2ms at OFFSET 500), and MAX_PAGE bounds how deep OFFSET can go. · `resolveWindow` · `clampLimit`.
⛔ **The ONLY place that reads `syslog_events` directly** instead of a rollup — an aggregate has thrown away the individual event, which is exactly what an investigation needs. In exchange it is disciplined about it:
⛔ **A time window is MANDATORY and BOUNDED** (`MAX_WINDOW_DAYS`=8, default last hour). `resolveWindow()` never returns an unbounded or inverted range whatever it is handed. At ~133 GB/day an open-ended search is not a slow query, it is an outage for the ~1,500 rows/sec ingest on the same disk. A clamped range sets `clamped:true` and the UI says so.
⛔ **Truncation is REPORTED**, never silent: the query asks for `limit + 1`, drops the probe row, and returns `truncated`. "Here are 100 of many" and "here are the only 100" are different answers and only one is true.
⛔ **A malformed filter is REJECTED and surfaced** in `rejected`, never silently ignored — dropping `srcIp=10.1.1` would return every host's traffic and read as a confident answer about that one host.
⛔ **Every value is a bind parameter and every column name comes from the `FILTERS` whitelist.** This is the only query in the codebase assembled from user-supplied input, on a security product; `tests/logSearch.test.js` carries the injection guard. LIKE metacharacters are escaped so a literal `%` cannot silently widen a search to everything.
A bare address filters by equality, a CIDR by containment (`<<=`).

## lib/syslog/archive.js

`appendBatch(dir, lines, now)` -> `{ok, bytesRaw, bytesCompressed, file, error}` · `pruneArchive(dir, retentionDays, now)` · `archiveStats(dir)` · `fileNameFor` / `dayKey` / `ARCHIVE_FILE_RE`.
⛔ **Why a file and not a column.** Measured 2026-09-08: PostgreSQL stores `message` at 752 bytes against 748 bytes of text -- NO compression, because TOAST only compresses once a tuple exceeds ~2 KB and these rows are ~1 KB. And it could never match a file anyway: the 10.8x measured on this live stream (13.3x in FWA own archives) comes from compressing ACROSS lines, where a row can only compress against itself (2-3x). The gap is architectural, so the fix is.
⛔ **Concatenated gzip members, one per flush.** Chosen for CRASH SAFETY over ratio: a single long-lived stream compresses marginally better and is unreadable end-to-end if the process dies mid-write -- the one failure that matters for an archive, because you find it months later. Per-flush members mean a crash damages at most the final member. gzip defines a stream as a sequence of members, so the day file stays readable by `gunzip`/`zcat`/`zgrep`.
⛔ **Never throws.** A full or unmounted archive volume degrades to a logged warning; the database is the primary store and ingest must survive it. Archiving happens BEFORE the DB insert while the spool file is still on disk, so a crash costs a replay (at worst a duplicated member), never a lost line.
⛔ `pruneArchive` only ever deletes names matching `ARCHIVE_FILE_RE`, and falls back to the documented default on junk retention input rather than computing a cutoff that wipes everything.

## lib/syslog/eventShape.js

`buildEvent(raw, frame, payload, deviceId)` -> the event object `eventStore.flattenRow()` consumes. Pure — no DB, no sockets, no clock. Never throws.
⛔ **This is the middle of a THREE-hop field path**: `vendorParsers` -> `buildEvent` -> `eventStore` COLUMNS/flattenRow. Miss any hop and the field does not error, it stores NULL — which reads exactly like "the device never sent it". On 2026-09-08 the parser and the store were both updated for eight new fields and this hop was not; 360,025 events were written with every new column silently null.
⛔ It was extracted from `services/collector.js` for exactly that reason: that file starts listeners on require and cannot be unit-tested, so the hop had no test. `tests/eventShape.test.js` now walks a REAL captured log line end to end and fails if any column the store persists is unreachable from the parser, with an explicit excused-columns list so a new column must be either wired or consciously excused.
⛔ `bytesSummable` resolves to `false`, never null — the column is NOT NULL, and "we could not tell" must mean "do not sum it".

## lib/syslog/rollups.js

`floorHour(date)` / `addHours` / `sweepWindow(now, hours)` -> `{from, to}` — UTC hour buckets. `to` is the start of the NEXT hour so the in-progress hour is included and corrected on every later sweep; `from` reaches back one hour further than requested so the earliest bucket is rebuilt WHOLE.
`recomputeWindow(pool, from, to)` -> `{ok, hourlyRows, ruleRows, talkerRows, appRows, blockedRows, ms, error}` — rebuilds all FIVE rollups over one window, in ONE transaction. ⛔ **DELETE-then-INSERT, never increment-on-insert**: that makes every cycle idempotent and self-healing, so a missed cycle, a restart, a double-run or a retry can never double-count. Never throws — the caller is a timer inside the collector.
⛔ **ONE SCAN, FIVE ROLLUPS.** `WINDOW_TEMP` materializes the window into a `rollup_src` temp table and all five aggregate THAT; none may reference `syslog_events` or `received_at`. Before this (measured live 2026-09-08, 9.3M rows in 3h) each rollup was a parallel seq scan of the whole 9.9 GB daily partition — ~9.1 GB of buffer reads EACH, five times, giving an 84s recent sweep every 5 min and a 170s wide sweep hourly; at the steady state (~133 GB/day) the hourly wide sweep alone would have read ~600 GB off the disk simultaneously taking ~1,500 inserts/sec. The temp table omits `message`, ~90% of a row by bytes and read by no rollup.
⛔ **`ON COMMIT DROP`, never an explicit DROP** — the client returns to a POOL, so a surviving temp table would leak onto a pooled connection and the next sweep would fail with "relation already exists"; ON COMMIT DROP also cleans up on ROLLBACK. `ANALYZE rollup_src` runs before the aggregations because a fresh temp table has no statistics at all.
⛔ The window now appears in exactly ONE statement, so a DELETE range disagreeing with its INSERT range — the bug that broke `syslog_rule_hits_daily` — is structurally impossible.
`runRollupMaintenance(pool, {wide, recentHours, lookbackHours, sliceHours, now})` — one tiered cycle. ⛔ **The WIDE tier is SLICED**: it rebuilds one `WIDE_SLICE_HOURS` (6) slice of the lookback per pass, rotating deterministically off the clock, because a single-pass 24h sweep grew 155s -> 248s -> 327s on the live fleet as the partition filled and began overrunning the 5-minute cycle. ⛔ Slicing, never SHRINKING the lookback — a shorter lookback silently and permanently under-counts any bucket that receives a late event. ⛔ The slice overlap is the SLICE COUNT, not one hour: `now` advances an hour per pass while the index steps back a whole slice, so the window drifts a full slice-count over a rotation, and a one-hour overlap left the OLDEST hours covered by no slice at all (caught by the coverage test, not by review). The `recent` tier is deliberately NOT sliced — slicing the live tier would stall the dashboards. ⛔ The WIDE sweep is not optional: `received_at` is stamped at parse time and never rewritten, so an event that lands late belongs to a bucket already out of the recent window. Without the wider periodic sweep that bucket is never revisited and the rollup under-counts PERMANENTLY, with no error anywhere (LogVault shipped exactly that bug with a 2-hour window).
`backfillRange(pool, from, to, onProgress)` — manual recovery for a gap longer than the wide window; one day at a time so a multi-week backfill is never a single enormous transaction.
`trimDetailRollups(pool, retentionDays)` -> `{days, deleted, error}` — bounded retention for the three DETAIL rollups only. ⛔ Junk/zero/negative input falls back to 30 rather than deleting the whole table; the day count is a BOUND PARAMETER; and the error is RETURNED rather than swallowed, because a silently un-trimmed high-cardinality table is how a disk fills up with every health signal still green.
`WINDOW_TEMP` / `HOURLY_INSERT` / `RULE_INSERT` / `TALKER_INSERT` / `APP_INSERT` / `BLOCKED_INSERT` exported for `tests/rollups.test.js` + `tests/detailRollups.test.js` to assert against.
⛔ Every byte aggregate is `sum(...) FILTER (WHERE bytes_summable)` and is never COALESCEd to 0 — see `vendorParsers.bytesSummable`.

## lib/syslog/trafficStats.js

⛔ **Every query here reads a ROLLUP, never `syslog_events`** — that is the entire reason the rollups exist. Two documented exceptions: VPN per-event DETAIL (bounded by `log_class` + a recent window, and carrying per-event fields an aggregate would destroy) and ingest health (`syslog_ingest_stats` is already one small row per flush).
⛔ **"No data" is NULL, never 0** — a fleet not yet collected from renders "—". A dashboard showing 0 events/sec when the collector is DOWN looks identical to a quiet network.
Permanent-rollup readers: `getTrafficTimeline(pool, hours)`, `getTopTalkers(pool, hours, limit)`, `getActionBreakdown`, `getTopRules(pool, days, limit)`, `getIngestHealth(pool, minutes)`, `getVpnActivity`, `getVpnActivityByDevice`, `getThreatActivity`, `getClassTimeline(pool, logClass, hours)`.
Country/user/URL readers (Phase 8b): `getTopCountries(pool, hours, limit)` -> `{countries, internal, unreported}` (⛔ internal + unreported are RETURNED, not dropped — excluded silently the percentages would total 100% of a smaller number while presenting as 100% of traffic), `getTopUsers(...)` -> `{users, attributed, totalEvents, coveragePct}` (⛔ coverage is stated; identity is resolved on only a fraction of events), `getTopUrlCategories(...)`, `isInternalCountry(v)`.
Detail-rollup readers (Phase 8b): `getTopHosts(pool, hours, limit)`, `getTopApplications(pool, hours, limit)` -> `{applications, unclassified}`, `getProtocolBreakdown(pool, hours)`, `getTopBlockedDestinations(pool, hours, limit)`, `getDeviceTrafficStats(pool, hours)`.
⛔ `getTopTalkers` and `getTopHosts` answer DIFFERENT questions and must not be conflated: the first ranks the FIREWALLS sending us syslog (`source_ip` of the datagram), the second ranks the HOSTS inside the traffic those firewalls described (`src_ip` parsed from the payload). One returns ~16 rows, the other thousands.
⛔ `getTopApplications` returns rows with no application as a separate `unclassified` COUNT rather than a synthetic `(unknown)` row — that row would usually rank #1 and bury the real answer behind a label that means nothing.
⛔ `getDeviceTrafficStats` lists every ACTIVE device including ones that sent NOTHING (`events:0`, `lastSeen:null`). A firewall that has silently stopped logging is the most valuable row in that table; a query returning only devices present in the rollup would hide exactly it.

## lib/vpnTabs.js,,Tab models for the two VPN pages — pure CommonJS, same shape as `dashboardTabs.js`. `FLEET_VPN_TABS` (status | activity) · `DEVICE_VPN_TABS` (overview | users | tunnels) · `resolveFleetVpnTab` / `resolveDeviceVpnTab` (always return a VALID key) · `buildVpnTabHrefs(basePath, tabs, searchParams, activeKey, dropParams)`.,⛔ **Tabs here are a COST control, not just layout.** Only the active tab queries. The VPN log view costs ~7s on a COLD cache and it is always cold — a 26 GB/day ingest evicts those rows from a 4 GB buffer pool long before an operator next visits — so stacking it meant every visit paid that even to read the tunnel list. Same reasoning as the dashboard rendering only its active tab.,⛔ `buildVpnTabHrefs` PRESERVES filters but DROPS the other tabs' page params: a page number from the list you are leaving is meaningless in the list you are arriving at, and carrying it lands you on page 7 of something you just opened.,,## lib/pagination.js

Shared server-side pagination. Pure, dependency-free CommonJS (no DB, no React) so both Server Components and API routes use it.
`resolvePage(raw)` -> `>= 1` · `resolvePageSize(raw, def)` (capped at `MAX_PAGE_SIZE` 500) · `totalPages(total, pageSize)` -> `>= 1` · `pageWindow(page, pageSize, total)` -> `{page, pageSize, limit, offset, totalPages}` · `buildPageHref(basePath, searchParams, overrides)` · `describeRange(page, pageSize, total)` · `paginateArray(items, page, pageSize)` · `DEFAULT_PAGE_SIZE` 50.
⛔ **A page number is USER INPUT.** `resolvePage` always returns a usable page (handles arrays, junk, negatives), and `pageWindow` **clamps a past-the-end page to the LAST page** — a bookmarked `?page=40` after rows were deleted must not render a blank table, which reads as "everything is gone".
⛔ **The total must be honest.** `describeRange` renders `51–100 of 1,522` so the rows on screen are never mistaken for the whole set, and returns **null** rather than inventing a count when the caller genuinely cannot count — `<Pagination>` then says "total not counted". Same class of honesty as log search's truncation notice.
⛔ `buildPageHref` preserves every other query param: losing the active filter on "next" silently changes what the reader is looking at halfway through reading it. A `null` override REMOVES a param, which is how page 1 drops `page=` from the URL.
`paginateArray` is for genuinely computed in-memory collections only — prefer SQL `LIMIT/OFFSET` + `COUNT` wherever rows come from a table.

## lib/dashboardTabs.js

`DASHBOARD_TABS` -> `{key,label,description}[]` — the dashboard's tab model, the single source for the tab bar, the `?tab=` whitelist and the default. ⛔ `key` is a URL value and therefore a public contract: add and deprecate, never rename in place.
`resolveDashboardTab(raw)` -> `string` — ALWAYS returns a key present in `DASHBOARD_TABS`, never the caller's input and never undefined. Handles the array Next.js produces for a repeated param (`?tab=a&tab=b`) by taking the first entry, and trims/lowercases a hand-typed value. A `?tab=` is user-supplied input, and a blank dashboard is indistinguishable from an outage.
`dashboardTabByKey(key)` -> tab | `null`.
Pure, dependency-free CommonJS (no DB, no React) so the Server Component imports it and `tests/dashboardTabs.test.js` unit-tests it. The **Traffic** tab was deliberately absent until there was something real behind it; `services/collector.js` shipped 2026-09-08 and it was added the same day.

## lib/engines/configRetention.js

`runConfigRetention(pool, options)` -> `Promise<{dryRun, durationMs, deviceConfigs, configBackups}>` — daily retention over `device_configs` + `config_backups`. ⛔ NEVER THROWS (per-table errors land in `summary.<table>.error`), idempotent, and structurally incapable of deleting a baseline, a device's newest row, its `MIN_KEEP_*` most recent rows, or a non-`'auto'` backup — every one of those tests is written TWICE, once in the classify query and once in the DELETE. `options`: `{configRetentionDays, backupRetentionDays, minKeepConfigs, minKeepBackups, maxRowsPerRun, dryRun}`; `dryRun:true` runs only the classification and reports `wouldDelete`. Per-run row cap (5000/table, oldest-first) so a first run on a huge table drains over several runs rather than one giant transaction, reported as `capped:true` so the log never understates.
`formatRetentionSummary(summary)` -> `string[]` — pure; the engine.log lines, which state what was KEPT and by which protection alongside what was deleted.
Exports `DEFAULT_CONFIG_RETENTION_DAYS` (60) / `DEFAULT_BACKUP_RETENTION_DAYS` (365) / `MIN_KEEP_CONFIGS` (10) / `MIN_KEEP_BACKUPS` (5) / `DEFAULT_MAX_ROWS_PER_RUN` / `AUTO_BACKUP_LABEL` — `services/engine-worker.js` imports the defaults as its env-parsing fallbacks rather than hardcoding a second copy, so worker/`.env.local.example`/CLAUDE.md cannot drift.

Verified against live production data 2026-08-25 (1,730 rows / 449 MB / 16 devices): at the default 60d the job is a provable no-op (nothing on this fleet is older than 41 days); at 30d it would free 150 MB and at 14d 351 MB, and in ALL THREE the delete set contained zero baselines, zero newest-per-device rows, and left every device at or above the min-keep floor.

## lib/engines/deviceHealth.js

Added 2026-08-03. PURE derived-status layer over the four lifecycle/health tables
(`device_licenses`/`device_ha_status`/`device_disk_usage`/`device_content_versions`) — no DB
access, and `now` is always an explicit parameter (never `Date.now()` baked in) so every branch is
fixture-testable. Same "scoring/banding over data another module collected" role as `riskScore.js`.

Status is computed at READ time, not stored as findings: the raw facts are persisted, and
"is that expiring/stale/degraded" is a pure function of those facts plus the current time, so
storing it would only create a second thing that can go stale.

`licenseStatus(row, now, warnDays=60)` -> `{status:'expired'|'expiring'|'ok'|'perpetual'|'unknown', daysRemaining}`
— the device's own `expired===true` wins over date arithmetic (clock skew, grace periods), but
`expired===false` is NOT taken as authoritative the other way, since a currently-valid licence can
still be days from lapsing. 60-day window (vs `ruleAnalysis.js`'s 14 for rules) because a support
contract needs procurement lead time.
`worstLicenseStatus(rows, now)` — worst-by-severity, tie-broken by soonest expiry so a summary tile
points at the most urgent renewal.
`signatureStatus(row, now, staleDays=7)` / `worstSignatureStatus(...)` -> `stale|ok|unknown` — 7
days because Palo Alto ships AV/threat content at least daily.
`haStatus(row)` -> `{status:'standalone'|'healthy'|'degraded'|'unknown', reasons[]}` — `degraded` on
peer-connection-not-up, config-not-synchronized, `version_compat_ok===false`, a missing peer state,
or a `last_nonfunctional_reason`. ⚠️ A `User requested` suspension deliberately does NOT degrade a
pair (the parser already keeps it out of that column).
`diskStatus(rows)` -> worst `use_percent` banded `critical`(>=90)/`warning`(>=80)/`ok`.

⛔ Every function returns `unknown` rather than a confident value on missing/unparseable data —
the same tri-state discipline `config_applies` and compliance `pass_when` already enforce.

## lib/engines/deviceInventory.js

Everything behind the Devices page in one place (added 2026-08-06, v2.56.0). `getDeviceInventory(pool, {sort})` -> `{rows, tiles, sortKey}`; also `decorate(row)`, `computeTiles(rows)`, `SORT_OPTIONS`.

One query gathers real columns/aggregates; posture is derived in JS so it reuses `riskScore.js` and `securityScore.js` rather than re-implementing them in SQL. The per-device security score uses the SAME composition as the fleet score (for one device, "devices with patch_now" is 0 or 1), so a row and the dashboard tile can never disagree. A device with no analysis rows passes `[]` for hygiene so it reports "not measurable" rather than a confident 100 it hasn't earned.

⛔ CVSS lives on `advisories`, NOT on `device_cve_assessments` (the assessment stores SecVault's judgement, the advisory the published severity) — the join is required.
⛔ Support expiry is NOT `MIN(expires_at)`: that returns the OLDEST licence, which on a real device lapsed years ago (HRIS's earliest is 2021-12-24), and as a "supported until" figure reads as the current date. Split into `expired_count` / `soonest_future_expiry` / `unknown_expiry_count` — three states, three different actions. A perpetual licence (NULL date + raw 'Never') is correctly none of them.
⛔ `SORT_OPTIONS` is a plain KEY SET, not ORDER BY fragments. Sorting happens in JS (score/risk are derived); the query has no ORDER BY. It briefly held fragments naming `security_sort`/`risk_sort`, columns that never existed — fixed v2.57.0. The raw `?sort=` param is only ever a lookup key, never interpolated into SQL.

## lib/engines/riskScore.js

`computeRiskScore(findings)` -> `{score: number, band: 'low'|'medium'|'high'|'critical', raw: number}` — tallies severity counts from a raw findings array then scores.
`computeRiskScoreFromCounts(counts)` -> `{score, band, raw}` — weighted (critical:10/high:5/medium:2/info:0), **each tier's contribution capped independently BEFORE summing** (critical 60/high 30/medium 20, info uncapped since its weight is already 0 — caps deliberately sum above 100, so the outer `Math.min(100,...)` clamp is load-bearing) — fixed 2026-07-23, see CLAUDE.md's Rule Analysis Dashboard section for why the old "clamp the total" formula saturated at 100 for 13/14 of a real fleet, and for the same-day follow-up that raised the critical cap from an initial 40 (still below the high/critical band boundary) to 60. `raw` is the true UNCAPPED sum, diagnostic only, no current caller reads it.
`computeRuleRiskBand(ruleFindings, enabled)` -> `'low'|'medium'|'high'|'critical'|'attention'` — per-rule risk band = worst severity among the rule's own findings; `'attention'` for an enabled rule with zero findings, `'low'` for a disabled one. Untouched by the 2026-07-23 fix (different function, per-rule not per-device).
`SEVERITY_WEIGHTS` -> `object` — `{critical:10, high:5, medium:2, info:0}`.
`TIER_CAPS` -> `object` — `{critical:60, high:30, medium:20}` (no `info` key — its weight is 0, so a cap could never bind; 2026-07-23).
`MAX_SCORE` -> `number` — `100`.

## lib/engines/ruleReorder.js

`computeRecommendedOrder(rules, findings)` -> `{recommendedOrder: RuleRow[], changedRuleIds: string[], unresolvedRuleIds: string[], resolvedFindingCount: number, unresolvedFindingCount: number}` (pure) — topological sort (Kahn's algorithm) over `reorder_candidate` findings' precedence constraints; cycles left unresolved/unmoved rather than guessed; stable-merge minimal diff from current order.

## lib/engines/vpnSummary.js

`summarizeVpnConfig(vendor, configParsed)` -> `{supported, hasConfig, enabled?, sourceInterface?, port?, idleTimeout?, minTlsVersion?, foundAt?, fields, lowConfidence?, error?}` — vendor-dispatched (fortinet/cisco_asa/sangfor/paloalto) VPN config interpreter over already-collected `config_parsed`; never throws, degrades to `error:true`.

## lib/engines/vulnerabilityCategory.js

`CATEGORIES` -> `object` — `{RCE, PRIV_ESC, INFO_DISCLOSURE, DOS, OTHER}` display-label map.
`CWE_CATEGORY_MAP` -> `object` — curated CWE-numeric-id → category map (~35 entries).
`normalizeCweId(raw)` -> `string|null` — normalizes `"CWE-78"|"cwe-78"|78` → `"78"`; null for unparseable/NVD placeholder values.
`categorizeCwes(cweIds)` -> `string` — priority-ordered (RCE>PRIV_ESC>INFO_DISCLOSURE>DOS>OTHER) categorization of a CWE list; never throws, defaults to `'Other'`.
`extractCweIdsFromRawData(rawData)` -> `string[]` — pulls CWE ids from NVD/CVE-Record/CSAF raw_data shapes; never throws, `[]` on failure.
`backfillVulnerabilityCategories(pool)` -> `Promise<{processed: number}>` — one-time-safe-rerunnable backfill of `cwe_ids`/`vulnerability_category` for advisories with `vulnerability_category IS NULL`.

## lib/engines/snmpConfigDetection.js

`detectSnmpConfig(vendor, configParsed)` -> `{supported, hasConfig, enabled: boolean|null, foundAt?, fields, lowConfidence?, error?}` — vendor-dispatched (fortinet/paloalto) detector for "does config show SNMP already configured"; never returns/touches the actual community string or SNMPv3 secret.
`looksConfigured(detected)` -> `boolean` — convenience predicate: `hasConfig && enabled !== false`.

## lib/engines/configAuditor.js

`runComplianceAuditForDevice(deviceId, pool)` -> `Promise<{findings: object[]}>` — loads device+config+applicable `audit_checks`+rule findings+zone roles, evaluates every check (config-predicate / rule_scan / ruleset_property), DELETE+reinsert `audit_findings` in one transaction.
`evaluateCheck(check, configParsed)` -> `{status: 'pass'|'fail'|'warning'|'na', detail: string}` — evaluates a config-predicate check via `applicability.evaluatePredicate` + `pass_when` polarity. ⛔ Short-circuits `predicate_type: 'not_evaluable_from_config'` to `na` FIRST, before the `pass_when` guard (those checks carry a placeholder `pass_when` that is never consulted). `na` is excluded from the score denominator; the finding is still written and shown with its `reason`.
`evaluateRuleScanCheck(check, ruleFindingsByType)` -> `{status: 'pass'|'fail'|'warning', detail, matchedRuleIds: string[]}` — checks whether any rule carries one of the check's target Phase-5 finding types.
`evaluateRulesetPropertyCheck(check, rules, zoneRoleMap?, ruleFindingsByType?)` -> `{status: 'pass'|'fail'|'warning'|'na', detail, matchedRuleIds?}` — evaluates `has_explicit_deny_all`/`blocks_icmp`/`no_external_to_internal_access` against a device's live rule set.
`statusFromResult(result, passWhen)` -> `'pass'|'fail'|'warning'` — maps a tri-state predicate result + polarity to a compliance status.

## lib/engines/notificationDispatch.js
Added 2026-08-01. Consumed by services/engine-worker.js's `notification-dispatch` job (5-59 min, `NOTIFICATIONS_POLL_INTERVAL_MINUTES`).

`runNotificationDispatch(pool)` -> `Promise<{dispatched: number, errors: number}>` — for each of the 3 alert types (`patch_now_cve`/`compliance_critical`/`config_diff`), fetches currently-open items (near-verbatim copies of app/api/events/route.js's `fetchPatchNow`/`fetchConfigDiffs` query shapes, plus a new `audit_findings`+`audit_checks.severity='critical'` query — compliance has no ack mechanism, so "open" there is just every currently-failing critical check), reconciles `notification_dispatch_log` (clears anything no longer open), skips anything already dispatched+still-open, else sends via lib/notify.js's `dispatchNotification` to every channel whose `alert_types` matches, THEN writes the dispatch-log row (send-before-log, so a crash mid-send risks a duplicate message next tick rather than a silently-lost alert). Best-effort per item/channel — one bad webhook or malformed item never stops the rest.
(internal, not exported: `fetchOpenPatchNowCve`/`fetchOpenComplianceCritical`/`fetchOpenConfigDiff`, `buildMessage`.)

## lib/engines/complianceReport.js
Added 2026-08-02. Consumed by `app/api/compliance/report/{pdf,generate}` and `services/engine-worker.js`'s monthly `compliance-report` job.

`buildReportData(pool)` -> `Promise<{fleet, perDevice, findingsAppendix, generatedAt}>` — `fleet` via `dashboardSnapshot.js`'s `computeFleetComplianceScores`; `perDevice` and `findingsAppendix` (fail+warning only, grouped by device) are each a deliberate 5th duplicate of the fleet-scoring formula (see `app/api/compliance/fleet/route.js`'s own "kept as a literal array, not an import" comment — same established convention, not unified).
`generateReportPdf(pool)` -> `Promise<Buffer>` — pure-JS vector PDF via **`pdfkit`** (no browser/native process — rewritten 2026-08-02, replacing an abandoned `puppeteer-core`+headless-Edge implementation that failed to launch specifically under the NSSM Windows services; see CLAUDE.md's Compliance Reports entry). Drawing helpers (`drawCover`/`drawTable`/`stampHeadersFooters`/`sectionTitle`/`pdfSafe`/`installPdfSafeText`) ported from `spanvault/api/reportsPdf.js`'s pattern — read-only reference on this dev machine, not a runtime import (no cross-suite-app dependency). `bufferPages:true` + a final `stampHeadersFooters` pass over `doc.bufferedPageRange()` adds running header/footer + page numbers once total page count is known. Returns the assembled `Buffer` via `doc.on('data'/'end'/'error')`, used identically by the on-demand download route and the email-attachment scheduler.
`dispatchMonthlyReport(pool)` -> `Promise<{skipped: boolean, reason?, period, sent?}>` — shared orchestration for BOTH the scheduled job and the manual `POST /generate` route (one code path). Idempotent per `'YYYY-MM'` period via `compliance_report_log`'s partial unique index; emails every `notification_channels` row with `channel_type='email'` + `'compliance_report'` in `alert_types`; logs `status='error'` (not `'success'` with 0 recipients) if every channel send fails, so the unique index never blocks a same-month retry.
(internal, not exported: `buildPerDeviceStandards`, `buildFindingsAppendix`, `buildFleetSummaryTable`, `buildPerDeviceTable`, `buildFindingsTable`, `renderReportBody`, `currentPeriod`, `scoreColorHex`.)

## lib/engines/exposureCorrelation.js

`EXPOSURE_FINDING_TYPES` -> `string[]` — `['any_any', 'overly_permissive', 'risky_service', 'external_exposure']`.
`getExposureCorrelationForDevice(deviceId, pool)` -> `Promise<{finding: {id, rule_id, finding_type, severity, detail}, cves: {advisory_id, cve_id, cvss_score, kev_listed, advisory_url}[]}[]>` — device-level join of open exposure-widening rule findings with open `patch_now` CVE assessments (both excluding acknowledged/dismissed).
`countDevicesWithExposureCorrelation(pool)` -> `Promise<number>` — fleet-wide count of devices with ≥1 correlation.

## lib/engines/reachabilityMatrix.js

`computeZoneReachability(rules)` -> `{zones: string[], matrix: Object<string, Object<string, {verdict: 'allow'|'deny'|'unspecified', ruleName: string|null}>>, hasZoneData: boolean}` (pure) — single-device zone×zone reachability matrix via first-matching-enabled-rule-wins walk in `sequence_number` order.

## lib/engines/objectResolver.js

Added 2026-08-02, for `app/api/devices/[id]/access-path`'s per-device "Access Path Query" tool
(`components/analysis/AccessPathTab.js`) — resolves `firewall_rules` address/service field entries
(almost always OBJECT NAMES, e.g. `"LAN-subnet"`) to real IP ranges/ports via a device's
`network_objects` rows, recursively expanding `address_group`/`service_group` membership
(cycle-guarded). Nothing else in this codebase resolves object NAMES — `ruleAnalysis.js`'s
`fieldCovers`/`fieldEquals` only compare address-list values as strings/sets. Pure, no DB access —
caller loads a device's `firewall_rules` + `network_objects` once and passes both in.

`resolveAddressField(fieldValues, addressObjectsByName)` -> `{ranges: {start,end}[], unresolvedFqdns: string[], unresolvedNames: string[], isAny: boolean}` — literal IP/CIDR/range first, else object lookup + recursive group expansion; an FQDN value or an unmatched name never silently becomes a non-match.
`resolveServiceField(fieldValues, serviceObjectsByName)` -> `{protocols: {proto, portStart:number|null, portEnd:number|null}[], unresolvedNames: string[], isAny: boolean}` — ⛔ object-name lookup MUST come first, literal-parse fallback second (opposite order from `resolveAddressField`) — a bare object name like `"HTTPS"` is shape-indistinguishable from a bare protocol keyword like `"icmp"`; parsing the raw entry first would silently misread the object name as a protocol literal.
`matchesAddress(resolved, queryIpUint32)` / `matchesService(resolved, queryProto?, queryPort?)` -> `'match'|'no-match'|'unresolved'` — tri-state; an unresolved object is never coerced to `'no-match'`.
`queryAccessPath(rules, objects, {srcIp, dstIp, protocol?, port?})` -> `{verdict, matchedRule, hasCaveat, walk}` — walks enabled rules in `sequence_number` order; the FIRST rule not definitively excluded (none of src/dst/service resolved `'no-match'`) decides — including a rule whose match involved an `'unresolved'` object, which still wins but sets `hasCaveat:true` rather than being skipped past. No rule decides -> `verdict:'unspecified'`, NEVER `'deny'` — no default/implicit-policy data exists anywhere in this codebase. `walk` includes every excluded rule that was still partially relevant (at least one dimension not `'no-match'`), for audit transparency.

Deliberately single-device, config-only — was true unconditionally until `topology.js` (below,
added 2026-08-02) added a cross-device layer ON TOP of this file, reusing `queryAccessPath()`
UNCHANGED per hop; `objectResolver.js` itself still never touches more than one device's data.
Sangfor's `getObjects()` is a stub (always empty) — on Sangfor devices only literal IP/port values
typed directly into a rule can ever resolve; the API route surfaces this as an explicit `note`, not
a silently-wrong verdict.

## lib/engines/topology.js

Added 2026-08-02, for `app/api/topology/path-query`'s fleet-wide "Path Query" tool
(`components/topology/PathQueryTab.js`) — Phase 1 of a multi-hop, cross-device path simulator
(Tufin/AlgoSec-style). Adds ONE layer on top of `objectResolver.js`'s already-shipped, UNCHANGED
`queryAccessPath()`: infers which devices are adjacent (shared subnet), applies NAT translation
between hops, and crosses devices via longest-prefix-match routing. Pure functions except the API
route itself, which owns all DB querying (`fleetData` is fully pre-loaded, same "load everything up
front" convention as `objectResolver.js`).

`buildAdjacencyGraph(interfacesByDevice)` -> `Map<string, {deviceId,interfaceName}[]>` keyed by
`` `${deviceId}::${interfaceName}` `` — two DIFFERENT devices' interfaces whose `device_interfaces.ip_address`
ranges overlap (via `cidrUtils.rangeOverlaps`) are adjacent; O(n²) over total fleet interface count
(accepted, same precedent as `ruleAnalysis.js`'s O(n²) shadow analysis — interface counts are orders
of magnitude smaller than rule counts).
`buildFleetTopologyGraph(devices, interfacesByDevice, vpnTunnelsByDevice?)` -> `{nodes: {id,name,vendor,hasInterfaceData}[], edges: {sourceDeviceId,sourceInterface,targetDeviceId,targetInterface,type:'subnet'|'vpn',tunnelName?,status?}[]}`
(added 2026-08-02, for `components/topology/FleetMap.js`'s visual diagram; `vpnTunnelsByDevice` param
added 2026-08-03) — reuses `buildAdjacencyGraph()` internally for `type:'subnet'` edges, deduping its
bidirectional entries into one edge per device PAIR (dedupe key qualified by edge type, so a subnet
edge and a VPN edge for the same pair coexist rather than colliding); every active device becomes a
node EVEN with zero `device_interfaces` rows (`hasInterfaceData:false`), so the map stays honest about
fleet coverage gaps instead of silently omitting uncollected devices.
`buildVpnEdges(deviceList, vpnTunnelsByDevice, ifacesByDevice, seenPairs)` -> `{type:'vpn', ...}[]`
(added 2026-08-03) — a SECOND, independent adjacency signal: branch firewalls often reach the fleet
over unnumbered IPsec tunnel interfaces (`ip: 0.0.0.0` — confirmed live on several Fortinet devices),
invisible to `buildAdjacencyGraph()`'s subnet-overlap check. Cross-references each device's
`vpn_ipsec_tunnels.peer` (already collected fleet-wide by the pre-existing `getVpnTunnels()` adapter
capability, no new collection added) against every OTHER device's `device_interfaces.ip_address`
(stripped of `/prefix`) for an EXACT match — a peer gateway IP must equal a specific address, not
just fall in a shared range. Skips `status !== 'up'` tunnels (down/unknown isn't live connectivity)
and unparseable/`'0.0.0.0'` peers (a real, recurring dialup/unassigned-gateway placeholder value).
**Deliberately visual-only** — NOT wired into `simulateMultiHopPath()`'s adjacency graph; a tunnel's
peer IP alone doesn't say what's routable through it (would need per-tunnel selector subnets).
`resolveRoute(routes, destIpUint32)` -> `{nextHopIp:string|null, interfaceName}|null` — longest-prefix-match
against one device's `device_routes`; `nextHopIp:null` means directly-connected (path ends here,
successfully) — callers MUST distinguish this from "no route at all" (`null` return).
`applyNat(natRules, addressObjectsByName, srcIp, dstIp)` -> `{srcIp, dstIp, natApplied, natRuleName, natUnresolved}`
— reuses `objectResolver.resolveAddressField`/`matchesAddress` UNCHANGED against `nat_rules`' `original_*`
fields (same JSONB-array-of-object-names shape as `firewall_rules`); translates via the first literal
`/32` found in `translated_*`, flags `natUnresolved` rather than guessing when a matched rule has no
usable literal.
`simulateMultiHopPath(fleetData, {srcIp, dstIp, protocol?, port?})` -> `{finalVerdict, hops, note?}`
— finds the entry device by source-IP-in-interface-subnet match (no match -> `unspecified`, never
guessed), then loops (capped at `MAX_HOPS = 25`, defensive against a routing loop between
misconfigured devices) calling `queryAccessPath()` per device, applying NAT, resolving the route,
and crossing the adjacency graph — stopping on a `deny`, a dead-end route, the fleet boundary
(egress subnet not shared with any known device), or the hop cap, each with an explanatory `note`.
Never silently upgrades a trailing/unresolved path to a confident verdict.

**Vendor scope**: `getInterfaces()`/`getRoutingTable()`/`getNatRules()` (optional adapter methods,
see `lib/adapters/interface.js`) are implemented by `paloalto` (BOTH SSH and API transport, as of
2026-08-03) and `fortinet`'s SSH transport only — Fortinet's API transport and the other 4 vendors
are not yet wired (no live device to verify against, for any of them). Fortinet's `getNatRules()`
(added 2026-08-02, live-verified against TSR-TL — see `cliParser.parseFortinetNatRulesOutput()`)
derives NAT from `show firewall policy`/`vip`/`ippool` rather than a separate rulebase: destination
NAT resolves cleanly via VIP objects (they bind to a real physical `extintf`); source NAT
(`set nat enable`) resolves to the egress interface's own IP ONLY when `dstintf` names a real
interface — an SD-WAN virtual interface (e.g. `"virtual-wan-link"`, the common case on live
policies) has no IP of its own, so that case reports `translatedSrcAddresses: null`
(`natUnresolved`), never a guessed WAN link. A device pair not covered by either vendor's
collection simply won't chain together in the adjacency graph — the query still returns a result,
just possibly ending earlier ("path continues beyond SecVault's managed fleet") than the real
network topology.

## lib/engines/ruleAnalysis.js

`analyzeRules(rules, options)` -> `Promise<{rule_id, finding_type, severity, detail, affected_rule_ids, remediation}[]>` (async, pure — yields to event loop every 25 outer-loop iterations) — Phase 5 engine: 12 finding types (`any_any, overly_permissive, external_exposure, risky_service, unused, log_disabled, expiring_soon, shadow, redundant, correlation, generalization, reorder_candidate`); pairwise checks skipped above `maxRulesForShadow` (default 1000).
`runAnalysisForDevice(deviceId, pool)` -> `Promise<{findings: number, byType: Object<string, number>}>` — loads rules+options+zone roles, analyzes, DELETE+reinsert `rule_analysis_results` under `pg_advisory_xact_lock`, snapshots `device_risk_history`.
`runAnalysisForAllDevices(pool)` -> `Promise<{devices: number, totalFindings: number, errors: {device_id, error}[]}>` — runs analysis for every active device; per-device failure isolated.
`DEFAULT_RISKY_PORTS` -> `object[]` — default risky-service definitions (telnet/ftp/rdp/smb/etc.).
`DEFAULT_OPTIONS` -> `object` — `{unusedDays, expiryWindowDays, riskyPorts, maxRulesForShadow, zoneRoles}`.

## lib/engines/ruleRelationships.js

`clusterRelationshipFindings(findings)` -> `{ruleIds: string[], findings: object[], worstSeverity: string}[]` (pure) — union-find clustering of `shadow|redundant|correlation|generalization|reorder_candidate` findings into connected rule-relationship groups; sorted worst-severity-first then by size.
`SEVERITY_RANK` -> `object` — `{critical:0, high:1, medium:2, info:3}`.

## lib/engines/zoneClassification.js

`VALID_ROLES` -> `Set` — `{'internal','external','dmz'}`.
`normalizeZoneName(zoneName)` -> `string` — trim+lowercase.
`getZoneRoleMap(deviceId, pool)` -> `Promise<Record<string, 'internal'|'external'|'dmz'>>` — per-device zone→role lookup map from `zone_classifications`.
`getDeviceZones(deviceId, pool)` -> `Promise<{zone_name, role}[]>` — every distinct real zone name seen in a device's `firewall_rules`, left-joined against classification; `[]` on failure (never throws).
`setZoneRole(deviceId, zoneName, role, pool)` -> `Promise<void>` — upserts one zone's role for one device; throws on invalid role/empty name.
`clearZoneRole(deviceId, zoneName, pool)` -> `Promise<void>` — deletes a zone's classification row (reverts to unclassified).

## lib/engines/versionComparator.js

`parseVersion(vendor, versionString)` -> `number[]` — dispatches to per-vendor tuple parser (forcepoint/fortinet/paloalto/cisco_asa/checkpoint/sangfor); unknown vendor falls back to plain dot-split.
`compareVersions(tupleA, tupleB)` -> `-1|0|1` — tuple-wise comparison, pads shorter with trailing zeros.
`isInRange(vendor, deviceTuple, rangeMin, rangeMax, maxExclusive?, safeCheckpoints?)` -> `boolean` — range membership test; checks named per-hotfix-train `safeCheckpoints` first (via `isSafeOnMatchingTrain`), then min/max bounds.
(internal, not exported: `parseForcepointVersion` (also the generic dot-split fallback + empty-segment filter), `parseFortinetVersion`, `parsePanosVersion`, `parseCiscoAsaVersion`, `parseCheckpointVersion`, `VENDOR_PARSERS` dispatch table, `isSafeOnMatchingTrain(deviceTuple, checkpointTuple)` -> `boolean`.)

---

## lib/adapters/interface.js

`FirewallAdapter` (abstract base class) — constructor({device, pool}); defines the adapter contract: `testConnectivity()` -> `{ok, latency_ms, message}`, `getVersion()` -> `{version_string, version_tuple, build, model}`, `getRules()` -> `NormalizedRule[]`, `getConfig()` -> `{raw, parsed}`, optional `getObjects()` -> `{addresses, addressGroups, services, serviceGroups}`, optional `getSnmpMetrics()` -> `{cpuPercent, memoryPercent, sessionCount, uptimeSeconds, raw, lowConfidence?, targetHost}`, optional `getPerformanceMetrics()` -> the SAME shape as `getSnmpMetrics()` but read over the device's EXISTING management transport (added 2026-08-04, v2.50.0 — paloalto both transports + fortinet SSH). Preferred over `getSnmpMetrics()` by `services/engine-worker.js`'s `snmp-poll` job, which for this method polls every ACTIVE device (no `snmp_enabled` opt-in, no separate `snmp` credential). Same `snmp_metric_snapshots` table, so `lowConfidence` still applies — it is a TRANSPORT change, not a new metric source, optional `getInterfaces()` -> `{interfaces: {name,ipAddress,zone,vdom,enabled}[]}`, optional `getRoutingTable()` -> `{routes: {destinationCidr,nextHopIp,interfaceName,protocol,metric,vdom}[]}`, optional `getNatRules()` -> `{rules: {sequenceNumber,enabled,natType,original*Addresses,translated*Addresses}[]}` (added 2026-08-02, for `lib/engines/topology.js` — paloalto/fortinet SSH transport only as of Phase 1; both implement it, see `topology.js`'s own entry for Fortinet's per-policy-derived NAT shape) — every concrete adapter extends this. [SENSITIVE]

## lib/adapters/index.js

`getAdapter(device, pool)` -> `FirewallAdapter instance` — resolves vendor+mgmt_method to a concrete adapter class via `ADAPTERS`/`DEFAULT_METHOD` tables. [SENSITIVE]
`collectAndStore(device, pool)` -> `Promise<{version, rulesCount, configCollected, configChanged, analysisFindings, complianceFindings, objectsCollected?, objectFindings?, interfacesCollected?, routesCollected?, natRulesCollected?, errors[]}>` — full per-device collect pipeline: version/rules/config persistence + Phase 5 rule analysis + Phase 6 diff/backup + Phase 7 compliance audit + optional object-catalog/usage analysis + optional topology data (interfaces/routes/NAT, added 2026-08-02 — each of the 3 checked/stored independently, one failing never blocks the others), each step isolated in try/catch. [SENSITIVE]
`storeDeviceInterfaces(deviceId, interfaces, pool)` / `storeDeviceRoutes(deviceId, routes, pool)` / `storeNatRules(deviceId, rules, pool)` (internal, not exported) -> DELETE+reinsert per device in one transaction, same pattern as `lib/engines/objectUsage.js`'s `storeObjects()`.
`SUPPORTED_VENDORS` (const array) — `Object.keys(ADAPTERS)`, the 6 canonical vendor slugs.

## lib/adapters/credentials.js

`parseApiCredential(plaintext, vendorLabel?)` -> `{apiKey, username, password}` — parses the `rest_api`/`smc_api`-style stored credential JSON (or legacy bare token string); throws secret-free errors on unusable input. [SENSITIVE]

## lib/adapters/sshClient.js

`runCommands(conn, commands, options?)` -> `Promise<Array<{command, output}>>` — opens one ssh2 shell session, runs commands expect-style against a prompt regex, handles --More-- pagination, enable-mode login; FROZEN CONTRACT for Cisco ASA/Sangfor. [SENSITIVE]
`parseJsonCredential(plaintext)` -> `{username, password, enable_password?}` — parses a stored SSH credential JSON string. [SENSITIVE]

## lib/adapters/snmpCredential.js

`parseSnmpCredential(plaintext)` -> `{version:'v1'|'v2c', community} | {version:'v3', username, authProtocol, authPassword, privProtocol, privPassword}` — parses the stored `snmp` credential_type JSON, validates v3 auth/priv consistency. [SENSITIVE]
`VALID_AUTH_PROTOCOLS` (const array) — `['MD5','SHA']`.
`VALID_PRIV_PROTOCOLS` (const array) — `['DES','AES']`.

## lib/adapters/forcepoint/index.js

`ForcepointAdapter` (class extends FirewallAdapter) — SMC-only adapter (never SSHes to engines). Methods: `_getConn()`, `testConnectivity()`, `_resolveEngine(conn)` (strict name-match, throws on ambiguity), `getVersion()`, `getRules()` (throws if no policy href, never returns [] on failure), `getConfig()` (redacts via `parser.redactEngineElement`), `getObjects()` (server-wide network/service catalog, degrades per-category), `getSnmpMetrics()` (DELIBERATE exception — polls `device.snmp_host` directly via UDP SNMP, required field for this vendor, always `lowConfidence:true`). [SENSITIVE]

## lib/adapters/forcepoint/smc.js

`smcRequest({smcHost, smcPort, apiKey, allowSelfSignedSsl, path, method})` -> `Promise<object|null>` — low-level SMC REST fetch wrapper, 15s timeout, self-signed TLS accept-by-default. [SENSITIVE]
`getApiInfo(conn)` -> `Promise<object>` — `GET /api/` connectivity/version check.
`getElement(conn, href)` -> `Promise<object>` — generic HATEOAS href follower.
`getEngines(conn)` -> `Promise<object[]>` — paginated `/api/elements/engines`, follows href for summary-only entries, logs `[SMC Debug]` on first element.
`getPolicy(conn, policyHref?)` -> `Promise<object|object[]>` — follows a policy href, or lists `/api/elements/fw_policy` when no href given.
`getNetworkElements(conn)` -> `Promise<object[]>` — paginated `/api/elements/network_elements`, logs `[SMC Debug]` sample.
`getServiceElements(conn)` -> `Promise<object[]>` — paginated `/api/elements/service_elements`, logs `[SMC Debug]` sample.

## lib/adapters/forcepoint/parser.js

`parseEngineVersion(engineElement)` -> `{version_string, version_tuple, model}` — checks `software_version`/`version`/`engine_version`/`dynamic_package` candidates in that preference order.
`parsePolicy(policyElement, networkElements, serviceElements)` -> `NormalizedRule[]` — throws when neither `rules` nor `fw_ipv4_access_rules` field is present at all (retrieval failure, not empty ruleset).
`parseConfig(engineElement)` -> `{raw, parsed}` — wraps an ALREADY-REDACTED engine element; caller must redact first.
`findEngineByIdentity(engines, device)` -> `object|null` — strict case-insensitive name match, never falls back to positional pick.
`describeEngineCandidates(engines, limit?)` -> `string` — human-readable candidate list for error messages.
`redactEngineElement(value, depth?)` -> `any` — recursive secret-key redaction (`SECRET_KEY_PATTERN` incl. phash/pre-shared/keytab), fail-closed, bounded depth 12. [SENSITIVE]
`parseAddressObjects(networkElements)` -> `{addresses, addressGroups}` — classifies host/network/address_range/group elements.
`parseServiceObjectCatalog(serviceElements)` -> `{services, serviceGroups}` — classifies tcp/udp/icmp service elements and groups.
`mapAction(rawAction)` -> `string|null` — SMC action vocabulary → NormalizedRule action.
`isSecretKey(key)` -> `boolean` — tests a key against `SECRET_KEY_PATTERN`. [SENSITIVE]
`classifyNetworkElement(el)` -> `'group'|'host'|'network'|'address_range'|'other'` — explicit `type` field wins, falls back to shape inference.
`classifyServiceElement(el)` -> `'group'|'service'` — same explicit-type-first pattern.

## lib/adapters/fortinet/index.js

`FortinetAdapter, FortinetSshAdapter` (re-exported; SSH class defined in `./ssh.js`)
`FortinetAdapter` (class extends FirewallAdapter) — FortiOS REST transport, token or session (username/password) auth. Methods: `_getConn()`, `_withSession(fn)` (session login/logout lifecycle), `testConnectivity()`, `getVersion()`, `_discoverVdoms(conn)` -> `string[]|null`, `_getRulesForVdom(conn, vdom, sequenceStart, prefixRuleName)`, `getRules()` (multi-VDOM aware, throws whole on one VDOM's failure), `getConfig()` (11 config sections incl. ntp/dns/log_syslogd/password_policy/fortiguard/autoupdate_schedule, redacts raw backup text), `getVpnSessionSummary()` (VDOM-aware SSL-VPN session count), `getObjects()` (address/addrgrp/service/servicegroup per VDOM, `_collectObjectCategory`), `getSnmpMetrics()` (4 scalar OIDs, `lowConfidence:false`). [SENSITIVE]
`restAddressToNamedAddress(entry)` -> `{name, type?, value}|null` — module-level helper, maps FortiOS cmdb address entry to getObjects() contract.
`restGroupToNamedGroup(entry)` -> `{name, members}|null` — maps addrgrp/servicegroup entry, tolerates bare-object `member`.
`restServiceToNamedService(entry)` -> `{name, value}|null` — maps custom service entry to e.g. `"tcp/443"`.

## lib/adapters/fortinet/api.js

`fortiRequest(conn, path, {rawText?, method?, formBody?, vdom?})` -> `Promise<object|string>` — authenticated FortiOS REST request (token or session cookie+CSRF), redirect-to-login detection. [SENSITIVE]
`loginSession(conn)` -> `Promise<{cookieHeader, csrfToken}>` — POST /logincheck, success determined by presence of real ccsrftoken cookie, not HTTP status. [SENSITIVE]
`logoutSession(conn)` -> `Promise<void>` — POST /logout, closes admin session.
`getSystemStatus(conn)` -> `Promise<object>` — GET /monitor/system/status.
`getFirmware(conn)` -> `Promise<object>` — GET /monitor/system/firmware.
`getPolicyStats(conn, vdom?)` -> `Promise<object>` — GET /monitor/firewall/policy (hit counts, per-VDOM).
`getConfigBackup(conn)` -> `Promise<string>` — GET /monitor/system/config/backup?scope=global (raw text, unredacted). [SENSITIVE]
`getVdoms(conn)` -> `Promise<object>` — GET /cmdb/system/vdom.
`getFirewallPolicies(conn, vdom?)` -> `Promise<object>` — GET /cmdb/firewall/policy.
`getFirewallAddresses(conn, vdom?)` -> `Promise<object>` — GET /cmdb/firewall/address.
`getFirewallAddrgrp(conn, vdom?)` -> `Promise<object>` — GET /cmdb/firewall/addrgrp.
`getFirewallServiceCustom(conn, vdom?)` -> `Promise<object>` — GET /cmdb/firewall.service/custom.
`getFirewallServiceGroup(conn, vdom?)` -> `Promise<object>` — GET /cmdb/firewall.service/group.
`getSystemGlobal(conn)` -> `Promise<object>` — GET /cmdb/system/global.
`getInterfaces(conn)` -> `Promise<object>` — GET /cmdb/system/interface.
`getSslVpnSettings(conn)` -> `Promise<object>` — GET /cmdb/vpn.ssl/settings.
`getSslVpnMonitor(conn, vdom?)` -> `Promise<object>` — GET /monitor/vpn/ssl (active session list).
`getSnmpSysinfo(conn)` -> `Promise<object>` — GET /cmdb/system/snmp/sysinfo.
`getAdmins(conn)` -> `Promise<object>` — GET /cmdb/system/admin. [SENSITIVE]
`getNtp(conn)` -> `Promise<object>` — GET /cmdb/system/ntp.
`getDns(conn)` -> `Promise<object>` — GET /cmdb/system/dns.
`getLogSyslogdSetting(conn)` -> `Promise<object>` — GET /cmdb/log/syslogd/setting.
`getPasswordPolicy(conn)` -> `Promise<object>` — GET /cmdb/system/password-policy.
`getFortiguard(conn)` -> `Promise<object>` — GET /cmdb/system/fortiguard.
`getAutoupdateSchedule(conn)` -> `Promise<object>` — GET /cmdb/system/autoupdate/schedule.
`withVdom(path, vdom)` -> `string` — appends `?vdom=`/`&vdom=`.
`extractCsrfToken(cookies)` -> `string|null` — finds/unquotes `ccsrftoken*` cookie. [SENSITIVE]
`parseSetCookies(response)` -> `Map<name,value>` — parses Set-Cookie headers.

## lib/adapters/fortinet/parser.js

`parseVersionInfo(firmwareBody, statusBody)` -> `{version_string, version_tuple, build, model, serial, hostname}` — merges firmware+status monitor responses.
`parsePolicies(policies, statsResults, {vdom?, prefixRuleName?, sequenceStart?})` -> `NormalizedRule[]` — maps cmdb policy array + hit-count stats to NormalizedRule.
`parseVdomNames(body)` -> `string[]|null` — extracts VDOM names from cmdb/system/vdom body; null means "assume single implicit VDOM".
`redactSecretFields(value, depth?)` -> `any` — recursive secret-key blanking for `parsed` config object, fail-closed. [SENSITIVE]
`buildHitCountIndex(statsResults)` -> `Map<policyid,{hit_count,bytes}>`.
`extractResults(body)` -> `any` — unwraps cmdb `{results: ...}` envelope.
`mapAction(rawAction)` -> `string|null` — FortiOS action → NormalizedRule action.
`mapLogTraffic(logtraffic)` -> `boolean` — `logtraffic` field → `log_enabled`.
`namesOf(field)` -> `string[]` — extracts names from FortiOS reference-array fields.
`withVdomRaw(rule, vdom)` -> `object` — attaches vdom tag to raw_rule.

## lib/adapters/fortinet/cliParser.js

`parseConfigTree(text)` -> `object (root Node)` — tokenizes/parses FortiOS `config/edit/set/end/next` grammar into a tree.
`findBlock(tree, path)` -> `Node|null` — top-level-only block lookup.
`findBlockDeep(tree, path)` -> `Node|null` — first deep match of a `config <path>` block anywhere in the tree.
`findBlocksDeep(tree, path)` -> `Node[]` — every deep match (VDOM-mode duplicates).
`flattenSettings(node)` -> `{key: string|string[]}` — unwraps a node's `set` tokens.
`flattenEntries(node)` -> `Array<{name, ...settings}>` — mirrors cmdb table-endpoint shape.
`parseSystemStatus(text)` -> `{version_string, build, model, serial, hostname, vdom_mode}` — parses `get system status` CLI output.
`isMultiVdom(statusInfo)` -> `boolean` — true when `vdom_mode !== 'disable'`.
`countActiveVpnSessions(text)` -> `number|null` — counts rows under "SSL[-]VPN Login Users:" header (fixed 2026-07-23 to tolerate the real hyphenated device output); null means header not found (untrusted, not a confirmed zero).
`vdomNamesFromConfigText(text)` -> `string[]|null` — parses `show system vdom` output.
`isSafeVdomName(name)` -> `boolean` — validates VDOM name before CLI interpolation.
`policiesFromConfigText(text)` -> `object[]|null` — extracts `config firewall policy` entries as REST-shaped objects; null means no policy block found (retrieval failure, not empty).
`parseFullConfiguration(redactedText)` -> `{global, interfaces, ssl_vpn, snmp, admins, ntp, dns, log_syslogd, password_policy, fortiguard, autoupdate_schedule, collected_via:'ssh'}` — builds getConfig()'s `parsed` object from an already-redacted dump.
`redactConfig(text)` -> `string` — line-by-line secret redaction incl. multi-line quoted values, `ENC` prefix catch-all. [SENSITIVE]
`looksLikeConfig(text)` -> `boolean` — sanity check that text is a real config dump.
`looksLikeCliError(text)` -> `boolean` — matches known FortiOS CLI rejection strings.
`ipMaskToPrefixLength(mask)` -> `number|null` — dotted netmask → CIDR prefix.
`entriesFromConfigText(text, blockPath)` -> `object[]|null` — generic single-block entry extractor for getObjects().
`addressEntryToNamedAddress(entry)` -> `{name, type?, value}|null`.
`groupEntryToNamedGroup(entry)` -> `{name, members}|null`.
`serviceEntryToNamedService(entry)` -> `{name, value}|null`.
`tokenize(str)` -> `string[]` — splits a `set` value into quoted/bare tokens.
`countUnescapedQuotes(s)` -> `number`.
`entryToPolicyObject(entry)` -> `object` — one `edit <id>` entry → REST-shaped policy (defaults `action` to `'deny'`).
`isSecretKey(key)` -> `boolean` — deliberately broad secret-key matcher. [SENSITIVE]
`redactSetLine(rawLine, blockPath)` -> `{line, opensMultiline, isSecret}` — redacts one `set` line, context-sensitive for SNMP community. [SENSITIVE]
`scalarToken(value)` -> `string|null` — unwraps a bare-or-1-array token value.

## lib/adapters/fortinet/ssh.js

`FortinetSshAdapter` (class extends FirewallAdapter) — FortiOS CLI/SSH transport. Methods: `_getSession()`, `_run(commands, extraOptions?)`, `testConnectivity()`, `_getSystemStatus()`, `getVersion()` (incl. serial/hostname), `getVpnSessionSummary()` (dispatches single/multi-VDOM), `_getVpnSessionSummarySingleVdom()`, `getVpnSessionSummaryMultiVdom(status)`, `_discoverVdomsForVpnPoll(status)`, `_rulesFromPolicyOutput(output, opts)`, `getRules()` (throws, never `[]`, on connection/CLI failure; multi-VDOM via `_getRulesMultiVdom`), `_getRulesSingleVdom()`, `_assertVdomEditSucceeded(vdom, editOutput)`, `_getRulesMultiVdom(status)`, `_getConfigText()` (cached, throws on rejection/non-config output), `getConfig()` (redacts before parsing), `getObjects()` (per-VDOM address/addrgrp/service/servicegroup, never throws), `_resolveVdomListForObjects(status)`, `_collectObjectCategory(vdomList, command, blockPath, label, mapFn)`, `_appendObjectEntries(...)`, `getSnmpMetrics()` (4 scalar OIDs, `lowConfidence:false`). [SENSITIVE]

## lib/adapters/paloalto/index.js

`PaloaltoAdapter, PaloaltoSshAdapter` (re-exported; SSH class defined in `./ssh.js`)
`PaloaltoAdapter` (class extends FirewallAdapter) — PAN-OS XML API transport (api_key or username/password→keygen). Methods: `_resolveApiKey()` (cached promise per instance), `_getConn()`, `testConnectivity()`, `getVersion()`, `getRules()` (default-vsys xpath, falls back to any-vsys deep search when zero rules found, then hit-count enrichment), `_enrichHitCounts(conn, rules, vsysName)` (additive, never throws), `getConfig()` (redacts raw XML + config tree before parsing), `getObjects()` (reads back stored `config_parsed` via `getLatestConfigParsed`, no new device call), `getSnmpMetrics()` (PAN-COMMON-MIB + HOST-RESOURCES-MIB, always `lowConfidence:true`), `getInterfaces()`/`getRoutingTable()`/`getNatRules()` (added 2026-08-03, live-verified against ITC-SLY, for `lib/engines/topology.js` — `getNatRules()` reuses `sshParser.parseNatPolicyOutput()` directly, see this file's own `sshParser` require comment). [SENSITIVE]
`averageCpuFromProcessorLoadRows(rows)` -> `number|null` — module-level SNMP helper, averages hrProcessorLoad rows.
`indexHrStorageColumn(rows)` -> `{rowIndex: value}` — reassembles a walked hrStorage column by row index.
`computeMemoryPercentFromHrStorage(session, timeoutMs, host)` -> `Promise<{rows, matchedRowIndex, memoryPercent, matchedDescr?}>` — walks 4 hrStorage columns, matches physical-RAM row by descr text.

## lib/adapters/paloalto/api.js

`panRequest(conn, params, {timeoutMs?})` -> `Promise<{raw, response, result}>` — API-key-authenticated PAN-OS XML request. [SENSITIVE]
`generateApiKey(conn)` -> `Promise<string>` — `?type=keygen` username+password → API key; **password travels as a URL query param (inherent to PAN-OS's own keygen protocol)** — SecVault never logs the constructed URL and the response body is never echoed into errors. [SENSITIVE]
`showSystemInfo(conn)` -> `Promise<object>` — op `show system info`.
`getSecurityRules(conn)` -> `Promise<object>` — config-get on default-vsys security rulebase xpath.
`getSecurityRulesAnyVsys(conn)` -> `Promise<object>` — config-get, predicate-free xpath across all device/vsys entries.
`showRunningConfig(conn)` -> `Promise<{raw, result}>` — op `show config running`, 120s timeout.
`getRuleHitCount(conn, vsysName)` -> `Promise<object>` — op `show rule-hit-count vsys <name> ...`.
`getEffectiveSecurityPolicy(conn)` -> `Promise<{raw, result}>` — op `show running security-policy`, the Panorama-managed-device merged-policy fallback (2026-07-23). ⛔ Live-verified 2026-08-25: the response is the CLI's brace TEXT wrapped in a single `<member>` element, NOT structured XML. Its text is therefore routed through `sshParser.parseEffectiveSecurityPolicy()` (35 rules live), not `parser.parseEffectiveSecurityPolicy()`.
`showPushedSharedPolicy(conn)` -> `Promise<object>` — op `<show><config><pushed-shared-policy/></config></show>` (2026-08-25). The PREFERRED Panorama-managed-device source: clean structured XML that `parser.parseRulesDeep()` extracts unmodified, keeping real object names and full application lists. 33 rules live against PAKFood.
`DEFAULT_VSYS` (const string) — `'vsys1'`.
`SECURITY_RULES_XPATH` (const string) — default-vsys rulebase xpath.
`SECURITY_RULES_XPATH_ANY_VSYS` (const string) — predicate-free fallback xpath.
`redactSecrets(text, secrets)` -> `string` — scrubs literal/URL-encoded secret forms + `key=`/`password=`/`user=` query params from error strings, anchored on parameter NAME (survives re-encoding). [SENSITIVE]
`redactKey(text, apiKey)` -> `string` — back-compat single-secret alias of redactSecrets. [SENSITIVE]
`extractErrorMessage(msg)` -> `string|null` — flattens PAN-OS `<msg>` error node shapes.
`showInterfacesAll(conn)` -> `Promise<object>` (added 2026-08-03, live-verified) — op `<show><interface>all</interface></show>` — ⛔ NOT the usual nested-tag convention (`<all/>` is rejected; `all` must be the tag's VALUE, not a further nested tag).
`showRoutingRoute(conn)` -> `Promise<object>` — op `show routing route`, standard nested-tag form; response is clean structured `<entry>` XML (no column-position parsing needed, unlike SSH).
`showRunningNatPolicy(conn)` -> `Promise<object>` — op `show running nat-policy`; response's `<result><member>` text is byte-identical in format to the SSH transport's plain text — see `parser.js`'s note on why no XML-specific NAT parser exists.

## lib/engines/securityScore.js

Pure, no-DB fleet Security Score (added 2026-08-05, v2.53.0). `computeSecurityScore({activeDevices, devicesWithPatchNow, devicesWithScheduled, deviceRiskScores, fleetCompliancePct})` -> `{score, components[], measuredWeight}`; also `securityScoreBand(score)` (excellent/good/fair/poor), `vulnerabilitySubscore`, `hygieneSubscore`, `complianceSubscore`, `WEIGHTS`, `SCHEDULED_EXPOSURE_FACTOR`.

0-100 **higher is better**, weights vulnerability 40 / hygiene 30 / compliance 30. ⛔ POLARITY: riskScore.js is 0-100 higher-is-WORSE and feeds this; the inversion happens ONLY in `hygieneSubscore` and must not be "simplified" away — getting it backwards throws nothing and renders a plausible number that is exactly wrong. ⛔ An unmeasurable component is dropped from the DENOMINATOR (like compliance's `na`), never scored 0; all-null -> `null`, rendered "—". `monitor`-band CVEs contribute nothing by design.

## lib/engines/fleetHeadline.js

The six dashboard headline numbers + Security Score, in ONE definition (added 2026-08-05, v2.53.0). `getFleetHeadline(pool)`, `getPreviousHeadline(pool)`, `getDeviceRiskScores(pool)`, `getCveExposure(pool)`. ⛔ Exists because BOTH the dashboard and the nightly snapshot job need these; separate implementations would make tomorrow's delta compare two different metrics. ⛔ `getDeviceRiskScores` maps `computeRiskScoreFromCounts(r).score` — that function returns `{score, band, raw}`, and passing the object through silently made the whole hygiene component "not measurable" (real bug, v2.53.0). `getPreviousHeadline` may return per-field nulls (rows predate the columns) — callers must render NO delta, never 0.

## lib/engines/connectivityHistory.js

Append-only fleet reachability log over `device_connectivity_history` (added 2026-08-05, v2.54.0). `recordConnectivity(pool, deviceId, {reachable, latencyMs, source, message})`, `getFleetConnectivityTrend(pool, hours, bucketMinutes)`, `getFleetConnectivityNow(pool)`.

⛔ `recordConnectivity` NEVER THROWS — every caller is doing something more important (test/collect/metric poll) and must not fail because a log insert did. ⛔ Adds NO device load: written only from work that already talked to the device. `source` ('test'|'collect'|'metrics') is recorded because those cadences differ wildly. Trend omits empty buckets rather than emitting 0 — a gap in sampling is not an outage. `getFleetConnectivityNow` distinguishes `neverChecked` from `unreachable`.

## lib/corners.js

Client-only corner-style switch (rounded/square), added 2026-08-05 (v2.52.0). A structural MIRROR of `lib/theme.js` — same localStorage key shape, same `data-*` attribute on `<html>`, same `secvault:*` CustomEvent, same no-flash inline script in `app/layout.js`. Exports `CORNERS_KEY`, `getCorners()`, `applyCorners(corners)`, `toggleCorners()`, `CORNERS_INIT_SCRIPT`. Stores `'rounded'|'square'`; square stamps `data-corners="square"`, rounded REMOVES the attribute (rounded is `:root`'s default, not a second branch).

⛔ Works ONLY because every rounded surface resolves through `var(--radius)` / `var(--radius-sm)` / `var(--radius-pill)` — `:root[data-corners="square"]` in `app/globals.css` overrides just those three. A component hardcoding a numeric `borderRadius` opts itself out SILENTLY (stays rounded while its neighbours square off). ~32 such strays were tokenized in v2.52.0; the ONE deliberate exemption is `RuleHygieneDonut`'s 10px legend swatch at 2px, where `--radius-sm`'s 6px would render as a circle. True circles (status dots, avatars) use `50%` directly and are intentionally outside the switch. No DB, no `settings` table, not admin-gated — a per-browser preference.

## lib/adapters/paloalto/parser.js

`parseSystemInfo(systemInfoResult)` -> `{version_string, version_tuple, build, model, serial, hostname}` — parses `show system info` XML result (hostname on XML/API transport is doc-derived, not yet live-verified — unlike SSH's flat-text field, which IS confirmed).
`parseRules(rulesResult)` -> `NormalizedRule[]` — parses default-vsys rulebase `<entry>` list.
`parseRuleEntry(entry, idx)` -> `NormalizedRule` — one PAN-OS XML rule `<entry>` object → NormalizedRule. Exported 2026-08-04 (v2.51.0) for `components/config/DiffViewer.js`, which uses it to turn a whole-rule add/remove in an XML/API config diff back into a rule it can TABLE rather than dump as raw nested structure — same client-side reuse precedent as `sshParser.ruleFromBraceEntry`. `idx` only sets `sequence_number`, which a point-in-time diff snapshot doesn't use. Never throws.
`parseRulesDeep(rulesResult)` -> `NormalizedRule[]` — shape-agnostic deep walk for the any-vsys fallback, collects every `security.rules` container.
`parseRuleHitCount(hitCountResult)` -> `{[ruleName]: hitCount}` — shape-agnostic deep walk for `show rule-hit-count` response.
`parseEffectiveSecurityPolicy(result)` -> `NormalizedRule[]|null` — Panorama-managed-device merged-policy fallback (2026-07-23), XML/API transport. Deep-walks for any `@_name`+`action`-bearing entry; returns `null` (not `[]`) when nothing rule-like is found. ⛔ **Superseded, and the guessed shape was disproven live on 2026-08-25** — PAN-OS returns brace TEXT in a `<member>`, so this matched nothing and returned `null` on every device. Kept only as `index.js`'s third/last-resort tier in case a future PAN-OS returns the documented shape. See `connectors.md` item 4.
`parseConfig(configResult, systemInfoResult)` -> `object` — builds getConfig()'s parsed tree, merges `system_info`.
`redactConfigXml(text)` -> `string` — regex-redacts `<tag>value</tag>` and `tag="value"` for SECRET_TAGS in raw XML, runs BEFORE parseConfig(). [SENSITIVE]
`redactConfigTree(node)` -> `any` — recursive secret-key redaction of the parsed object tree. [SENSITIVE]
`extractObjects(configTree)` -> `{addresses, addressGroups, services, serviceGroups}` — deep search for address/address-group/service/service-group containers.
`toArray(value)` -> `array` — fast-xml-parser single-vs-array normalizer.
`memberStrings(field)` -> `string[]` — normalizes `<member>` list fields.
`mapAction(rawAction)` -> `string|null` — PAN-OS rule action → NormalizedRule action.
`scalarText(value)` -> `string|null` — extracts scalar text from an XML node.
`parseInterfacesXml(result)` -> `{name,ipAddress,zone,vdom:null,enabled:true}[]` (added 2026-08-03, live-verified) — reads `result.ifnet.entry` directly (clean structured fields); does NOT cross-reference the separate `<hw>` link-state section for `enabled` (sub-interfaces don't appear there at all) — every entry with a real `<ip>` is treated as enabled, a documented simplification.
`parseRoutingTableXml(result)` -> `{destinationCidr,nextHopIp,interfaceName,protocol,metric,vdom:null}[]` — reads `result.entry` directly; same flag-based classification as `sshParser.parseRoutingTableOutput()` but no positional-token parsing needed (every field already arrives separated). Host (`H`-flag) routes excluded, same reasoning as the SSH parser.
(No `parseNatPolicyXml` — the NAT op-command's response is reused via `sshParser.parseNatPolicyOutput()`, see `index.js`'s entry above.)

## lib/adapters/paloalto/sshParser.js

`parseSystemInfoOutput(text)` -> `{version_string, build, model, hostname, serial, fields}` — parses `show system info` flat "key: value" CLI output (hostname live-confirmed on this transport).
`parseSecurityRules(text)` -> `{rules, containersFound, tree}` — parses brace-format config, collects every `rulebase(/pre|post)/security/rules` container.
`resolveVsysNames(tree)` -> `string[]` — best-effort named-vsys discovery for hit-count enrichment (falls back to `['vsys1']`).
`parseRuleHitCountOutput(text)` -> `{[ruleName]: hitCount}` — line-based table parser for `show rule-hit-count` CLI output.
`parseConfig(redactedText, systemInfoOutput)` -> `object` — builds getConfig()'s parsed tree incl. full `.tree`, built from ALREADY-REDACTED text.
`redactConfig(text)` -> `string` — line-by-line secret redaction, quote-structure-preserving (2026-07-20 fix: no longer corrupts brace structure when a quoted free-text field merely contains the word "password"). [SENSITIVE]
`looksLikeCliError(text)` -> `boolean`.
`looksLikePanosConfig(text)` -> `boolean` — accepts both `set` and brace shapes.
`extractObjects(tree)` -> `{addresses, addressGroups, services, serviceGroups}` — brace-tree equivalent of parser.js's extractObjects.
`looksLikeEffectiveSecurityPolicy(text)` -> `boolean` — gate for `show running security-policy` output shape (Panorama-managed fallback).
`parseEffectiveSecurityPolicy(text)` -> `NormalizedRule[]` — parses the Panorama-managed merged-policy fallback command (enabled always true, hit_count always 0, log_enabled defaults true, no NAT).
`parseSystemInfoLines(text)` -> `{key: value}` — raw key:value line parser.
`redactLine(line)` -> `string` — redacts one line, quote-span-aware. [SENSITIVE]
`redactValuePreservingStructure(rest)` -> `string` — redacts a value while keeping quotes/`;` intact. [SENSITIVE]
`findQuotedSpans(line)` -> `Array<{start,end,terminated}>` — mirrors tokenizer's quote-escape handling.
`mapAction(value)` -> `string|null`.
`tokenizeBraceConfig(text)` -> `Array<{kind, text?}>` — brace-format tokenizer.
`parseBraceConfig(text)` -> `object` — full recursive-descent parse to a nested object.
`findSecurityRulesContainers(node, depth)` -> `object[]` — deep search for rulebase/pre-rulebase/post-rulebase security.rules containers.
`parseInterfacesOutput(text)` -> `{name,ipAddress,zone,vdom:null,enabled:true}[]` (added 2026-08-02, live-verified against HRIS, for `lib/engines/topology.js`) — `show interface all`'s logical-interface table; column-padded with 2+ spaces (split on `/\s{2,}/`, not plain whitespace — the "zone" column can be entirely empty, collapsing 7 tokens to 6, handled explicitly).
`parseRoutingTableOutput(text)` -> `{destinationCidr,nextHopIp,interfaceName,protocol,metric,vdom:null}[]` — `show routing route`; the "flags" column can hold MULTIPLE space-separated codes (`"A S"`, `"A C"`) — classified positionally (destination/nexthop/metric fixed, then flag-shaped tokens consumed, then the next token is the interface) rather than a fixed column count. Host (`H`) routes excluded.
`parseNatPolicyOutput(text)` -> `nat_rules`-shaped `{sequenceNumber,enabled,natType,original*Addresses,translated*Addresses}[]` — `show running nat-policy`'s COMPILED policy; a bidirectional static NAT rule appears as TWO separate blocks (outbound `source <ip>`/`translate-to "src: ..."`, return `destination <ip>`/`translate-to "dst: ..."`), each parsed as its own independent row. Also used by the API transport (`api.js`'s `showRunningNatPolicy()` response is byte-identical in format). ⛔ Fixed 2026-08-03 (found live on ITC-SLY): a `dynamic-ip-and-port` (PAT/overload) rule's `translate-to` string has the egress INTERFACE NAME between `"src:"`/`"dst:"` and the IP (`"src: ethernet1/2 118.174.183.36(*) ..."`) — the original regex required the IP immediately after the label and silently produced zero rows for every PAT/overload rule (the most common real-world NAT type) until fixed to skip any token before matching the first dotted-quad.

## lib/adapters/paloalto/ssh.js

`PaloaltoSshAdapter` (class extends FirewallAdapter) — PAN-OS SSH/CLI transport. Methods: `_getSession(extraInitCommands?)`, `_run(commands, opts?)`, `_getSystemInfo()` (cached), `_getConfigText()` (cached, enters `configure` mode, throws on rejection/non-config; logs targeted "rulebase" search / shallow-block-key listing on the no-match case), `testConnectivity()`, `getVersion()` (incl. serial/hostname), `getRules()` (throws unless containers found or Panorama fallback succeeds), `_getEffectivePolicyRules()` (Panorama-managed `show running security-policy` fallback), `_enrichHitCounts(configTree, rules, containersFound)` (skips unless exactly 1 unambiguous container/vsys), `getConfig()` (redact-then-parse), `getObjects()` (reads back stored config_parsed.tree, no new SSH call), `getSnmpMetrics()` (identical OID set to index.js, `lowConfidence:true`). [SENSITIVE]

## lib/adapters/checkpoint/index.js

`CheckpointAdapter` (class extends FirewallAdapter) — Mgmt API adapter, mgmt_ip points at the management server not the gateway. Methods: `_getConn()`, `_fetchAllPages(session, command, extraBody)`, `_fetchGatewaysAndServers(session)`, `_fetchAccessRulebasePages(session, layerUid)`, `_findGateway(session)` (strict identity match, no fallback), `testConnectivity()`, `getVersion()`, `_showGatewayElement(session, gateway)`, `_resolvePolicyPackage(session, packages, pkgResponse)` (4-route resolution, throws rather than positional pick), `getRules()`, `getConfig()` (redacts gateway/api_versions), `getObjects()` (hosts/networks/ranges/groups/tcp+udp services/service-groups, per-category try/catch). [SENSITIVE]

## lib/adapters/checkpoint/api.js

`cpRequest(session, command, body)` -> `Promise<object|null>` — session-scoped POST wrapper.
`login(conn)` -> `Promise<string(sid)>` — POST login with apiKey or username/password. [SENSITIVE]
`logout(session)` -> `Promise<void>` — POST logout, never throws.
`withSession(conn, fn)` -> `Promise<any>` — login/run/logout lifecycle wrapper, guarantees logout in finally.

## lib/adapters/checkpoint/parser.js

`parseRulebasePages(pages)` -> `NormalizedRule[]` — merges object-dictionaries across pages, flattens sections, warns on malformed pages.
`findGatewayByIdentity(objects, device)` -> `object|null` — strict ipv4/name match, requires gateway-like `type`, never falls back.
`redactSecrets(value, depth?)` -> `any` — recursive keyword-based redaction of gateway/api_versions config. [SENSITIVE]
`extractInstalledPolicyName(gateway)` -> `string|null` — tries 8 doc-derived field paths.
`matchPackageByNameOrUid(packages, needle)` -> `object|null` — exact case-insensitive lookup, never positional.
`findPackagesTargetingGateway(packages, gateway)` -> `object[]` — packages whose installation-targets include this gateway (or `'all'`).
`describePackages(packages, limit?)` -> `string` — human-readable candidate list.
`describeGatewayCandidates(objects, limit?)` -> `string` — human-readable candidate list incl. IP.
`parseGatewayVersion(gateway)` -> `{version_string, version_tuple, build, model}`.
`parseHostObjects(objects)` -> `NamedAddress[]` — show-hosts → addresses.
`parseNetworkObjects(objects)` -> `NamedAddress[]` — show-networks → addresses.
`parseAddressRangeObjects(objects)` -> `NamedAddress[]` — show-address-ranges → addresses.
`parseGroupObjects(objects)` -> `NamedGroup[]` — show-groups / show-service-groups (shared shape).
`parseTcpServiceObjects(objects)` -> `NamedService[]` — `{name, value:'tcp/<port>'}`.
`parseUdpServiceObjects(objects)` -> `NamedService[]` — `{name, value:'udp/<port>'}`.
`extractMemberName(member)` -> `string|null` — resolves a group member (inline object or bare uid).
`buildObjectDictionary(objectsDictionary)` -> `Map<uid,object>`.
`resolveName(value, dict)` -> `string|null` — resolves a uid/inline-object ref to a name.
`resolveNameList(field, dict)` -> `string[]`.
`mapAction(actionField, dict)` -> `string|null` — Check Point action → NormalizedRule action.
`flattenRulebase(items, out?)` -> `object[]` — recurses into access-sections.
`normalizeRule(rule, dict, fallbackSequence)` -> `NormalizedRule`.
`isLogEnabled(rule, dict)` -> `boolean` — track.type resolution.
`extractHitCount(rule)` -> `number`.
`isGatewayLikeType(type)` -> `boolean` — `/gateway|cluster/i` test.

## lib/adapters/cisco_asa/index.js

`CiscoAsaAdapter` (class extends FirewallAdapter) — SSH/CLI ASA adapter. Methods: `_getSession()`, `_run(commands)`, `testConnectivity()`, `getVersion()`, `getRules()` (throws on privilege rejection, best-effort hit-count enrichment), `_privilegeErrorMessage(command)`, `getConfig()` (redacts before storing/parsing), `getObjects()` (never throws, parses unredacted config for objects/groups), `getSnmpMetrics()` (CISCO-FIREWALL-MIB + CISCO-PROCESS-MIB + CISCO-MEMORY-POOL-MIB, `lowConfidence:false`). [SENSITIVE]

## lib/adapters/cisco_asa/parser.js

`parseShowVersion(text)` -> `{version_string, model, build}`.
`parseAccessListConfig(text)` -> `NormalizedRule[]` — extended ACLs only, remarks attached as comments.
`parseHitCounts(text)` -> `{[normalizedAceText]: hitcnt}` — parses `show access-list` output.
`parseRunningConfig(text)` -> `{hostname, interfaces, snmp, http_server_enabled, ssh_sources, telnet_sources, usernames, version, webvpn}` — structured Phase 6 predicate object; SNMP communities never stored, only `<redacted>`. [SENSITIVE]
`parseObjects(text)` -> `{addresses, addressGroups, services, serviceGroups}` — `object`/`object-group` block parser.
`redactConfig(text)` -> `string` — 17 REDACTION_RULES + SNMPv3-user two-secret handler. [SENSITIVE]
`looksLikeCliError(text)` -> `boolean`.
`looksLikeRunningConfig(text)` -> `boolean`.
`normalizeAceForMatch(line)` -> `string` — strips line-number/hitcnt/hash suffix for hit-count matching.
`parseExtendedAce(line, tokens, aclName)` -> `NormalizedRule|null` — parses one extended-ACE line.
`redactLine(line)` -> `string` — per-line redaction dispatcher. [SENSITIVE]
`maskToCidr(mask)` -> `number|null` — dotted netmask → CIDR prefix.
`parseObjectBlockLine(line, block)` -> `void` — mutates an open object/object-group block.

## lib/adapters/sangfor/index.js

`SangforAdapter` (class extends FirewallAdapter) — SSH adapter, Cisco/Huawei-flavored CLI fallback tries. Methods: `_getConn()`, `_runOne(conn, options, command)`, `_tryCommands(conn, options, commands)`, `_getConfigText()` (cached, tries 3 config-dump command syntaxes), `testConnectivity()`, `getVersion()`, `getRules()` (throws only on total retrieval failure, `[]` for genuine "no parseable blocks"), `getConfig()` (redacts raw + parsed sections), `getObjects()` (deliberately returns empty stub — no live device/doc trail to ground a parser against), `getSnmpMetrics()` (standard MIB-II/HOST-RESOURCES-MIB only, always `lowConfidence:true`, `sessionCount` always null). [SENSITIVE]

## lib/adapters/sangfor/parser.js

`parseVersionOutput(text)` -> `{version_string, build, model}` — best-effort `show/display version` extraction.
`parseRulesFromConfig(text)` -> `NormalizedRule[]` — block-header (`policy`/`rule`) grouping + keyword-class field extraction, redacts `raw_rule.text`. [SENSITIVE]
`parseConfigSections(text)` -> `{hostname?, version?, interfaces?, ssl_vpn:{enabled:null|true|false}}` — best-effort structural hints; ssl_vpn detection is low-confidence, doc-ungrounded.
`redactConfig(text)` -> `string` — keyword-triggered rest-of-line redaction + PEM private-key block redaction, fail-closed. [SENSITIVE]
`mapAction(word)` -> `string|null` — ACTION_MAP lookup.

## lib/feeds/index.js

`runFullSync(pool)` -> `Promise<{nvd, paloalto_psirt, fortinet_psirt, kev}>` — sequential orchestrator (NVD→PaloAlto→Fortinet→KEV), each isolated.
`getLastSyncStatus(pool)` -> `Promise<object[]>` — last 10 `feed_sync_log` rows.
`getFeedStatusBySource(pool)` -> `Promise<{nvd, paloalto_psirt, fortinet_psirt, kev}>` — latest row per feed_name, nvd entry gains `.circl` usage summary.
`summarizeCirclUsage(nvdErrors)` -> `{used, eventCount}` — scans an NVD sync's errors array for `[CIRCL fallback]`-prefixed entries.

## lib/feeds/kev.js

`syncKev(pool)` -> `Promise<{marked_kev, unmarked_kev, errors}>` — downloads CISA KEV JSON, marks/unmarks `advisories.kev_listed` by cve_id; skips unmark step if feed parses to zero ids (guards against wiping every row). `FETCH_TIMEOUT_MS = 20000`, independently defined (not shared/imported from nvd.js).

## lib/feeds/nvd.js

`fetchAndUpsertVendorCves(pool)` -> `Promise<{inserted, updated, errors, byVendor}>` — runs NVD API 2.0 sync for every vendor in `VENDOR_CPES`, with CIRCL fallback on network-level failure (`err.status == null`).
`fetchAndUpsertForcepointCves(pool)` -> `Promise<{inserted, updated, errors}>` — deprecated back-compat wrapper, Forcepoint-only.
`VENDOR_CPES` (const object) — `{forcepoint, fortinet, paloalto, cisco_asa, checkpoint, sangfor}` → live-verified `virtualMatchString` CPE arrays. Forcepoint has 2 entries (dual-CPE, pre/post v7.1 rebrand) — see cve-pipeline.md. `FETCH_TIMEOUT_MS = 20000`, independently defined.
`backfillNvdNativeVersionRanges(pool)` -> `Promise<{checked, updated}>` — added 2026-07-31, same shape as paloalto.js's `backfillPaloAltoVersionRanges` below but for the other five vendors' NVD-native-shaped (`raw_data.configurations` present) rows only; explicitly excludes `vendor='paloalto'` (already fully covered) and skips any row whose `raw_data` isn't NVD-native shape (a PSIRT/CSAF/CIRCL CVE Record uses a different, unaffected version model — see the function's own header comment). Reuses this file's own `extractAffectedRanges`/`extractFixedVersions` directly, no duplicated logic.
(internal: `extractVersionFromCriteria` — rejects any wildcard-containing CPE version segment as of 2026-07-23 fix; `branchRangeFromWildcardCriteria` — expands a wildcarded segment into a real branch range instead.)

## lib/feeds/paloalto.js

`fetchAndUpsertPaloAltoAdvisories(pool)` -> `Promise<{inserted, updated, skipped, errors}>` — pulls the bulk PSIRT beta advisories endpoint (346 CVE-Record-shaped entries in one call), filters to `product==='PAN-OS'`. `FETCH_TIMEOUT_MS = 20000`, independently defined.
`backfillPaloAltoVersionRanges(pool)` -> `Promise<{checked, updated}>` — retroactively re-derives `affected_version_ranges`/`fixed_in_versions` from already-stored `raw_data` for existing `vendor='paloalto'` rows, using the current (fixed) extraction logic; no re-fetch.

## lib/feeds/fortinet.js

`fetchAndUpsertFortinetAdvisories(pool)` -> `Promise<{inserted, updated, errors, skipped}>` — RSS discovery → per-advisory CSAF 2.0 JSON (HTML-table-scrape fallback), 1s rate-limited sequential loop, merges multi-entry same-CVE version data. `FETCH_TIMEOUT_MS = 20000`, independently defined.

---

## Contradictions vs CLAUDE.md found while building this file

1. `lib/credStore.js`'s CLAUDE.md code sample is a simplified/stale snapshot — the real `setCredential` is a single `INSERT ... ON CONFLICT DO UPDATE` (2026-07-19 concurrency fix), not the DELETE-then-INSERT shown in CLAUDE.md's "credStore" section sample code. Functionally described correctly elsewhere in CLAUDE.md's bug-sweep history; just the front-matter sample is outdated.
2. CLAUDE.md's "Schema Migration" section describes `lib/migrate.js` as running `schema.sql`, but doesn't centralize the now-5 additional best-effort backfill/cleanup passes `main()` runs (each is individually documented elsewhere in CLAUDE.md, just not summarized in one place).
3. ~~`lib/auditChecksSeed.js` count vs CLAUDE.md~~ — resolved 2026-07-30: both now state 45, confirmed by direct tally. `ruleset_property` was found to have drifted separately (CLAUDE.md said "two checks," code has three — `no_external_to_internal_access` was undocumented); corrected in CLAUDE.md and detailed in `.ai-codex/compliance-pipeline.md`.
4. Two undocumented same-day (2026-07-23) additions with no CLAUDE.md entry yet: Fortinet's `hostname` field extraction (mirrors the already-documented `serial` fix pattern) and Palo Alto XML/API's `hostname` extraction (explicitly marked doc-derived/unverified in-code). `backfillPaloAltoVersionRanges()` IS documented (added same session, see CLAUDE.md's NVD CPE Matching section) — not a gap, listed here only for completeness.

## `lib/engines/logHit.js` (added 2026-09-08)

Produces `device_cve_assessments.log_hit` — decision rule 2 of the CVE priority tree, which had
never had a producer, so the column was `false` fleet-wide because nothing ever looked.

Exports: `classifyAction()`, `getCuratedPorts()`, `getDeviceInterfaceIps()`,
`runLogHitCorrelation(pool, {lookbackDays, now})`, `ALLOWED_ACTIONS`, `BLOCKED_ACTIONS`.

Fires `log_hit = true` only when ALL hold: the advisory has a curated `port_exposed` condition;
traffic arrived at one of the DEVICE'S OWN `device_interfaces` addresses on that port; the source
was PUBLIC (outside RFC1918/loopback/link-local/CGNAT); and the action was in `ALLOWED_ACTIONS`.

⛔ `ALLOWED_ACTIONS` includes `close`/`client-rst`/`server-rst`, which are Fortinet SESSION-END
actions — the session existed, so the service was reached. Live proof: FortiGate SSL-VPN on 10443
is reached from public sources and logged `close`/`client-rst`, NEVER `allow`. Matching only
`allow` would miss the most exposed service on the fleet. Palo Alto's `reset-both` looks like
the same family but is a BLOCK.

⛔ An action in neither list is `unknown` and never fires. Rule 2 outranks CVSS 9.0, so an
unrecognised vendor verb must not be able to manufacture a `patch_now`.

⛔ Two SKIP paths write nothing at all, rather than writing `false`: a device with no syslog
coverage in the window, and a device with no collected interface addresses (without which
traffic TO the device is indistinguishable from traffic THROUGH it). Both are UNMEASURED, and
`false` there would be the failed-read-as-a-fact bug again.

⛔ Ports are ORed (any curated port reached ⇒ reached), unlike `applicability.js` which ANDs its
conditions — different question: "does it apply" vs "was it reached".

Never throws; per-device errors are collected into the returned summary. Re-runs
`updatePrioritiesForDevice()` for every device whose value changed. Zero curated conditions ⇒
returns immediately without touching `syslog_events`.

## `lib/engines/advisoryCuration.js` (added 2026-09-08)

Read-only curation surface for `advisory_conditions`, which was EMPTY fleet-wide — leaving every
advisory at `config_applies = unknown`, decision rule 5, and 152 of 155 assessments in a single
`scheduled` band.

Exports: `extractCveRecord(rawData)`, `getCurationWorklist(pool)`, `summarizeWorklist(items)`.

⛔ EXTRACTS ONLY, never infers. It surfaces what the vendor and CISA already published
(description, affected products, CWEs, references, solution, CISA ADP SSVC exploitation/
automatable) so a human can judge. Deriving a predicate from advisory prose is the
"documentation lies" trap. Worked example: CVE-2026-24858 is KEV + CVSS 9.4 and names
FortiAnalyzer/FortiManager/FortiWeb — this fleet runs FortiGate.

⛔ `cvssScore` and `pct` are `null`, never `0` — "no published score" and "0% curated" must not
look like a real zero. Worklist covers only advisories with at least one assessment.

## `lib/engines/exposure.js` + `lib/engines/exposureQuery.js` (added 2026-09-08)

Internet Exposure & Attack Surface — the roadmap's #1 differentiator, scoped honestly.

Split deliberately: `exposure.js` is PURE (path construction + scoring, unit-testable with no DB),
`exposureQuery.js` loads rows and attaches observed-traffic evidence. Reuses `objectResolver.js`
UNCHANGED as its address/service resolver (`buildObjectMap` was exported for this) — the same
pattern topology.js follows.

Reconstructs `Internet -> public IP:port -> [DNAT] -> internal host:port`, permitted by rule N.

⛔ SCOPE STOPS AT THE INTERNAL HOST ADDRESS. The roadmap's graph continues into applications,
identities and data stores; SecVault has no asset or identity inventory, so drawing that would
invent the most security-critical half. The UI says "the device itself" or names the NAT target,
never more.

⛔ THREE-STATE `observation`, and it is the point of the feature:
`observed` (allowed traffic from a PUBLIC source arrived) / `not_observed` (we had syslog coverage
and saw none — a real measurement) / `unmeasured` (no coverage — NOT safe). `unmeasured` and
`not_observed` must never render alike, and an unobserved path is NEVER filtered out or scored
down: an unused open door is still open.

⛔ Severity is EXPLAINABLE — every point carries a reason string, surfaced under the table.
Observation only ever ADDS; `unmeasured` moves the score in neither direction, so a logging gap
cannot masquerade as risk.

Vendor reality handled: a rule frequently names the INTERNAL address (Fortinet VIPs), so paths
match the rule against both the public face and the NAT target — matching only the public side
misses the entire published service. Only `nat_type='destination'` counts; source NAT is outbound.
IPv4 only, explicitly. `device_interfaces.ip_address` carries the literal sentinel `'N/A'` on live
rows and is filtered before any inet cast.

## `syslog_device_inbound_hourly` (rollup, added 2026-09-08)

⛔ EXISTS FOR ONE REASON: the same question against raw `syslog_events` took OVER TWO MINUTES for
ONE device over ONE day (measured live). The `(device_id, received_at)` index cannot help a
`dst_ip` predicate, so it scans the whole device-day. BOTH `exposureQuery.js` and `logHit.js` read
this rollup and neither may revert to raw events — pinned by tests in both files.

Bounded by a join to the device's OWN interface addresses plus destination-NAT published addresses
(~300 rows fleet-wide); rolling up every destination would be unbounded internet addressing.
`allowed` and `public_source` are nullable booleans classified ONCE at rollup time — an action in
neither the allow nor block list stays NULL, and consumers test `IS TRUE`, never `= true`, so an
unknown vendor verb can never escalate a CVE. The regex guard runs BEFORE the `::inet` cast: the
`'N/A'` sentinel would otherwise abort the sweep transaction and take the other eight rollups down
with it.

## `lib/syslog/actions.js` (added 2026-09-09)

THE single source of truth for "was this traffic allowed or blocked", as firewalls actually spell it.

Exports: `ALLOWED_ACTIONS`, `DENIED_ACTIONS` (Sets), `classifyAction()` (→ `allowed|blocked|unknown`),
`sqlList()`, `ALLOWED_SQL`, `DENIED_SQL` (parenthesised, directly substitutable SQL fragments).

⛔ WHY IT EXISTS: there were FOUR divergent deny lists — `rollups.js` (4 verbs), `eventShape.js`
(7), `threatStats.js` (5, exported and imported by nothing), `logHit.js` (13) — and the NARROWEST
drove every dashboard number. Measured live, that under-counted blocks by 6.8% fleet-wide and 24%
on URL-category rows, because `block-url` (the only URL-filtering block verb PAN-OS emits) was
missing; `block` itself never appears on this fleet at all. `syslog_blocked_dst_hourly` DROPPED
those rows entirely (a WHERE, not a FILTER), so they were unrecoverable from the rollup.

⛔ THREE-STATE. A verb in neither set is `unknown` and must never be folded into either. Fortinet's
`close`/`client-rst`/`server-rst` are session-END verbs — the session existed, so the service was
reached — while Palo Alto's `reset-both` resembles them and is a BLOCK.

⛔ `sqlList()` returns the PARENTHESES too. A bare comma list produced `lower(action) IN 'deny',...`
— a syntax error that would abort the whole nine-rollup sweep transaction.

Consumers: `rollups.js` (all rollups), `trafficStats.js`, `threatStats.js`, `eventShape.js`.
`logHit.js`/`exposureQuery.js` keep their own literal list DELIBERATELY — they read the rollup's
pre-classified `allowed`/`public_source` booleans instead, and must test `IS TRUE`, never `= true`,
so the rollup's NULL-for-unclassifiable can never escalate a CVE.

## `lib/engines/exposure.js` — direction gating (added 2026-09-09)

`externalZoneIds(interfaces)` / `ruleDirection(rule, externalIds)` → `inbound|internal|unverified`.

⛔ THE BIGGEST CORRECTNESS BUG THIS ENGINE HAS HAD. Without a direction test,
`src_addresses:['any']` on an INTERNAL rule read as "reachable from the entire internet" and
`dst_addresses:['any']` on an OUTBOUND rule matched every public face. Live: 257 of 403 paths (64%)
were false positives, ALL at maximum score, so they outranked the genuine ones. Fixing it took the
fleet 403 → 149 paths; TSR-TL 5 → 0 (all internal5→internal3), and TUG's real camera port-forward
became the top finding instead of ranking below fabrications.

Both vendor shapes appear in `src_zones`: Palo Alto puts the interface's ZONE there (WAN1, Untrust),
Fortinet puts the interface NAME (wan2) — and Fortinet's public interfaces frequently carry no zone
at all. `externalZoneIds` therefore collects BOTH from any interface with a public IP.

⛔ `unverified` (no zone data) still REPORTS the path, flagged `directionVerified:false`, because
under-reporting exposure is the more dangerous error. It just may not claim to be confirmed.

## `tests/moduleLoad.test.js` (added 2026-09-09)

Requires every module under `lib/` and `services/` (79). Exists because a syntax error shipped in
`trafficStats.js` and three gates missed it: `node --check` was chained after a script that exited
non-zero so it never ran, no test imported the file, and `npm run build` does not evaluate
server-only modules. A LOAD test, not a behaviour test — do not let it discourage real tests.

## `lib/engines/deviceDiscovery.js` (added 2026-09-09)

Surfaces firewalls sending syslog from an address matching no `devices` row.

Exports: `correlateSender()` (PURE), `runDeviceDiscovery(pool, opts)` (never throws),
`getDiscoveredDevices(pool)`.

⛔ IT SURFACES, IT NEVER AUTO-INSERTS INTO `devices`. The request was "auto add them to the
inventory"; this reads that as "auto-surface a reviewable list", and the difference is the safety
story. UDP syslog is unauthenticated and trivially spoofable, and `devices` is NOT NULL on
vendor/mgmt_method — auto-inserting would both admit spoofed senders into the CVE/compliance/
security-score denominators AND assert a vendor for the 2 of 8 live senders that have none.

⛔ MOST "UNKNOWN" SENDERS ARE ALREADY KNOWN. Measured live: 5 of 8 unmatched senders are HA PASSIVE
PEERS already held in `device_ha_status.peer_mgmt_ip`, each independently confirmed by
`peer_serial`. Those are offered as LINK (writing `device_syslog_sources`), never promote — naive
auto-add would have created five duplicate firewalls on the first run. Correlation is computed at
READ time, never stored: `peer_mgmt_ip` swaps on failover, so a cached match would go stale and read
as a fact (same discipline as deviceHealth.js).

⛔ A peer address must NEVER reach `devices.mgmt_ip` — that is what every adapter opens SSH/HTTPS to.

Anti-fabrication: two-dimensional threshold (>= 2 distinct rollup hours AND >= 100 events); loopback/
link-local/CGNAT excluded in SQL; `vendor_conflict` when one address emits more than one vendor (a
relay, not a device). The UPSERT COALESCEs every observation so a pass that saw no vendor cannot
ERASE one an earlier pass saw — vendor detection is intermittent, and one live sender read 0% for a
full hour. Operator decisions (`status`, `decided_*`, `promoted_device_id`, `linked_device_id`) are
never touched by the job.

⛔ `DISCOVERY_LOOKBACK_HOURS` is MANDATORY and must stay far shorter than `SYSLOG_RETENTION_DAYS`:
the rollup copies `device_id` verbatim and never re-resolves it, so historical rows for a promoted
sender keep `device_id` NULL permanently and an unbounded window would re-list every promoted device
forever.

Runs in the ENGINE (`device-discovery`, hourly at :35, offset from `log-hit` at :20), NOT the
collector — nothing goes in a path handling 250-1,400 events/sec for a feature producing ~8 rows an
hour, and "seen across >= 2 distinct hours" is a rollup question an in-memory accumulator would lose
on every deploy restart.

## `lib/syslog/authOutcomes.js` + `lib/syslog/vpnAuthStats.js` (added 2026-09-09)

VPN login locations — "where are users logging in from, and which are attacks".

⛔ THREE-STATE. `classifyAuthOutcome()` returns `success|failure|null`, and null ("not an
authentication event") is the answer for ~95% of VPN rows: IPsec negotiation, HIP checks,
tunnel-latency reports, pre-login page fetches.

⛔ THE TRAP THAT MAKES THIS A MODULE: PAN-OS writes `status=success` on rows that are NOT logins.
`portal-prelogin`/`before-login` carried success on 3,399 rows in three hours — the portal serving
its page to an anonymous browser, carrying no username. `gateway-connected`/`gateway-register`/
`gateway-setup-ipsec` also carry success and are later stages of the SAME login. So the rule is
gate on the EVENT ID first, then read status; reading status alone inflates successful logins by
roughly an order of magnitude.

⛔ COVERAGE IS LOPSIDED. Measured over 12h: Fortinet logged 2,037 `ssl-login-fail` against ~4
successes — its SSL-VPN success logids are effectively absent, which is a DEVICE-SIDE logging
setting. The UI renders that as "not reported", never 0, and shows NO fleet-wide success/failure
ratio: it would be a Palo Alto ratio with Fortinet's failures in the denominator.

Two attack rules, no score and no severity band (CLAUDE.md bans that class of unfounded escalation):
  A `findUsernameSprayers()` — one address, >= 5 DISTINCT usernames, zero successes. The
    discriminator is the username count, not failure volume: a user mistyping a password fails
    against ONE username. Live separation was 18 vs 1.
  B `findFailureOnlyCountries()` — a country with failures and no successes. ⛔ DISABLED unless a
    vendor actually reported a success in the window; applied to Fortinet data it would flag every
    country including Thailand, where the real users are.

⛔ Private-range pseudo-countries are bucketed, never ranked: PAN-OS writes
"172.16.0.0-172.31.255.255" into the country field and FortiOS writes "Reserved". Both are the
vendor's own answer, kept verbatim, but neither is a location.

Reads `syslog_vpn_auth_hourly`, NEVER raw `syslog_events` — the equivalent raw query was measured at
85.6 SECONDS over 24h (the log_class index finds the rows; they are ~84k needles across a 26 GB
partition, costing 38,502 cold reads).

## `PAN_GLOBALPROTECT` map in `lib/syslog/vendorParsers.js` (added 2026-09-09)

GlobalProtect's own positional map — eventId 8, stage 9, srcUser 12, srcRegion 13, publicIp 15,
error 26, description 27, status 28 — VERIFIED against captured lines from TUM-FW-ACTIVE, counted
field by field across three subtypes. Separate from PAN_COMMON because PAN_COMMON is not common past
index 7; reading it here produced srcIp="vsys1" and application="SM-A066B-<hostid>".

⛔ Index 27 is a QUOTED description genuinely containing commas ("Pre-tunnel latency: 34ms,
Post-tunnel latency: 26ms"), so this must be read with splitCsv() — a naive split shifts the status
at 28. ⛔ Index 4 is the Threat/Content type ("0"), NOT a subtype; the real one is the Event ID at 8.
Fortinet VPN rows carry the peer as `remip=`, not `srcip=`, which is why src_ip was NULL on 100% of
them.

## `lib/engines/ruleChangeRequests.js` (added 2026-09-09, v2.93.0)

The rule-cleanup loop — roadmap Tier 1 item 1. Propose rules for removal, hand the list to whoever
edits the firewall, then **verify against the re-collected ruleset whether they actually went**.

⛔ **The verify half is the whole point.** Listing unused rules is not novel; ManageEngine Firewall
Analyzer has done it for years by inferring usage from logs. SecVault re-collects the ruleset on a
schedule, so it can *state* whether the change was made instead of asking someone to remember. If
this ever degrades into an export button the feature has lost its reason to exist.

Exports: `getCleanupCandidates`, `createRequest`, `submitRequest`, `abandonRequest`,
`verifyRequestsForDevice`, `listRequests`, `getRequest`, plus `REMOVABLE_FINDING_TYPES` /
`VALID_STATUS`.

- `REMOVABLE_FINDING_TYPES` = `unused` | `redundant` | `shadow`. Deliberately **not** every finding
  type: `overly_permissive` means "tighten this", not "delete it", and putting it in a deletion
  list would invite exactly the wrong action.
- `getCleanupCandidates(pool, deviceId)` returns **`{ eligible, withheld }`** — both lists, always.
  A cleanup screen that shows 21 candidates without saying 9 more were held back looks complete and
  is not, so the exclusion is part of the contract rather than an internal filter.
  Two exclusions, each with a `reason` string:
  1. **`hit_count IS NULL` — never measured.** 164 of 1,716 rules on the live fleet, because
     Fortinet SSH / Sangfor / Palo Alto SSH cannot report hit counts at all. "We cannot tell whether
     this rule is used" is not a reason to delete it. ⛔ A measured `0` is the opposite — it is the
     device's own counter affirmatively reporting no matches, and it is the evidence the whole
     feature runs on.
  2. **`rule_id_vendor IS NULL` — no durable identity.** The rule could be proposed and then never
     verified, leaving the request unverifiable forever, which looks like progress and is not.
  Dismissed findings are dropped silently — a dismissal is a decision, not a measurement gap.
- `createRequest` **re-validates server-side** against `getCleanupCandidates` and throws naming the
  offending rules. It does not silently shorten the request: the operator would otherwise believe a
  rule was queued that never was. The UI filter is a convenience; this is the guarantee.
- `verifyRequestsForDevice(pool, deviceId)` **never throws** — it returns
  `{checked, removed, stillPresent, unverifiable, error}`, because it runs as a post-step of
  `collectAndStore` and a bookkeeping problem must never break a collection run.
  ⛔ It requires `devices.last_rules_collected_at > submitted_at` **strictly** before concluding
  anything. `firewall_rules` is DELETEd and reinserted on every successful pull, so "the rule is
  absent" only means something if a pull succeeded after the request was raised. Without that guard
  a device whose rule collection has been failing reports every requested rule as `removed` —
  turning a collection outage into a fabricated success, the worst direction this feature can be
  wrong in. It also re-checks items already marked `unverifiable`, so a request unsticks itself once
  collection recovers.
  ⛔ The parent rollup promotes to `partial` only when no item is still `pending`/`unverifiable` —
  `partial` means "we looked and some were not done", which is a claim an unverifiable item does not
  support.

Pinned by `tests/ruleChangeRequests.test.js` (25 assertions), which covers the "we could not
measure this" case for both halves: unmeasured `hit_count`, missing `rule_id_vendor`, no successful
pull since submission, and a pull landing in the same instant as the submission.

### `ruleChangeRequests.js` — four contract fixes made during the UI build (same day)

Found by building the surface against it, all four in the "a record that quietly says less than the
truth" family:

1. ⛔ **`eligible` is one row per FINDING; a request stores one item per RULE.** 10 rules on the
   live fleet carry two or three removable findings at once (`Block-Line-Streaming` is unused AND
   shadowed AND redundant). `createRequest` built its lookup with a plain last-wins `Map`, so the
   stored `evidence` kept ONE reason and the exported request would give a reviewer one where three
   were found — and it is **not re-derivable later**, because `firewall_rules` and
   `rule_analysis_results` are both rebuilt on every pull. Now merged by `mergeByRule()`:
   `evidence.findings` holds all of them, and the single `finding_type` column takes the
   WORST-severity finding rather than the alphabetically first.
2. `eligible` and `withheld` now share ONE row shape (`shape(r)`), so a caller can render a
   held-back rule in the same table as an offered one. If showing the exclusion costs a second
   query, the exclusion is what gets dropped. ⛔ `hitCount` stays **null** on a withheld row — it is
   the unmeasured value that caused the exclusion.
3. `abandonRequest` was doing `note = COALESCE($2, note)`, overwriting the INSTRUCTION written for
   whoever edits the firewall with the abandon reason. New `rule_change_requests.abandon_reason`
   column; `note` is never touched.
4. ⛔ The status rollup's `NOT EXISTS (… outcome <> 'removed')` is **vacuously true for a request
   with zero items**, which would flip it to `verified` — a fabricated success in the one query
   here that must never produce one. `createRequest` guarantees at least one item so it was
   unreachable, but "unreachable today" is not a property a later caller preserves; every branch is
   now guarded on the request having items. `verified_at` is also stamped for `partial` now, since
   that is the outcome an operator most needs dated.

## Security-score coverage: "never assessed" vs "assessed, nothing found" (v2.94.0)

⛔ **The same bug existed at BOTH levels and was found from the screen, not the code.** On
2026-09-09 the Devices table showed **OKF(F2) at 100/100** — a perfect security score for the one
firewall in the fleet that had never been collected at all. An operator scanning that column would
skip the only device that needed attention.

`vulnerabilitySubscore` is "how many of N devices carry a patch_now/scheduled finding". Feeding it
EVERY active device as N counts a never-assessed device as an assessed-and-clean one. Both call
sites did this:

- `lib/engines/deviceInventory.js` `decorate()` — passed `activeDevices: 1` unconditionally. Now
  gated on `last_cve_assessed_at IS NOT NULL OR assessment_count > 0`, passing `null` otherwise so
  the engine drops the 40% component from the denominator. Hygiene and compliance were already
  correct here; only vulnerability was not.
- `lib/engines/fleetHeadline.js` `getDeviceCounts()` — passed `devices.total`. Now returns a
  SEPARATE `cve_assessed` count, and `getFleetHeadline` uses that as `activeDevices`. Measured live:
  16 active / 15 assessed took the vulnerability component from 51 to **48**.

⛔ **The number that matters is not that 3-point gap, it is the FRESH INSTALL.** With nothing
assessed, `total` as the denominator scores vulnerability a perfect 100 at its full 40% weight, and
the dashboard headline announces excellent security for a fleet SecVault has never looked at.

⛔ **A measured ZERO must keep scoring well.** Only NEVER-ASSESSED becomes unmeasurable. The fix is
about evidence that a run happened, never about the counts being zero — do not "harden" this by
making zero pessimistic.

⛔ The two coverage signals are **ORed**, matching `computeTiles`/`CveCell`/`deviceInventory`: a
timestamp proves a run happened, and surviving assessment rows prove one happened even if it
predates the column. ANDing them reports the whole fleet unmeasured until the matcher next runs.

⛔ **Dropping devices from the denominator is correct but must be SAID.** `getFleetHeadline` returns
`devicesCveAssessed` and `HeadlineStats.js` renders "N firewalls not yet assessed for
vulnerabilities and left out of this score". A fleet number quietly averaged over fewer devices than
the fleet on screen is its own dishonesty.

⛔ `lib/engines/dashboardSnapshot.js` persists this nightly, so rows written before v2.94.0 carry
the optimistic value permanently. Past snapshots are not rewritten — same stance as the missed-
snapshot backfill.

Pinned by `tests/deviceSecurityScoreCoverage.test.js`, including the counter-test that a measured
zero still scores 100.

## `lib/engines/deviceDiscovery.js` — the `managed` correlation kind (v2.94.0)

⛔ **A discovered sender was never reconciled against the inventory.** Reported from the screen
2026-09-09: `/devices/discovered` listed `FG200ETK18912640_OkeanosFOOD` at `10.204.6.1` under
"These addresses match nothing SecVault knows" — while that address WAS `devices.mgmt_ip` for the
active, collected device `OKF(F2)`. Discovery had worked correctly (the device was added at 03:52,
the row was last seen unmatched at 03:00); nothing ever went back and re-checked.

Correlation previously covered `device_ha_status.peer_mgmt_ip` and `device_syslog_sources.source_ip`
but **not `devices.mgmt_ip`** — the most obvious match of all. New fourth kind, `managed`, plus a
`normalizeAddress()` helper.

⛔ **THE TYPE TRAP THAT HID IT.** `devices.mgmt_ip` is **TEXT**; `discovered_devices.source_ip` (and
every `syslog_*.source_ip`) is **INET**. pg renders the INET as `10.204.6.1/32`, so a direct
comparison silently never matches, and `host()` is no help because `host(text)` does not exist —
which is exactly how this survived. Matching is therefore done in JS after normalisation:
- INET side: trim, lowercase, strip a trailing `/nn` rendering artefact.
- TEXT side: trim, lowercase, **mask NOT stripped** — a `mgmt_ip` of `10.204.6.0/24` is a SUBNET,
  not an address, so anything still containing `/` normalises to `null` and matches nothing.
- `null`/blank on either side never matches another `null` — two missing facts must not manufacture
  a device match.

⛔ **Deliberately NOT a SQL join.** `d.mgmt_ip::inet = dd.source_ip` throws for the WHOLE query the
first time any row holds a hostname or a typo, taking the page down instead of failing to match one
sender. A test asserts the SQL contains no `mgmt_ip::inet`.

⛔ **READ TIME, not write time**, and the reason is specific: `promoted_device_id`/`linked_device_id`
survive a device deletion only because of `ON DELETE SET NULL` plus the existing resurrect `UPDATE`.
A match on `mgmt_ip` has **no foreign key to null out**, so a stored verdict could never be
un-stuck — it would strand the row exactly the way that existing ⛔ comment exists to prevent.
`mgmt_ip` is also editable, so a stamped status goes stale on a renumber. And it would mean writing
`status`, which this file states everywhere is an OPERATOR DECISION, not an observation. Nothing in
the read path writes; a test pins that `getDiscoveredDevices` issues no INSERT/UPDATE/DELETE.

Matches `devices.mgmt_ip` **and** `devices.snmp_host` — the same two columns
`services/collector.js`'s `refreshDeviceMap()` uses to attribute an event, so discovery and
ingestion cannot disagree about what counts as known. Precedence: managed → known-alias → ha-peer.

⛔ **A now-managed sender is SHOWN, not hidden.** It moves to its own group naming the device it
matched, because an operator who remembers reviewing an address needs to know where it went, not to
find it silently vanished. Live result: unmanaged drops from 2 to **1** (StarUnion, genuinely
unmanaged), with OKF(F2)'s address listed as managed.

## Background job runner in `services/engine-worker.js` (v2.94.0)

Claims `background_jobs` via `claimNextJob` every **5 seconds** (a `setInterval`, not a cron task —
this is a button's latency budget, not housekeeping, and node-cron's natural unit is the minute),
with a 5-minute `reapStaleJobs` pass. Drains at most 5 jobs per tick; `jobQueueInFlight` prevents
re-entry.

⛔ **Four containment layers, because CLAUDE.md's rule is that one failed job must never crash the
service:** each handler in its own try/catch (a throw becomes `status:'failed'`); a separate
try/catch around the CLAIM itself (a dead DB just retries next tick); both invoked through the
existing `runTrackedJob` so `shutdown()` waits for in-flight work; and
`require('./deviceDeletion')` is **lazy inside the handler** — a module-scope require of a broken or
missing file would take down every scheduled job in the service, so a bad delete module fails that
one job with "The device was NOT deleted" instead.

⛔ **Startup order in `main()`: reap FIRST, then start the queue, both BEFORE the multi-minute
feed-sync/rule-pull startup passes.** A deploy restart is precisely what strands `running` rows, and
the partial unique index would then block re-queueing that device forever. Starting the queue early
means a Collect Now clicked seconds after a deploy is served rather than queued behind a feed sync.
`shutdown()` calls `stopJobQueue()` first — those timers are NOT in `scheduledTasks`, which
`scheduleJobs()` reassigns wholesale.

### The `rulesCount` tri-state across a job boundary

⛔ `background_jobs` has no JSON column, so the worker writes the structured collect result into
`detail` **as JSON**. That indirection is the whole point: a rendered sentence cannot be re-read by
the client, and JSON carries `null` as `null`. `collectAndStore.rulesCount` → `null|undefined → null`,
else `Number(...)`, explicitly never `?? 0` → `detail` → the route's `normalizeDetail` parses it
back (non-JSON detail, e.g. the delete engine's plain progress strings, passes through as `message`)
→ the component branches on `Number.isFinite`. A genuine `0` says "Collected — 0 rules."; `null` or
absent says "Collected, but the device reported no rule count — the ruleset was NOT updated."
Tests assert no `?? 0`/`|| 0` on any of the three files, matched against COMMENT-STRIPPED source,
since those files document the anti-pattern they must not perform.

### What the operator sees, and the three states that are not failure

⛔ `progress_total` stays **NULL** for a collect — `collectAndStore` reports no step count and the
worker does not invent one — so "0 of 0" never renders; a count with no total shows
"(N so far — total not known)".

⛔ **A failed POLL is not a failed JOB.** After 2 consecutive poll failures the UI flips to
`--unmeasured` (no hue) with "Status unknown — SecVault could not read the job. The collect may
still be running." Never red, never "failed". The 20-minute client ceiling behaves the same way and
explicitly does not declare failure; the engine's 30-minute reaper is what actually decides, and it
writes `failed` with "whether the work completed is unknown", never `succeeded`.

A double-click follows the incumbent job rather than opening a second SSH session, via the partial
unique index on `background_jobs`.

⛔ **Test Connectivity stays SYNCHRONOUS** — one probe, not a three-capability collection. Do not
"consistently" background it; the latency it has is the latency it should have.

## `lib/engines/deviceDeletion.js` (added 2026-09-09, v2.94.0)

`runDeviceDeleteJob(pool, job, { onProgress })` → summary; throws `DeviceDeleteError`. Executed by
the engine worker's job queue. ⛔ It never calls `finishJob` — the worker claimed the job, so the
worker owns the terminal status.

Three stages, each in SEPARATE transactions (so committed progress is a fact on disk and a re-run
resumes):

1. **DELETE derived rollup rows**, 11 `syslog_*_hourly` tables, batches of 5,000. `syslog_rollup_hourly`
   first — it is the only one that can fail the whole delete (see gotchas.md's 23505 entry).
2. **Batch-NULL `syslog_events.device_id`**, 20,000/batch with a 200 ms pause, each its own
   transaction. ⛔ Raw events are FORENSIC EVIDENCE and are never deleted — the device record goes,
   the logs stay. Setting an FK column to NULL takes no lock on `devices`, so the collector keeps
   inserting throughout; this is the stage that used to run *inside* the delete and stall ingestion.
3. **DELETE the device row**, one short transaction.

⛔ **23505 is impossible by construction, not by luck.** Stage 1 runs minutes before stage 3 and the
rollup sweep runs every few minutes, so a fresh row can re-arm the collision in the gap. Stage 3
therefore does, in ONE transaction and in this order: `SELECT … FROM devices WHERE id=$1 FOR UPDATE`
→ `DELETE FROM syslog_rollup_hourly WHERE device_id=$1` → `DELETE FROM devices`.

⛔ **Partial failure is reported with what actually committed** — "4,102 rollup rows deleted;
1,240,000 raw events unlinked (kept); device row: not reached. Re-running resumes from here." Never
a bare failure, and never a success that was not observed.

## Adapter exports added 2026-09-09 (failed-read contract sweep)

- `lib/adapters/checkpoint/parser.js` → **`parseLayeredRulebasePages(layerGroups)`** — multi-layer
  rulebase assembly with continuous `sequence_number` renumbering. Single-layer delegates straight
  to `parseRulebasePages`, so existing collections are byte-identical.
- `lib/adapters/sangfor/parser.js` → **`detectCliRejection(output)`** — a NEGATIVE guard only. It
  is bounded to two shapes (the FIRST non-empty line matches a rejection pattern, or the whole
  response is ≤6 non-empty lines and any line does) specifically so a real config containing
  "error" or "invalid input" inside an object name cannot be discarded as a rejection. ⛔ No
  positive-anchor parser was invented — CLAUDE.md forbids writing a parser for hardware that cannot
  be tested, and no live Sangfor device exists. A device on an unlisted dialect now fails LOUDLY
  instead of storing a banner as its config.

## `lib/syslog/vpnAuthStats.js` — country grouping for Unusual Sources (v2.99.0)

New exports: **`groupSourcesByCountry`**, **`heatBand`**, **`SOURCES_PER_COUNTRY`**.

`/vpn` → Login Locations listed **247 flagged sources as a flat list**, one stanza each, which the
operator had to scroll through endlessly. Now grouped into country rows (11 on the live fleet),
each expanding to its sources and then to the per-source evidence — all server-rendered
`<details>/<summary>`, no client JS.

⛔ **The worst offender is previewed WITHOUT a click.** Collapsing the list is the goal, but burying
the address running an 837-username spray behind two expansions would be a worse product than the
scrolling. Every country row prints its worst source inline, and that preview survives group
truncation (pinned by test).

⛔ **Two different "country" counts, and they must not be conflated.** ~20 countries have ANY
authentication attempt; only **11 contain a flagged source**. The header states the flagged number
explicitly for that reason.

⛔ **Grouping happens on the NORMALISED country**, because Fortinet reports names (`United States`)
and Palo Alto reports ISO codes (`US`) — grouping on the raw value splits one country into two rows.
A source with no resolvable geo gets its OWN group with `country: null` (never an invented
`"Unknown"`), drawn hueless/hatched at its real proportional width and ranked by failures rather
than sunk to the bottom.

⛔ Heat colour comes from `components/analysis/severityRamp.js`'s `SEVERITY_FILL` — not a seventh
local map, and never blue. `heatBand()` returns `null` (hueless) rather than `'low'` when there is no
denominator: an unrankable group must not be drawn as a mild one.

⛔ **This change is PRESENTATION ONLY.** `findUsernameSprayers` and `findFailureOnlyCountries`'
per-vendor gate are untouched — that gate is what stops the rule flagging Thailand, where the real
users are, and a test pins that Thailand never appears.

## `lib/syslog/vpnPresence.js` (added 2026-09-10, v2.99.0)

`getVpnUserPresence(pool, { days, deviceId })` — the per-user × per-day grid behind the VPN
presence heatmap. Reads `syslog_vpn_auth_hourly`, never raw events.

⛔ **IT MEASURES AUTHENTICATION, NOT CONNECTED TIME, and every surface says so.** A login held open
for eight hours counts as ONE hour here; a client that re-authenticates every 30 minutes counts as
several. The user asked for "how long they were connected" and this is not that — labelling it as
connected time would be a fabricated measurement. True duration needs Phase B's `vpn_sessions`
history.

⛔ **A day with syslog but no SUCCESSFUL-login evidence cannot support a zero for anybody.** The
first live run rendered 2026-09-08 as an earned zero for all 231 users — there were 17 hours of
syslog from 14 firewalls, and zero rows in `syslog_vpn_auth_hourly` because the VPN rollup was not
populating yet. That is now `no-vpn-logs`. When a day has failures but no successes the tooltip says
so explicitly: *a gap in what the firewall reports, not evidence this user stayed away*.

⛔ **Coverage is derived from `syslog_rollup_hourly`, NOT from the VPN table.** Asking "were there
VPN rows that day" cannot tell a dead collector from a quiet Sunday.

⛔ **`usernames_truncated` is honoured in both directions**: a user ABSENT from a capped day is
hatched (their absence proves nothing), and a user PRESENT in one is drawn with a dashed outline and
labelled "AT LEAST", because the count is a floor.

⛔ The fan-out trap that inflated VPN failures 8.4x earlier the same day is pinned here: no query
both unnests `usernames` and sums `event_count`, and a test asserts it. Verified live —
`sum(day.authEvents)` equals a plain `sum(event_count)` over the same window (10,585).

## `lib/engines/vpnSessions.js` — session HISTORY (extended 2026-09-10, v2.99.0)

`storeVpnSessions()` still DELETE+reinserts `vpn_active_sessions` (who is connected RIGHT NOW,
meaning unchanged) and now, in the SAME transaction, upserts `vpn_sessions` history keyed
`(device_id, username, login_time)`. Full rationale and every ⛔ rule: CLAUDE.md's "VPN Session
History" section. Reading side is `getVpnSessionHistory(pool, {deviceId, username, since, until,
openOnly, limit})`.

⛔ `since` filters on OVERLAP, not on `login_time` — a session that began before the window and was
still up inside it belongs in the answer. Filtering on start time alone would hide exactly the
long-running sessions an operator is looking for.

⛔ Retention (`runVpnSessionRetention()`, `VPN_SESSION_RETENTION_DAYS`=365) ages rows on
**`last_seen_at`, not `login_time`** — a session still being observed is never deleted however long
it has been up. It NEVER THROWS (returns `{deleted, retentionDays, error}`) so one table's failure
cannot abort the daily sweep it shares with the other three snapshot tables, which keep their own
180-day window.

⛔ `DEFAULT_VPN_SESSION_RETENTION_DAYS` is EXPORTED from here so the worker and `.env.local.example`
cannot drift from the engine's own default.

## `lib/engines/vpnDetections.js` (added 2026-09-10, v2.100.0)

`getVpnDetections(pool, { hours, baselineDays, now })` — six named VPN detections computed at READ
time over `syslog_vpn_auth_hourly`. No table, no cron job, no env var (the `deviceHealth.js` /
baseline-drift precedent). ⛔ A stored severity would stop matching its own evidence the moment a
threshold moved.

`credential_spray` · `brute_force` · `account_targeted` · `new_country_for_user` · `country_change` ·
`off_hours_success`.

⛔ **`credential_spray` REUSES `vpnAuthStats.findUsernameSprayers()` unchanged** as its candidate set
— it names the finding and attaches evidence, it does not re-derive the flagging. Two files deciding
"is this a sprayer" separately would eventually disagree.

⛔ **Every detection carries `status: 'measured' | 'insufficient_baseline' | 'no_data'`** plus
`baseline: {required, have, unit, satisfied, firstBucketAt}`, and BOTH `findings[]` and
`unverifiable[]`/`unverifiableTotal` (list capped at 25, total always exact). An observation that
could not be judged is COUNTED, never dropped — dropping it makes a gap look like a clean result.

⛔ **"We have never seen this user" (`no-user-baseline`) and "this user has never done this" (a real
finding) are separate code paths and separate output arrays.** Rendering them the same way is the
failed-read-as-a-fact bug in detection form. Live today: `new_country_for_user` and
`off_hours_success` are both `insufficient_baseline` — history is 1.08 days, they need 7 and 14.

⛔ **A device that reports failures but no successes is excluded from every success-dependent
detection, explicitly.** TSR-TL is exactly that. The cost is real and accepted: the fleet's STRONGEST
brute-force candidate (`administrator` ← `179.43.145.110`, Panama, ≥57 attempts over 23h, breadth 1)
is reported as UNVERIFIABLE rather than asserted, because only success-blind devices saw it.

⛔ **`country_change` is NOT impossible travel and must never be relabelled as it.** Verified: no
city and no lat/lon exists anywhere (`syslog_events` carries `src_country` only), so there is no
distance or velocity model to build. It reports the country pair and the hour gap, and its own
caveats state that a commercial VPN, proxy or mobile carrier can change apparent country
legitimately. A `gapHours === 0` row is labelled "same hour" and deliberately avoids "and then" —
two equal bucket timestamps carry no ordering.

⛔ **What keeps Thailand out is the existing SUCCESS GATE, not a country allowlist.** Measured: Thai
NAT gateways do reach spray-shaped username counts (`110.170.190.2` = 7 usernames / 10 failures) but
each also has successes, so `findUsernameSprayers` excludes them. Do not add a geographic allowlist —
it would break the moment an attacker used a Thai host.

Measured false-positive picture, live: of 212 measured spray findings, **0 are Thai-attributed, 0 are
RFC1918/CGNAT, and 0 have ever produced a successful login** anywhere in retained history — 9.9% of
2,137 sources flagged.

## `lib/engines/vpnTrafficAttribution.js` (added 2026-09-10, v2.101.0)

`getVpnUserTraffic(pool, {days, deviceId, username, topUsers, until})` — joins `vpn_sessions.assigned_ip`
against the **`syslog_talker_hourly`** rollup to attribute traffic to NAMED VPN users. Read-time, no
table, no cron job. Also exports the pure `attributeTraffic()`, `normalizeIp`, `clampInt`,
`UNATTRIBUTED_REASONS`.

⛔ **`syslog_talker_hourly` is the ONLY per-address aggregate in the database.** Verified: 174 of 187
live `assigned_ip` values appear in it as `src_ip`, so the join key is empirical, not assumed.
`syslog_blocked_dst_hourly` and `syslog_app_hourly` have NO `src_ip` in their grain, so per-user
destinations and applications are **not possible** and are not approximated — the panel says so.

⛔ **`syslog_events` IS REFUSED, and a test asserts this module never references it.** There is no
index on `src_ip` and partitions are 27 GB/day; a per-user destination query is a full partition scan
against a database taking ~1,000 inserts/sec. An index is not the answer either — at 28M rows/day the
write cost lands on the collector.

⛔ **An hour is attributed ONLY if it falls ENTIRELY inside exactly one session's tenure on that
address.** Partial hour → unattributed. Two sessions overlapping → unattributed AND a recorded
collision (detected across ALL devices, since pools can overlap). No session → gap. Each reason
carries its own bucket/event counts and renders as its own panel, never a footnote.

⛔ **Why that strictness is not paranoia — measured live:** over 7 days of rollup, 3,023 gap buckets
carrying 550,722 events belong to no retained session, versus 2,838 attributed. Two-thirds of
pool-address traffic happened when these sessions did not hold the address. "Most recent holder wins"
would have filed it under a named human being.

⛔ **Coverage is clipped PER GATEWAY, not fleet-wide** (`DEVICE_COVERAGE_SQL`): each session's tenure
is clipped to its own device's first observation. A fleet-wide bound would let a gateway added later
claim weeks its sessions could not be enumerated in — an hour would read as unambiguous while an
invisible second session held the address. Same false unambiguity through the side door. Pinned.

⛔ **Filters are applied AFTER attribution**, so narrowing by user or device can never make an
ambiguous address look clean. Pinned by a test.

Live first run: 226 joinable sessions / 0 unjoinable; **150 of 191 address-hours (78.5%)** and
22,932 of 33,580 events attributed to 105 named users; 1 REAL collision (two different users on one
address, correctly given to neither). Bytes were dense (105/105 measurable) because `bytes_summable`
is true exactly for PAN-OS session-close rows and these gateways are all Palo Alto.

## `lib/engines/vpnTunnelHealth.js` (added 2026-09-10, v2.103.0)

`getVpnTunnelHealth(pool, {now, staleAfterMinutes, pollEvidenceLookbackDays, deviceId})` — site-to-site
IPsec tunnel health, computed at READ time. No table, no cron job (the `deviceHealth.js` precedent).

⛔ **`vpn_ipsec_tunnels` is a LATEST SNAPSHOT** — confirmed live: `count(DISTINCT collected_at)` is
exactly 1 for every device with rows. So **"down since" is NOT derivable**; every tunnel carries
`downSince: null` plus a `downSinceReason`, and the panel states it above the table because
`collected_at` sits right there looking like an answer.

⛔ **A stale snapshot collapses EVERY status to `unmeasured` — including `down`.** A stale "down"
never enters the down list, and fleet counts come only from fresh devices. Live: TSR_EKC held a
34-day-old `up` that was being displayed as current fact.

⛔ **`coverage` is five-valued, never a zero**: `reporting` / `no_rows_polled` / `no_rows_unconfirmed`
/ `unsupported` / `support_unknown`. It uses `device_connectivity_history(source='vpn')`, NOT
`devices.last_rules_collected_at` — that column is stamped by the daily rule/config pull, a different
job. **No column anywhere records a successful TUNNEL pull**, so a tunnel command that failed on a
reachable device is indistinguishable from a device with none configured, and `coverageReason` says so.

⛔ **`downObservable` — reporting tunnels and reporting DOWN tunnels are different capabilities.**
Palo Alto's `show vpn ipsec-sa` and cisco_asa's `show vpn-sessiondb l2l` list ESTABLISHED tunnels
only, so a down tunnel is ABSENT rather than a row saying "down". Live that is **141 of 151 tunnels**.
For those devices the count is CURRENTLY-ESTABLISHED tunnels, not CONFIGURED ones, and a zero in
"Tunnels down" is not a measurement. The UI states this; do not let it read as an all-clear.

⛔ `classifyTunnelStatus` recognises only `up`/`down` — the complete enumeration SecVault's own
adapters write. Anything else is `unknown` AND lands in `unrecognisedStatuses` so the enumeration is
widened on evidence, never on a guess. A lint-shaped test greps the eight adapter sources and fails
if `VENDOR_TUNNEL_SUPPORT` disagrees with which actually define `getVpnTunnels()`.

### `vpnTrafficAttribution` — `result.scope` (added 2026-09-11, v2.104.0)

`attributeTraffic()` now also returns one record per UNATTRIBUTED bucket and per-address `ipTotals`;
`scopeUnattributed(attributed, subjectSessions)` (pure, exported) narrows them to a filtered subject,
and `result.scope` carries the outcome (null when no filter is active).

⛔ **The fleet fields (`unattributed`, `collisions`, `totals`) are UNCHANGED under every filter.** A
bucket that cannot be tied to the subject never vanishes — it stays in the fleet line. `scope ⊆ fleet`
is pinned by a test over every subject. Before this, a filtered view printed the fleet's 728 buckets /
169,066 events as if they were that user's answer, and listed other employees' addresses under their
name.

⛔ **The tie differs PER REASON and each label says which**: `partial_hour` and `collision` are tied by
the subject's OWN session; `gap` is tied by ADDRESS ONLY, because by definition nobody held it then —
so it is labelled "this traffic belongs to NOBODY; it is shown because the address is one they held at
another time". Conflating those two ties would attribute a gap to a person.

⛔ **Filters still apply AFTER attribution** — the rule that stops narrowing making an ambiguous address
look clean. A test asserts the session query takes exactly 3 params (window start/end + ceiling), that
neither the username nor a `device_id =` predicate reaches SQL, and that all pool addresses are still
fetched.

Four zero cases, reusing the existing `{reason, reasonText}` shape: `filter_matched_no_sessions` ·
`no_traffic_on_subject_addresses` · `no_attributable_traffic_for_subject` ·
`nothing_unattributed_for_subject`. ⛔ Only the LAST draws a table — it is a MEASURED zero
(`bucketsConsidered > 0`). The other three draw no table at all, because zeros there would be
fabricated.

Live: `eng_itc_HirunC` scopes to 45 buckets / 10,354 events — **9.9%** of their own traffic, where the
page previously said "27% of all traffic seen". Of 185 named users, 175 have scoped unattributed
traffic and 10 hit the clean-zero branch.

## lib/reports/ — the reporting platform (v2.119.0-v2.121.0)

`chassis.js` — the ONE shared pdfkit drawing surface. Exports palette (`ACCENT NAVY MUTED LIGHT
BORDER GREEN INK STATUS_RED ORANGE YELLOW BLUE UNMEASURED`), text helpers (`pdfSafe`
`installPdfSafeText` `fmtStamp`), layout (`layoutOf` `ensureSpace`) and blocks (`drawCover`
`sectionTitle` `paragraph` `labelledNote` `drawTable` `stampHeadersFooters`). ⛔ Extracted in
v2.119.0 from TWO diverged copies (`complianceReport.js` and `ruleChangeRequestReport.js`) — the
change-request copy had grown an `ensureSpace` guard against pdfkit orphaning a table header across
pages and the compliance copy never received it. New report builders MUST use this and must not
hand-roll a cover, table, heading or footer. `drawCover` is parameterised (`fixedGeometry`,
`titleSize`, `footerStamp`) purely to reproduce each pre-existing report's exact geometry.

`catalogue.js` — the single registry. `SCOPES` (`fleet`/`device`/`entity`), `REPORTS`, `reportById`,
`visibleReports(caps)`, `clientSafe(entry)`. Each entry: `id name summary icon contents scope
capability formats optionalDevice? params? builder`. `builder` is a LAZY thunk
(`() => require('./x').generateXPdf`) so the registry stays requireable from a client component
without dragging pdfkit and the engine graph behind it.
⛔ `clientSafe()` is an **ALLOW-LIST**, written as "pick these fields" not "delete builder" — the
next field added might also be a function. It strips `builder`/`capability` and deep-copies `params`.
Passing a raw entry to a client component is what made `/reports` render blank in v2.120.0 with a
bare digest while every test passed and the build was clean.

`reportStats.js` (v2.121.0) — `getReportStats(pool)` / `tilesFor(reportId, stats)`. ONE query of
scalar subqueries (172ms live) feeding the `/reports` panel's headline tiles for all five reports.
⛔ Returns **null** on failure, never a zero-filled object — a Reports page of confident zeros is
indistinguishable from a clean fleet. ⛔ The tiles are an at-a-glance count, NOT the report's own
result (the report applies acknowledgements, coverage rules, caps and the priority tree), and the
panel says so — otherwise every legitimate difference reads as a bug in one of them.

`pdfCompare.js` — `comparePdfs(a, b)` / `contentStreams(buf)`. Decompresses every content stream and
compares DRAWING OPERATORS, normalising `/CreationDate`, `/ModDate`, `/ID` and the report's own
rendered timestamp (which is hex inside `TJ` arrays). Returns `{equal, reason, streams,
firstDifference}` — note the key is `equal`, not `identical`. Used to prove a refactor left an
existing report's output untouched.

Builders, all `generateXPdf(pool, options = {}) -> Promise<Buffer|null>` (null ONLY when a named
record does not exist), each split into a `buildXData` / `renderXPdf` pair so the data half is
testable against a stub pool: `executiveSummary.js` (R1), `ruleHygiene.js` (R3),
`vulnerabilityPosture.js` (R5). `lib/engines/complianceReport.js` and
`lib/engines/ruleChangeRequestReport.js` predate the platform and are registered from where they are.

### The Phase D builders (added 2026-09-15, v2.123.0)

Four more, same contract as above (`generateXPdf(pool, options) -> Promise<Buffer|null>`,
`buildXData`/`renderXPdf` split, chassis-only drawing, engines reused UNCHANGED — none of them
re-implements a verdict, a duration or a status threshold).

`segmentationPosture.js` (R6) — declared zone-to-zone boundaries checked two ways. Reuses
`segmentationData.evaluateSegmentation` + `segmentation.summarise` so the PDF cannot disagree with
the on-screen board. ⛔ Colours the three violations `active > unverified > permitted`, matching
`ACTION_ORDER` rather than the board's old tints — which were ranked backwards and were corrected
in the same release (see CLAUDE.md's Segmentation Intent section). ⛔ `deviceId` narrows WHICH PAIRS
ARE LISTED, never how one was decided: segmentation is an estate-wide judgement and the document
says so, so a narrowed copy cannot be mistaken for the whole policy.

`fleetLifecycle.js` (R7) — renewal planning. ⛔ Derives per-vendor capability from the ADAPTER
REGISTRY (`typeof adapter.getX === 'function'`, nothing connected, nothing called) rather than from
a hardcoded vendor matrix, because CLAUDE.md's prose on Fortinet coverage has now been wrong twice.
⛔ Expiry is FOUR states: a date, perpetual (`expires_raw = 'Never'`), unknown, and `not_licensed`
(FortiOS `'n/a'`, 44 of 305 live rows) which is excluded from the renewal table and counted
separately. ⛔ "No licence rows" is split into `not_supported` (a product limit, hueless) vs
`not_collected` (the device can answer and we have nothing — a failure to chase); identical-looking
in an empty table, completely different owners.

`changeAudit.js` (R8) — what changed, when, and whether anyone reviewed it. ⛔ **Sanitises diff
paths at EXTRACTION**, using `configDiff.js`'s own `PATH_SHAPE_VIOLATION` shape test: a live PAN-OS
`config_diffs` row can carry ~10 KB of raw brace-grammar config *in the path field* (a parser
mis-segmentation `configDiff.js` already documents), which is a config excerpt wearing a key's
clothes. That file names THREE independent render surfaces that each needed fixing; this report was
the FOURTH. Such an entry is reported as **corrupted, never as a credential field** — labelling it
one because the blob happens to contain `phash` would be a confident false claim. ⛔ Separates
"collected, and nothing changed" from "we did not successfully collect" and counts the second;
silence on a change-audit reads as calm. Deliberately does NOT use `finding_acknowledgements` (that
is R3's rule-hygiene review workflow, a different question) or `change_summary` (a cached string
that can be stale or oversized; counts are recomputed from the payload).

`vpnAccessReview.js` (R9) — ⛔ the only entry carrying `VIEW_IDENTITY`; it names individual people,
their source countries and their connection times. ⛔ **States how deep the session record actually
is, directly under the review window on the cover** — `vpn_sessions` began 2026-09-10 and ages on
`VPN_SESSION_RETENTION_DAYS`, so a 365-day review can run over five days of data; the cover
previously asserted "Session history covers <window start> to now" above 411 distinct users.
`historyCoversWindow` is TRI-STATE (`true` / `false` / `null` = could not be read) and `null` never
renders as coverage. ⛔ `getVpnDetections` has no per-device filter, so a device-scoped review
carries FLEET-WIDE detections and says so; and the detection window is clamped at 192h by the
engine, so it is read back from the engine's own answer rather than from what was asked for.

## lib/engines/cloudApps.js + lib/feeds/cloudApps.js — cloud catalogue (v2.125.0)

Names an address or hostname against published cloud address space, so a rule
referencing `outlook.office365.com` or permitting 52.112.0.0/14 is readable instead of opaque.
Live on the reference fleet: **144 of 510 distinct FQDN address objects named (28%)**, plus 53
literal IP objects that fall inside published ranges — 35 of those in Exchange Online space, i.e.
hardcoded Microsoft IPs that break when Microsoft rotates them.

**Engine (pure).** `matchHost` / `matchIp` / `catalogueStatus` / `suggestApplications`.
- ⛔ `unavailable` IS A DISTINCT STATE FROM `no_match`. An empty catalogue means we could not check;
  it never means "not a cloud app". This product installs on segmented networks where the feeds are
  unreachable by design, so that confident negative would be the failed-read-as-a-fact bug in its
  most plausible form. Pinned.
- ⛔ A WILDCARD MATCHES SUBDOMAINS, NEVER THE APEX. Measured cost on this fleet: **8 objects**
  (`microsoft.com`, `office.com`, `office365.com`, `yammer.com`, `lync.com`, …) go unnamed that a
  looser rule would have claimed. Accepted deliberately — under-claiming leaves something
  unlabelled, which is visible and harmless; over-claiming puts a confident wrong name on a rule.
- ⛔ SMALLEST RANGE WINS; two providers claiming the same space is reported `ambiguous`, never
  silently resolved.
- ⛔ A PROVIDER IS NOT AN APPLICATION. AWS's catch-all `AMAZON` is carried verbatim. A feed with no
  service breakdown (Cloudflare) is labelled by provider alone, with `service` honestly null.
- ⛔ THE FEED'S GRANULARITY IS OURS. Microsoft publishes four service areas and 125 of the 144 live
  matches land in its catch-all. Teams can be said; Word cannot.
- ⛔ `catalogueStatus` has FOUR states — `empty` / `stale` / `unknown_age` / `ok`. Stale is still
  USABLE: published ranges move slowly and refusing to name anything from a two-week-old copy is
  worse than naming it with its age attached.
- ⛔ `Number(range_start)` is deliberate — node-pg returns BIGINT as a STRING, and a lexical
  comparison would silently match the wrong ranges.

**Feed.** `syncCloudApps(pool)` → Microsoft 365 / AWS / Google Cloud / Cloudflare, each isolated.
Registered as `cloud_apps` in `feed_sync_log` and run LAST in `runFullSync` so a slow publisher can
never delay the advisory feeds. Live: **11,766 rows in 2.1s.**
- ⛔ A PLAUSIBILITY FLOOR PER SOURCE guards the prune (`MIN_PLAUSIBLE`). A 200 with a truncated body
  must not be able to empty the catalogue — that turns one bad response into "your fleet uses no
  cloud services". Below the floor NOTHING is written or deleted and the sync reports failed.
- ⛔ Deduped on the unique key before insert: Postgres aborts an `ON CONFLICT DO UPDATE` that would
  touch a row twice, so one repeated value would fail an entire sync. Live, Microsoft's 250 parsed
  entries collapse to 226.
- ⛔ IPv6 prefixes are SKIPPED, not stored. The matcher is IPv4; storing rows it can never match
  would overstate coverage.
- Batched via `unnest()` at 1,000 rows per statement — AWS publishes 10,517 prefixes and a row per
  round trip made a sync ten thousand of them.
- `clientRequestId()` keeps Microsoft's GUID stable per install in `settings`, which is what their
  service expects; a fresh GUID per call looks like a new client every sync.

⛔ `suggestApplications()` PROPOSES AND NEVER CREATES. An auto-created application is a declaration
with nobody behind it, which is worse than the stale-but-owned map the competing products ship.

## lib/engines/applicationImpact.js + applicationRetire.js — Phase 2 (v2.129.0)

Both invert the application view: given the declared flows, which RULES matter, and what happens if
one goes. Neither re-implements flow evaluation — both consume `applicationView.evaluateFlowOnDevice`
/ `evaluateAllApplications` unchanged, so "claimed" means exactly what `orphanCoverage` means by it.
Two implementations of "does this rule permit this flow" would eventually disagree, and the wrong one
would be authorising a deletion.

**`applicationImpact.js`** — `buildImpactIndex` (pure) / `impactForRule` / `serialiseImpactIndex` /
`getImpactIndex`. Four states and the three zeroes never look alike (see routes.md). Live: the index
over 16 firewalls takes ~1,053 ms and serialises to 42.6 KB.

**`applicationRetire.js`** — `buildClaimIndex` / `planRetirement` (pure) / `planApplicationRetirement`
/ `retireApplication`. Evaluation runs ONCE per plan; only devices this application actually claims a
rule on are then asked for their cleanup verdict.

### ⛔ What the live fleet does to both, and why it is the RIGHT answer

Neither feature can reach a confident conclusion on this fleet today, and that is the honest outcome
rather than a defect:

- Impact: **29 rules across 12 firewalls** are touched by the one declared application;
  `rulesBreakingSomething = 0` and **`rulesUnknown = 29`**. The column reads "cannot tell" everywhere.
- Retire: **29 claimed, 0 proposed, 29 withheld** — 28 `unverified_evaluation`, 1 `usage_not_measured`.

One root cause, measured: **14 of 16 firewalls carry rules referencing an address or service the
device never reported** (TUFF and TUM 27 each, ITC-SK 22, TSR_EKC 17, HRIS 10). Where that is true,
"only this application claims it" is not established, so nothing may be proposed. Only `OKF(F2)` and
`TUG` evaluate cleanly.

⛔ **Closing that object-collection gap is what makes both features productive here** — not changing
either engine. An engine that concluded anyway would be guessing about a firewall change.

The case the impact feature exists for does already appear: on `TUM(TUTH1)`, `Salaya_TO_SAPRise` is
offered as an `unused` removal candidate with a MEASURED zero hit count — and the declared
application's flows run through it. It renders `2 flows — cannot tell`, naming the application,
above the checkbox that would propose its removal.

## lib/feeds/vendorPsirt.js — the inventory gate (v2.130.0)

`registerVendorPsirt` / `inventoryVendors` / `planVendorPsirts` / `SKIPPED`. Decides which vendor
PSIRT feeds this installation should fetch. See CLAUDE.md's Feed Sources section for the durable
rules; the mechanics:

- `inventoryVendors(pool)` returns `{ok:true, vendors:Set}` or `{ok:false, error}`. ⛔ It NEVER
  returns an empty set on failure — an empty set is an instruction ("skip everything") and a failure
  is not, and a caller cannot tell them apart once that distinction is lost.
- `planVendorPsirts(inventory, registry)` returns one entry per registered feed with `shouldRun` and,
  when skipped, a `reason` that names what still covers the vendor (NVD/CIRCL) and states that
  existing advisories are kept. ⛔ A bare "skipped" reads as "this vendor is no longer watched".
- ⛔ Fails OPEN on `{ok:false}`, `null`, `undefined` or a malformed result. Pinned four ways.
- Registration is keyed by the `devices.vendor` slug EXACTLY, and a test asserts every key exists in
  `VENDOR_META` — a near-miss spelling would compare against the inventory forever without matching,
  i.e. silently mean "never run", which looks identical to the gate working when you own none of that
  vendor.

Live: 11 Palo Alto and 5 Fortinet devices, so both registered feeds run. The four unowned Tier-1
vendors were never PSIRT feeds to begin with; what this changes for them is nothing, and what it
changes the day one is decommissioned is that its feed stops rather than failing quietly forever.

---

## productLicense.js / productLicenseData.js (v2.131.0) — the commercial licence

Pure/plumbing split, same shape as segmentation and workQueue. Full rules in CLAUDE.md's
"Commercial Licensing" section — this is the API surface.

**productLicense.js** (pure; `getServerId()` is the only impure call)
- `getServerId()` → `{serverId, weak, source, hash}`. `SCV-` + 32 hex of
  sha256(hostname + '-' + MachineGuid). ⛔ Falls back to a MAC address, not to '' — NetVault's
  returns '' so every machine failing the same way AND sharing a hostname shares a licence.
  `weak:true` on a fallback, surfaced in the panel rather than presented as certain.
- `deriveServerId(hostname, guid, mac, prefix)` — the testable seam.
- `validateLicenseKey(key, localHash, now)` → `{valid, payload?, error?, code?}` where code is
  `unreadable|wrong_server|wrong_product|expired`. Decrypts the NocVault generator's exact format.
- `serverIdMatches(payloadServerId, localHash)` — ⛔ PREFIX-AGNOSTIC (`SCV-`/`NCV-` both match).
- `coversSecVault(modules)` — ⛔ FAILS CLOSED on empty/missing, the opposite of the satellites.
- `getLicenseStatus({installDate, licenseKey, localHash, deviceCount, now})` → the verdict.
  FIVE statuses; `invalid` is its own, never a silent fall-through to `trial`.
- `deviceAllowance(status, payload)` → limit or **null = unlimited**. ⛔ An absent maxDevices is
  unlimited, not zero (`Number(null)` is 0 and 0 is finite).
- `canAddDevice(verdict)` → `{allowed, reason, code}`. The ONLY thing the device limit does.
- `monitoringAllowed()` → literal `true`, in every state. Pinned by a source-shape test.
- `writeAllowed(verdict)` → false only for `expired`/`invalid`; ⛔ **true for null/undefined** —
  the billing gate fails OPEN.
- `licenceSentence(verdict)` → `{tone, text}`; names the date and the device count, never
  "expiring soon". ⛔ An undeterminable state is `unknown` and HUELESS, never green.
- `bannerFor(info)` — re-exported from **`lib/licenceBanner.js`**, which is a separate,
  IMPORT-FREE module. ⛔ The banner is a `use client` component and this file requires
  `child_process`/`crypto`, so importing it from the browser bundle fails the build outright. The
  rule is not duplicated — one definition, re-exported — and a test asserts `BANNER_STATUS` deep-
  equals `STATUS` so the restated literals cannot drift. Silent on a healthy trial/licence;
  `expired` and `invalid` are NOT dismissible.

**productLicenseData.js** (takes a pool)
- `getLicenseVerdict(pool, {force, now})` — 5-minute cache; ⛔ **only a clean read is cached**, so a
  one-second blip cannot pin the install into "unknown" for five minutes.
- `resolveInstallDate(pool)` — settings first, else derived from the first user account (then the
  oldest device) and written back. ⛔ Deleting the row does not buy a fresh 30 days.
- `countMonitoredDevices(pool)` — `active = true` (same definition the PSIRT gate uses).
  ⛔ Returns **null on failure, never 0**.
- `activateLicense` / `clearLicense` / `invalidate`.
- `licenceBlockForWrite(pool)` / `licenceBlockForNewDevice(pool)` — route guards returning
  `{status, body}` or null. Both ⛔ fail OPEN on an unreadable state.

Enforced in exactly three places: `POST /api/devices` (the licensed unit),
`PUT /api/settings` (inside the admin-field branch only), `POST /api/users`.
`tests/productLicense.test.js` — 35 cases; 7 mutations verified to bite.

---

## ldapRoles.js (v2.134.0) — which role a directory user gets

Pure `resolveRole` + three pool-taking storage functions. Full rules in CLAUDE.md; the surface:

- `resolveRole({groups, mappings})` → `{role, outcome, matched, reason}`.
  Outcomes: `mapped` | `legacy_no_mappings` | `no_matching_group` | `groups_unreadable`.
  ⛔ ZERO mappings → `admin` (legacy ramp, preserves every existing install through the upgrade).
  ⛔ `groups === null` → refused; an unreadable read is not "no groups".
  ⛔ Most privileged match wins.
- `normaliseDn(dn)` — lowercases and trims around commas ONLY; spaces inside a value are
  significant (`CN=Help Desk`).
- `isMappableRole(role)` — validated against rbac's `ASSIGNABLE_ROLES`, never a local list.
- `isPermitted(resolution)` — deliberately not `!!role`.
- `loadMappings(pool)` ⛔ **THROWS** on a read failure; `[]` is an instruction, not an absence.
- `upsertMapping` / `deleteMapping`.

`app/api/auth/[...nextauth]/route.js` uses it twice: at `authorize()` (refusing the login when the
mapping table is unreadable) and in `jwt()` on EVERY token use, so a revoked mapping applies at once
rather than at JWT expiry. 24 tests, 7 mutations verified to bite.

## `lib/feeds/cveHub.js` (v2.137.0) — central CVE feed consumer

`fetchAndUpsertHubAdvisories(pool)` -> `{inserted, repaired, updated, unchanged,
degradeRefused, vendorConflict, multiVendorCollapsed, errors, feed_version,
feed_sha256, feed_rows}`; or `{notRun:true, reason}` when `CVE_HUB_LICENSE_KEY` is
unset. Also exports the pure `hasRanges`, `hubIsBetter`, `applyFeed` and the pinned
`FEED_PUBLIC_KEY_SPKI_B64`.

Pulls the Ed25519-signed advisory corpus from `nocvault-eol`
(`/api/v1/cve-feed`). **Exists because this server cannot reach NVD at all** — the
sites' internal public IP ranges overlap NVD's address space. Full rationale,
measurements and the five apply rules are in CLAUDE.md's "Central CVE feed"
section; do not re-derive them here.

The three things most likely to be broken by a well-meaning edit:
- **`hubIsBetter` requires `matchability === 'matched'`**, not merely a non-empty
  array — an `unmatchable` row carrying an array must never overwrite a good local
  one.
- **Rule 3 (never blank out real ranges) is expressed TWICE** — the JS predicate
  and a `WHERE` clause on the `UPDATE`. Removing either leaves the other holding.
- **Signature verification throws.** It is not advisory, and the bytes are verified
  before `JSON.parse`, not after.

Wired in `lib/feeds/index.js` as `runCveHubSync`, running **FIRST in
`runFullSync`** — `advisories.cve_id` is UNIQUE with one vendor, so feed order is
the attribution rule. Logged to `feed_sync_log` as `cve_hub`; `skipped` when not
configured. Tests: `tests/cveHub.test.js` (18 cases, 6 mutations verified).

`lib/syslog/trafficStats.js` — optional device scope (v2.141.0). getTrafficTimeline,
getActionBreakdown, getTopHosts, getTopApplications, getProtocolBreakdown and
getTopBlockedDestinations all take an OPTIONAL trailing `deviceId`; `null` means the
fleet. ⛔ APPENDED, never inserted — reordering would turn an existing caller's `limit`
into a device id. ⛔ An unrecognised id returns NO ROWS, never the fleet. New:
`getDeviceSyslogCoverage(pool, deviceId, hours)` -> `{everSent, inWindow, events,
lastBucket}`, which is what lets a per-device view tell "sends no syslog" from "was
quiet". ⛔ getTopApplications returns `{applications, unclassified}`, NOT an array, and
its unclassified count is scoped too — unscoped it captioned one firewall's list with
the fleet's total.

`getDeviceNamedThreats(pool, deviceId, hours, limit)` -> `{threats[], total}` (v2.142.0).
⛔ A NULL `threat_name` is COUNTED as an explicit `(unnamed)` row, never dropped: live,
946,434 of ITC-SK's 949,950 threat events (99.6%) carry no name, so filtering them would
hide almost the entire threat volume while looking tidier. ⛔ This is ATTACK CONTEXT and
must never feed the CVE priority tree — threat signatures were measured and REJECTED as a
band modifier because they fire on nearly every device.

`getDeviceInboundHits(pool, deviceId, hours, limit)` -> rows from
`syslog_device_inbound_hourly` (v2.142.0) — the same evidence /exposure and `log_hit` are
built on. ⛔ `publicSource` and `allowed` are SEPARATE facts and neither may be collapsed
into the other. ⛔ Ordered by `(public_source AND allowed) DESC` before volume: one allowed
hit on a management port outranks a million blocked scans, and ranking by count buries it.

`getTopRules` also takes the optional trailing `deviceId` now.
