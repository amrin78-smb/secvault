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

`CHECKS` -> `object[]` — curated array of compliance check definitions (`checkId, name, description, standards, vendor, severity, predicateConfig, remediationGuidance`); predicate types include `config_key_exists`/`config_value_equals`/`config_value_matches`/`feature_enabled`/`admin_access_from_zone`/`not_evaluable_from_config`/`rule_scan`/`ruleset_property`. Current count (45) matches CLAUDE.md's Compliance Engine section — recount via `grep -c "checkId:"` if this file changes. Full mechanics: `.ai-codex/compliance-pipeline.md`.
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

`computeFleetCveSeverity(pool)` -> `Promise<{critical, high, medium, low}>` — fleet-wide (active devices) CVE counts by CVSS bucket; unscored CVEs excluded from all buckets.
`computeFleetComplianceScores(pool)` -> `Promise<{overall: number|null, byStandard: Record<string, number|null>, byStandardCounts: Record<string, {pass,fail,warning}>}>` — fleet-wide pass/(pass+fail+warning) scores per standard + overall; `null` when unmeasurable. `byStandardCounts` (added 2026-08-02, additive — `computeAndStoreDashboardSnapshot` below ignores it) is the raw counts behind each percentage, for `lib/engines/complianceReport.js`'s fleet summary section.
`computeAndStoreDashboardSnapshot(pool)` -> `Promise<{cve, compliance}>` — computes + `UPSERT`s today's `fleet_dashboard_snapshots` row (idempotent per calendar day).

## lib/engines/objectUsage.js

`analyzeObjectUsage(objects, rules)` -> `{object_id, finding_type: 'unused'|'duplicate', detail, related_object_ids}[]` (pure) — namespace-partitioned (address vs service) unused/duplicate object detection with transitive group-membership closure.
`storeObjects(deviceId, objects, pool)` -> `Promise<{count: number}>` — DELETE+reinsert `network_objects` from an adapter's `getObjects()` result.
`runObjectUsageAnalysisForDevice(deviceId, pool)` -> `Promise<{findings: object[]}>` — loads objects+rules, analyzes, DELETE+reinsert `object_analysis_results` in one transaction.

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
`evaluateCheck(check, configParsed)` -> `{status: 'pass'|'fail'|'warning', detail: string}` — evaluates a config-predicate check via `applicability.evaluatePredicate` + `pass_when` polarity.
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
`buildFleetTopologyGraph(devices, interfacesByDevice)` -> `{nodes: {id,name,vendor,hasInterfaceData}[], edges: {sourceDeviceId,sourceInterface,targetDeviceId,targetInterface}[]}`
(added 2026-08-02, for `components/topology/FleetMap.js`'s visual diagram) — reuses `buildAdjacencyGraph()`
internally, deduping its bidirectional entries into one edge per device PAIR; every active device becomes
a node EVEN with zero `device_interfaces` rows (`hasInterfaceData:false`), so the map stays honest about
fleet coverage gaps instead of silently omitting uncollected devices.
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

**Phase 1 vendor scope**: `getInterfaces()`/`getRoutingTable()`/`getNatRules()` (optional adapter
methods, see `lib/adapters/interface.js`) are implemented ONLY by `paloalto`/`fortinet`'s SSH
transport — API transport and the other 4 vendors are not yet wired. Fortinet's `getNatRules()`
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

`FirewallAdapter` (abstract base class) — constructor({device, pool}); defines the adapter contract: `testConnectivity()` -> `{ok, latency_ms, message}`, `getVersion()` -> `{version_string, version_tuple, build, model}`, `getRules()` -> `NormalizedRule[]`, `getConfig()` -> `{raw, parsed}`, optional `getObjects()` -> `{addresses, addressGroups, services, serviceGroups}`, optional `getSnmpMetrics()` -> `{cpuPercent, memoryPercent, sessionCount, uptimeSeconds, raw, lowConfidence?, targetHost}`, optional `getInterfaces()` -> `{interfaces: {name,ipAddress,zone,vdom,enabled}[]}`, optional `getRoutingTable()` -> `{routes: {destinationCidr,nextHopIp,interfaceName,protocol,metric,vdom}[]}`, optional `getNatRules()` -> `{rules: {sequenceNumber,enabled,natType,original*Addresses,translated*Addresses}[]}` (added 2026-08-02, for `lib/engines/topology.js` — paloalto/fortinet SSH transport only as of Phase 1; both implement it, see `topology.js`'s own entry for Fortinet's per-policy-derived NAT shape) — every concrete adapter extends this. [SENSITIVE]

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
`PaloaltoAdapter` (class extends FirewallAdapter) — PAN-OS XML API transport (api_key or username/password→keygen). Methods: `_resolveApiKey()` (cached promise per instance), `_getConn()`, `testConnectivity()`, `getVersion()`, `getRules()` (default-vsys xpath, falls back to any-vsys deep search when zero rules found, then hit-count enrichment), `_enrichHitCounts(conn, rules, vsysName)` (additive, never throws), `getConfig()` (redacts raw XML + config tree before parsing), `getObjects()` (reads back stored `config_parsed` via `getLatestConfigParsed`, no new device call), `getSnmpMetrics()` (PAN-COMMON-MIB + HOST-RESOURCES-MIB, always `lowConfidence:true`). [SENSITIVE]
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
`getEffectiveSecurityPolicy(conn)` -> `Promise<{raw, result}>` — op `show running security-policy`, the Panorama-managed-device merged-policy fallback (2026-07-23). Request construction proven (same CLI-to-XML convention as every other op command here); response SHAPE is doc-derived, not yet live-verified — see `parser.parseEffectiveSecurityPolicy()`.
`DEFAULT_VSYS` (const string) — `'vsys1'`.
`SECURITY_RULES_XPATH` (const string) — default-vsys rulebase xpath.
`SECURITY_RULES_XPATH_ANY_VSYS` (const string) — predicate-free fallback xpath.
`redactSecrets(text, secrets)` -> `string` — scrubs literal/URL-encoded secret forms + `key=`/`password=`/`user=` query params from error strings, anchored on parameter NAME (survives re-encoding). [SENSITIVE]
`redactKey(text, apiKey)` -> `string` — back-compat single-secret alias of redactSecrets. [SENSITIVE]
`extractErrorMessage(msg)` -> `string|null` — flattens PAN-OS `<msg>` error node shapes.

## lib/adapters/paloalto/parser.js

`parseSystemInfo(systemInfoResult)` -> `{version_string, version_tuple, build, model, serial, hostname}` — parses `show system info` XML result (hostname on XML/API transport is doc-derived, not yet live-verified — unlike SSH's flat-text field, which IS confirmed).
`parseRules(rulesResult)` -> `NormalizedRule[]` — parses default-vsys rulebase `<entry>` list.
`parseRulesDeep(rulesResult)` -> `NormalizedRule[]` — shape-agnostic deep walk for the any-vsys fallback, collects every `security.rules` container.
`parseRuleHitCount(hitCountResult)` -> `{[ruleName]: hitCount}` — shape-agnostic deep walk for `show rule-hit-count` response.
`parseEffectiveSecurityPolicy(result)` -> `NormalizedRule[]|null` — Panorama-managed-device merged-policy fallback (2026-07-23), XML/API transport. Deep-walks for any `@_name`+`action`-bearing entry (shape-agnostic by design, mirroring `parseRulesDeep`'s approach); tolerant of both the SSH-transport's confirmed-live combined `"application/service"` field and a separate application/service fallback shape. Returns `null` (not `[]`) when nothing rule-like is found — caller (`index.js`) treats `null` as "fallback not usable." DOC-DERIVED, NOT YET LIVE-VERIFIED — see CLAUDE.md's "Palo Alto SSH — RESOLVED" section, "XML/API transport fallback" subsection.
`parseConfig(configResult, systemInfoResult)` -> `object` — builds getConfig()'s parsed tree, merges `system_info`.
`redactConfigXml(text)` -> `string` — regex-redacts `<tag>value</tag>` and `tag="value"` for SECRET_TAGS in raw XML, runs BEFORE parseConfig(). [SENSITIVE]
`redactConfigTree(node)` -> `any` — recursive secret-key redaction of the parsed object tree. [SENSITIVE]
`extractObjects(configTree)` -> `{addresses, addressGroups, services, serviceGroups}` — deep search for address/address-group/service/service-group containers.
`toArray(value)` -> `array` — fast-xml-parser single-vs-array normalizer.
`memberStrings(field)` -> `string[]` — normalizes `<member>` list fields.
`mapAction(rawAction)` -> `string|null` — PAN-OS rule action → NormalizedRule action.
`scalarText(value)` -> `string|null` — extracts scalar text from an XML node.

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
