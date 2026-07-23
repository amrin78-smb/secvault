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

`CHECKS` -> `object[]` — curated array of compliance check definitions (`checkId, name, description, standards, vendor, severity, predicateConfig, remediationGuidance`); predicate types include `config_key_exists`/`config_value_equals`/`config_value_matches`/`feature_enabled`/`admin_access_from_zone`/`not_evaluable_from_config`/`rule_scan`/`ruleset_property`. NOTE: actual count exceeds the "44" CLAUDE.md's Compliance Engine section currently states — see gotchas.md.
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
`main()` -> `Promise<void>` (not exported, run via `require.main === module`) — orchestrates: runSchema → seedUsers → seedAuditChecks (NOT best-effort, throws loud) → backfillVulnerabilityCategories (best-effort) → cleanupVolatileConfigDiffs (best-effort) → regenerateOversizedChangeSummaries (best-effort) → migrateZoneClassificationsToPerDevice (best-effort) → backfillPaloAltoVersionRanges (best-effort).
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

## lib/engines/configDiff.js

`diffConfigs(oldParsed, newParsed, vendor?)` -> `{added, removed, modified}` (pure) — deep recursive diff of two parsed config trees; applies vendor-specific volatile-path filtering + defense-in-depth secret redaction; caps at 500 entries.
`summarizeDiff(diff)` -> `string` — human one-liner (`"N added, M removed — e.g. path1, path2"`), with sanitized/truncated example paths.
`isEmptyDiff(diff)` -> `boolean` — true if added/removed/modified are all empty.
`detectAndStoreDiff(deviceId, pool, vendor?)` -> `Promise<{changed: boolean, diffId: string|null, summary: string|null}>` — diffs the 2 latest `device_configs` snapshots and inserts a `config_diffs` row if changed.
`createBackup(deviceId, label, pool)` -> `Promise<{backupId: string|null}>` — copies latest `config_raw` into `config_backups` (`label` ∈ auto/manual/pre-change).
`filterDiffForCurrentRules(diff, vendor)` -> `object` — re-applies current volatile-path filter + secret redaction to an already-computed diff object. [SENSITIVE] (secret-redaction pass over stored config diffs)
`cleanupVolatileConfigDiffs(pool)` -> `Promise<{checked, deleted, updated}>` — retroactive migration: deletes/updates existing `config_diffs` rows per current noise/secret rules. [SENSITIVE]
`classifyDiff(diff)` -> `{ruleChanges: object[], sections: object[]}` — presentation-layer grouping of a diff into a rule-change table + labeled sections; pure, read-time only.
`regenerateOversizedChangeSummaries(pool)` -> `Promise<{checked, updated}>` — backfill: re-derives `change_summary` for any oversized (>500 char) stored row.

## lib/engines/dashboardSnapshot.js

`computeFleetCveSeverity(pool)` -> `Promise<{critical, high, medium, low}>` — fleet-wide (active devices) CVE counts by CVSS bucket; unscored CVEs excluded from all buckets.
`computeFleetComplianceScores(pool)` -> `Promise<{overall: number|null, byStandard: Record<string, number|null>}>` — fleet-wide pass/(pass+fail+warning) scores per standard + overall; `null` when unmeasurable.
`computeAndStoreDashboardSnapshot(pool)` -> `Promise<{cve, compliance}>` — computes + `UPSERT`s today's `fleet_dashboard_snapshots` row (idempotent per calendar day).

## lib/engines/objectUsage.js

`analyzeObjectUsage(objects, rules)` -> `{object_id, finding_type: 'unused'|'duplicate', detail, related_object_ids}[]` (pure) — namespace-partitioned (address vs service) unused/duplicate object detection with transitive group-membership closure.
`storeObjects(deviceId, objects, pool)` -> `Promise<{count: number}>` — DELETE+reinsert `network_objects` from an adapter's `getObjects()` result.
`runObjectUsageAnalysisForDevice(deviceId, pool)` -> `Promise<{findings: object[]}>` — loads objects+rules, analyzes, DELETE+reinsert `object_analysis_results` in one transaction.

## lib/engines/riskScore.js

`computeRiskScore(findings)` -> `{score: number, band: 'low'|'medium'|'high'|'critical', raw: number}` — tallies severity counts from a raw findings array then scores.
`computeRiskScoreFromCounts(counts)` -> `{score, band, raw}` — weighted sum (critical:10/high:5/medium:2/info:0), clamped to 100, banded.
`computeRuleRiskBand(ruleFindings, enabled)` -> `'low'|'medium'|'high'|'critical'|'attention'` — per-rule risk band = worst severity among the rule's own findings; `'attention'` for an enabled rule with zero findings, `'low'` for a disabled one.
`SEVERITY_WEIGHTS` -> `object` — `{critical:10, high:5, medium:2, info:0}`.
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

## lib/engines/exposureCorrelation.js

`EXPOSURE_FINDING_TYPES` -> `string[]` — `['any_any', 'overly_permissive', 'risky_service', 'external_exposure']`.
`getExposureCorrelationForDevice(deviceId, pool)` -> `Promise<{finding: {id, rule_id, finding_type, severity, detail}, cves: {advisory_id, cve_id, cvss_score, kev_listed, advisory_url}[]}[]>` — device-level join of open exposure-widening rule findings with open `patch_now` CVE assessments (both excluding acknowledged/dismissed).
`countDevicesWithExposureCorrelation(pool)` -> `Promise<number>` — fleet-wide count of devices with ≥1 correlation.

## lib/engines/reachabilityMatrix.js

`computeZoneReachability(rules)` -> `{zones: string[], matrix: Object<string, Object<string, {verdict: 'allow'|'deny'|'unspecified', ruleName: string|null}>>, hasZoneData: boolean}` (pure) — single-device zone×zone reachability matrix via first-matching-enabled-rule-wins walk in `sequence_number` order.

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

`FirewallAdapter` (abstract base class) — constructor({device, pool}); defines the adapter contract: `testConnectivity()` -> `{ok, latency_ms, message}`, `getVersion()` -> `{version_string, version_tuple, build, model}`, `getRules()` -> `NormalizedRule[]`, `getConfig()` -> `{raw, parsed}`, optional `getObjects()` -> `{addresses, addressGroups, services, serviceGroups}`, optional `getSnmpMetrics()` -> `{cpuPercent, memoryPercent, sessionCount, uptimeSeconds, raw, lowConfidence?, targetHost}` — every concrete adapter extends this. [SENSITIVE]

## lib/adapters/index.js

`getAdapter(device, pool)` -> `FirewallAdapter instance` — resolves vendor+mgmt_method to a concrete adapter class via `ADAPTERS`/`DEFAULT_METHOD` tables. [SENSITIVE]
`collectAndStore(device, pool)` -> `Promise<{version, rulesCount, configCollected, configChanged, analysisFindings, complianceFindings, objectsCollected?, objectFindings?, errors[]}>` — full per-device collect pipeline: version/rules/config persistence + Phase 5 rule analysis + Phase 6 diff/backup + Phase 7 compliance audit + optional object-catalog/usage analysis, each step isolated in try/catch. [SENSITIVE]
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
`getEffectiveSecurityPolicy(conn)` -> `Promise<{raw, result}>` — op `show running security-policy`, the Panorama-managed-device merged-policy fallback (2026-07-24). Request construction proven (same CLI-to-XML convention as every other op command here); response SHAPE is doc-derived, not yet live-verified — see `parser.parseEffectiveSecurityPolicy()`.
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
`parseEffectiveSecurityPolicy(result)` -> `NormalizedRule[]|null` — Panorama-managed-device merged-policy fallback (2026-07-24), XML/API transport. Deep-walks for any `@_name`+`action`-bearing entry (shape-agnostic by design, mirroring `parseRulesDeep`'s approach); tolerant of both the SSH-transport's confirmed-live combined `"application/service"` field and a separate application/service fallback shape. Returns `null` (not `[]`) when nothing rule-like is found — caller (`index.js`) treats `null` as "fallback not usable." DOC-DERIVED, NOT YET LIVE-VERIFIED — see CLAUDE.md's "Palo Alto SSH — RESOLVED" section, "XML/API transport fallback" subsection.
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
3. `lib/auditChecksSeed.js`'s own header comment already flags itself as having been miscounted twice before ("count corrected again 2026-07-19"); CLAUDE.md's Compliance Engine section states "44 checks," but the current file's actual entry count is meaningfully higher by direct tally. Worth a fresh recount next time either file is touched.
4. Two undocumented same-day (2026-07-23) additions with no CLAUDE.md entry yet: Fortinet's `hostname` field extraction (mirrors the already-documented `serial` fix pattern) and Palo Alto XML/API's `hostname` extraction (explicitly marked doc-derived/unverified in-code). `backfillPaloAltoVersionRanges()` IS documented (added same session, see CLAUDE.md's NVD CPE Matching section) — not a gap, listed here only for completeness.
