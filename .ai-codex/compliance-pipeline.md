# Compliance Pipeline — End-to-End Map

> Read this before touching any Phase 7 compliance code (`lib/auditChecksSeed.js`,
> `lib/engines/configAuditor.js`, `lib/engines/dashboardSnapshot.js`, `/compliance` routes/pages).
> Verified directly against the current code on 2026-07-30. Where CLAUDE.md and the code differed,
> it is called out under "CLAUDE.md contradictions" at the bottom — CLAUDE.md has been corrected to
> match in the same pass that created this file.

Scope: how the curated `audit_checks` library gets evaluated against a device's collected
config/rules, resolves to a four-state finding, and rolls up into a compliance score.

---

## Stage-by-stage flow

### 1. SEED — curated check library, not a `.sql` seed file

`lib/auditChecksSeed.js`'s `CHECKS` array, upserted by `seedAuditChecks(pool)` (`INSERT ... ON
CONFLICT (check_id) DO UPDATE`), called unguarded from `lib/migrate.js`'s `main()` — a seed failure
means zero compliance checks fleet-wide, so it must fail the migrate run loudly, not swallow the
error. Hand-editable JS (same convention as `advisory_conditions`), not raw SQL, because the file's
own header comment tracks per-check field-path groundedness against real parser output (e.g. which
Fortinet config sections a given check's path actually depends on) — that reasoning doesn't fit a
`.sql` row.

**Current count: 45 checks** (`grep -c "checkId:" lib/auditChecksSeed.js` — recount directly if you
touch this file, it has been miscounted more than once before). Predicate-type breakdown as of this
writing: `config_key_exists` (12), `feature_enabled` (8), `rule_scan` (8),
`not_evaluable_from_config` (7), `config_value_matches` (5), `ruleset_property` (3),
`admin_access_from_zone` (2), `config_value_equals` (2). `not_evaluable_from_config` checks are
deliberate honest degradation (structural gaps the adapter can't collect, not "not yet wired up" —
see the file's header comment for which is which). Since 2026-08-25 they resolve `na`, NOT
`warning`, so they no longer count against the compliance score — see stage 3 below.

### 2. LOAD — per-device inputs, one query each, shared across every check

`runComplianceAuditForDevice(deviceId, pool)` (`lib/engines/configAuditor.js:434`) loads, once per
run:
- The device row (vendor — determines which vendor-scoped checks apply).
- `getLatestConfigParsed(deviceId, pool)` (from `applicability.js`, same function the CVE pipeline
  uses) + `hasUsableConfig()` guard — feeds config-predicate checks only.
- Every applicable `audit_checks` row: `WHERE vendor IS NULL OR vendor = $1`.
- `rule_analysis_results` bucketed by `finding_type` (`loadRuleFindingsByType`, line 411) — feeds
  `rule_scan` checks AND is reused by the `no_external_to_internal_access` ruleset property (see
  below), never recomputed twice.
- Raw `firewall_rules` columns needed for ruleset-property evaluation (`action`, addresses,
  services, `enabled`, `src_zones`/`dst_zones`) — only fetched when `ruleCount > 0`.
- `getZoneRoleMap(deviceId, pool)` — best-effort; a load failure is caught and logged, never thrown,
  and just means `no_external_to_internal_access` resolves `na` for every check this run (empty
  map → no zone has a role → `na`), same fail-safe posture as `ruleAnalysis.js`'s own zone-role load.

### 3. EVALUATE — three distinct predicate shapes, each with a different "nothing to measure" story

**(a) Config-predicate checks** (`evaluateCheck`, line 55) — reuses `applicability.js`'s
`evaluatePredicate()`, the SAME evaluator `advisory_conditions` uses. This is the tri-state → four-
state polarity problem CLAUDE.md documents: `evaluatePredicate()` only knows `yes`/`no`/`unknown`,
with no concept of "good." Each check's `predicate_config.pass_when` (`'yes'|'no'`) supplies the
polarity: `statusFromResult()` maps `unknown → warning`, `result === passWhen → pass`,
else `fail`. **`pass_when` missing or not exactly `'yes'`/`'no'` → `warning`, never a silent default
polarity** — a curated-data bug, not a device problem. No usable config at all →
`na` for every config-predicate check on that device (checked once, outside this function).

⛔ **`predicate_type: 'not_evaluable_from_config'` → `na`, short-circuited at the TOP of
`evaluateCheck()` (changed 2026-08-25).** It previously fell through to `evaluatePredicate()`'s
`default: return 'unknown'` and became a `warning`, which put it in the score denominator. Wrong
bucket: a `warning` is a fact about the DEVICE (we asked a real question of a collected config and
the answer was indeterminate), whereas these checks are unanswerable BY CONSTRUCTION — nothing an
operator changes on the firewall makes them answerable, because the fact is inherently per-rule or
needs telemetry a config snapshot never holds. That is a fact about SECVAULT, and scoring a device
down for it is the same error as `hit_count`'s old `NOT NULL DEFAULT 0`. Measured live across the
16-device fleet: 43 of 61 warnings were this; fleet score 46% → 51%, every device up 3-7 points,
with no check changing between pass and fail. Handled BEFORE the `pass_when` guard on purpose —
these carry a placeholder `pass_when` that is never consulted. The finding is still WRITTEN and
still displayed with its `reason`: `na` removes it from the score, never from the operator's
manual-verification list.

**(b) `rule_scan` checks** (`evaluateRuleScanCheck`, line 119) — "does ANY rule on this device carry
one of these Phase 5 `finding_type`s," reusing `ruleAnalysis.js`'s already-decided findings rather
than re-detecting per-rule conditions here. Fixed polarity, no `pass_when`: every `rule_scan` check
today is a "this bad pattern should not exist" check, so zero matches is always `pass`. Zero
collected rules → `na` (line 496-503), not a vacuous `pass`.

**(c) `ruleset_property` checks** (`evaluateRulesetPropertyCheck`, line 372) — positive existence
questions directly against a device's current `firewall_rules` content (not Phase 5 findings, not
one fixed config path). Three properties as of this writing:
- `has_explicit_deny_all` (line 227) — an enabled deny-synonym rule with unrestricted
  source/destination/service. Cisco ASA's `ip`/`ip4`/`ip6` protocol tokens are treated as
  service-field wildcards (`SERVICE_ANY_ALIASES`, line 200) — without this, the single most common
  real ASA explicit-deny-all pattern (`deny ip any any`) failed the check entirely.
- `blocks_icmp` (line 258) — an enabled deny-synonym rule whose service list matches
  `(^|[^a-z])icmp` (line 257) — deliberately not `\bicmp\b`, because FortiOS's own built-in
  `ALL_ICMP` service object doesn't have a word boundary before "ICMP" (`_` is a `\w` char), which
  made the check FAIL on a device that was correctly blocking ICMP with FortiOS's own default object.
- `no_external_to_internal_access` (line 324, added 2026-07-18 alongside the other two) — reuses
  `ruleAnalysis.js`'s already-computed `external_exposure` finding for the actual pass/fail, but has
  a THIRD outcome the other two properties don't need: `na` when this device's own zones haven't
  been classified as both External and Internal yet (`getZoneRoleMap`) — reporting `pass` just
  because zero rules happened to match, when the real reason is "we can't tell," is exactly the
  silent-good-news trap this engine's tri-state design exists to prevent, and matters here
  specifically because `zone_classifications` starts completely empty on every fresh install.

An unrecognized `property` value, or zero collected rules, resolves `warning`/`na` respectively —
never a silent guess.

### 4. WRITE — DELETE + reinsert per device, one transaction

`runComplianceAuditForDevice` (lines 538-578): `BEGIN` → `DELETE FROM audit_findings WHERE
device_id = $1` (line 542) → insert one row per evaluated check → `COMMIT` (or `ROLLBACK` + rethrow
on any error). `client.release()` runs in a `finally`, always — a thrown error before release would
otherwise leak a pool client per failed audit run.

### 5. TRIGGERS — two call paths

1. **`collectAndStore`** (`lib/adapters/index.js:274-275`) — runs automatically after every
   successful per-device collect, right after the Phase 6 config-diff block.
2. **On-demand** — `POST /api/compliance/[deviceId]/run` (`app/api/compliance/[deviceId]/run/route.js`),
   admin-gated (`isAdmin`/`forbiddenResponse`), returns 404 (not a generic 500) when
   `runComplianceAuditForDevice` throws its `Device not found: ...` error.

### 6. SCORE — `na` excluded from the denominator, `null` not `0`

`computeFleetComplianceScores(pool)` (`lib/engines/dashboardSnapshot.js:64`) and the per-device
`scorePctFromCounts` in `app/(dashboard)/compliance/page.js` both use the same formula: `round(100 *
pass / (pass + fail + warning))`, `na` rows excluded entirely from the denominator, `null` (rendered
"—", never `0`/`NaN`) when nothing is measurable for that standard/device yet.

---

## CLAUDE.md contradictions / staleness found

- CLAUDE.md's Compliance Engine section previously said `ruleset_property` covers "two checks"
  (`has_explicit_deny_all`, `blocks_icmp`) — the code has a third,
  `no_external_to_internal_access` (added the same day as the other two, per `configAuditor.js`'s
  own header comment), confirmed by `auditChecksSeed.js`'s actual `ruleset_property` count of 3.
  **Corrected in CLAUDE.md in the same pass that created this file.**
- The "45 checks" count CLAUDE.md states matches a direct recount (`grep -c "checkId:"
  lib/auditChecksSeed.js` = 45) — `.ai-codex/lib.md`'s own "Contradictions vs CLAUDE.md" note
  claiming CLAUDE.md still said "44" was itself stale; corrected in the same pass.
