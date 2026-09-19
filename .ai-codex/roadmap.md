# SecVault Roadmap

Living document. **Built-state reviewed 2026-09-19** (v2.148.0). The measured FLEET FIGURES
below are from **2026-09-09** (15 active devices, ~74M syslog events/day) unless a line restates
them, and the FWA feature comparison that motivated this product is from the same date.

⛔ **THIS FILE WENT 24 VERSIONS STALE (v2.124.0 -> v2.148.0) AND SAID SO NOWHERE.** It carried
"Still open, unchanged: Phase 2" for a phase shipped in v2.129.0, and described RBAC as
"admin/viewer only" nineteen versions after `viewer` was retired. That is the exact failure its own
header warns about one paragraph down, in the file written to prevent it. Two lessons, both now
acted on: a review date is not a freshness guarantee unless something re-reads it, and the
"Already built" table is the half that MUST be updated in the same commit as the work — a missing
future item costs a conversation, a missing BUILT item costs a rebuild.

⛔ **Read `## Already built` before proposing anything.** Several items that read as missing are
done — CLAUDE.md's own "Not built yet" section was stale by a whole phase when this was written,
and a roadmap that re-proposes finished work is worse than no roadmap.

Every number below is measured, not estimated. Where something is uncertain it says so.

---

## Already built (do not re-propose)

| Capability | Evidence on the live fleet |
|---|---|
| Syslog ingestion, spool, archive, partitioned raw store | ~74M events/day, 30-day raw window |
| Ten traffic/security rollups + a separate fast threat rollup | 219k talker, 146k blocked-dst, 114k app rows |
| **Rule-hit correlation from logs (Phase 8b)** | 8,803 rule-hit rows, all 15 devices |
| **Tri-state `hit_count`** | 164 unmeasured / 466 measured-zero / 1,086 with hits |
| Rule analysis, 10 finding types | 185 `unused`, 252 `overly_permissive`, 153 `shadow` |
| **Rule cleanup loop, request → export → verified against the ruleset** | v2.93.0 |
| CVE pipeline + KEV + priority tree | 159 live assessments |
| `log_hit` producer | `lib/engines/logHit.js` |
| Compliance engine + monthly PDF | 45 checks, 5 standards |
| Topology, access-path, fleet map | — |
| VPN login geography + spray detection | `syslog_vpn_auth_hourly` |
| Device discovery from unmatched senders | `discovered_devices` |
| Log search (forensic) | 25/50/100/200 per page, index-backed |
| Design system, density, saved views, ⌘K | v2.87–v2.90 |
| Answer-first headline sentences on every major page | `lib/answers.js`, 9 builders, v2.106+ |
| RBAC (3 roles, capability grants), MFA (TOTP), HTTPS | v2.107–v2.112 |
| **Segmentation intent — CAN it, and DID it** | v2.113.0; live: `untrust -> private` permitted by 2 rules, 0 hits |
| Tunnel health answer-first + coverage bar | v2.114.0 |
| **Work queue, one ranked list across all 9 engines** | v2.115.0; live: 19 act-now / 60 scheduled / 6 needs-a-human |
| Reporting platform, catalogue + 10 reports | Phase D, v2.123.0 |
| **Application-centric view, Phase 1** | v2.124.0; `applications`/`application_flows`, two engines, `/applications`, work-queue source #10 |
| **Application intent Phase 2 — rule impact + retirement** | v2.129.0; `IMPACT_CLAIM`, proposals through the existing `ruleChangeRequests` loop. ⛔ Neither can CONCLUDE on this fleet (14 of 16 firewalls reference objects the device never reported) and that is correct — the fix is collecting the objects, not loosening the engine |
| **Vendor PSIRT gated on the inventory** | v2.130.0; a vendor's own feed runs only if that vendor is deployed. Gate FAILS OPEN; a skip is WRITTEN with a reason |
| **Commercial licensing** | v2.131.0; trial/valid/grace/expired/**invalid**, per-firewall count. ⛔ Monitoring runs in EVERY licence state including expired |
| **Check Point / Forcepoint CPE coverage** | v2.132.0; 4 -> 22 strings, ~107 CVEs. ⛔ Honest gain on a Gaia R80+ fleet is ~7 -> 20, not 7 -> 107 |
| **Backup and restore** | v2.133.0; daily SYSTEM task, self-verifying archive, `.env.local` included, dry-run restore |
| **LDAP group-to-role mapping** | v2.134.0; replaced the hardcoded `admin` for any successful bind. Search-then-bind — the old direct-bind DN could not have existed in the customer's directory |
| **Central CVE feed (`cve_hub`)** | v2.137.0-v2.139.0; Ed25519-signed corpus from nocvault-eol, because this server's egress **cannot reach NVD at all** (internal public ranges overlap NVD's). Live: 439 advisories that could never match a device, now matchable. Local NVD is SKIPPED only when the hub actually delivered, and a FROZEN hub is visible (`checked_at`, not `generated_at`) |
| **Exposure filtered by firewall** | v2.140.0; table only — the fleet figures above it stay fleet-wide and say so |
| **Per-firewall Traffic tab + drill-through to log search** | v2.141.0-v2.143.0; nine widgets, per-source error isolation, the 24h window travels with the link |
| **Log search bounded by EXECUTION TIME** | v2.144.0; the third bound. Cost tracks how RARE the value is, not which column is indexed — the indexed column was the 11-second one |
| **Server health tab** | v2.145.0; disk per volume, database size, retention, ingest, service liveness inferred from what each service WRITES (NSSM reports a crash-looping process as Running) |
| **Two bug sweeps + the open-items pass** | v2.146.0-v2.148.0; 25 fixes, all one family. See those commits before assuming a "missing" honesty guard is missing |

---

## Tier 1 — highest leverage, and only possible because the data now exists

### 1. Close the rule-cleanup loop — **DONE v2.93.0**
**Why first.** This is FWA's flagship report *and* the place SecVault can beat it outright. FWA
infers rule usage from logs alone. SecVault has three independent signals for the same rule —
log evidence, the device's own hit counter, and the parsed config — and it already knows which of
those it could not measure. Nobody else can say "this rule is unused **and here is why we are
sure**".

**The gap was workflow, not analysis** — 185 unused findings existed and an operator could not act
on them as a batch. Shipped: `rule_change_requests` / `rule_change_request_items` +
`lib/engines/ruleChangeRequests.js`, cleanup selection on the Cleanup tab, a request list/detail
view, CSV + PDF export, and verification wired into `collectAndStore`.

⛔ **One premise in the original item was wrong and was NOT built as written.** "Verify against
the next `config_diffs`" would have been the wrong signal: `config_diffs` compares consecutive
CONFIG snapshots, which for several vendors do not carry the ruleset in a form that proves a
specific rule by vendor ID is gone. Verification instead runs against the re-collected
`firewall_rules` rows, which is where rule identity actually lives.

⛔ That in turn needed a new column. `devices.last_collected_at` is stamped when ANY capability
succeeded, so a device whose RULE pull had been failing for a week still looked freshly collected
— and since `firewall_rules` is DELETEd and reinserted only on a SUCCESSFUL pull, "the rule is
absent" would have been read off a stale ruleset and reported every requested rule as removed. A
collection outage would have rendered as a completed cleanup. `devices.last_rules_collected_at`
is stamped only on the success path, and verification requires it to be STRICTLY newer than
`submitted_at`.

⛔ The tri-state held throughout: a rule whose hit count is unmeasured is refused from a request
server-side, not warned about — 164 of 1,716 rules on the live fleet. `getCleanupCandidates`
returns `{eligible, withheld}` so the UI cannot silently show a shorter list, and `unverifiable`
is rendered as its own state rather than as a failure.

Deliberately NOT built: any manual "mark as done" control. A request becomes `verified` because
the re-collected ruleset says the rules are gone. A tick box would have reduced this to the
export button FWA already has.

### 2. Threshold and anomaly alerting
**Why.** A security product that cannot say "denied traffic from this country just tripled" is
missing table stakes, and FWA has had it for a decade. The dispatch half already exists
(`notification_channels`, `notificationDispatch.js`, four alert types) — what is missing is any
alert driven by a *measurement* rather than a state change.

Candidates the rollups already support, at no new collection cost: denied-traffic spike per
device/country, new attacker source, threat-severity escalation, VPN auth-failure burst (the
credential spraying found on 2026-09-08 would have fired this), collector ingest drop.

⛔ Thresholds must be explicit and per-rule, never a magic "anomaly score" — see CLAUDE.md's
rejection of a composite `log_hit` definition for the same reason.

### 3. Report library and scheduling
**Why.** FWA's real stickiness is not any single report; it is that a manager receives one every
Monday without asking. SecVault has the renderer (`pdfkit`, `complianceReport.js`) and a monthly
scheduler, for exactly one report.

Generalise to: a report type registry, a schedule per report, a recipient list per schedule.
First three worth having — fleet security posture, rule hygiene / cleanup candidates, traffic and
top talkers.

⛔ Reuse `compliance_report_log`'s pattern: a partial unique index enforcing one success per
period, because the job runs both on cron and at every service start.

---

## Tier 2 — parity gaps against ManageEngine FWA

| FWA capability | SecVault today | Work |
|---|---|---|
| **Change management workflow** (request → approve → implement → verify) | **Half done v2.93.0.** Request → implement → verify exists for RULE REMOVALS (`rule_change_requests`, verified against the re-collected ruleset). Any other kind of change is still detected after the fact by `config_diffs` only | Small–medium. Remaining: an approval step, and requests for changes that are not deletions. ⛔ Do NOT generalise the verifier by pointing it at `config_diffs` — that was the original plan and it is wrong: a config diff cannot prove a specific rule by vendor ID is gone on every vendor, which is why v2.93.0 verifies against `firewall_rules` instead |
| **Capacity planning / bandwidth forecast** | Rollups hold the history; no trend projection | Medium. ⛔ Only for vendors where `bytes_summable` is true — FortiOS cumulative counters are already excluded and must stay excluded |
| **Custom report builder** | Fixed reports only | Large. Defer until the report registry above exists |
| **Multi-tenancy / site scoping** | `devices.site` exists and is **empty on 14 of 15 devices** | Small technically, but pointless until sites are actually populated. Blocked on data, not code |
| **Granular RBAC** | **THREE roles since v2.110.0** (`super_admin`/`admin`/`operator`, nine capabilities); `viewer` is retired and unassignable. This line said "admin/viewer only" for nineteen versions | Only if a customer asks for something the nine capabilities cannot express. ⛔ Grants are listed explicitly per role, never derived by subtraction |
| Forensic log search | `/logs`, index-backed, honest about depth caps | **Done, arguably better than FWA** |
| Compliance reporting | 45 checks, 5 standards, PDF | **Done** |
| VPN reporting | Sessions, geography, spray detection | **Done, beyond FWA** |

---

## Tier 3 — data-integrity debt (small, high value, mostly one-sitting each)

1. ~~Missed daily snapshots are never backfilled.~~ **DONE v2.91.0** — and the real bug was worse
   than the gaps. TWO startup paths cancelled each other: an unconditional run in `main()`, then a
   guarded "if missing" check in `scheduleJobs()` which is called *after* it, so the guard always
   found the row the unconditional run had just written and was a permanent no-op. Because the
   write was `ON CONFLICT DO UPDATE`, every deploy restart REPLACED that day's snapshot with
   mid-day numbers — a day's trend point was whatever the last restart happened to see. Past gaps
   stay permanent by design.
2. ~~CVSS v3/v4 not normalised.~~ **CLOSED AS NOT FIXABLE — the item rested on a wrong premise.**
   "Pick one authoritative version and normalise" assumed both metrics were usually available for
   the same CVE. Measured 2026-09-09: of 1,001 advisories exactly **1** carries both a v3 and a v4
   metric, and of the 159 live assessments **110 are banded on v4 with no v3 available at all**.

   ⛔ So choosing v3 as authoritative would leave 110 assessments UNSCORED, which the priority tree
   reads as "not scored" — it would lose real signal to buy a consistency that does not exist. And
   v3 and v4 use different formulas and metrics; there is no valid conversion, so any "normalised"
   score would be a fabricated number of exactly the kind this codebase bans.

   Each CVE carries whichever version its CNA published. The mix is **structural, not a defect**.
   The real fix was the one already shipped in v2.90.3 — record `cvss_source` and `cvss_version` so
   a score cannot silently change meaning — plus surfacing the version in the UI (v2.92.0) so
   nobody compares two numbers that were never on the same scale.

   ⛔ Do not reopen this as a normalisation task. If it is reopened at all, the only honest version
   is "re-score every CVE ourselves from its vector", which needs a full v3 and v4 implementation
   and is a different, much larger piece of work.
3. ~~`CveCell` cannot distinguish "assessed and clean" from "never assessed".~~ **DONE v2.91.0**
   via `devices.last_cve_assessed_at`; the remaining call sites closed in v2.92.0
   (`OverviewCveCard.js`, `CvePostureTab.js`, and the device CVE tab, which had been asserting
   "This device HAS been assessed" purely because a version row existed — a precondition, never
   evidence of a run). ⛔ The SCORE call sites closed in v2.94.0, after the bug surfaced on screen rather than in
   code review: the Devices table showed **OKF(F2) at 100/100** — a perfect security score for the
   one firewall never collected at all. `vulnerabilitySubscore` was being fed EVERY active device
   as its denominator, so never-assessed counted as assessed-and-clean. Fixed in
   `deviceInventory.js` (per-device) and `fleetHeadline.js` (fleet, 51 -> 48 measured live), with
   the excluded count now STATED on the tile rather than silently averaged away.

   ⛔ The fresh install was always the real risk, not the 3-point gap: with nothing assessed,
   vulnerability scored a perfect 100 at full 40% weight and the dashboard announced excellent
   security for a fleet SecVault had never looked at.

   ⛔ Still open: `components/dashboard/CveSeveritySummary.js` has no coverage statement at all,
   and `lib/engines/dashboardSnapshot.js` persists the pre-fix value in rows already written, so
   that much of the gap stays baked into history.
4. ~~Fleet tiles lack `cveNoVersion` and a config-snapshot count.~~ **DONE v2.91.0.** While doing
   it, found `licence_row_count` was computed but never projected, so `supportNoData` silently
   equalled the whole fleet and the Support tile claimed "Not collected for any device" about 15
   devices whose licences ARE collected.
5. ~~Config snapshots are not deduped at write time.~~ **DONE v2.92.0 — and the stated premise was
   wrong.** "508 of 1,730 byte-identical" does not reproduce: measured today, only 60 of 2,160
   (2.8%) are byte-identical. But by SecVault’s OWN definition of no-change (`isEmptyDiff`),
   **93.3%** are duplicates — corroborated by only 142 `config_diffs` rows across 2,160 snapshots.
   An exact-byte hash would have saved 2.8%; the semantic key saves ~93%. ⛔ The hash fails in
   OPPOSITE directions per vendor: Fortinet’s `config_raw` carries ~412 volatile bytes per pull
   while its `config_parsed` is stable; Palo Alto’s `config_raw` is stable while its
   `config_parsed` carries volatile `system_info`.
6. ~~Wide rollup sweep takes ~900s per 6h slice.~~ **PROFILED AND HALVED in v2.92.0.** ⛔ The item's
   own assumption was wrong: `work_mem` was never the lever — every pass reports `Batches: 1`
   using 129 kB–13 MB of the 32 MB configured, so nothing ever spilled.

   The real cost is the TEMP-TABLE BUILD — **63% of a 3h sweep**, and no log line reported it at
   all. Writing into a TEMP table makes the statement parallel-unsafe, so the planner picks a
   single-threaded Seq Scan of the whole daily partition (1,881,660 pages read to return the
   588,017 that hold the window). `SET LOCAL enable_seqscan = off` around the build ONLY takes a
   3h sweep from 268s to 135s. ⛔ The win is selectivity-dependent — measured worst case (window
   covering 81% of its partition) is only 10%, but never a regression. Expect 30–50% typical.

   Two follow-ups, both deliberately deferred with reasons: a **BRIN index on
   `syslog_events.received_at`** would make the correct plan cheap rather than hinted (and help
   log search too), and **grid-anchoring `wideSliceWindow`** would drop the window from 10h to 7h
   — but that changes a coverage property `tests/rollups.test.js` pins, so it needs its own
   decision rather than riding along with a performance fix.
7. ~~SNMP Overview sparkline cannot show per-sample confidence.~~ **DONE v2.91.0** — provenance
   vocabulary shared via `components/snmp/chartGrammar.js` so the sparkline and the full page
   cannot draw the same sample two ways.

---

## Tier 4 — collection coverage (blocked on hardware, not effort)

- Fortinet HA and disk (no HA-enabled FortiGate to verify against)
- Fortinet API-transport topology; the other four vendors' interfaces/routes/NAT
- Fortinet IPS/AV: **zero `eventtype=infected` and no `ips` subtype in 24h** — either genuinely
  clean or the log types are not enabled. Worth asking the firewall team before building anything
  that assumes the data will arrive.

⛔ All of these are governed by CLAUDE.md's "verify against live responses before writing any
parser" rule. Do not write a parser for a device that cannot be tested.

---

## Commercial (decision taken 2026-09-09: "internal now, sellable later")

Branding is already token-swappable via `lib/branding.js` + `globals.css`; there is deliberately
no admin UI for it. Revisit white-label config, per-tenant scoping and a WCAG AA audit only when
an external customer is real.

---

## How to choose

If the next session has one day: **Tier 3 item 1** (snapshot backfill), then start Tier 1 item 2
(threshold alerting) — the dispatch infrastructure already exists, so it is mostly rule definition.

~~If it has a week: **Tier 1 item 1**.~~ Done v2.93.0. The next largest is **Tier 1 item 2**
(threshold alerting) — dispatch already exists, so it is mostly rule definition — then **item 3**
(report library), which item 1’s export now gives a second report type to generalise from.

## ⛔ `advisories.cve_id` is UNIQUE with ONE vendor — a CVE can be squatted (raised 2026-09-10)

CLAUDE.md already states "a CVE affecting two vendors stays with whichever ingested it first". That
was written as a tolerable simplification. Live evidence says it has teeth:

**CVE-2022-0778** (OpenSSL) is republished by Fortinet as FG-IR-22-059 and is still in FortiGuard's
current RSS. In this database it belongs to **`paloalto`, with 6 real version ranges and
`matchability='matched'`**. Whichever feed had run first would own it — and a feed that could only
supply a bare score with no ranges would have permanently displaced 6 real ones.

This is why the Fortinet degraded RSS path REPORTS but does not STORE (see `cve-pipeline.md`). That
is a workaround at one call site, not a fix: any current or future feed can still squat.

The real fix is making the identity per-vendor — `UNIQUE (cve_id, vendor)` plus a per-vendor read
path — so two vendors can each hold their own advisory for the same CVE. That is a schema change
touching `advisories`, `device_cve_assessments`, `versionMatcher`, the KEV cross-reference and every
fleet count, so it needs its own decision. Adding more feeds (CVE.org, EPSS) RAISES this risk, since
each new source is another candidate first-ingester.

## Two live data bugs found 2026-09-10, reported not fixed

### 1. ⛔ CORRECTED 2026-09-11 — the 0.0 scores are the VENDOR’s, not a SecVault fabrication

This entry originally said the fix belonged "in the producing feed plus a `lib/migrate.js`
backfill", on the assumption that `lib/feeds/paloalto.js` was inventing a 0 for "no score".
**That was wrong.** Checked against the source records: Palo Alto’s own advisory genuinely
contains `"baseScore": 0` inside a real `cvssV3_1` / `cvssV4_0` block, with a matching
zero-impact vector (`AV:P/AC:H/.../C:N/I:N/A:N`) — a vendor placeholder for third-party CVEs it
republishes without scoring. There is nothing in the feed to fix.

⛔ The real question is a SCORING decision, not a parsing one: **should a vendor-published
placeholder 0.0 be stored as a score at all?** Today CVE-2022-22963 sits at 0.0 in SecVault
against a published 9.8, and 46 `paloalto` rows are in this shape. Storing it means the priority
tree reads a real 0 and files a 9.8 as `monitor`; discarding it means treating a number the vendor
did publish as absent. Either way it needs deciding deliberately.

⛔ `lib/feeds/cveorg.js` surfaces these as `suspicious_zero_scores`, but its predicate is
`cvss_score = 0 AND cvss_source IS NULL` — and those rows now carry `psirt` after the v2.104.0
writer fix, so **that report will go quiet**. Re-point it before relying on it.

(Original entry below, kept for the CVE ids it names.)
### 1b. The 0.0 rows, as first found
Three are real CVE ids that CVE.org scores properly: CVE-2023-44487 → **7.5**, CVE-2023-4863 → **8.8**,
CVE-2022-22963 → **9.8**. So **CVE-2022-22963 sits in `monitor` on a fabricated 0 when decision-tree rule 3
(`cvss>=9.0`) should fire.** A real, live mis-prioritisation.
⛔ It is NOT safe to fix with a blanket rule: a 0.0 base score is publishable, and 682 rows predate
`cvss_source`, so "0.0 with no source is fake" would also condemn a genuine 0.0. The fix must be per-row and
evidence-based (an authoritative source publishing a different score), in the producing feed plus a
`lib/migrate.js` backfill. `cveorg`’s run summary already surfaces them as `suspicious_zero_scores`.

### 2. `nvd.js` never asks CIRCL for the score it actually has
CIRCL’s legacy per-CVE endpoint returns NVD’s own CVSS and is reachable while NVD itself is blocked; the
search endpoint SecVault uses does not carry it. This was the concrete path to filling the 255 missing scores.

⛔ **RE-MEASURE BEFORE WORKING THIS — the central CVE feed (v2.137.0) changed its premise.** The hub
publishes NVD-derived records straight into `advisories`, so some of those 255 may already be
scored, and the remaining gap may be a different set of rows entirely. The "255" is a 2026-09-10
figure taken before the hub existed. Count it again first; a fix sized against a number that has
moved is how effort lands on the wrong rows.

## Reporting platform — Phase D complete (2026-09-15, v2.123.0)

Nine reports registered in `lib/reports/catalogue.js`: Executive Security Posture, Rule Hygiene,
Vulnerability & Patch Posture, Compliance (fleet or one standard), Segmentation Posture, Lifecycle &
Support, Configuration Change Audit, VPN Access Review, Rule Change Request. All nine verified
building against the live fleet through the route's own dispatch shape.

Still deferred, deliberately:
- **Scheduling and delivery** (Phase C). Only the monthly compliance report is scheduled today, via
  its own `compliance_report_log` + `notification_channels` path. Generalising that to any report
  means a schedule table, a run history, and surfacing failures in the work queue.
- **Per-device VPN detections.** `getVpnDetections` has no device filter, so a device-scoped access
  review carries fleet-wide detections. Closing this is an engine change, not a report change.
- **Per-user destinations in the VPN review.** Not possible without a rollup schema change —
  `syslog_app_hourly`/`syslog_blocked_dst_hourly` carry no `src_ip`, and `syslog_events` is refused
  (no `src_ip` index, ~28M rows/day).
- **A render/page-load smoke harness.** There is still none. v2.120.0 shipped a blank `/reports`
  with every test passing and a clean build; the gap is covered today only by shape guards on what
  crosses into client components.

## Application-centric view — ⛔ PHASE 1 **BUILT** (v2.124.0); phases 2-4 still proposed

Full proposal: `.ai-codex/application-view-plan.md`. The one capability where both Tufin
(SecureApp) and AlgoSec (AppViz/BusinessFlow) ship a real product and SecVault has nothing.

The thesis, and the reason it is worth building here: **their application map is DECLARED and never
re-verified** — accurate the day it is typed, decaying silently after, with no statement of what it
could not check. Ours would be a declaration re-evaluated against the collected rulebase on every
pull. That is `/segmentation`'s pattern moved from zone granularity to flow granularity, so most of
it is assembly: `objectResolver.queryAccessPath()` already takes exactly the (src, dst, proto, port)
tuple a flow is, and is already reused unchanged by `topology.js` and `exposure.js`.

⛔ **Three hard limits established by measurement, not assumption** (detail in section 4 of the
plan):
1. **No syslog rollup carries both flow endpoints** — every one is source-keyed or
   destination-keyed. So "did this FLOW carry traffic" is unanswerable today; only "did the RULE
   permitting it see traffic" is, and Phase 1 must use the weaker words. `syslog_events` is refused
   as a fallback for the same reasons VPN traffic attribution refuses it.
2. **`syslog_rule_hits_hourly.source_ip` is the FIREWALL, not the session source** — 20 distinct
   values over 7 days against `syslog_talker_hourly`'s 77,416. Nothing consuming it today is wrong;
   the name is the trap. Documented in `lib/schema.sql` in the same commit as this plan.
3. **Topology collection covers 2 of 6 vendors**, so a flow crossing the others is UNVERIFIED —
   ⛔ never "broken".

Recommendation was **Phase 1 only** (declared applications + rulebase verification + orphan-rule
coverage), then reassess against the live fleet. **That is now shipped** — `applications` /
`application_flows`, `lib/engines/applicationView.js` (pure) + `applicationViewData.js`,
`/api/applications/**` gated on `OPERATE`, the `/applications` page, and a tenth work-queue
source. Two departures from the plan, both deliberate and both written up in CLAUDE.md:

1. **`queryAccessPath()` could NOT be reused.** The plan called it "the load-bearing one"; it
   requires src/dst to be SINGLE /32 addresses and throws otherwise, and a declared flow is almost
   never a point. The engine does exact range decomposition instead, reusing that file's
   `resolveAddressField`/`resolveServiceField` — the genuinely hard part — unchanged.
2. **Multi-hop is not modelled.** Each device is evaluated independently and volumes are NEVER
   unioned across devices, so §4.3's "topology covers 2 of 6 vendors" does not bite Phase 1 at all.

⛔ **PHASE 2 IS BUILT (v2.129.0) — this paragraph said "still open, unchanged" for it through
nineteen versions.** Rule impact (`IMPACT_CLAIM`, one claim, pinned by a test that rejects the
words *safe*, *reachable*, *unused* and *guarantee*) and retirement (which PROPOSES through the
existing `ruleChangeRequests` loop and never deletes) both shipped. ⛔ Neither can CONCLUDE on this
fleet today — 14 of 16 firewalls carry rules referencing an address or service the device never
reported, so impact reads "cannot tell" for all 29 touched rules and retirement proposes 0 of 29.
That is the correct behaviour and the fix is COLLECTING THE MISSING OBJECTS, not loosening either
engine.

Still open: **Phase 3** (a `syslog_flow_hourly` rollup — a storage decision dressed as a feature,
to be argued on its own measured cardinality) and **Phase 4** (discovery). Phase 1 remains the live
thing to reassess against the fleet — note that with nothing declared the honest answer is "no
items", which is what the work-queue source returns.
