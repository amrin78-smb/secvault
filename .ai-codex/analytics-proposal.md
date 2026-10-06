# Analytics without an LLM — **A1-A5, A7 AND A8 BUILT**, A6/A9 proposal only

⛔ **THIS TITLE READ "PROPOSAL, mostly NOT BUILT" AFTER FIVE OF THE NINE HAD SHIPPED.** That is
the error this repo pays for most: a stale "not built" sends a session off to rebuild working
code, and this very file records the same mistake being made about `objectUsage.js` in its own A4
section. The tracking table below is the answer to "what is built"; the per-item sections that
follow are the ORIGINAL PROPOSAL TEXT, kept as the design record, and a built item says so in its
heading. For what actually shipped read `roadmap.md`'s `## Already built`, then `pages.md` and
`lib.md`.

**Raised 2026-09-25.** Every figure here was measured against the live fleet on that date with the
read-only role; none is estimated. Re-measure before acting on any of them — the SQL is in the
appendix at the bottom for exactly that reason.

⛔ **Read `roadmap.md`'s `## Already built` and `### ⛔ Deliberately NOT doing` before adding to
this file.** Three of the ideas below were nearly written as new and are not: threshold/anomaly
alerting is already `roadmap.md` Tier 1 #2, bandwidth forecasting is already Tier 2, and a general
flow-grain rollup was MEASURED AND REFUSED on 2026-09-22 (`roadmap.md`, "`syslog_flow_hourly` — THE
PROPOSED SHAPE IS REFUSED"). What this file adds to those is measurement, not a new proposal.

---

## Tracking table — start here

Tick `Done` in the SAME commit as the work, per `roadmap.md`'s own rule. `[ ]` not started ·
`◨` partial · `✅` done (shipped in a released version) · `⧖` **built and in the tree but NOT
RELEASED** — no version bump, no `releaseNotes` entry.

⛔ `⧖` is not a courtesy state. `[ ]` would send a session to rebuild it; `✅` would have someone
look for it in a release that does not carry it. Both are wrong in a way that costs work.
⛔ **Nothing carries `⧖` today** — A7 held it and shipped in v2.191.0. The state stays defined
because the next unreleased item will need it.

| # | Item | Tier | Effort | New table? | Done |
|---|---|---|---|---|:--:|
| A1 | **Upgrade planner** — collapse 246 assessments into ~16 upgrade decisions | 1 | S | no | ✅ v2.187.0 |
| A2 | **Blind-spot register** — which devices look healthy because we cannot see them | 1 | S–M | no | ✅ v2.188.0 |
| A3 | **Log-derived rule usage** — a second evidence source for `hit_count` | 1 | M | no | ✅ v2.189.0 |
| A4 | **Object & rule consolidation** — exact set algebra, needs no hit counts | 2 | M | no | ✅ v2.190.0 |
| A5 | **Fleet conformance / odd-one-out** — discovers checks the 45-check library lacks | 2 | M | no | ✅ v2.190.0 |
| A6 | Seasonal baselines — **NOT a new item**, it is `roadmap.md` Tier 1 #2. See §A6 for why it cannot arm yet | — | — | — | [ ] |
| A7 | **Change → outcome correlation** — the most differentiating; it built its OWN control rather than waiting on A6 | 3 | M–L | no | ✅ v2.191.0 |
| A8 | **Remediation velocity (survival)** — its honest output is an indictment, and that is the point | 3 | S | no | ✅ v2.192.0 |
| A9 | **VPN behavioural profiles** — 608 users, 38 days; gate PER USER, and only 34% of users have a usable baseline | 3 | M | no | [ ] |

⛔ **No new table is required for anything in this file.** Every item is read-time over data already
collected, which is also why none of them may store a verdict — the same rule `/segmentation` and
`/applications` already follow.

---

## ✅ A1 BUILT (v2.187.0) — and the design rule it needed was not in the proposal

Live: **246 open assessments across 16 firewalls -> 16 upgrade decisions**, 27 unplannable.

⛔ **THE PROPOSAL MISSED THE ONE RULE THAT MATTERS.** It said "take the Pareto frontier — the
lowest version clearing the most weighted risk". Implemented literally, that told three FortiGates
running 7.4.9 to go to **7.6.7** — a platform migration — because it cleared 8 where the in-branch
7.4.12 cleared 3. Both numbers correct, the advice wrong. `inBranch` and `crossBranch` are separate
fields and the in-branch option is recommended EVEN WHEN a branch move clears more. A ranking
proposal is not a recommendation design; that only showed up against real versions.

## The finding that should shape the ordering

The expected answer to "what intelligent analytics can we build" is *anomaly detection*. The
measurements say otherwise.

⛔ **SecVault's analytics are not bounded by algorithms. They are bounded by EVIDENCE COVERAGE, and
the gaps are uneven, measurable, and mostly closable.** So the ordering is: first turn existing
findings into decisions (needs no new evidence), then measure and close the coverage gaps, and only
then statistical detection — which on this fleet cannot arm for another week or two regardless.

Measured 2026-09-25, 16 devices:

| | |
|---|---|
| `firewall_rules` | 1,782 — **235 unmeasured** `hit_count`, 446 measured-zero, 1,101 with hits |
| of those 235 | **181 are Fortinet**; all five Fortinets are 100% unmeasured. **TUG** is the only Palo Alto like it (54 of 54) |
| `network_objects` | 10,092 defined, **3,298 (33%) referenced by no rule and no group**, and **2,989 rule references resolve to no object** |
| syslog coverage | **15 of 16 devices.** PAKFood is fully collected (33 rules, 17 CVE assessments, 24 audit findings, 17 interfaces, collected same day) and sends **zero** log events |
| `device_versions` | 3,727 rows, 16 devices, **0 version changes in 70 days**. Re-measured 2026-09-28: 3,954 rows, still **0 changes in 74 days** — see §A8, now built |
| `fleet_dashboard_snapshots` | 55 rows over 69 calendar days — **14 missing days** |
| hour-of-week baseline | **2.4 weeks**, 405 distinct hours — below the 3 weeks a seasonal model needs. Re-measured 2026-09-28: **2.86 weeks / 481 hours**, crossing the gate 2026-09-29 — see §A6 |
| `audit_findings` | 181 pass / 165 fail / 39 `na` / 19 warning → scorePct **49.6%** |
| `rule_analysis_results` | 1,164 across 11 types |

⛔ **Two of those are not "data quality", they are the product lying by omission today.** PAKFood
has no traffic evidence of any kind, and every Fortinet has no rule-usage evidence — yet both
render beside fully-evidenced devices with nothing saying so. That is this codebase's signature bug
at fleet scale, which is why A2 is Tier 1 rather than a nicety.

---

## What "intelligent" means here

Inference nobody typed in, by a method that can be shown on screen. The product already does this —
the priority decision tree, segmentation verdicts, `applicationView`'s box decomposition. The
palette, all implementable in plain Node with **zero dependencies** (`package.json` has no
`devDependencies` and `npm ci` ships to a firewall box — that constraint is not negotiable):

set & interval algebra · graph traversal · robust statistics (median/MAD, CUSUM, Theil–Sen) ·
survival analysis with right-censoring · information theory · canonical-key grouping ·
association lift · Pareto frontiers · growth extrapolation with stated error bars.

⛔ **Deliberately excluded: k-means and anything with random initialisation or a trained
artefact.** Not because it is "AI" — because a verdict that changes between runs on identical data
cannot be defended to a customer, and defensibility is the entire product thesis.

---

## ✅ BUILT v2.187.0 — A1 — Upgrade planner *(Tier 1, small, highest value-to-effort here)*

*Original proposal text. Shipped as `/vulnerability?tab=upgrade`, `lib/engines/upgradePlan.js` +
`upgradePlanData.js`. Read the ✅ A1 note above first — it records the one rule the proposal below
got wrong.*

**The question: what single action clears the most risk on this firewall?**

`/vulnerability` lists 246 assessments. Measured: **every Palo Alto device carries 17 open
advisories across 7 distinct target versions** — so one upgrade to the highest target clears all
17. The three Fortinet TSR devices: 7 advisories, 5 targets. Sixteen devices, sixteen decisions.

**Method.** Per device, for each candidate target in `device_cve_assessments.fixed_in`, count the
advisories that target clears using the vendor's own comparator (`versionComparator.js`, unchanged).
Take the Pareto frontier — the lowest version clearing the most weighted risk — and rank devices by
risk cleared per upgrade.

⛔ **30 of 246 assessments carry NO fix version, and that includes ALL THREE `patch_now` rows.**
Live: **CVE-2026-24858**, CVSS 9.4, KEV-listed, on TSR_EKC / TSR_EKM / TSR-TL, `fixed_in` NULL,
`matchability` = `matched`. The fleet's only urgent CVEs are currently un-actionable. That gets its
own counted `no_known_fix` bucket at the TOP of the output, never folded into "everything else" and
never omitted — a planner that quietly dropped what it could not plan would hide the single most
important thing it knows. (Likely cause: FortiGuard's advisory pages are Cloudflare-challenged, so
the vendor's own fix version is never collected. See `roadmap.md` / CLAUDE.md on the block.)

⛔ **It ranks, it does not schedule.** A target version that clears the most CVEs may be a release
the customer will not run. The output is evidence for a decision, not the decision.

`lib/engines/upgradePlan.js` (pure) + `upgradePlanData.js`. Read-time.

---

## ✅ BUILT v2.188.0 — A2 — Blind-spot register *(Tier 1, small–medium)*

*Original proposal text. Shipped as `/coverage`, `lib/engines/coverageRegister.js` +
`coverageRegisterData.js`, and work-queue source #11 (`coverage`, which can never reach
`act_now` — every item is `unmeasured` by construction). Live: 0 of 16 devices fully covered.*

**The question: which devices look healthy because SecVault cannot see them?**

This is the `verify` band of the work queue generalised to the fleet, and it has live hits today:

| device | the gap, measured | the consequence nothing currently states |
|---|---|---|
| **PAKFood** | 0 syslog buckets; 77 of 77 object references unresolvable | no `log_hit`, no traffic verdicts, no segmentation "DID" evidence, and `/applications` cannot conclude |
| **all 5 Fortinets** | 100% unmeasured `hit_count` (30/30, 8/8, 27/27, 38/38, 78/78) | `unused` can never fire — while these are the **highest-logging devices on the fleet** (5,573–11,676 buckets each) |
| **TUG** | 54 of 54 unmeasured, the only Palo Alto so affected | a per-device collection regression nothing reports |
| **TSR_EKC / TSR-TL** | 40/40 and 22/22 object references unresolvable | blocks application impact + retirement, per CLAUDE.md |
| **`fleet_dashboard_snapshots`** | 14 missing days of 69 | any trend line over it interpolates across gaps silently |

**Method.** A device × evidence-source matrix, each cell carrying a derived consequence sentence
rather than a bare count ("no hit counts → `unused` cannot fire here → 38 rules cannot be assessed
for cleanup").

⛔ **It must rank by CONSEQUENCE, not by gap size.** A device missing one evidence source that
gates five engines outranks one missing three that gate nothing. Otherwise it becomes a
completeness checklist nobody works.

`lib/engines/coverageRegister.js`. Read-time, no new table.

---

## ✅ BUILT v2.189.0 — A3 — Log-derived rule usage *(Tier 1, medium)*

*Original proposal text, and all three honesty rules below were kept. Shipped as an ADDITIVE
grade on `ruleHitCorrelation.js`, `components/analysis/UsageGrade.js`, the `Hits` column on
`/devices/[id]/rules` becoming `Usage`, and the grade carried into the change-request document.*

**The question: can the syslog already stored close the hit-count gap?**

Partly — and the split is vendor-specific in a way that is not recorded anywhere else:

| | rows | distinct rule **id** | distinct rule **name** |
|---|---|---|---|
| Palo Alto | 78,733 | **0** | 223 |
| Fortinet | 61,193 | 44 | 47 |

⛔ **PALO ALTO LOGS CARRY NO RULE ID AT ALL** (78,733 rows, every one NULL). `roadmap.md`'s
"Already built" row reads *"Rule-hit correlation from logs (Phase 8b) — 8,803 rule-hit rows, all 15
devices"*, which is true and reads as fleet-wide coverage. By rule ID it is **Fortinet only**.

Of the 235 unmeasured rules: **54 Fortinet match a log rule-id**, and **30 Palo Alto match by name
only** — ~84 of 235 (36%) gain usage evidence, and for Fortinet logs are the *only* possible source.

⛔ **Three honesty rules, all load-bearing:**
1. **This never writes into `hit_count`**, which means "what the DEVICE reported". It is a separate
   `usage_evidence` field carrying its own provenance.
2. **ID-match and NAME-match are different grades.** Rule names are neither unique nor stable
   across a config change. A name match may not authorise a deletion, and the `ruleChangeRequests`
   evidence bar accepts only the ID grade.
3. ⛔ **Absence from logs is NOT a measured zero.** The window is 16.8 days and Palo Alto logs carry
   no rule id at all, so "not seen" stays `unmeasured`. Inverting that would manufacture deletion
   candidates out of a logging gap — the exact failure `hit_count`'s tri-state exists to prevent.

Reuses `ruleHitCorrelation.js`'s existing tri-state rather than re-deriving it; two files deciding
"is this rule in use" would eventually disagree and the wrong one would be recommending deletions.

---

## ⛔ A4 CORRECTION — HALF OF IT WAS ALREADY BUILT (measured 2026-09-25)

The section below reads as though object consolidation needs building. **It does not.**
`lib/engines/objectUsage.js` has existed since 2026-08-03, runs after every object collection, and
holds **4,297 `unused` + 1,361 `duplicate` findings across 13 devices** in `object_analysis_results`,
refreshed 2026-09-24. It already does transitive group closure, and it is already namespace-
partitioned (a 2026-07-18 fix, because an address object and a service object may share a name).

⛔ **A stale "not built" is the costliest kind of index error** — CLAUDE.md says so about Phase 8b,
and this file reproduced it. Anyone acting on the table below without checking would have rebuilt a
working engine.

What was ACTUALLY missing, measured:

| | |
|---|---|
| `nat_rules` as a reference surface | **NOT counted** — 155 NAT rules across 15 devices |
| objects reported `unused` that a NAT rule references | **11**, across 6 Palo Altos |
| rule consolidation (any field) | **does not exist at all** |

Each of those 11 is a suggestion to delete an object NAT depends on.

⛔ **AND THE RULE-CONSOLIDATION COUNTS BELOW OVER-COUNT — INCLUDING MY OWN FIRST PASS AT THEM.**
A quick `GROUP BY` over zones/addresses/services gives ~181 removable rows. The real figure is
**156**, because the canonical key must ALSO include `applications`, `log_enabled`, `nat_enabled`,
`schedule` and `expiry_date`. Measured incrementally on the live fleet for the SERVICE case:
zones-only 46 groups/69 rows → **+applications 10/13** → +schedule/expiry/log/nat 9/11.

`firewall_rules.applications` is the vendor L7 app-ID — a **matching constraint, not metadata**.
Two rules differing in service AND in app-ID are not one rule written twice, and merging them
changes what the firewall matches. Same for the other four: merging a logged rule with an
unlogged one silently changes what is recorded.

Live result from the real engine: **92 groups / 156 removable rows — 41 `safe_to_merge` (55 rows),
51 `needs_review` (101 rows)**, in 272 ms over 1,782 rules. `needs_review` dominating by rows is
the honest outcome, not a bug.

---

## ✅ BUILT v2.190.0 — A4 — Object & rule consolidation *(Tier 2, medium)*

*Original proposal text — read the A4 CORRECTION immediately above it first: the OBJECT half was
already built. Shipped as `lib/engines/ruleConsolidation.js` + `ruleConsolidationData.js`, the
Consolidation tab on `/devices/[id]/analysis`, and `nat_rules` counted as a reference surface in
`objectUsage.js`.*

Exact set algebra. ⛔ **Needs NO hit counts**, which makes it the one cleanup analytic that is
CONCLUSIVE on Fortinet, where every other one is blocked.

| measured | |
|---|---|
| objects referenced by no rule and no group | **3,298 of 10,092 (33%)** |
| duplicate objects (same value, different name, same device) | **582 groups, 771 redundant** |
| rules identical but for DESTINATION | 79 groups, **115 removable** |
| rules identical but for SOURCE | 90 groups, **198 removable** |
| rules identical but for SERVICE | 69 groups, **92 removable** |

⛔ **This is NOT the existing `generalization` finding type.** That is a PAIRWISE SUBSUMPTION
relation (rule S covers rule R) and it lives in `PAIRWISE_FINDING_TYPES`, which is **O(n²) and
capped** — so it is skipped entirely on a large ruleset (IDC FW has 721 rules). Consolidation is
O(n) canonical-key grouping and works at any size. Check `ruleAnalysis.js` before extending either.

⛔ **A consolidation candidate is NOT proven safe.** Merging two rules that are not adjacent in
`sequence_number` changes semantics if any rule between them matches the same traffic. The engine
must test for intervening interference and downgrade to "candidate — needs review" when it cannot
prove non-interference. ⛔ And it **proposes through the existing `ruleChangeRequests` loop**, which
already verifies against the re-collected ruleset. No second verifier, no "mark as done".

⛔ **"Referenced by nothing" is not "safe to delete" either** — an object may be referenced by a
config path this product does not parse. It is a review list.

---

## ⛔ A5 MEASUREMENT — THE COHORT IS `(vendor, mgmt_method)` (measured 2026-09-25)

The section below says "for each (vendor, config path)". **Grouping by VENDOR ALONE would have made
this a false-finding machine on its first run**, which is the exact failure its own ⛔ rule warns
about:

**TUG is the only Palo Alto collected over SSH.** Its parser emits an entirely different structure
(`tree`/`hostname`/`sw_version`) from the ten on the API (`devices`/`shared`/`mgt-config`), so
grouped by vendor it deviates on essentially EVERY path — and every one of those findings is false.
The real fact is "it was collected a different way". Live cohorts: `paloalto/api` 10 ·
`fortinet/ssh` 5 · `paloalto/ssh` **1** (which must, and does, yield nothing).

**Depth 3, measured.** Fortinet plateaus at 377 paths at any depth; Palo Alto averages 55/65/78/152
at depth 2/3/4/6 while `present-on-exactly-1` grows 14→17→40→97 against `all agree` 46→48→50→75
— **noise outpaces comparable ground ~3:1 with depth.**

**The signal is real.** At depth 3, same path present everywhere and values disagreeing:
`fortinet/ssh` **21 findings**, `paloalto/api` **4**. Examples: `dns.protocol` 4× `dot` vs OKF(F2)
`cleartext`; `global.admin-https-redirect` 4× `enable` vs OKF(F2) `disable`;
`system_info.device-certificate-status` 8× `Valid` vs HRIS + PAKFood `None`. **OKF(F2) is the
minority in 10 of the 12 strongest** — one firewall built to a different standard, which is exactly
the insight this analytic promises.

⛔ **AND THE PROOF OF ITS OWN CENTRAL RULE IS IN THAT LIST.** `global.admin-ssh-port` is 4× `22`
against OKF(F2)'s `5022` — OKF is the ONLY firewall not on the default SSH port, i.e. the HARDENED
one, and the majority is the weaker configuration. Reporting the deviation is right; calling it
misconfigured would be exactly backwards.

⛔ **Device-IDENTITY paths must be excluded** or they manufacture guaranteed-useless findings:
`system_info.netmask` fires 9v1 on HRIS, and every firewall legitimately has its own management
address.

---

## ✅ BUILT v2.190.0 — A5 — Fleet conformance / odd-one-out *(Tier 2, medium)*

*Original proposal text — read the A5 MEASUREMENT immediately above it first: the cohort is
`(vendor, mgmt_method)`, NOT vendor, and grouping by vendor alone would have made this a
false-finding machine on its first run. Shipped as `/conformance`,
`lib/engines/fleetConformance.js` + `fleetConformanceData.js`.*

**The question: which device is configured unlike its peers?**

11 Palo Altos and 5 Fortinets, all with `config_parsed`. For each (vendor, config path), build the
value distribution and flag small minorities: *"10 of 11 Palo Altos set X; ITC-SK does not."*

⛔ **The only proposal here that DISCOVERS checks rather than evaluating curated ones.** The
45-check library is hand-written and finite; conformance finds deviations nobody thought to encode.

⛔ **MAJORITY IS NOT CORRECTNESS, and this rule is absolute.** The output is "1 of 11 differs",
never "misconfigured". The one device may be the only correct one. It is a triage lens and must be
labelled as one, or it becomes a machine for generating confident false findings at fleet scale —
strictly worse than the gap it closes, on a product whose pitch is that it does not assert without
evidence.

⛔ Needs **depth and cardinality bounds** on path enumeration before it touches a 721-rule device.

---

## ◨ IN PROGRESS — A6 — Seasonal baselines: NOT a new item

⛔ **THE ARMING GATE IN THIS SECTION IS WRONG, AND THE HARNESS PROVED IT (2026-10-05).** It gates on
"≥3 weeks for a 168-bucket hour-of-week model", crossed 2026-09-29. Three weeks is ~3 observations
per bucket, and **three observations cannot support a tail threshold**: to place two observations
above a quantile q you need `2/(1-q)` of them — 40 for q=0.95, 200 for q=0.99. The honest gate is
OBSERVATIONS PER BUCKET measured against the chosen threshold, which is what
`lib/engines/seasonalBaseline.js`'s `minObservationsFor()` implements.

Measured on this fleet's own span (~649h, 3.9 weeks):

| grain | buckets | obs/bucket | highest supportable q | FP per bucket |
|---|---:|---:|---:|---:|
| hour-of-week (the proposed grain) | 168 | 3.9 | — | **unusable** |
| hour-of-day × weekday/weekend | 48 | 13.5 | 0.852 | 14.8% |
| hour-of-day | 24 | 27.0 | 0.926 | 7.4% |

⛔ **SO THE PROPOSED GRAIN NEEDS ~40 WEEKS, NOT 3**, and a gate counting weeks would have armed it
anyway on a baseline that cannot support its own threshold. `selectGrain()` picks the finest grain
the data actually supports and **upgrades itself** as history accumulates, with no code change —
verified: 4 weeks → hour-of-day, 45 weeks → hour-of-week.

⛔ **PERSISTENCE IS WHAT MAKES THE FEATURE SURVIVABLE, AND THE ARITHMETIC SAYS SO.** 16 devices ×
168 hours = 2,688 device-hours/week, so a 5% per-bucket rate is ~142 false alerts a week — exactly
how `new_finding` got pulled from the Alerts feed in July. `scripts/a6Harness.js` measures both
false positives AND sensitivity against PLANTED anomalies (a detector that never fires has a perfect
FP rate and is useless) and the synthetic sweep is unambiguous:

| config | false alerts/day | planted events found |
|---|---:|---:|
| hour-of-day q=0.95 **persist=1** | 20.65 | 100% |
| hour-of-day q=0.95 **persist=2** | 1.17 | 100% |
| hour-of-day q=0.975 **persist=3** | **0.02** | **100%** |

Single-bucket rules are unusable at any quantile; persistence collapses them without costing
sensitivity.

### ✅ STAGE 2 BUILT, 2026-10-06 — two detectors, and two REFUSED on measurement

`lib/engines/anomalyDetections.js` (pure) + `anomalyDetectionsData.js` (plumbing), dispatched as
**one alert type per detector**.

| detector | measured | shipped |
|---|---|:--:|
| **device stopped logging** | **0.074 alerts/day** — 16 silent device-hours in 9,720 (0.16%) over 27 days, in exactly TWO runs (3h, 13h): silence here is rare AND clustered | ✅ |
| **denied traffic above normal** | **2.48 alerts/day, 100% sensitivity** — hour-of-day, q=0.90, 3 consecutive hours | ✅ |
| total-events spike | 6.91 alerts/day at the best configuration the data supports | ❌ |
| VPN auth burst | 3.32/day, **and 33% of control buckets fired against the ~10% a 0.9 quantile can produce** | ❌ |

⛔ **THE VPN REFUSAL IS A DIAGNOSIS, NOT A TUNING FAILURE.** That 33%-vs-10% gap is DRIFT: VPN auth
failures rose **~7x over the window** (mean per row 1 → 3 → 5 → 5 → 7 by week) while denied traffic
stayed flat. A STATIC seasonal baseline is the wrong instrument for a trending metric and a looser
threshold would not fix it. ⛔ **The trend is itself worth someone's attention** and is a live
observation about this fleet, not a modelling note.

⛔ **AN UNMEASURED DETECTOR CANNOT BE REGISTERED.** `assertRegisteredDetector()` throws at module
load unless `EVIDENCE[key]` carries an alert rate, a sensitivity (or a stated reason it does not
apply), a date and a method. Adding either refused candidate back needs a harness run, not a
judgement call.

⛔ **THE SILENCE DETECTOR NEEDS NO BASELINE AT ALL**, and is the one the rest of the product most
needs: a firewall that stopped reporting contributes no CVEs, no failing checks and no rule
findings — CLAUDE.md's own words, it "renders as the healthiest device on the fleet". ⛔ A device
that has **never** reported is `no_data`, never "stopped" — that is an uncollected device, a
different fact with a different owner.

⛔ **THE BASELINE EXCLUDES THE JUDGED WINDOW.** An anomaly inside its own baseline raises its own
threshold. Measured boundary: masking begins once the anomaly exceeds **(1−q)** of a bucket's
observations — at q=0.9, 5% and 9% are still found, 11% FRAGMENTS (7 runs instead of 1), 15% and
25% are fully MASKED. The default 24h window against 28 days is **3.6%**, so the default is safe by
a wide margin; a caller raising `judgeWindowHours` is not, and a test pins that.

⛔ **THE TOGGLE GATES DISPATCH, NEVER DETECTION**, one type per detector via
`notification_channels.alert_types[]` — no new env var, no new page. Muting denied-traffic must not
mute a firewall going dark. Deliberately the OPPOSITE call from `work_act_now`, which collapses
twelve sources into one: there the sources share a vocabulary, here each detector measures a
different fact with its own measured rate.

⛔ **MARGINS ARE SMALL AND ARE STATED.** Live findings ranged from 0.4% to 1025% above the
threshold (median 7%, p25 3.2% over 31 runs in 28 days). A 10% floor would discard 71% of runs and
is NOT applied — it is a second knob, unmeasured against sensitivity. Instead the alert prints its
own margin, with a decimal below 1% so a real exceedance can never render as "0% above it". The
small margins are the expected cost of q=0.90, which is all 4 weeks of history supports; q=0.95
becomes reachable ~2026-10-25 and `selectGrain()` adopts it with no code change.

---

### ✅ ON-SCREEN SURFACE, 2026-10-06 — `components/alerts/AnomalyPanel.js`

⛔ **STAGE 2 SHIPPED WIRED TO DISPATCH ONLY, AND THAT WAS A GAP, NOT A PHASE.** Detection ran every
15 minutes and the findings went nowhere unless a channel subscribed — and the reference fleet has
**zero notification channels configured**, so two real silences (15h, 13h) and three denied-traffic
exceedances were computed and discarded on every cycle. A product that measures something and shows
nobody is indistinguishable from one that never measured it.

It renders on **`/alerts`**, beside the feed and deliberately NOT in it: the feed is a paginated SQL
UNION over stored, acknowledgeable rows, while an anomaly finding is computed at read time, has no
row and nothing to acknowledge — the same "no stored verdict" call `/segmentation` and
`/applications` make. No new sidebar entry.

⛔ **COVERAGE IS RENDERED, NOT JUST FINDINGS.** Each detector reports how many firewalls it judged
versus could not, hatched and hueless, because "no findings" and "could not look" are the same empty
list. ⛔ **`"Nothing needs attention."` WAS UNCONDITIONAL AND BECAME A LIE** — it spoke for the whole
page while the panel above it could be reporting a firewall that stopped logging 15 hours ago. It
now speaks only for the feed it belongs to.

⛔ **THREE DEFECTS SURVIVED A CLEAN BUILD AND 5,778 PASSING TESTS; LOADING THE PAGE CAUGHT ALL
THREE.**
1. `<TimeAgo date={...}>` where the prop is `value` — every finding rendered **"started —"**, the
   NOT-MEASURED em-dash over a timestamp measured exactly. The inversion this product exists to
   refuse, shipped by a one-word prop name.
2. The subtitle edit silently did nothing: a line-based script inserted above its own target and
   then wrote to a stale index, reporting success. A no-op that announced itself as a change.
3. The silence link pointed at `/logs`, which needs `view_log_search` — a capability `operator` does
   NOT hold, while `/alerts` is gated on `OPERATE`. A dead link for exactly the role most likely to
   be reading it. Now the device page.

⛔ **AND THE SMOKE MARKER WAS ADDED TO THE WRONG FIELD FIRST.** `markers` is an **OR**, so the feed's
existing marker satisfied it while the panel rendered nothing — verified by deleting the panel and
watching the sweep still report `ok /alerts` at 33,556 bytes instead of ~63,000. `alsoMarkers` is the
**AND** that exists for precisely this shape, and the file says so. With it the sweep fails:
*"a REQUIRED second section did not render — one section of this page is blank"*.

---

### ✅ MEASURED ON THE LIVE FLEET, 2026-10-05 — the method is picked

Harness run against production `syslog_rollup_hourly` (read-only, rollups only), 15 devices,
646 hours, metric = denied traffic per device-hour:

| grain | q | persistence | fired/bucket | alerts/day | planted events found |
|---|---:|---:|---:|---:|---:|
| hour-of-day | 0.90 | 1 | 8.0% | 15.39 | 100% (15/15) |
| hour-of-day | 0.90 | 2 | 8.0% | 5.96 | 100% (15/15) |
| **hour-of-day** | **0.90** | **3** | 8.0% | **2.48** | **100% (15/15)** |

Everything else in the sweep reports `insufficient_baseline` — including every hour-of-week row,
as predicted.

⛔ **THE MEASURED RATE IS 13x WHAT INDEPENDENCE PREDICTS.** At an 8% per-bucket rate a 3-hour
persistence rule should give `0.08³ × 24 × 15 = 0.18` alerts/day. The real figure is **2.48** —
because firewall traffic is AUTOCORRELATED: an anomalous hour is far more likely to be followed by
another. This is precisely why the threshold is measured and not computed, and it is the same class
of error that made A7 discard median+MAD.

⛔ **"alerts/day" IS AN ALERT RATE, NOT A FALSE-POSITIVE RATE.** A7 could measure false positives
because it had LABELS (days with no config change are known-change-free). A6 has none, so some of
those 2.48 may be real. It is an UPPER BOUND, and the number that matters operationally anyway.

⛔ **A HARNESS BUG PRODUCED A CONFIDENT FALSE CONCLUSION FIRST, AND THE SHAPE OF THE RESULT IS WHAT
GAVE IT AWAY.** Planting was multiplicative on the existing value, and **30.7% of device-hours have
ZERO denied events** (2,962 of 9,654) — so a third of planting sites were undetectable by
construction, and with 3-hour persistence any window touching one could never fire. Sensitivity
barely moved with magnitude (57% at 3x, 42% at 6x, 41% at 10x), which is not how a threshold
detector behaves. Reported as-is it would have been a damning finding about the DETECTOR that was
really a finding about the HARNESS. Planting is now additive against the device's own normal level,
which is what a real scan looks like; sensitivity went to 100%.

⛔ **q=0.95 IS NOT REACHABLE YET AND WOULD BE BETTER.** It needs 40 observations/bucket = 960h of
TRAINING data (5.7 weeks); the fleet has 646h total. Reachable around **2026-10-25**, and
`selectGrain()` will adopt it with no code change.

⛔ **THE 0.85 TRAIN SPLIT IS A HARNESS ARTEFACT, NOT A SETTING.** A holdout is needed to measure;
in production the baseline uses all history and judges each new hour as it arrives. At a 0.7 split
nothing qualified at all — 18.8 observations/bucket against the 20 needed, short by 1.2.

⛔ **THE SHIPPING THRESHOLD IS STILL UNCHOSEN.** The table above is SYNTHETIC — it proves the
harness can tell a good configuration from a blind one, nothing more. Real firewall traffic is what
falsified the last method, and only real rollups can pick. **Running the harness against
`syslog_rollup_hourly` on the live fleet is the next step and needs read access to it.**

---

### Original section, kept as the design record

This is `roadmap.md` **Tier 1 #2, "Threshold and anomaly alerting"**, already raised and unbuilt.
What this file contributes is the measurement that says when it can work, and one method constraint.

⛔ **IT CANNOT ARM TODAY — BUT IT IS ONE DAY AWAY. RE-MEASURED 2026-09-28**,
`syslog_rollup_hourly` spans **481 distinct hours = 2.86 weeks, 2.9 observations per hour-of-week
bucket** (it was 405 hours / 2.4 weeks when this file was raised on 2026-09-25). Collection started
2026-09-08, so the ≥3-week gate for a 168-bucket hour-of-week model is crossed on **2026-09-29**.
Build it **gated**, reporting `insufficient_baseline` with the baseline it needed and the baseline
that exists — exactly as the six VPN detections do, rendering hatched and hueless, never a green
all-clear. It then arms itself with no code change.

⛔ **THE "MEDIAN + MAD, NEVER MEAN + σ" CONSTRAINT BELOW HAS SINCE BEEN CONTRADICTED BY
MEASUREMENT, ON THIS DATA, BY A7.** A7 tested exactly that method — Iglewicz–Hoaglin's modified
Z-score at its own standard 3.5 — over the same rollups and against a CONTROL of ordinary,
change-free days. It flagged **17.3% of them** (worst device 42.1%), because firewall traffic is
heavy-tailed and **a ROBUST estimator is not a DISTRIBUTION-FREE one**; it was replaced by the
device's own empirical quantile, whose false-positive rate is `1 - quantile` by construction, and
measured **5.3%**. A6's grain is not A7's — hour-of-week LEVELS, not day-over-day DELTAS — so this
does NOT prove median + MAD wrong here.

⛔ **THE DECISION TAKEN: run A7's control harness against A6's grain and pick on the MEASURED
false-positive rate, rather than inherit a constraint already falsified once on this data.**
`lib/engines/changeOutcome.js` already exports `buildBaseline`, `median`, `quantile` and
`BAND_QUANTILE` for exactly that reuse — a second implementation of "what is normal for this
device" would eventually disagree with the first. Whichever wins, the baseline stays an input to a
NAMED threshold, never a magic anomaly score, which is the roadmap's own rule and is unaffected.

*Original method constraint, kept as the design record:* median + MAD, never mean + σ — firewall
traffic is heavy-tailed, a single spike poisons a mean, and the detector then under-reports for a
week.

⛔ **Highest-value detector when it does arm: a device that STOPS logging** — which is A2's finding
made continuous, and is why A2 should land first.

---

## ✅ BUILT v2.191.0 — A7 — Change → outcome correlation *(Tier 3, medium–large)*

⛔ **RELEASED IN v2.191.0.** `lib/engines/changeOutcome.js` + `changeOutcomeData.js` +
`components/analysis/ChangeOutcomeBoard.js`, rendered on `/devices/[id]/changes` above the change
list. This paragraph read "IN THE TREE, IN NO RELEASE" for a full release after the one that
carried it — corrected 2026-09-28. A stale "unreleased" costs the same as a stale "not built".

⛔ **AND IT DID NOT WAIT FOR A6.** The proposal below says this "requires A6's variance estimate,
which is why this is Tier 3". It does require a variance estimate — and it BUILDS ITS OWN, per
device, from the same daily series, rather than depending on a seasonal model that still cannot
arm. The dependency stated below did not hold; A6 remains unbuilt and was never a blocker.

⛔ **THE CONTROL IS THE FEATURE.** "Did this change actually change anything?" is only answerable
after ORDINARY day-to-day variation on the same device has been measured — without a control every
post-change delta looks meaningful. Measured 2026-09-27, same fleet, same window:

| | avg delta |
|---|---|
| 24h either side of a CONFIG CHANGE (61 changes) | **+13.6%** |
| 24h either side of an ORDINARY DAY (284 pairs) | **+17.6%** |

⛔ **THE CHANGE-ADJACENT DELTA IS SMALLER THAN THE NOISE.** Per-change deltas ran −92.1% to
+126.0% against a fleet p90 of absolute daily variation of 113.8% — every one of those 61
"effects" sits inside ordinary fluctuation. A naive build of this feature — compute the
before/after delta and print it — would have produced 61 plausible percentages and an operator
would have read causation into every one. So the engine reports no bare delta at all: it reports
a delta against that device's own measured variability, and its common answer is
`indistinguishable`.

⛔ **THE BAND IS PER DEVICE.** Measured p90 of absolute daily variation spans **23.2% (HRIS) to
284.3% (Vietnam-YCC)**, a 12x spread. One fleet-wide band would flag routine Vietnam-YCC
fluctuation as an effect AND miss a genuine change on HRIS.

⛔ **MEDIAN + MAD WAS TRIED, MEASURED WRONG, AND REJECTED — AND ONLY THE CONTROL REVEALED IT.**
The first version used Iglewicz–Hoaglin's modified Z-score at its own standard 3.5 threshold:
robust, published, and the correct answer to the mean+σ trap the A6 section below warns about.
Against the control it flagged **49 of 284 ordinary, change-free day-pairs — 17.3%** (worst
device 42.1%). A detector that fires on one ordinary day in six manufactures effects from noise,
which is precisely the failure this engine exists to prevent, reached by a correct-looking robust
statistic. ⛔ The cause: 3.5 assumes approximately normal data while these deltas are
heavy-tailed (medians 2.4%–30% against p90s of 23%–284%), so MAD measures a tight core the tail
routinely clears — **a ROBUST estimator is not a DISTRIBUTION-FREE one.** Replaced with the
device's own EMPIRICAL QUANTILE (`BAND_QUANTILE = 0.95`), whose false-positive rate is
`1 - quantile` BY CONSTRUCTION rather than by hope; measured 5.3%. Median and MAD are still
computed and reported, as DESCRIPTION only, and must never decide anything.

⛔ **AND THE RESOLVED BANDS ARE WHY A SINGLE FLEET-WIDE NUMBER CANNOT WORK.** Measured on the
live fleet after the v2.191.0 deploy, each device's own band: HRIS **±29.2%**, ITC-SLY ±144.8%,
SMT ±151.6%, OKF(F2) ±159.0%, ITC-SK ±185.4%, IDC FW **±344.9%** — a **12x spread**. A constant
picked anywhere in that range is simultaneously far too tight for IDC FW, where a doubling of
traffic is an ordinary Tuesday, and far too loose for HRIS, where it would hide everything short
of a 3x move. ⛔ So the per-device band is not a refinement of a global threshold that could be
simplified back into one later; there is no single value it is approximating.

First full run after that deploy: 16 devices, 0 failures, **203 changes judged — 66
`indistinguishable`, 137 `window_incomplete`, and 0 `exceeded_normal_variation`.** The zero is
the intended shape of an honest answer, not a broken detector: nothing on this fleet currently
moves outside its own ordinary variation, and `window_incomplete` dominating simply says the
rollup history is still shorter than most changes need. ⛔ **PAKFood reports
`insufficient_baseline`** — it is the fleet's zero-syslog firewall, the same device the A2
blind-spot register exists to name, so the two features agree about it instead of one of them
quietly scoring it as calm.

Other constants: `MIN_BASELINE_PAIRS = 10`; `DEFAULT_WINDOW_HOURS = 24`, ⛔ **not a tuning knob**
— 61 changes have a complete 24h window either side and only 18 have 7 days, so widening it buys
precision by discarding most of the subject.

⛔ **SIX VERDICTS, AND `window_incomplete` EARNED ITS PLACE ON THE FIRST LIVE RUN.** Four changes
dated 2026-09-08 — the rollup's OWN FIRST DAY — reported **+814%**, +691% and +239% and cleared
every band, because their 24h "before" window lay in the hours when the collector had only just
started. Nothing to do with any firewall: a confident, plausible, completely wrong number, this
codebase's signature bug arriving through the front door of a feature built to prevent it. ⛔ It
was tested before the traffic existed to test it against, which is the only reason the state was
there when the artefact appeared. The full set: `indistinguishable` ·
`exceeded_normal_variation` · `no_traffic_window` · `insufficient_baseline` ·
`baseline_degenerate` · `window_incomplete`.

⛔ **THE VERDICT IS `exceeded` vs `indistinguishable`, DELIBERATELY NOT "significant", AND IT
MAKES NO CAUSAL CLAIM.** `OUTCOME_CLAIM` is exported and `tests/changeOutcomeBoard.test.js`
rejects the causal vocabulary from every string the view emits. ⛔ `indistinguishable` is NOT "no
effect" — it is a statement about what can be RESOLVED. ⛔ A thin baseline reports its own
insufficiency rather than a clean result, and a failed read suppresses every verdict AND every
count rather than rendering a quiet fleet — zero changes assessed otherwise reads exactly like a
fleet whose changes were all uneventful.

⛔ `getChangeOutcomes()` (the fleet entry point) exists but **nothing calls it outside the
tests**. There is no fleet A7 surface today.

*Original proposal text follows.*

203 `config_diffs` (99 in the last 30 days, 9 unreviewed) against `syslog_rollup_hourly`. For each
change, compare a window either side: deny rate, volume, threat counts.

Strategically **the most differentiating item in this file** — SecVault is the only product in this
market holding the change record and the traffic outcome in one database, which is CLAUDE.md's own
framing ("the log storage is not the point; the fusion is").

⛔ **Co-occurrence, NEVER causation.** Worded as "was followed by", with the normal variability
stated alongside — otherwise ordinary fluctuation is dressed up as an effect. That requires A6's
variance estimate, which is why this is Tier 3 and not Tier 1.

---

## ✅ BUILT v2.192.0 — A8 — Remediation velocity / survival *(Tier 3, small)*

`lib/engines/remediationVelocity.js` (pure) + `remediationVelocityData.js` +
`components/vulnerability/RemediationVelocity.js`, on the new FOURTH tab of `/vulnerability`
(`?tab=velocity`, "Remediation velocity"; the list is now `posture`, `advisories`, `upgrade`,
`velocity`). Read-time, no API route, no stored verdict, no cron job. Runs in **638 ms**.

⛔ **THE PREDICTION BELOW IS SUPERSEDED, AND THE REAL FIGURE IS SHARPER.** It said "0 version
changes across 16 devices in 70 days". Measured on the live fleet 2026-09-28:

- **246 open exposures, 0 remediated, median time-to-remediate NOT REACHED in 74 observed days.**
- **0 of 16 firewalls have ever changed version** — 3,954 version rows, 16 distinct
  (device, version) pairs.
- **3 KEV-listed exposures open at least 69 days.**
- 794 advisories testable; 0 reconstructed remediation events.

Four design points the proposal did not anticipate, each of which a later session needs:

⛔ **1. `device_cve_assessments.assessed_at` COULD NOT BE USED AS AN EXPOSURE START.** All 246
live rows carry the SAME timestamp, today's, because the row is rewritten on every match run. It
records when SecVault last LOOKED, not when the exposure began; a duration measured from it would
report every exposure as hours old, for ever, resetting every six hours — a confident, plausible,
wrong number. A test scans for it.

⛔ **2. A REMEDIATED EXPOSURE LEAVES NO ROW**, so the obvious query cannot be written at all.
Events are RECONSTRUCTED from `device_versions`, which is append-only, using
`versionComparator.isInRange` UNCHANGED. Without that path the 0% would be unfalsifiable —
indistinguishable from an engine that never looked — and the 0% is only KNOWN to be real because
the reconstruction would have found an event had there been one.

⛔ **3. TWO CLOCKS, BOTH REPORTED, NEITHER BLENDED.** 59 of 246 exposures were published by the
vendor more than 30 days before SecVault held them (mean 27, **max 276**). CVE-2025-31514 reads 69
days by our clock and **350 by the vendor's**. `daysSinceKnown` is what an operator is accountable for;
`daysSincePublished` is how long the firewall was actually exposed. A single blended figure would be
wrong in both directions at once. Both are LOWER BOUNDS — left-censored at collection start.

⛔ **4. KAPLAN–MEIER "SURVIVAL" MEANS STILL VULNERABLE.** S(t)=100% is the worst available
result wearing the number a dashboard tints green and puts a tick beside. The view NEVER renders
`survivingPct`; it renders `remediatedPct`, inverted ONCE in the engine (the call
`securityScore.js` makes about `riskScore`'s polarity), and a 0% is tinted DANGER, never the
hueless "not measured" treatment — it was measured, and the answer is bad.

*Original proposal text follows.*

Kaplan–Meier with right-censoring is ~30 lines and needs no library.

⛔ **Its honest first output on this fleet is an indictment: 0 version changes across 16 devices in
70 days.** 100% censored — nothing has been patched in the entire observation window. That single
number is worth more than any curve, and it is invisible today because nothing measures it.

⛔ **Censored rows are reported, never dropped.** An advisory still open is not an advisory fixed
slowly; dropping censored observations would report a remediation time computed only from the
devices that did remediate — which here is none of them.

---

## ⛔ NOT BUILT — A9 — VPN behavioural profiles *(Tier 3, medium)*

**RE-MEASURED 2026-09-28: 7,145 sessions, 608 distinct users, 38 days of history, 11.8 sessions
per user** (was 5,954 / 557 / 35 days on 2026-09-25). Per-user baselines of hour-of-day, session
duration and client.

⛔ **AND THE FLEET AVERAGE HIDES THE ONLY NUMBER THAT MATTERS: just 209 of 608 users (34%) have
≥10 sessions.** That is the hard evidence for the rule below, which was raised on reasoning alone
— a fleet-level gate would arm the detector for the TWO-THIRDS of users who have no usable
baseline, on the strength of the busy accounts, and every one of those would be judged against a
profile built from a handful of logins.

⛔ **Gate PER USER, not fleet-wide.** At ~10 sessions per user many individuals have no usable
baseline while the fleet aggregate looks healthy — a fleet-level gate would arm the detector for
everyone on the strength of the busy accounts.

⛔ **Stale-account detection needs history this fleet does not have.** Every user has been seen
within 30 days because there are only 38 days of data; "quiet for 90 days" is unanswerable until
December and must report `insufficient_history`, not zero.

---

## Refusals — and what each would cost

Stating these matters as much as the proposals: a roadmap that does not name its impossibilities
will have one of them quietly approximated.

| wanted | why not | what it would take |
|---|---|---|
| Per-flow traffic usage (src → dst:port) | **Already MEASURED AND REFUSED 2026-09-22** — see `roadmap.md`. The full grain compresses only 5.3:1 on a busy hour (~9.9M rows/day, ~360 GB/year, kept indefinitely) | the DECLARED-flow-keyed rollup already specified there (~35k rows/day). Do not re-propose the general shape |
| Per-user destinations / applications | no `src_ip` in `syslog_app_hourly` or `syslog_blocked_dst_hourly` | same schema change |
| Impossible travel | **no city and no lat/lon exists anywhere** — `syslog_events` carries `src_country` only | a geo-IP corpus. ⛔ And `country_change` must never be renamed to imply it |
| EOL / obsolescence analytics | ⛔ **`eol_catalogue` is NOT in this database.** The nocvault-eol hub has 2,770 rows; SecVault has the table missing entirely | a signed feed mirroring `cveHub.js`. **Probably the largest missing DATASET available to this product** |
| Anything learning from operator decisions | `compliance_exceptions` 0, `rule_change_requests` 0, `finding_acknowledgements` 0, `segmentation_intents` 1, `applications` 5 | nothing to learn from, and will not be for months. ⛔ Do not build an analytic whose input is a table nobody writes to |
| MTTR from version movement | data exists, **zero events** | patching to actually happen (see A8) |

---

## Engineering shape

Every item follows the existing convention: a **pure engine** (data in, verdict out, unit-testable)
plus a `*Data.js` plumbing file. Read-time; **no stored verdicts** — a verdict is a function of the
current rulebase and traffic window, and a stored one goes stale and is then read as fact.

Sizing: `syslog_rollup_hourly` is only 65,188 rows, so read-time is comfortable. ⛔ Only
`syslog_talker_hourly` (3.46M) and `syslog_app_hourly` (2.04M) need bounded windows, and
`syslog_events` is never touched without a narrow `received_at` bound.

⛔ Per `tests/README.md` and CLAUDE.md, each engine's tests must pin the **"we could not measure
this"** case, not only pass and fail. That is the one that regresses silently, because the wrong
answer is a plausible number rather than a crash.

**Suggested order: A1 → A2 → A3 → A4 → A6 (gated, arms itself) → A5 → A8 → A7 → A9.**

---

## Appendix — re-measuring

Every figure above came from these, run read-only as `claude_readonly`. Re-run before trusting any
number in this file; the fleet moves.

```sql
-- hit_count tri-state, the bound on every usage-based analytic
SELECT count(*) rules,
       count(*) FILTER (WHERE hit_count IS NULL) unmeasured,
       count(*) FILTER (WHERE hit_count = 0)     measured_zero,
       count(*) FILTER (WHERE hit_count > 0)     with_hits
FROM firewall_rules;

-- A1: does every open assessment carry a target version?
SELECT priority_band, count(*) n,
       count(*) FILTER (WHERE fixed_in IS NOT NULL AND fixed_in <> '') with_target
FROM device_cve_assessments GROUP BY 1;

-- A2: silence -- inventory devices vs their newest rollup bucket
SELECT d.name, d.vendor, max(r.bucket_hour) last_log
FROM devices d LEFT JOIN syslog_rollup_hourly r ON r.device_id = d.id
GROUP BY 1,2 ORDER BY 3 NULLS FIRST;

-- A3: do logs name a rule, per vendor?
SELECT vendor, count(*) rows,
       count(DISTINCT rule_id) ids, count(DISTINCT rule_name) names
FROM syslog_rule_hits_hourly GROUP BY 1;

-- A4: objects nothing references (see the probe script for the full CTE with group members)
SELECT count(*) FROM network_objects;

-- A6: baseline depth -- needs >= 3 weeks for an hour-of-week model
SELECT round(EXTRACT(epoch FROM (max(bucket_hour)-min(bucket_hour)))/604800.0,1) weeks_span,
       count(DISTINCT date_trunc('hour', bucket_hour)) distinct_hours
FROM syslog_rollup_hourly;

-- A8: have device versions EVER moved?
SELECT count(*) devices, max(dv) max_distinct_versions
FROM (SELECT device_id, count(DISTINCT version_string) dv FROM device_versions GROUP BY 1) s;
```
