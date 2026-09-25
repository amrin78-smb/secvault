# Analytics without an LLM — PROPOSAL, mostly NOT BUILT

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
`◨` partial · `✅` done.

| # | Item | Tier | Effort | New table? | Done |
|---|---|---|---|---|:--:|
| A1 | **Upgrade planner** — collapse 246 assessments into ~16 upgrade decisions | 1 | S | no | ✅ v2.187.0 |
| A2 | **Blind-spot register** — which devices look healthy because we cannot see them | 1 | S–M | no | [ ] |
| A3 | **Log-derived rule usage** — a second evidence source for `hit_count` | 1 | M | no | [ ] |
| A4 | **Object & rule consolidation** — exact set algebra, needs no hit counts | 2 | M | no | [ ] |
| A5 | **Fleet conformance / odd-one-out** — discovers checks the 45-check library lacks | 2 | M | no | [ ] |
| A6 | Seasonal baselines — **NOT a new item**, it is `roadmap.md` Tier 1 #2. See §A6 for why it cannot arm yet | — | — | — | [ ] |
| A7 | **Change → outcome correlation** — the most differentiating, depends on A6 | 3 | M–L | no | [ ] |
| A8 | **Remediation velocity (survival)** — today its honest output is an indictment | 3 | S | no | [ ] |
| A9 | **VPN behavioural profiles** — 557 users, 35 days, gate PER USER | 3 | M | no | [ ] |

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
| `device_versions` | 3,727 rows, 16 devices, **0 version changes in 70 days** |
| `fleet_dashboard_snapshots` | 55 rows over 69 calendar days — **14 missing days** |
| hour-of-week baseline | **2.4 weeks**, 405 distinct hours — below the 3 weeks a seasonal model needs |
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

## A1 — Upgrade planner *(Tier 1, small, highest value-to-effort here)*

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

## A2 — Blind-spot register *(Tier 1, small–medium)*

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

## A3 — Log-derived rule usage *(Tier 1, medium)*

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

## A4 — Object & rule consolidation *(Tier 2, medium)*

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

## A5 — Fleet conformance / odd-one-out *(Tier 2, medium)*

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

## A6 — Seasonal baselines: NOT a new item

This is `roadmap.md` **Tier 1 #2, "Threshold and anomaly alerting"**, already raised and unbuilt.
What this file contributes is the measurement that says when it can work, and one method constraint.

⛔ **IT CANNOT ARM TODAY.** `syslog_rollup_hourly` spans **2.4 weeks / 405 distinct hours**; a
168-bucket hour-of-week model needs ≥3 weeks to have more than ~2 observations per bucket. Build it
**gated**, reporting `insufficient_baseline` with the baseline it needed and the baseline that
exists — exactly as the six VPN detections do, rendering hatched and hueless, never a green
all-clear. It arms itself in one to two weeks with no code change.

⛔ **Median + MAD, never mean + σ.** Firewall traffic is heavy-tailed; a single spike poisons a mean
and the detector then under-reports for a week. This is compatible with the roadmap's own rule that
thresholds be "explicit and per-rule, never a magic anomaly score" — the baseline is an input to a
NAMED threshold, not a composite score.

⛔ **Highest-value detector when it does arm: a device that STOPS logging** — which is A2's finding
made continuous, and is why A2 should land first.

---

## A7 — Change → outcome correlation *(Tier 3, medium–large)*

203 `config_diffs` (99 in the last 30 days, 9 unreviewed) against `syslog_rollup_hourly`. For each
change, compare a window either side: deny rate, volume, threat counts.

Strategically **the most differentiating item in this file** — SecVault is the only product in this
market holding the change record and the traffic outcome in one database, which is CLAUDE.md's own
framing ("the log storage is not the point; the fusion is").

⛔ **Co-occurrence, NEVER causation.** Worded as "was followed by", with the normal variability
stated alongside — otherwise ordinary fluctuation is dressed up as an effect. That requires A6's
variance estimate, which is why this is Tier 3 and not Tier 1.

---

## A8 — Remediation velocity / survival *(Tier 3, small)*

Kaplan–Meier with right-censoring is ~30 lines and needs no library.

⛔ **Its honest first output on this fleet is an indictment: 0 version changes across 16 devices in
70 days.** 100% censored — nothing has been patched in the entire observation window. That single
number is worth more than any curve, and it is invisible today because nothing measures it.

⛔ **Censored rows are reported, never dropped.** An advisory still open is not an advisory fixed
slowly; dropping censored observations would report a remediation time computed only from the
devices that did remediate — which here is none of them.

---

## A9 — VPN behavioural profiles *(Tier 3, medium)*

557 distinct users, 5,954 sessions, **35 days** of history, 468 users active in the last 7 days.
Per-user baselines of hour-of-day, session duration and client.

⛔ **Gate PER USER, not fleet-wide.** At ~10 sessions per user many individuals have no usable
baseline while the fleet aggregate looks healthy — a fleet-level gate would arm the detector for
everyone on the strength of the busy accounts.

⛔ **Stale-account detection needs history this fleet does not have.** Every user has been seen
within 30 days because there are only 35 days of data; "quiet for 90 days" is unanswerable until
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
