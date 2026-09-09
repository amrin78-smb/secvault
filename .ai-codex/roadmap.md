# SecVault Roadmap

Living document. Last reviewed **2026-09-09** against the live fleet (15 active devices,
~74M syslog events/day) and against the ManageEngine Firewall Analyzer (FWA) feature comparison
that motivated this product.

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
| CVE pipeline + KEV + priority tree | 159 live assessments |
| `log_hit` producer | `lib/engines/logHit.js` |
| Compliance engine + monthly PDF | 45 checks, 5 standards |
| Topology, access-path, fleet map | — |
| VPN login geography + spray detection | `syslog_vpn_auth_hourly` |
| Device discovery from unmatched senders | `discovered_devices` |
| Log search (forensic) | 25/50/100/200 per page, index-backed |
| Design system, density, saved views, ⌘K | v2.87–v2.90 |

---

## Tier 1 — highest leverage, and only possible because the data now exists

### 1. Close the rule-cleanup loop
**Why first.** This is FWA's flagship report *and* the place SecVault can beat it outright. FWA
infers rule usage from logs alone. SecVault has three independent signals for the same rule —
log evidence, the device's own hit counter, and the parsed config — and it already knows which of
those it could not measure. Nobody else can say "this rule is unused **and here is why we are
sure**".

**The gap is workflow, not analysis.** 185 unused findings exist and an operator cannot currently
act on them as a batch. Needed: a cleanup campaign view (select findings → export as a change
request → mark submitted → verify against the next `config_diffs` that the rule actually went).

⛔ Must keep the tri-state visible throughout: a rule whose hit count is `unmeasured` must never
appear in a "safe to delete" list. 164 rules are in that state today.

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
| **Change management workflow** (request → approve → implement → verify) | `config_diffs` detects changes after the fact; no request side | Medium. The verify half is the hard part and SecVault already has it — a change request that auto-closes when the matching diff appears would be genuinely better than FWA |
| **Capacity planning / bandwidth forecast** | Rollups hold the history; no trend projection | Medium. ⛔ Only for vendors where `bytes_summable` is true — FortiOS cumulative counters are already excluded and must stay excluded |
| **Custom report builder** | Fixed reports only | Large. Defer until the report registry above exists |
| **Multi-tenancy / site scoping** | `devices.site` exists and is **empty on 14 of 15 devices** | Small technically, but pointless until sites are actually populated. Blocked on data, not code |
| **Granular RBAC** | admin/viewer only, deliberately | Revisit only if a customer asks; a coarse boundary is safer |
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
2. **CVSS v3/v4 not normalised.** 110 of 159 live assessments are scored on v4, 49 on v3, 255
   advisories carry no vector. Provenance is now recorded (v2.90.3); choosing one authoritative
   version is the open decision, and needs a re-match.
3. ~~`CveCell` cannot distinguish "assessed and clean" from "never assessed".~~ **DONE v2.91.0**
   via `devices.last_cve_assessed_at`. Two call sites remain unblocked but not yet updated:
   `OverviewCveCard.js` and `CvePostureTab.js` — both can now gate their zeros on the stamp.
4. ~~Fleet tiles lack `cveNoVersion` and a config-snapshot count.~~ **DONE v2.91.0.** While doing
   it, found `licence_row_count` was computed but never projected, so `supportNoData` silently
   equalled the whole fleet and the Support tile claimed "Not collected for any device" about 15
   devices whose licences ARE collected.
5. **Config snapshots are not deduped at write time.** 508 of 1,730 snapshots were byte-identical
   to their predecessor (~161 MB). Retention bounds it; the write path still creates it.
6. **Wide rollup sweep takes ~900s per 6h slice** and skips cycles. Needs profiling per pass, not
   a guess — `work_mem` is already 32MB, so the obvious lever is gone.
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

If it has a week: **Tier 1 item 1** (rule cleanup workflow). It is the strongest differentiator
against the tool this product exists to replace.
