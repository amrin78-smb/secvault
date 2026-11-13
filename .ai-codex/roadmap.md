# SecVault Roadmap

Living document. **Built-state PARTIALLY reviewed 2026-11-12** (v2.225.0): the A6 / threshold-alerting
claims and the "How to choose" section were corrected, and **nothing else in this file was
re-verified.** The previous full review was **2026-09-22** (v2.162.0), i.e. ~60 versions back, so
treat every other ✅/[ ] here as a claim about a commit rather than a measurement. The measured
FLEET FIGURES below are from **2026-09-09** (15 active devices, ~74M syslog events/day) unless a
line restates them, and the FWA feature comparison that motivated this product is from the same
date.

⛔ **AND IT WENT STALE AGAIN, BY 28 VERSIONS, IN THREE PLACES AT ONCE.** A6 shipped in v2.196.0;
this file said it was unbuilt in its analytics paragraph, described Tier 1 item 2 as missing in its
own section, and — the expensive one — **recommended building it** under "How to choose", which is
the section a session acts on directly. ⛔ **The cost was not a wasted rebuild this time, it was a
false claim to a customer**: a competitor-comparison deck was generated off this file and listed
threshold/anomaly alerting as something Firewall Analyzer had and SecVault did not. A stale roadmap
does not merely waste a conversation; it can be quoted outward. Found 2026-11-12 while re-measuring
the two refused A6 candidates.

⛔ **THIS FILE ALSO WENT 24 VERSIONS STALE (v2.124.0 -> v2.148.0) AND SAID SO NOWHERE.** It carried
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

## ⭐ COMPLETENESS BACKLOG — raised 2026-09-22, after the six-agent sweep

Where the product is genuinely weak, ranked. Every row carries the MEASUREMENT that justifies its
priority, because the whole point of this product is not asserting things without one. Tick the
Done column in the same commit as the work.

⛔ **THE HEADLINE JUDGEMENT, so nobody re-litigates it from scratch:** the ideas and the evidence
discipline are the strong part and they held up under adversarial review. What does not hold up is
the ratio of SURFACE AREA to VERIFICATION. Six parallel reviewers found ~40 defects in ONE DAY's
code (v2.156.0-v2.159.0), four of them already live on the reference fleet. There is no reason the
other ~150 versions are cleaner — only less examined. **The next months of value are in depth:
fewer claims, better verified.**

### P1 — do these before any new feature

| # | Item | Why, measured | Done |
|---|---|---|:--:|
| 1 | ✅ **v2.162.0** — **Route / component / DB-integration tests** | 3,460 tests and **zero** of any of those three kinds. The 28-page smoke sweep is the ONLY thing that loads a page. All four defects that reached the live fleet on 2026-09-21 sat in that gap: a 500 reachable only through a route, an auth mechanism nobody had read the library for, a writer broken on the line endings that actually ship. | ✅ |
| 2 | ✅ **v2.163.0** — **Compliance: state the COVERAGE DENOMINATOR, stop printing a bare per-standard %** | `/compliance` shows **"NIST 42%"** computed from **7 checks** — of which 3 are vendor-specific, so ~5 apply per device, and 4 are generic firewall hygiene (`rule-no-any-any-allow`, `rule-logging-enabled-on-rules`, `rule-has-explicit-deny-all`, `rule-no-external-to-internal-access`) wearing a framework's name. Library totals: CIS_V8 44, ISO_27001 35, PCI_DSS 21, SANS 12, NIST 7, out of 45 checks. This is the ONE place the product overclaims, and it is the product's own denominator rule turned inward. | ✅ |
| 3 | ✅ **v2.163.0** — **Compliance: exception / compensating-control workflow** | 151 failing checks fleet-wide and no way to record an accepted risk with an expiry. Every real audit conversation is "yes, and here is why that is mitigated". Without it the 51% score is un-actionable and people stop opening it — the same dynamic that got `new_finding` pulled from Alerts in July. CLAUDE.md already notes critical compliance failures have no acknowledgement mechanism. | ✅ |
| 3b | ✅ **v2.165.0** — **Compliance: say how old the score is** | Found while answering "how often do the checks run". Two of sixteen firewalls were scored on configurations collected 10 and 46 days ago, rendered beside fourteen 12-hour-old ones with nothing distinguishing them. ⛔ The age shown had to be the CONFIG's, not the last run's: the auditor reads the newest `device_configs` row whatever its age and stamps `detected_at = now()`, and TSR_EKC's audit had already run **18 days after** its last successful collection. A "run checks now" button would therefore have put a fresh date on month-old evidence — which is why the panel links to COLLECTION instead. | ✅ |

| 3c | ✅ **v2.166.0** — **Compliance reports: per firewall as well as per framework** | The report could narrow to one FRAMEWORK (a declared param) but not one FIREWALL — the entry was `scope: FLEET` and the route REFUSED a `deviceId` with a 400. Traffic Activity already solved this with `optionalDevice: true`, its own comment citing the compliance report as the precedent it copied; the pattern went one way and never came back. ⛔ Not a filter: every read re-scopes in SQL, so `applicable` becomes "can run on THIS vendor". Verified live — NIST on TSR_EKC reads *5 apply to this firewall's vendor* against the fleet's *7 ran across 16 firewalls*. | ✅ |
### P2 — structural, gets more expensive every month

| # | Item | Why, measured | Done |
|---|---|---|:--:|
| 4 | ✅ **v2.167.0** — **Predicate engine: iterate collections, not one fixed dot-path** | The single-path limit is the ROOT CAUSE of `predicate_type: 'not_evaluable_from_config'`, and `na` is **55 of 404** findings (14%). Anything genuinely per-rule is unanswerable by construction. Fixing this converts a real slice of `na` into actual answers and shrinks the "manual verification" pile. ✅ Built as `rule_property`, the UNIVERSAL quantifier beside `ruleset_property`'s existential one. ⛔ The data was already collected and never looked at: `raw_rule` is the verbatim vendor rule on the table this audit already queries. Live result: `na` 54 → 39, `fail` 153 → 165, and **622 enabled allow rules across nine Palo Altos have no log-forwarding profile**. ⛔ 33 Panorama-pushed rules are UNDECIDABLE, not violations. | ✅ |
| 5 | ✅ **v2.168.0** (foundation) — **RBAC device scoping** | Every role sees the ENTIRE fleet; there is no per-device or per-site grant. Fine for one 27-device organisation, and a hard cap on ever serving an MSP, a holding company, or "the Vietnam team sees Vietnam's firewalls". Architectural, so the cost only grows. ✅ Built DEFAULT-DENY: `user_device_scopes` + `lib/deviceScope.js` + a coverage register that fails the build on an unclassified surface. ⛔ Shipped at **4 aware / 71 blocked / 39 no-device-data** — a scoped account is REFUSED by anything not yet scope-aware, so partial coverage means LESS access, never a leak. Proven live: a 2-device account saw 2 of 16, out-of-scope returned 404, and **0 of 15 other firewalls were named anywhere in the list page response**. ⛔ **v2.168.0 SHIPPED THE REGISTER UNENFORCED** — `isScopeAware()` was never called at runtime, so a scoped account would still have been served the whole fleet on `/compliance`. Fixed in **v2.169.0**: `lib/deviceScopePaths.js` + `middleware.js`, with the scope flag in the JWT beside the role. Verified live — scoped account gets 307/403 on blocked surfaces and 1 of 16 devices on the aware ones, while an unscoped admin is unaffected on all of them. Settings → Users now has the editor. Opening up the remaining 71 surfaces is ongoing work, one at a time, each raising the floor. | ◨ |
| 6 | **`syslog_flow_hourly` rollup** | Already documented as the blocker for per-flow traffic evidence. Until it exists `/applications` keeps answering "cannot tell" and people stop opening it. ⛔ A storage decision argued on measured cardinality, NOT a query change. | [ ] |

### P3 — real, but not urgent

| # | Item | Why | Done |
|---|---|---|:--:|
| 7 | **Change-request → ticketing (ServiceNow / Jira / webhook)** | The VERIFY half is the moat; the REQUEST half is a CSV someone emails. The product proves a change happened but cannot participate in how it gets approved. | [ ] |
| 8 | **Scheduled report delivery** | ✅ **BUILT v2.225.0** — `report_schedules` / `report_delivery_log`, any catalogued report, daily/weekly/monthly to a named email channel. Deferred by the user 2026-09-21 ("not that important now"); picked up 2026-11-12. ⛔ No `next_run_at`: due-ness is derived each tick. | [x] |
| 9 | **One fleet-wide SMTP relay** | SMTP is fully built (`lib/notify.js`, nodemailer, send-test route) but configured PER EMAIL CHANNEL, so there is no page labelled SMTP and it reads as missing. A single relay configured once and reused would match the expectation. | [ ] |

### P4 — sweep leftovers, each a one-sitting fix

Found by the 2026-09-21 sweep, triaged as not worth a release of their own. All VERIFIED unless noted.

| # | Item | Done |
|---|---|:--:|
| 10 | ✅ **DONE v2.164.0** — the page sweep's `& node ... 2>&1` bypassed `Invoke-Native`, so node's TLS warning became a TERMINATING NativeCommandError and the first deploy that actually ran the sweep reported "completed WITH ERRORS" over a 28/28 pass. Four more unrouted redirects remain in `Restore-`/`Uninstall-SecVault.ps1` and `SecVault-Tls.ps1` (openssl), pinned as a SHRINKING allow-list in `tests/installerNativeCalls.test.js` rather than edited blind — those scripts are destructive or unexercised on a normal deploy. openssl is the one worth doing first: it writes progress to stderr routinely. | [ ] |
| 10b | `Update-SecVault.ps1` logs **"Step succeeded"** when the page sweep SKIPS — three deploys reported success for a gate that never ran. Cosmetic now the credentials are set, still dishonest. | [ ] |
| 11 | `drawBarChart` with more rows than fit a page shreds labels and bars onto different pages (`ensureSpace` can only add ONE page). Unreachable today — every call site caps at 15. | [ ] |
| 12 | Chart captions sit OUTSIDE the height reservation, so the sentence stating a chart's denominator can land on the next page. | [ ] |
| 13 | `drawDonut` has no `opts.format`, unlike `drawBarChart` — a byte-valued donut would print "1.1B" for one gigabyte. | [ ] |
| 14 | `lib/consoleUrl.js` accepts a zero-padded IPv4 and silently saves a DIFFERENT address (`192.168.010.1` → octal → `192.168.8.1`). | [ ] |
| 15 | `gatherSegmentation` returns `[]` when called with no opts (the 15-min dispatch path), reported as `{ok:true, count:0}` — so a `violation_active` can show in `/work` as Act now and never reach a channel. Same shape as the bug v2.153.0 fixed. | [ ] |
| 16 | `feedStatus`: an UNLISTED state ranks -1, wins the reduce, matches no branch, and falls through to `FEEDS OK`. The documented "drift makes the pill go loud" property does not exist — it goes green. Latent on today's seven states. | [ ] |
| 17 | `feedStatus`: blocked + skipped with nothing rated reports "deliberately skipped", claiming SecVault chose not to collect over feeds a publisher REFUSED. Reachable on a hub-only site (live: `nvd` skipped, `fortinet_psirt` blocked). | [ ] |
| 18 | `docs/SIZING-AND-BACKUP.md` says ~8.4 GB/day archive; measured **4.0**. | [ ] |
| 19 | `backfillPaloAltoVersionRanges` still reports `cleaned up 302` every deploy, rewriting 351 advisory rows to identical values. Gated but flagged; first place to look if advisory matching regresses. | [ ] |
| 20 | Stale `E:\SecVault_Backups` (~4.7 GB) left beside the current backup set. | [ ] |

### P4b — open after the analytics build (A1-A5 + A7), raised 2026-09-27

Same triage as P4: real, each one a sitting, none worth a release of its own.

⛔ **EVERY DEPLOY LOSES SYSLOG, AND `dropped` REPORTS 0 WHILE IT HAPPENS** (measured
2026-09-28, deferred deliberately — raised with the user, answer was "nothing for now").
`Update-SecVault.ps1` stops `SecVault-Collector` unconditionally, so the gap is a whole
`npm ci` + `next build` wide, not a service restart. Measured against a steady ~83,000
events/minute across three deploys in one 45-minute window:

| deploy | minutes absent | shortfall |
|---|---|---|
| v2.193.0 | 15:57-15:59 | ~200,600 |
| v2.193.1 | 16:15-16:18 | ~278,400 |
| v2.193.2 | 16:25-16:28 | ~195,365 |

~674,000 events for three deploys; five went out that day, so **over a million events**
lost from a 30-day forensic window.

⛔ **`syslog_ingest_stats.dropped` IS 0 FOR EVERY ONE OF THOSE MINUTES**, and that is not
a bug in the counter — while the service is stopped the datagrams hit a closed UDP socket
and the OS discards them, so nothing is ever received to count. The rows are simply
ABSENT. A forensic search over that window returns clean empty minutes rather than a gap.
This is the file's own failed-read-as-a-fact rule aimed at the deploy process.

**The fix when it is wanted**: the collector only needs stopping when `npm ci` will
actually touch `node_modules` (Windows file locks are the reason) or when `services/**`
changed. Neither was true for v2.193.1 or v2.193.2 — `package-lock.json` was unchanged and
the collector's code was identical — and both conditions are detectable before anything is
stopped. Worth pairing with a written marker for the window it WAS down, so the gap is
visible rather than silent.
⛔ **None of these is done — do not read the ✅ rows in the analytics table below as
covering them.** Every one was verified against the source on the date raised.

| # | Item | Done |
|---|---|:--:|
| 21 | **`upgradePlan` presents a DERIVED fix boundary as a vendor commitment.** `lib/reports/chassis.js` now exports `FIX_PROVENANCE` / `fixProvenance()` / `fixVersionCell()` — four states, `PUBLISHED` / `DERIVED` / `UNKNOWN` / `NONE` — and green is reserved for `PUBLISHED`. ⛔ **`lib/reports/vulnerabilityPosture.js` IS ALREADY WIRED** (both the per-firewall table and the fleet-grouped row, which goes green only when EVERY firewall's target is vendor-published) — this item was raised as covering it and does not. What is genuinely unwired is **`lib/engines/upgradePlan.js` / `upgradePlanData.js`**: neither reads `fixed_in_versions` or `affected_version_ranges` at all, so an upgrade target derived from a `versionEndExcluding` boundary is recommended in the same voice as one the vendor published. ⛔ `unplannable` wants a THIRD reason, `fix_version_derived`, beside today's `no_known_fix` and `fix_version_unreadable` — a derived bound is a plannable target but **not a vendor commitment**, which is a different fact from having no target at all. No schema change. | [ ] |
| 22 | **The CVE hub should populate `fixed_in_versions` AT SOURCE** (the `nocvault-eol` project), rather than SecVault deriving the boundary out of `exclude_fixed: true` on ingest and then defending that repair against the vendor feed. Measured: only **10 of 955** hub advisories populate the field, while many carry the boundary in a range — so the derivation is load-bearing today and is the wrong place for it. ⛔ Cross-repo: nothing in THIS repo fixes it, and the local derivation must stay until the hub actually ships the field. | [ ] |
| 23 | **A failed feed waits a full cycle — there is no retry.** `feed-sync-and-match` self-catches, logs, and the next `node-cron` tick is `FEED_POLL_INTERVAL_HOURS` away (**6h** by default). A transient DNS or 503 therefore costs six hours of discovery, and nothing distinguishes "failed once, will retry at 18:00" from "failing every cycle" on the feed pill. A bounded in-job retry with backoff, or a short-interval re-arm for a feed whose last run failed. | [ ] |
| 24 | **`versionComparator.parseVersion` returns FABRICATED ZEROS for a version it cannot read**, and says nothing. `parseVersion('fortinet', 'nope')` is `[0,0,…]`, which every conceivable target compares "at or above" — this codebase's most-repeated bug living in a version parser. ⛔ **`upgradePlan.branchOf` and its sibling ARE guarded** (a no-digit test plus an every-component-is-finite test, added 2026-09-27 after a KEV row with `fixed_in: 'Not applicable'` was reported as CLEARED and excluded from `unplannable`). ⛔ **THE REMAINING CALL SITES HAVE NOT BEEN AUDITED**: `lib/engines/versionMatcher.js` (3 sites), `lib/feeds/nvd.js`, `lib/feeds/paloalto.js`, and every adapter's `version_tuple` (`checkpoint/parser.js`, `cisco_asa/index.js`, `fortinet/parser.js`, `fortinet/ssh.js`, `paloalto/parser.js`, `paloalto/ssh.js`, `sangfor/index.js`). The right fix is probably at the source — return `null` for unreadable input and make every caller say what it does about that — but that is a breaking change across a matcher on the CVE path, so measure before moving it. | [ ] |
| 25 | **`tests/fixedVersionFromRanges.test.js` still pins EXACT SOURCE TEXT rather than behaviour.** Its section 3 slices `lib/feeds/fortinet.js` around `affected_version_ranges = CASE` and regex-matches the wording of the downgrade guard, so a harmless rename or reformat disarms it silently — a guard that cannot fire, which is the defect this repo names most often. ⛔ Its section 4 (the `cveHub` half) was ALREADY converted after the old four-regex version was demonstrated inert against a real disagreement, and `tests/fixBoundary.test.js` owns that behaviour — so the pattern to follow already exists in the same file. Convert section 3 the same way. | [ ] |
| 26 | ⛔ **AN UN-ENUMERATED OBJECT GROUP RESOLVES TO A CONFIDENT `no-match`, WITH NO `unresolved` SIGNAL.** `lib/engines/objectResolver.js:159,319`. Three cases exit the group branch silently — empty `members`, a cycle, and a chain deeper than `MAX_GROUP_DEPTH` (50) — so `matchesAddress`/`matchesService` fall through to a definitive exclusion built from an object nobody read. The in-code comment justifies it for the CYCLE case only; the same branch covers the other two, where nothing was ever expanded. ⛔ **ROOT CAUSE IS ALREADY WRITTEN DOWN AND THE FIX ALREADY EXISTS ELSEWHERE**: `objectUsage.storeObjects` stores `members: (g && g.members) || []`, so a group the adapter enumerated WITHOUT members is indistinguishable from a genuinely empty one — and the identical defect was fixed in `ruleConsolidation`'s `dimensionOverlap` on 2026-09-26 ("a zero-range non-wildcard extent is `unknown`, NOT `no`"). That fix was never applied to the resolver that `topology.js`, `exposure.js`, `applicationView.js` and `applicationRetire.js` all reuse. **Three wrong outputs reproduced:** (a) Access Path returns `verdict: deny, hasCaveat: false` for traffic a rule permits; (b) `/applications` flips a `violation` to `unspecified` with `unverified: false` and `unverifiedReasons: []` — a hole reported as CLOSED, the direction that file's own header names as dangerous; (c) `applicationRetire`'s "only this application claims it" safety property is defeated with ZERO taints, reducing defence-in-depth to the one independent `not_cleanup_eligible` gate. **Live:** two empty address groups exist today (`TELEMETRY` on OKF(F2) and Vietnam-YCC), neither currently referenced by a rule — latent, one adapter hiccup from real. ⛔ Also a LEAD into unswept ground: the same confident `no-match` very likely produces wrong verdicts on `/topology` and `/exposure`, neither of which was reviewed. | [ ] |
| 27 | ⛔ **7 `rule_scan` COMPLIANCE CHECKS RETURN `pass` WHEN RULE ANALYSIS HAS NEVER RUN.** `lib/engines/configAuditor.js:995-1012`. `evaluateRuleScanCheck` resolves `pass` whenever `ruleFindingsByType` holds nothing for its types, and its `na` guard keys ONLY on `skippedPairwiseFindingTypes(ruleCount)` — the 1000-rule O(n²) cap. A device with a collected ruleset and NO `rule_analysis_results` rows gets nothing from that guard. This is the exact bug the guard's own header describes ("a device with more than 1000 rules scored PASS on both and was CREDITED in the compliance denominator for an analysis SecVault deliberately declined to run") at a SECOND cause it does not cover. **Measured on the 74-check library: `rule_scan` is 7 of every device's 21-27 gradeable checks, 27-33% of the denominator.** TUFF(TUTH3) would go 8/21 = 38% to 13/21 = **62%** — a 24-point lift from an analysis that never ran. Latent on this fleet (all 16 devices hold analysis rows, min 4) but reachable for a newly-added device audited before its first analysis, or one whose analysis has never succeeded. | [ ] |
| 28 | ⛔ **THE `device_silent` DETECTOR FIRES AT 6.8x ITS RECORDED MEASURED RATE, AND NOTHING RE-MEASURES.** `lib/engines/anomalyDetections.js:131-141` records `alertsPerDay: 0.074`, justified 2026-10-06 on "16 silent device-hours in 9,720 (0.16%), falling in exactly TWO runs". Re-run against production 2026-11-13: **14 alerts over 28 days = 0.500/day**. TFM-MH now flaps on a ~2-hour cycle **12 separate times in 28 days** (39 silent hours of 672), and `SILENCE_MIN_HOURS = 2` sits at the minimum the persistence rule can express — so the "rare AND clustered" measurement that justified it no longer holds. `gatherAnomalies` emits one finding per RUN, so that is 12 separate "TFM-MH stopped sending syslog" notifications about one firewall, which is the `new_finding` noise failure that got an alert type pulled from the feed in July. ⛔ `assertRegisteredDetector` enforces that a measurement EXISTS, not that it still HOLDS — a guard that cannot fire on drift. ⛔ Note TFM-MH's flapping is itself a real collection problem worth chasing separately. | [ ] |
| 29 | ⛔ **A WINDOW-TRUNCATED SILENCE RUN GETS A NEW `natural_key` EVERY HOUR.** `lib/engines/anomalyDetectionsData.js:115` keys on `run.startAt`, and `loadReportingGrid` generates hours from `now() - 28 days`, so a run whose true start precedes the window has `startAt` clamped to the window's advancing left edge. The dispatcher's reconcile clears every `natural_key` absent from the new list, so each hour a firewall silent for >28 days produces a **false "resolved" on the old key plus a fresh notification on the new one — ~24/day, for ever**. Latent today (no device opens the window silent) but TFM-RN already has a 108-hour run. | [ ] |
| 30 | **The fleet compliance `overall` counts each finding once PER MAPPED STANDARD.** `lib/engines/dashboardSnapshot.js:88-102` sums `pass`/`measurable` across `STANDARDS`, so a check mapped to five frameworks counts five times and one mapped to none is excluded. The per-device page counts each finding once. Measured: 479/1016 = 47% (standard-expanded) against 175/365 = 48% (one row per finding). One point apart today, so nothing looks wrong — but `overall` feeds `computeSecurityScore`'s 30%-weighted compliance component and the nightly snapshot, and the skew moves with the library's standards mapping rather than with the fleet. | [ ] |
| 31 | ⛔ **`getVpnTunnels()` RETURNS `[]` ON A PARSE FAILURE INTO A DESTRUCTIVE WRITER THAT READS `[]` AS "no tunnels".** `lib/adapters/paloalto/index.js:825`, `paloalto/ssh.js:938`, `fortinet/ssh.js:577` all end `catch { return []; }`. The consumer `lib/engines/vpnTunnels.js:31` is `DELETE FROM vpn_ipsec_tunnels WHERE device_id = $1` then reinsert, and its own header states the opposite meaning: "an empty array legitimately clears the device's tunnels". Producer and consumer disagree about what `[]` means — the `getRules()`-returns-`[]` class one table over. **Live blast radius: 165 rows, 163 `up`** (fortinet/ssh 10, paloalto/api 152, paloalto/ssh 3). A firmware whose output the parser does not recognise wipes every real tunnel for that device and nothing errors; those devices then render as disconnected on the fleet map, which is exactly what the VPN-tunnel-peer edges exist to prevent. ⛔ `connectors.md` does describe this as "best-effort (`[]` on parse doubt)", so the adapter's `[]` was deliberate — **the defect is the contract mismatch with a destructive consumer**, and the preferred fix is a real tri-state (`[]` = none configured, `null` = could not tell, consumer skips the delete on `null`) rather than making the adapters throw.  ✅ **FIXED v2.225.3 — the tri-state, as this row recommended.** `storeVpnTunnels()` now reads an ARRAY as a measurement (`[]` = genuinely none, rows cleared), `null`/`undefined` as NOT MEASURED (DELETE skipped, returning before the transaction opens), and any other shape THROWS — the old `Array.isArray(t) ? t : []` also turned the `undefined` of a method falling off its own end into a wipe. ⛔ **THIS ROW UNDER-COUNTED THE SITES: there are FIVE, not three.** It named `fortinet/ssh.js:577` but not that the same file ALSO swallowed a per-VDOM parse failure to `[]` inside the multi-VDOM loop (so that VDOM counted as a success contributing zero rows), and it missed `fortinet/index.js` entirely. ⛔ **And both Fortinet transports returned a PARTIAL VDOM result as complete**, which is the rule CLAUDE.md already states for `getRules()` ("collect every VDOM or fail") in a second method that rule never looked at — one VDOM failing deleted that VDOM's tunnels. Both now return `null`; the pre-existing every-VDOM-failed branches still THROW, because that is a transport failure rather than an unreadable answer. ⛔ **Residual, stated not hidden:** `cisco_asa`'s `parseVpnSessiondbL2l()` fails closed to `[]` INTERNALLY, so output it cannot parse still arrives as a measured zero; tightening it needs live `show vpn-sessiondb l2l` output to verify against. `tests/vpnTunnelContract.test.js` (27 cases) asserts on the STATEMENTS ISSUED rather than source text, and **re-derives the implementation set from source** — its first draft hardcoded four files and missed the fifth, which was the live-fleet one. 9 mutations verified. | [x] |
| 32 | **`normalizeCountry()`'s ISO map is incomplete, so the fold it exists to perform is a no-op for 17 live codes.** `lib/syslog/vpnAuthStats.js`. Executed over every ISO-2 value in `syslog_vpn_auth_hourly`: **27 of 44 map, 17 return verbatim** (AR BB BE EC EG GE GF HU IL JM KZ LB LC MA MQ TT UZ), and **8 countries are split live** — worst **KZ 230,935 + Kazakhstan 909**, also BE 6 + Belgium 3,829, HU 3 + Hungary 2,782, GE 2 + Georgia 647. Consumers that group on the post-normalisation key therefore still split: the VPN login-locations ranking shows one country as two rows with split counts (and with a top-N limit the smaller row can drop off entirely), and `vpnDetections.js:190`'s country filter shows duplicate options — the exact symptom that file's own comment records as FIXED. ⛔ The map's own comment invites extension ("a country missing from this map still ranks — a visible prompt to extend"), so this is the prescribed remedy, not a redesign. The same-hour "authenticated from both TH and Thailand" false positive stays latent only because every cross-form username found is on `failure` rows and that detection reads successes. | [ ] |
| 33 | ⛔ **`CREDENTIAL_KEY` WAS READABLE BY EVERY LOCAL USER ON PRODUCTION, AND "ACL IT" HAD BEEN THE DOCUMENTED FIX SINCE v2.133.0 WITH NO CODE BEHIND IT.** `installer/Backup-SecVault.ps1` creates its backup directory with a bare `New-Item` and never set an ACL, while its own header says "the backup directory is as sensitive as the database — it holds the encryption key beside the encrypted credentials. ACL it." **Measured live on production 2026-11-13:** `E:\SecVaultBackup` carried `BUILTIN\Users:(I)(OI)(CI)(RX)` INHERITED from the volume root, over **14 `.env` copies and 28 `.pem` files** (14 retained sets) — so any non-admin local account could read `CREDENTIAL_KEY` (decrypting every row of `device_credentials`, i.e. the whole fleet's firewall passwords), `PG_ADMIN_PASSWORD` (the cluster superuser, shared with five sibling apps) and the console's TLS private key. The 02:30 `SecVaultBackup` task re-registers on every update, so it armed itself. ⛔ **A requirement in prose cannot fail a build, and the sentence reading as though it were handled is precisely what kept anyone from checking** — the guard-that-cannot-fire pattern aimed at this repo's worst secret. ✅ **FIXED v2.225.3**, both halves: production remediated by hand with the user's authorisation (`icacls /inheritance:r` granting only SYSTEM and Administrators `(OI)(CI)F`; verified **0 of 56 files still grant a non-admin principal**, and the task runs as SYSTEM which keeps full control), and the script now does it **on every backup rather than at creation** (every deployed server already HAS the directory, so a create-time fix reaches fresh installs only — the `CREATE TABLE IF NOT EXISTS` trap), **before the dump** (the exposure is created by writing the key there), VERIFYING the resulting ACL rather than trusting icacls' exit code. It WARNS and continues rather than refusing — skipping the backup would trade a conditional read exposure for a CERTAIN loss of recoverability — but clears `$backupComplete`, so the banner cannot claim success and the task result is non-zero. Executed on real Windows PowerShell **5.1.26100.9818** (both the success and the failure path, and idempotent on a second run); `tests/backupScripts.test.js` pins it, 6 mutations verified. | [x] |
| 34 | ⛔ **A SINGLE REJECTED INSERT CHUNK MAKES THE COLLECTOR RE-INSERT THE REST OF THE SPOOL FILE ~900 TIMES.** `lib/syslog/eventStore.js`'s `insertEvents()` catches per 500-row chunk and returns only an AGGREGATE `{stored, failedChunks}` with no record of WHICH chunks landed; `services/collector.js`'s `processSpoolFile()` keeps the file whenever `failedChunks > 0` and the next retry re-reads the ENTIRE file and re-inserts every chunk, including the ones that already committed. Quarantine needs BOTH `MIN_SPOOL_ATTEMPTS` (5) AND `SPOOL_RETRY_MS` (30 min), which at a 2s flush is ~900 retries — the time-based budget correctly fixed the 10-second stranding bug and multiplied this by ~180x. `archive.appendRecords()` also runs BEFORE the insert, so each retry appends a duplicate gzip member too, and the PK is `(received_at, id)` with `id BIGSERIAL`, so nothing dedupes. ⛔ **The TRIGGER is closed in v2.225.3** (a NUL byte, which PostgreSQL refuses in text, was reaching the insert because `message` bypassed every coercion; `toIntOrNull` was also unbounded against BIGINT) — **the AMPLIFICATION is not**. Latent today, measured: 42,947 cycles in 24h with `sum(received) = sum(stored) = 80,167,056` exactly, 0 dropped, `max(spool_backlog) = 0`; 1 drop cycle in 1,291,089 retained cycles. **Fix shape:** have `insertEvents` report WHICH records failed and have `processSpoolFile` atomically rewrite the spool file with only those, which also stops the archive duplication — a change to the durability core, so it wants deliberate work and live verification, not a rushed deploy. | [ ] |
| 35 | **The compressed archive — the only copy of the raw line for ~89% of traffic — has no health signal outside the collector's own stdout, and `archiveStats()`'s docstring claims otherwise.** It says it is used "by the collector's startup banner **and by the ingest-health view**"; a repo-wide grep finds exactly ONE caller, the startup banner. `archiveFailures` is never written to `syslog_ingest_stats` (no column) and never read by `lib/serverHealth.js`, whose only archive involvement is the VOLUME's free bytes. So a full disk, a permission change or an unwritable `SYSLOG_ARCHIVE_DIR` fails every append every 2 seconds with free space reported healthy and no product surface changed. Worse, the periodic ratio line that names `archiveFailures` is gated on `archiveRaw > ARCHIVE_LOG_EVERY_BYTES`, and `archiveRaw` only advances on SUCCESS — so when the archive fails COMPLETELY, the one line naming the failure never prints either. Same incident shape as the `SYSLOG_ARCHIVE_DIR` ENOENT bug this codebase already records, which was fixed at the env-parsing layer while the observability gap it ran through was not. | [ ] |
| 36 | **Nothing verifies that any syslog listener actually BOUND, and `spool_backlog` cannot express "could not read".** `sock.bind`/`server.listen` report failure only through an `'error'` handler that just logs; `main()` never inspects the outcome and then logs `collector ready`. If every port fails to bind the process stays alive with no socket, and `lib/serverHealth.js` derives collector liveness from `max(recorded_at) FROM syslog_ingest_stats` — which `doFlush()` writes only when there is a batch, so a deaf collector is indistinguishable from a quiet fleet. `lib/syslog/collectorConfig.js`'s own header names this exact pair: "'we are listening and receiving nothing' and 'we are not listening where they are sending' look identical from the inside" — the guard was built for the CONFIG half and has no counterpart for the BIND half. **Partly addressed in v2.225.3**: the three silent `readdir` catches now log and count (`noteSpoolUnreadable`), so an unreadable spool directory no longer reads as an empty one. **Still open:** the bind check, and `syslog_ingest_stats.spool_backlog` being `INTEGER NOT NULL DEFAULT 0` with no NULL available to mean unknown — a schema change. ⛔ Also UNCONFIRMED and needing a Windows measurement rather than an inference: both UDP sockets are created with `reuseAddr: true`, and on Windows `SO_REUSEADDR` may let a second process bind a UDP port already held, which would split or divert the datagrams. 514 is LogVault's collector port on the shared staging box. | [ ] |
| 37 | ⛔ **A WHOLE-CONFIG READ FAILURE IS PERSISTED AS A MASS CONFIG DELETION.** `lib/engines/configDiff.js`'s `detectAndStoreDiff` diffs the two newest `device_configs` rows with no test of whether the NEWER snapshot is usable, and `diffConfigs` treats `null`/`{}`/a partially-parsed tree as a legitimate config — so every section absent from a truncated snapshot is emitted as `removed`. Upstream, Fortinet's `looksLikeConfig` is `/^\s*config\s+\S+/im`, so ONE `config <word>` line anywhere passes and a truncated or scope-restricted dump is stored. **Measured on production:** device TSR_EKM, 2026-08-06 10:26 — `0 added, 142 removed` across six unrelated top-level sections (ssl_vpn 65, fortiguard 45, snmp 12, log_syslogd 10, ntp 8, autoupdate 2) — then `142 added, 0 removed` with an identical breakdown **54 minutes later**. Nothing changed on the device. The operator was shown "somebody wiped the SSL-VPN, FortiGuard, SNMP, NTP and syslog configuration of this firewall", and the false change also drove a CVE re-match, an `auto` backup row and the `config_diff` outbound alert type. Fleet-wide, 3 of 362 rows match the signature (`removed > 20 AND added = 0`); the other two have no matching re-add and may be genuine. ⛔ The lesson was applied to ONE subtree and not the whole: `preserveSystemInfoOnReadFailure` and `cleanupSystemInfoReadFailureDiffs` cover `system_info` only, and `isSystemInfoPath` cannot touch these 142 rows. The exact upstream cause is UNCONFIRMED (truncation is likeliest, but a VDOM-scoped pull or an access-profile change gives the same shape) and the source snapshots are past `CONFIG_RETENTION_DAYS`, so **do not record a mechanism without re-measuring**. **Fix shape:** a wholesale-disappearance guard in `detectAndStoreDiff` — a behaviour change on the collect/store path, so it needs its own verification. | [ ] |
| 38 | **`collapseObjectArrayIdentityCascades` persists `diffValue()` output without the redaction pass its sibling applies.** Step 1 re-diffs two whole stored objects and splices the result straight into the diff that `collapseHistoricalArrayShiftCascades` UPDATEs into `config_diffs`. Every other persisting `diffValue()` call site redacts first — `diffConfigs`, and `filterDiffForCurrentRules`, which performs the structurally identical re-decomposition and DOES call `redactSecretEntries`. So a secret nested inside an opaque whole-object entry can be promoted into its own named top-level leaf entry, unredacted, and the rewrite happens on every deploy because this repair is NOT ledger-gated. UNCONFIRMED as a live leak: it needs a row that simultaneously has a matching identity in both a whole-element `added` and `removed` entry on one array path AND carries a secret under a pattern-missed key; none found. Partly mitigated in v2.225.3, which made `isSecretPath` match any path SEGMENT rather than the leaf only. `cleanupVolatileConfigDiffs` also runs earlier in the same migrate block and does redact. | [ ] |
| 39 | ⛔ **`[job-reaper]` DECLARES A STILL-RUNNING JOB FAILED AFTER 30 MINUTES MEASURED FROM `started_at`, NOT FROM ITS LAST PROGRESS REPORT — AND A `device_delete` ON A BUSY FIREWALL CANNOT FINISH IN ONE RUN.** `reapStaleJobs` selects `WHERE status = 'running' AND started_at < now() - 30 min` and never looks at `progress_current`; once reaped, `reportProgress`'s `WHERE id = $1 AND status = 'running'` silently discards every later update, so the UI freezes on a `failed` row while the work continues, and `finishJob` (no terminal-status guard) later overwrites the verdict with no record it was ever reaped. The threshold is then guaranteed to be crossed: `unlinkSyslogEvents` uses `eventBatchSize: 20000` with `eventPauseMs: 200` and `maxBatchesPerTable: 5000`, i.e. **1,000 seconds of pure sleep** before any UPDATE time, and it THROWS at the cap. **Measured on production:** TUM(TUTH1) holds **840,638,199** `syslog_events` rows → **42,032 batches against a 5,000 cap = ~9 consecutive re-runs**; ITC-SK 473M, SMT 436M, OKF(F2) 238M are in the same class. `deviceDeletion.js`'s own DEFAULTS comment sizes the cap against "3.35M events for a single device, measured" and calls 5,000 generous — the busiest live device is **251x** that. The operator is told the worker stopped and that they should re-run, which the index now permits, and `jobQueueInFlight` is held throughout so **no Collect Now anywhere on the fleet can be claimed**. Not yet triggered: `background_jobs` holds 4 rows ever and both past deletes were on devices with no syslog. REFUTED: the duplicate does not run concurrently (`jobQueueInFlight` serialises it). **Fix shape:** reap on last progress rather than `started_at`, add a terminal-status guard to `finishJob`, and re-derive the batch cap against the real fleet. | [ ] |
| 40 | ⛔ **THE MULTI-HOP SIMULATOR PICKS THE NEXT FIREWALL BY SHARED-SUBNET ADJACENCY ALONE — `neighbors[0]` — IGNORING THE ROUTE'S OWN `next_hop_ip`, AND REPORTS NO AMBIGUITY.** `resolveRoute()` returns `nextHopIp` and the orchestrator uses it only to test `=== null`; the next device is the FIRST entry of the adjacency list, never compared against the next hop the device itself named. `buildAdjacencyGraph`'s own JSDoc says the value is "An array, not a single value … so this never assumes exactly one neighbor" — the orchestrator assumes exactly that, and the entry-device loop `break`s on the first matching interface under the comment "never guess a starting device". **Three live instances measured:** (1) `TUG ethernet1/2` holds `0.0.0.0/0 via 192.168.100.1` but the only adjacent device on that subnet is `HRIS ethernet1/2 = 192.168.100.254` — not the next hop — so any TUG-sourced internet path crosses into HRIS and reports HRIS's verdict; (2) `SMT::tunnel.3` has TWO neighbours, `IDC FW:tunnel.18` and `ITC-SLY:tunnel.4`, both at 169.254.0.2, so the second hop is a coin flip between two Palo Altos; (3) `10.254.254.0/24` is held by FOUR devices all at `.1`, so entry selection is by Map insertion order. This is the damage `tests/topologyAdjacency.test.js` describes — "evaluate the WRONG FIREWALL'S RULESET and return a confident allow/deny for a hop that does not exist" — reached by a path that test does not cover. **Fix shape:** prefer the neighbour matching `next_hop_ip`, and report ambiguity as a `note` rather than resolving it silently — a verdict-affecting change, so it needs its own measurement. | [ ] |
| 41 | **For Fortinet, `applyNat` treats derived per-policy NAT rows as one ordered first-match rulebase, so an `any/any` source-NAT row permanently shadows that device's destination NAT.** `lib/adapters/fortinet/cliParser.js` stamps `sequenceNumber = policy.policyid` on BOTH the destination row (from a VIP in `dstaddr`) and the source row (from `set nat enable`) — a firewall-policy id, not a NAT precedence ordinal. CLAUDE.md states the premise: "FortiOS has no separate ordered NAT rulebase like Palo Alto". Sorting those into one list and returning on first match lets a low-numbered policy's source NAT pre-empt every higher-numbered policy's destination NAT. **Measured:** TSR-TL's source-NAT row at policy 2 is `all/all`, so its only DNAT row (policy 6, `171.99.128.101 → 192.168.3.7`) can never apply — 1 of 1 DNAT rules on that device permanently unreachable, and inbound paths end in "no route known beyond this device" instead of reaching the internal host. Fleet-wide 11 DNAT rows sit after an `any/any` source row (IDC FW 7, TFM-MH 3, TSR-TL 1) but **only the TSR-TL one is a defect** — on Palo Alto the NAT policy genuinely IS first-match across the rulebase, so that ordering is faithful there. **Fix shape:** split the match by `nat_type` for vendors whose NAT is per-policy rather than an ordered rulebase. | [ ] |
| 42 | **`buildExposurePaths` drops a rule whose source or destination resolves to nothing, treating "we could not resolve it" as "not internet-facing", and the counter that would disclose it is incremented AFTER the drop.** `sourceHasPublic` is true only via `isAny` or a resolved non-private range, so a source of object names that resolve to nothing yields `ranges: []` with `unresolvedNames` populated — `matchesAddress`'s `'unresolved'` state — and is `continue`d exactly like a confirmed-internal rule; `unresolvedRules++` sits three lines after the `continue`, so a dropped rule is never even counted, and the counter is read by nothing under `app/` or `components/`. This is the direction `exposure.js` itself calls the worse one ("under-reporting exposure is the more dangerous error"). **Measured: zero live paths today.** 39 enabled allow rules fleet-wide have a fully unresolvable source (PAKFood 21, TSR_EKC 10, TSR-TL 8 — all three devices have no `network_objects` rows at all); of the inbound-or-unverified subset only TSR_EKC qualifies, and TSR_EKC has 0 `device_interfaces` rows so it produces no paths regardless. It bites the first time an inbound rule on an object-less device meets a collected public interface. Distinct from row 26 — these names match no `network_objects` row of any type. | [ ] |
| 43 | **`paloalto/sshParser.js` uses `if (srcTranslated) … else if (dstTranslated)`, so a PAN-OS NAT rule performing BOTH translations is stored as a source-NAT row only and its destination half never reaches `nat_rules`** — which would also hide a published address from `exposure.buildDnatMap`. Found while auditing the topology family; UNMEASURED (nobody counted how many live PAN-OS rules carry both), and the fix belongs with the adapter, not the engine. Measure before acting. | [ ] |
| 44 | ⛔ **~22 SITES RENDER SMALL BODY TEXT IN THE RAW SEVERITY RAMP, AT 3.44–3.64:1 IN THE DEFAULT LIGHT THEME — AND SEVEN OF THEM ARE THE WORDS "NOT MEASURED".** Each sets an INLINE `style={{ color: 'var(--yellow)' }}` or `'var(--sev-high)'` on 12–16px text, so the `--tint-*-fg` remap `StatCard`'s `TEXT_SAFE_VALUE` already performs is bypassed. `app/globals.css` records the numbers itself — "Measured on white: --orange 3.63:1 and --yellow 3.64:1. That clears WCAG 1.4.11's 3:1 for a non-text graphical object and FAILS 1.4.3's 4.5:1 for text." Worst instances: `cvssStyle` paints the CVSS score for the whole 7.0–8.9 HIGH band (the band boundary IS a contrast boundary, since >= 9 gets the passing `--red`), the log-search timeout banner that is the only thing separating "nothing matched" from "we never answered", and the `DeviceTrafficTab` banner naming which sources failed. ⛔ **The sub-class is worse than the contrast miss**: `ServerHealthWidgets.js` prints `These figures are NOT MEASURED, not zero` in amber, and `devices/[id]/page.js` prints `The size of this delete could not be measured` in `--sev-high` on the irreversible delete confirmation — while `components/ui/NotMeasured.js` states the rule being broken ("⛔ NEVER give this a colour from the severity ramp"). The same card uses `--unmeasured` for its VALUES and the severity ramp for the banner explaining them, so the mark is unlearnable. Dark theme passes (7.86–9.04:1); light is the default. ⛔ `tests/designSystemRamp.test.js` cannot see this shape — it matches a `color=` PROP on `<StatCard>` and object literals carrying `label:`+`value:`, not an inline style on arbitrary text, and says so in its own scope note. | [ ] |
| 45 | **Four accessibility defects on controls that are the only way to do something.** (a) `NotificationBell.js` renders each notification row as a bare `<div onClick>` with no `role`, no `tabIndex` and no key handler, so the per-alert deep links are MOUSE-ONLY (WCAG 2.1.1, Level A) — and the trigger has no `aria-expanded`/`aria-haspopup` (CONFIRMED live: both absent in the DOM). Mounted on all 30 dashboard pages; the sibling patterns in the same header (`HeaderSearch`, `JobCentre`) get both right. (b) `IdleTimeout.js` sets `role="alertdialog" aria-modal="true"` with NO focus management at all (`grep -c focus` → 0) — nothing moves focus in, confines Tab, restores it, or handles Escape — so `aria-modal` marks everything outside inert while the user's focus point is still out there, making "Stay signed in" unreachable for a screen-reader user. `components/ui/Modal.js` implements all four and documents why. (c) `ReachabilityTab.js` signals a segmentation violation by CELL OUTLINE COLOUR alone with the reason in a `title` on a non-focusable `<td>`; the `<Badge>` inside reads "Allow" on flagged and unflagged cells alike (WCAG 1.4.1). The rest of the repo pairs amber with a `⚠` glyph. (d) Four controls on privilege surfaces have NO accessible name — `LdapRolesPanel.js`'s three "Add a mapping" fields have visible labels that are siblings with no `htmlFor`/`id`, including the group-DN box that decides who becomes an Administrator, and `UsersPanel.js:235`'s per-row role `<select>`. `EntraRolesPanel.js`, written later over the same route, does it correctly, so this is house convention and the older panel predates it. | [ ] |
| 46 | **Two surfaces assert calm or completeness from a read they did not consult.** (a) `SecurityLogWidgets.js` awaits `getThreatCoverage(pool, 24)` into `coverage` and NEVER REFERENCES IT, rendering a plain `No named threats in the last 24 hours.` where its three sibling widgets render `<ThreatEmpty coverage={coverage}/>`. `lib/syslog/threatStats.js` names this exact string as what the guard exists to prevent — "a security dashboard asserting calm because its own aggregation has not run … it was the live state for the first minutes after the rollup shipped". (b) `OverviewComplianceCard.js` draws a 96px compliance donut plus six per-standard donuts with no gradeable-check denominator, calling neither `buildDeviceCoverage()` nor `deviceCoverageEvidence()` — the machinery v2.225.0 added for exactly this, and used one route over on `/compliance/[deviceId]`, whose `DeviceCoverageStrip` docblock says "the figure may never be read before the number of checks it rests on". So a Check Point at 78% off 9 gradeable checks is pixel-identical to a Fortinet at 78% off 25, on the first tab opened for a firewall, and clicking through shows the same score WITH a coverage grade — the two screens disagree about what the number is worth. | [ ] |
| 47 | **Three `StatCard` call sites can never show the dashed "not measured" border, and six KPI grids still use the `auto-fit` shape `KpiRow` was built to delete.** `StatCard` takes no `unmeasured` flag — it INFERS one from `color === 'var(--unmeasured)'` — and `ConformanceBoard` (5 tiles) and `VpnDetections` (4) pass `textColor` without `color`, so the attribute is never emitted although both render `<NotMeasured>` as the value. v2.200.0 is explicit that grey alone was judged insufficient (`--unmeasured` and `--text-muted` are four hex digits apart). Nine other call sites pair the two correctly, so the convention exists. `tests/cardSurfaces.test.js` pins the CSS rule and the `:not([data-unmeasured])` exclusion but never whether any caller sets the attribute, so it stays green. Separately, six grids are hand-rolled `repeat(auto-fit, minmax(...))` with 5 or 6 tiles — `ChangeOutcomeBoard` (6), `ConformanceBoard`/`ConsolidationTab`/`RiskyRulesTab` (5 each), `VpnDetections` (4), `DeviceStatusSummary` (3) — against `KpiRow`'s rule that `auto-fit` "cannot be fixed by tuning that number, because it does not know how many tiles there are". `ChangeOutcomeBoard`'s orphan is its QUIETEST tile, which its own ranking rules say must not be given prominence. Known-latent: `KpiRow`'s header already concedes it, and `tests/kpiRow.test.js` gates only three named adopters. | [ ] |
| 48 | **Three `.ai-codex/components.md` entries the code contradicts, on the file CLAUDE.md tells every session to read first.** (a) It says `HeadlineStats` "renders THREE SECTIONS" using "`.ov-grid[data-cols=N]`"; the code renders TWO `<section>`s and uses `<KpiRow>`, and `.ov-grid` was retired in v2.220.0 with no surviving CSS rule — `tests/overviewSections.test.js` asserts `!/ov-grid/`, so the build FAILS if a reader follows the index. The file contradicts itself: a later line already records the retirement, and the stale copy is the one filed where a reader would look. (b) It describes `ActiveVpnUsersTable` as a "CLIENT component … search box + 25-per-page pagination" eight lines after correctly recording that it is NO LONGER a client component because that state "AutoRefresh's router.refresh() silently reset mid-read" — so the later line instructs a reader to reintroduce the exact defect that was removed. (c) It names `IpsecTunnelsTable`'s prop `rows`; the signature is `{ tunnels, ... }`, so a call site following the index renders the component's own empty state, reporting a wiring mistake to the operator as a possible vendor collection gap. No live call site is affected today. Nothing in `tests/` validates `components.md` against component source. | [ ] |
| 49 | **Three ramp misuses on the evidence and brand axes.** (a) `ComplianceStandardsBreakdown.toneFor` returns `var(--accent-teal)` for the 75–89 band — `--accent-teal` IS `var(--primary)`, the token reserved for "this is interactive" — so the band ramp reads green → brand-teal → amber → red and a standard scoring 82% is drawn in the same hue as the "Compare devices" link two lines below. (b) `VpnDetections.STATUS_BADGE.measured` is `color: 'success'`, painting the EVIDENCE axis with the severity ramp's green, rendered immediately left of a `danger` findings count — so a credential-spray panel with 130 findings opens with a green chip read first, against CLAUDE.md's "the proof affordance may not borrow from the severity ramp at all". (c) `UserMenu.js:76` is `boxShadow: '0 2px 6px rgba(200,16,46,0.4)'` — `#C8102E`, the RETIRED suite red that `--primary` used to be: the avatar's fill was migrated to `var(--primary)` and the shadow tuned to the old red was not, so a teal circle sits in a red halo on every authenticated page. `tests/loginPage.test.js` is precisely the guard for that literal (`assert.doesNotMatch(src, /#C8102E|200\s*,\s*16\s*,\s*46/i)`) but its scope is the login page only, which is how this survived with the rule written down AND a test for it in the repo. | [ ] |

⛔ **A6 SHIPPED IN v2.196.0 AND THIS PARAGRAPH SAID IT HAD NOT, FOR 28 VERSIONS.** It read "A6 and
A9 remain UNBUILT" and predicted A6 would "arm with no code change" on 2026-09-29 — a prediction
this file then never came back to check. What actually happened is better than the prediction:
`lib/engines/anomalyDetections.js` + `anomalyDetectionsData.js` + `seasonalBaseline.js` ship **two
measured detectors** (`device_silent`, `denied_spike`) wired into `notificationDispatch.js`, and
**two candidates measured and REFUSED** (`total-events spike`, `vpn auth burst`). **A9 remains
genuinely unbuilt.** **A8 SHIPPED in v2.192.0** and A7 in v2.191.0. Do not read the ✅ rows there as
progress on A9.

### New analytics, measured 2026-09-25 — tracked in `analytics-proposal.md`

Nine analytics buildable with **no LLM and no local AI**, each grounded in a live measurement.
⛔ **The tracking table lives in `analytics-proposal.md`, not here** — one Done column, not two, or
they drift. `⧖` means BUILT AND IN THE TREE BUT NOT RELEASED: no version bump, no `releaseNotes`
entry. It is neither `[ ]` (which would send a session to rebuild it) nor `✅` (which would have it
looked for in a release that does not carry it). ⛔ **Nothing carries `⧖` today** — A7 held it and
shipped in v2.191.0; the state stays defined because the next unreleased item will need it.

Three items were nearly written as new proposals and are NOT: seasonal baselines are Tier 1 #2
below, bandwidth forecasting is Tier 2, and a general flow rollup was already refused.

The headline, because it reorders the usual instinct: **the analytics are bounded by EVIDENCE
COVERAGE, not by algorithms.** So decisions-from-existing-findings come first, coverage second,
detection third.

| # | Item | Measured justification | Done |
|---|---|---|:--:|
| A1 | **Upgrade planner** | 246 assessments → ~16 decisions. Every Palo Alto carries **17 advisories across 7 target versions**, so one upgrade clears all 17. ⛔ **30 of 246 have no fix version — including ALL THREE `patch_now`** (CVE-2026-24858, CVSS 9.4, KEV, on three Fortinets): the fleet's only urgent CVEs are un-actionable and nothing says so | **[x]** v2.187.0 |
| A2 | **Blind-spot register** | **PAKFood is fully collected and sends ZERO syslog**; all five Fortinets are 100% unmeasured `hit_count` while being the highest-logging devices on the fleet; TUG is 54/54 unmeasured. All three render beside fully-evidenced devices with nothing distinguishing them | **[x]** v2.188.0 |
| A3 | **Log-derived rule usage** | ~84 of 235 unmeasured rules gain evidence (54 Fortinet by rule-id, 30 Palo Alto by name). ⛔ Never written into `hit_count`; name-matching is a weaker grade and may not authorise a deletion | **[x]** v2.189.0 |
| A4 | **Object & rule consolidation** | 3,298 of 10,092 objects (33%) referenced by nothing; 771 duplicates; up to 405 rule rows removable. ⛔ Needs **no hit counts**, so it is the one cleanup analytic that is conclusive on Fortinet | **[x]** v2.190.0 |
| A5 | **Fleet conformance / odd-one-out** | 11 Palo Altos, 5 Fortinets. The only one that DISCOVERS checks the 45-check library lacks. ⛔ Majority ≠ correctness — reports "1 of 11 differs", never "misconfigured" | **[x]** v2.190.0 |
| A7 | **Change → outcome correlation** | Tier 3, and the most differentiating item in the file — SecVault is the only product here holding the change record and the traffic outcome in one database. ⛔ **THE CONTROL IS THE FEATURE:** measured 2026-09-27, 24h either side of a real config change averaged **+13.6%** (61 changes) against **+17.6%** for an ORDINARY day (284 pairs) — *the change-adjacent delta is smaller than the noise*, so a bare before/after percentage would have manufactured 61 effects. Verdict is `exceeded_normal_variation` vs `indistinguishable`, never "significant", and never causal. ⛔ This row read **⧖ BUILT, NOT RELEASED** for a full release after the one that carried it | **[x]** v2.191.0 |
| A8 | **Remediation velocity (survival)** | Tier 3. ⛔ Its honest first output IS the finding, and it is sharper than the proposal predicted: measured 2026-09-28, **246 open exposures, 0 remediated, median time-to-remediate NOT REACHED in 74 observed days**. **0 of 16 firewalls have ever changed version** (3,954 version rows, 16 distinct (device, version) pairs), and **3 KEV-listed exposures have been open at least 69 days**. 794 advisories testable, 0 reconstructed remediation events, 638 ms | **[x]** v2.192.0 |
| A9 | **VPN behavioural profiles** | Tier 3. Re-measured 2026-09-28: **7,145 sessions, 608 users, 38 days of history, 11.8 sessions/user — but only 209 of 608 users (34%) have ≥10 sessions.** ⛔ That is the hard number behind the proposal's "gate PER USER, not fleet-wide" rule: a fleet-level gate would arm the detector for the two-thirds of users who have no usable baseline. Stale-account detection stays unanswerable until December | [ ] |

⛔ **`eol_catalogue` IS NOT IN THIS DATABASE.** The nocvault-eol hub holds 2,770 rows; here the
table is absent entirely. Probably the largest missing DATASET available to this product — it would
need a signed feed mirroring `cveHub.js`. Not proposed yet, recorded so it is not forgotten.

### ⛔ Deliberately NOT doing — do not re-propose without new evidence

- **More vendors, more reports, more CVE feeds.** Eleven reports, six vendors, eight advisory
  sources already. Breadth is not the constraint; a seventh vendor adds surface area to a product
  that just demonstrated it can ship forty defects in a day.
- **Rewriting the evidence model.** It is the strong part and it survived adversarial review.

### Confidence note on the judgements above

Items 1-3 and 10-20 rest on code read closely and data measured live on 2026-09-21/22. Items 4-9
are partly inference from `CLAUDE.md` and these index files rather than from reading every engine —
and documentation in this repo was found WRONG twice on 2026-09-21 (the smoke harness called
unbuilt eight versions after it shipped; a chassis change called a no-op for every caller when it
moved the monthly compliance PDF). Re-measure before committing to 4-9.

## Already built (do not re-propose)

| Capability | Evidence on the live fleet |
|---|---|
| Syslog ingestion, spool, archive, partitioned raw store | ~74M events/day, 30-day raw window |
| Ten traffic/security rollups + a separate fast threat rollup | 219k talker, 146k blocked-dst, 114k app rows |
| **Rule-hit correlation from logs (Phase 8b)** | 139,926 rows, all 15 devices (2026-09-25; was 8,803 on 2026-09-09). ⛔ **BY RULE ID IT IS FORTINET ONLY** — Palo Alto logs carry **0 distinct rule ids across 78,733 rows**, names only. This row read as fleet-wide coverage and is not; see `analytics-proposal.md` A3 |
| **Tri-state `hit_count`** | 235 unmeasured / 446 measured-zero / 1,101 with hits (2026-09-25). ⛔ **181 of the 235 are Fortinet — all five are 100% unmeasured**, and TUG is the only Palo Alto like it (54/54) |
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
| Reporting platform, catalogue + **11 reports** | Phase D v2.123.0; +Traffic Activity v2.156.0, +Rule Risk by Traffic v2.158.0 |
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
| **A1 — Upgrade planner** | v2.187.0; `/vulnerability?tab=upgrade`, `lib/engines/upgradePlan.js` + `upgradePlanData.js`. Live: **246 open assessments across 16 firewalls → 16 upgrade decisions**, 27 unplannable. ⛔ `inBranch` is recommended EVEN WHEN a branch move clears more — the literal Pareto frontier told three FortiGates on 7.4.9 to go to 7.6.7, a platform migration, and both numbers were right while the advice was wrong |
| **A2 — Blind-spot register** | v2.188.0; `/coverage` (Monitor → Coverage), `lib/engines/coverageRegister.js` + `coverageRegisterData.js`, and **work-queue source #11** (`coverage`, in `NEVER_ACT_NOW_SOURCES` — every item is `unmeasured` by construction). Live: **0 of 16 devices fully covered**. Ranks by CONSEQUENCE, not gap count. SCOPE-AWARE — one of only a handful classified `aware` |
| **A3 — Log-derived rule usage, graded** | v2.189.0; `lib/engines/ruleHitCorrelation.js` gained an ADDITIVE grade (`logEvidence` values unchanged), `components/analysis/UsageGrade.js`, the `Hits` column on `/devices/[id]/rules` became **`Usage`**, and the grade travels into the change-request document. ⛔ Never written into `hit_count`; **ID-grade and NAME-grade are different grades** and only ID satisfies the `ruleChangeRequests` deletion bar; absence from logs stays `unmeasured`, never a measured zero |
| **A4 — Rule & object consolidation** | v2.190.0; `lib/engines/ruleConsolidation.js` + `ruleConsolidationData.js`, **Consolidation tab** on `/devices/[id]/analysis` (14 tabs now, inserted after `reorder`), plus `nat_rules` counted as an object reference surface in `objectUsage.js`. Live: **92 groups / 156 removable rows — 41 `safe_to_merge`, 51 `needs_review`** in 272 ms over 1,782 rules. ⛔ Needs NO hit counts, so it is the one cleanup analytic that is conclusive on the FortiGates. ⛔ Object consolidation was ALREADY BUILT (`objectUsage.js`, 2026-08-03) — the proposal said otherwise and would have had it rebuilt |
| **A5 — Fleet conformance / odd-one-out** | v2.190.0; `/conformance` (Risk → Conformance), `lib/engines/fleetConformance.js` + `fleetConformanceData.js`. ⛔ The cohort is `(vendor, mgmt_method)`, NOT vendor — TUG is the only Palo Alto collected over SSH and its parser emits a different structure, so a vendor-only grouping would have made this a false-finding machine on its first run. ⛔ MAJORITY IS NOT CORRECTNESS: `admin-ssh-port` is 4× `22` against OKF(F2)'s `5022`, i.e. the minority firewall is the HARDENED one |
| **A7 — Change → outcome** | v2.191.0; `lib/engines/changeOutcome.js` + `changeOutcomeData.js` + `components/analysis/ChangeOutcomeBoard.js`, rendered on `/devices/[id]/changes` above the change list. ⛔ This row said **"BUILT, NOT YET RELEASED"** for a full release after the one that shipped it — corrected 2026-09-28. See `pages.md` for the surface and the six verdicts. ⛔ **MEDIAN + MAD WAS TRIED HERE AND MEASURED WRONG** (17.3% of ordinary change-free days flagged); replaced by a per-device empirical quantile at a measured 5.3% |
| **A8 — Remediation velocity** | v2.192.0; `/vulnerability?tab=velocity` (the FOURTH tab), `lib/engines/remediationVelocity.js` + `remediationVelocityData.js` + `components/vulnerability/RemediationVelocity.js`. Live 2026-09-28: **246 open exposures, 0 remediated, median NOT REACHED in 74 observed days**, 0 of 16 firewalls have ever changed version, 3 KEV-listed exposures open ≥69 days, 794 advisories testable, 0 reconstructed events, 638 ms. ⛔ **`device_cve_assessments.assessed_at` COULD NOT BE USED** — all 246 live rows carry the same (today's) timestamp because the row is rewritten on every match run; it records when SecVault last LOOKED, not when the exposure began. ⛔ **A remediated exposure leaves NO ROW**, so events are reconstructed from append-only `device_versions` using `versionComparator.isInRange` UNCHANGED — without that path the 0% would be unfalsifiable, indistinguishable from an engine that never looked. ⛔ **TWO CLOCKS** (`daysSinceKnown` / `daysSincePublished`), both reported, never blended: 59 of 246 exposures were published >30 days before SecVault held them (mean 27, max 276). ⛔ Kaplan–Meier "survival" means STILL VULNERABLE, so S(t)=100% is the worst result wearing the number a dashboard tints green — the view never renders it |

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

### 2. Threshold and anomaly alerting — ✅ **BUILT v2.196.0** (two detectors; two refused)
⛔ **THIS SECTION DESCRIBED THIS AS UNBUILT FOR 28 VERSIONS, AND A CUSTOMER-FACING DECK WAS BUILT
OFF IT** that listed threshold/anomaly alerting as a competitor advantage SecVault lacked. It is
not. That is the concrete cost of a stale roadmap: not a wasted rebuild, a false claim to a
customer.

**Why.** A security product that cannot say "denied traffic from this country just tripled" is
missing table stakes, and FWA has had it for a decade. The dispatch half already existed
(`notification_channels`, `notificationDispatch.js`, four alert types); what was missing was any
alert driven by a *measurement* rather than a state change. **That is now built** —
`ANOMALY_ALERT_TYPES` is spread into `notificationDispatch.js`'s `ALERT_TYPES`, so an anomaly
reaches a Slack/Teams/email/webhook channel like any other alert.

Candidates the rollups already support, at no new collection cost: denied-traffic spike per
device/country, new attacker source, threat-severity escalation, VPN auth-failure burst (the
credential spraying found on 2026-09-08 would have fired this), collector ingest drop.

⛔ Thresholds must be explicit and per-rule, never a magic "anomaly score" — see CLAUDE.md's
rejection of a composite `log_hit` definition for the same reason.

⛔ **THE "3-WEEK GATE" PREDICTION BELOW WAS WRONG, AND `seasonalBaseline.js` FIXED THE REASON.**
This paragraph said A6 would arm on **2026-09-29** once `syslog_rollup_hourly` crossed three weeks,
giving "2.9 observations per hour-of-week bucket". Three observations cannot support a tail
threshold at all: the arming gate is OBSERVATIONS PER BUCKET, not weeks elapsed, and it is
`minObservationsFor(q) = ceil(2 / (1 - q))` — ~20 for q=0.90, so a 168-bucket hour-of-week model
needed **~14 weeks**, not three. A week-counting gate would have armed a model whose highest usable
quantile was **0.74**, i.e. a 26% false-positive rate by construction. The shipped detectors use
**hour-of-day** grain (24 buckets) for exactly that reason, and a thin bucket reports
`insufficient_baseline` — hatched and hueless, never a green all-clear.

⛔ **RE-MEASURED 2026-11-12 ON 65.3 DAYS (2.3x the October history). BOTH REFUSED CANDIDATES STILL
REFUSE.** `total-events spike` reaches 4.21 alerts/day at q=0.95 persist=3, still over the 3/day
bar, and q=0.975 / q=0.99 **cannot be armed at all** on 63 days — they need 80 and 200 observations
per bucket, i.e. 80 and 200 days, reached on **2026-11-27** and **2027-03-27**. `vpn auth burst`
prints as "viable" at 2.89 alerts/day and **must not be registered on that line**: 47.6% of buckets
fired against the ~10% a q=0.90 can produce by construction (worse than October's 33%), because the
series is TRENDING — mean failures per device-hour went 135 → 225 → 403 → 513 across five weeks,
driven by a real and growing external credential-stuffing campaign. A static baseline learns the
attack it exists to report. That candidate needs a trend-aware instrument, which is a new method
and needs its own harness run. Full detail and the re-measure dates are in
`lib/engines/anomalyDetections.js`'s own header.

⛔ **"MEDIAN + MAD, NEVER MEAN + σ" IS NO LONGER TAKEN ON TRUST — A7 FALSIFIED IT ON THIS DATA.**
A7 ran exactly that method (Iglewicz–Hoaglin's modified Z-score at its own standard 3.5) over the
same rollups, against a CONTROL of ordinary change-free days, and it flagged **17.3% of them**
(worst device 42.1%) — firewall traffic is heavy-tailed, and **a ROBUST estimator is not a
DISTRIBUTION-FREE one**. It was replaced by the device's own EMPIRICAL QUANTILE, whose
false-positive rate is `1 - quantile` BY CONSTRUCTION rather than by hope: measured **5.3%**. A6's
grain differs — hour-of-week LEVELS, not day-over-day DELTAS — so this does not prove median + MAD
wrong here. ⛔ **THE DECISION TAKEN: run A7's control harness against A6's grain and pick on the
MEASURED false-positive rate, rather than inherit a constraint already falsified once on this
data.** `lib/engines/changeOutcome.js` already exports `buildBaseline`, `median`, `quantile` and
`BAND_QUANTILE` for exactly that reuse. Either way the baseline is an input to a NAMED threshold,
never a composite anomaly score.

### 3. Report library and scheduling — ✅ **BUILT v2.225.0**
**Why.** FWA's real stickiness is not any single report; it is that a manager receives one every
Monday without asking. SecVault had the renderer (`pdfkit`, `complianceReport.js`) and a monthly
scheduler, for exactly one report.

The registry asked for here ALREADY EXISTED as `lib/reports/catalogue.js` (11 report types), whose
own header anticipated this work. What landed is the other two thirds: a schedule per report and a
recipient list per schedule, the latter reusing `notification_channels` rather than storing a second
copy of an address list. ⛔ The monthly compliance job was deliberately NOT ported onto it — it has
its own log table, index and alert type live on deployed servers, and rewriting it would risk a
double-send or a silent stop on the one report customers already receive.

⛔ Reuse `compliance_report_log`'s pattern: a partial unique index enforcing one success per
period, because the job runs both on cron and at every service start.

---

## Tier 2 — parity gaps against ManageEngine FWA

| FWA capability | SecVault today | Work |
|---|---|---|
| **Change management workflow** (request → approve → implement → verify) | ✅ **COMPLETED v2.225.0.** Request → implement → verify shipped v2.93.0 for RULE REMOVALS; v2.225.0 added the **approval step** (`approval_state`, gated on `manage_devices`, self-approval refused in JS and SQL with a 409) and **non-deletion request types** (`rule_modification`, `rule_addition`, `object_change`) | Done. ⛔ **The verifier was NOT generalised, and that remains the right call**: a modification or addition is present either way, so absence cannot test it — those types stop at `outcome='not_supported'`, which is NEVER folded into `unverifiable` (one is a capability gap that never clears, the other a collection gap that clears itself). Pointing it at `config_diffs` is still refused: a config diff cannot prove a specific rule by vendor ID is gone on every vendor. ⛔ Approval can never produce a `verified` — `approveRequest` writes the three approval columns and nothing else |
| **Capacity planning / bandwidth forecast** | ✅ **BUILT v2.225.0** as **/capacity, labelled "Bandwidth trend"** — `lib/engines/capacityForecast.js`, read-time, no schema change, no cron job | Done. ⛔ **10 of 16 devices are forecastable and all 10 are `paloalto`** — zero Fortinet, exactly as this row required, because FortiOS counters are cumulative. ⛔ **8 of those 10 report `no_detectable_trend`**, and the projection is WITHHELD there rather than softened — which is why the page is not called "capacity planning". ⛔ The 13-day gate is DERIVED from Sen's interval, the false-positive rate was MEASURED against a shuffled control (4.1–6.1%), and a robust percentile band was tried and refused for straddling zero on all ten devices |
| **Custom report builder** | ✅ **BUILT v2.225.0** — `custom_reports` + `lib/reports/customReport.js`: a named, saved selection of 9 sections that already exist in shipped reports, rendered through the same pdfkit pipeline. The registry this row waited for (`lib/reports/catalogue.js`) existed, and v2.225.0 put scheduling on it first | Done. ⛔ **Deliberately NOT a query builder** — arbitrary predicates would produce documents no engine stands behind. ⛔ Each section's caveats are rendered by the FRAMEWORK, not the section, so a user-chosen layout cannot strip the sentence that makes a figure honest. ⛔ **Not schedulable**: its scope is `entity` and `report_schedules.params` is a static allow-list that cannot carry a record id — a real follow-up, and the existing validator already refuses it rather than rendering a dead control |
| **Multi-tenancy / site scoping** | `devices.site` exists and is **empty on 14 of 15 devices** | Small technically, but pointless until sites are actually populated. Blocked on data, not code |
| **Granular RBAC** | **THREE roles since v2.110.0** (`super_admin`/`admin`/`operator`, nine capabilities); `viewer` is retired and unassignable. This line said "admin/viewer only" for nineteen versions | Only if a customer asks for something the nine capabilities cannot express. ⛔ Grants are listed explicitly per role, never derived by subtraction |
| Forensic log search | `/logs`, index-backed, honest about depth caps | **Done, arguably better than FWA** |
| Compliance reporting | **74 checks** (44 gradeable), 5 standards, PDF, and since v2.225.0 a per-DEVICE gradeable denominator beside every per-device score | **Done** ⛔ Do not read 74 as coverage: 30 rows are `not_evaluable_from_config`, which is honest rather than a shortfall — see the mock-fleet section below |
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

⛔ **THIS SECTION RECOMMENDED BUILDING SOMETHING THAT ALREADY SHIPPED, TWICE, FOR 28 VERSIONS.**
Both paragraphs below pointed the next session at "Tier 1 item 2 (threshold alerting) — dispatch
already exists, so it is mostly rule definition". It was built in **v2.196.0**. A "how to choose"
section is the one part of a roadmap a session acts on directly, so a stale recommendation here is
strictly more expensive than a stale status row elsewhere.

~~If the next session has one day: **Tier 3 item 1** (snapshot backfill), then start Tier 1 item 2
(threshold alerting).~~ Item 2 done v2.196.0.

~~If it has a week: **Tier 1 item 1**.~~ Done v2.93.0.

**Current state, 2026-11-12.** Tier 1 item 1 (rule cleanup loop) done v2.93.0; item 2 (threshold
alerting) done v2.196.0; **item 3 (report library and scheduling) is in progress in v2.225.0** —
`report_schedules` / `report_delivery_log` plus a schedule per report over
`lib/reports/catalogue.js`, which is the registry item 3 asks for and which already exists.
⛔ **Before picking anything from this file, check the claim against the code.** This document was
reviewed at v2.162.0 and the repository is far past it; every ✅/[ ] here is a claim about a commit,
not a measurement, and three separate A6 statements in this file were wrong by 28 versions.

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

### ⛔ MEASURED AND DEFERRED 2026-09-19 — instrumented instead (v2.151.0)

**The loss was not measurable, so the first change was to measure it.** Every upsert already
refused to clobber another vendor's row and then reported nothing: a permanently lost advisory
looked exactly like an update where nothing had changed. Both discovery feeds now count it
(`claimed_by_other_vendor`, with up to 10 worked examples naming the holding vendor) into
`feed_sync_log`. Fortinet is the exposed one — it runs LAST and republishes third-party CVEs.

**What the measurements say today:**

| question | measured |
|---|---|
| Stored CVEs matching 2+ supported vendors in NVD's own `configurations` | **0 of an 80-CVE spread** of the 1,021-CVE corpus |
| Palo Alto's published CVE ids held here under another vendor | **0 of 291** |
| CVEs the central hub holds under two vendors | **1 of 909** (CVE-2004-0112) |
| FK constraints that would have to move | **0** — all three reference `advisories(id)`, the UUID PK |

**What the change would cost, audited file by file:** 4 upserts break structurally (Postgres raises
`no unique or exclusion constraint matching the ON CONFLICT specification`); `cveHub.js` is keyed on
`cve_id` throughout and needs rekeying; ~8 read sites become WRONG in the dangerous direction — the
`/vulnerability` tiles (`COUNT(DISTINCT advisory_id)` aliased `*_cves`), the dashboard severity
histogram **which is persisted into the daily trend**, `RiskByCategory`, `reportStats` (PDF headline
figures) and `api/cve/fleet`; ~12 more silently pick an arbitrary vendor row, including the entire
advisory-curation surface, where a curator would write conditions onto one row and re-open the page
to find them gone. `lib/evidence.js` and `lib/answers.js` carry explicit comments promising these
numbers count DISTINCT CVEs — claims the change would falsify. And **no URL can address a specific
vendor's row**: every route is `[cveId]` with no vendor segment, which is the structural gap behind
every one of those.

⛔ **So it is a change to how this product COUNTS VULNERABILITIES, not a schema change**, and today
it buys about one CVE. Deferred on evidence, not on effort — and the counter is what will reopen it.
**Revisit when `claimed_by_other_vendor` is consistently non-zero**, which is the number to look for
in the NVD and Fortinet rows of `feed_sync_log`.

⛔ One thing the matcher makes safe either way, worth recording: `versionMatcher.js` selects
advisories with `WHERE vendor = $1` (the device's own vendor), so a second vendor row would be
picked up automatically with **no matcher change**, and no single DEVICE could ever double-count.
The inflation would be strictly fleet-level, across devices of different vendors.

## Two live data bugs found 2026-09-10 — #1 RESOLVED 2026-09-19, #2 still open

### 1. ⛔ RESOLVED — THERE WAS NO BUG, AND THE PROPOSED FIX WOULD HAVE CAUSED ONE

**Decision taken 2026-09-19 and recorded in CLAUDE.md: the vendor's 0.0 is a score, it is kept, and
no third-party score is imported over it.** Code, comments and `tests/cvssZeroScore.test.js` landed
with that decision.

⛔ **THIS ENTRY'S CENTRAL CLAIM WAS FALSE.** It said "CVE-2022-22963 sits in `monitor` on a
fabricated 0 when decision-tree rule 3 should fire — a real, live mis-prioritisation". Measured:
there is **no assessment for it at all**, nor for any of the other 45 zero-score rows. Palo Alto
declares PAN-OS `unaffected`, so no version range is extracted and no device can match. The entry
described a mis-prioritisation that was not happening, and prescribed importing CVE.org's 9.8 —
which is the Spring Framework's severity, and would have manufactured 46 urgent findings against a
product its vendor says is unaffected.

⛔ **WHAT WAS GENUINELY WRONG was two things neither of which this entry named:** the
`suspicious_zero_scores` report keyed on `cvss_source IS NULL` and therefore could not fire at all
after v2.104.0 stamped that column (live: 0 rows, permanently — re-pointed at zero-scores that DO
claim a version range, live 3 rows); and the guard that makes the whole thing safe had no test, no
comment, and was credited to the wrong line when one was first written.

(Original entry below, kept for the CVE ids it names and as a record of two successive wrong
diagnoses of the same rows — first "the feed fabricates a 0", then "the 0 is the vendor's but it
mis-prioritises".)

### 1-old. ⛔ CORRECTED 2026-09-11 — the 0.0 scores are the VENDOR’s, not a SecVault fabrication

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
**DONE 2026-09-19** — and this prediction was exactly right: measured before the change, the old
predicate returned 0 rows and could never return more.

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

## Reporting platform — Phase D complete (2026-09-15, v2.123.0); 11 reports as of v2.158.0

Registered in `lib/reports/catalogue.js`: Executive Security Posture, Rule Hygiene, Vulnerability &
Patch Posture, Compliance (fleet or one standard), Segmentation Posture, Lifecycle & Support,
Configuration Change Audit, VPN Access Review, Rule Change Request, **Traffic Activity** (v2.156.0,
charts v2.157.0) and **Rule Risk by Traffic** (v2.158.0). All verified building against the live
fleet through the route's own dispatch shape.

⛔ **EVERY REPORT NEEDS A DISTINCT GLYPH** and a test enforces it — the same wayfinding rule the
sidebar follows. Adding one means adding its icon to `GLYPHS` in `ReportWorkspace.js` as well as to
the catalogue entry; reusing an existing glyph fails `tests/reportRoute.test.js`.

### Operational reporting beyond Firewall Analyzer (proposed 2026-09-20, partly built)

The plan that produced the last three versions, recorded here because it lived only in a session
until now — which is how this file went 24 versions stale the first time.

| phase | what | state |
|---|---|---|
| 0 | Remove the dead FWA import scripts | done |
| 1 | Report chassis + catalogue hardening | done |
| 2 | **Scheduled report delivery** | ✅ **BUILT v2.225.0.** Was deferred by the user 2026-09-21 ("not that important now") |
| 3 | Traffic Activity report, arbitrary window | v2.156.0; charts and the web/application section v2.157.0 |
| 4 | **Rule Risk by Traffic** — the fusion report | v2.158.0 |

Phase 4 is what the competition structurally cannot build: a traffic tool has never read the
rulebase, a policy tool has never seen a packet. Live on this fleet, 11 of the 15 busiest rules
also carry a hygiene finding and 63% of the traffic on those rules runs on a flawed rule.

Still deferred, deliberately:
- **Scheduling and delivery** (Phase C). Only the monthly compliance report is scheduled today, via
  its own `compliance_report_log` + `notification_channels` path. Generalising that to any report
  means a schedule table, a run history, and surfacing failures in the work queue.
- **Per-device VPN detections.** `getVpnDetections` has no device filter, so a device-scoped access
  review carries fleet-wide detections. Closing this is an engine change, not a report change.
- **Per-user destinations in the VPN review.** Not possible without a rollup schema change —
  `syslog_app_hourly`/`syslog_blocked_dst_hourly` carry no `src_ip`, and `syslog_events` is refused
  (no `src_ip` index, ~28M rows/day).
- ~~**A render/page-load smoke harness.**~~ ⛔ **BUILT in v2.150.0** — this entry said "there is
  still none" for eight versions after it shipped, which is the precise failure this file's own
  opening paragraph complains about: a stale "not built yet" sends a session off to rebuild
  something that works. `scripts/smoke.js` signs in and loads all 28 pages asserting a per-page
  content marker, and `Update-SecVault.ps1` runs it after the HTTPS verify, non-fatally.
  ⛔ What IS still open: it needs `SMOKE_USER`/`SMOKE_PASS` in the deployed `.env.local` or it logs
  a SKIP rather than a pass, and it cannot be run from a dev machine with no local instance.

## Application-centric view — ⛔ PHASES 1 **AND 2** BUILT (v2.124.0, v2.129.0); phases 3-4 proposed

⛔ This heading said "phases 2-4 still proposed" while Phase 2 was live. The paragraph below
corrects it, but a reader scanning headings would not reach that — and `application-view-plan.md`
carried the same error in its own title until 2026-10-05.

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

---

## ⛔ `syslog_flow_hourly` — MEASURED 2026-09-22, THE PROPOSED SHAPE IS REFUSED

P2 #6 asked for a flow-grain rollup so `/applications` could answer "did this src → dst:port carry
traffic" instead of falling back to the weaker "a rule permitting it has seen traffic". The roadmap
required the decision be argued on measured cardinality. It now is, and the answer is no — **at the
proposed grain**.

Three hours sampled on the live fleet (never wider than one hour, per the `syslog_events` rule):

| hour | events | full flow grain | /24 subnet grain |
|---|---|---|---|
| 03:00 quiet | 1,823,848 | 193,873 | 41,745 |
| 11:00 busy | 4,719,321 | **884,882** | 135,854 |
| 20:00 evening | 1,985,879 | 223,163 | 50,373 |

⛔ **THE FULL GRAIN BARELY COMPRESSES — 5.3:1 ON THE BUSY HOUR.** A rollup that is one fifth of the
thing it summarises is not a rollup, it is a second copy with a longer retention. Weighting the
sampled hours across a day gives **~9.9M rows/day**, and these tables are kept INDEFINITELY:
roughly **360 GB in the first year**, still growing. Raw `syslog_events` is larger per day but is
bounded at 30 days; this would have no bound at all.

⛔ **AND THE MEASURING STICK IS NOT THE RAW TABLE, IT IS THE PERMANENT SET.** Every permanent
`syslog_*_hourly` rollup on this fleet totals **3.2 GB**. The full grain would be ~110x that in year
one; the /24 subnet grain ~1.8M rows/day, ~64 GB/year, still ~20x. Neither is a rollup-shaped cost.

⛔ **THE CROSS PRODUCT IS THE WHOLE PROBLEM, AND IT IS NOT FIXABLE BY COARSENING.** Source alone is
11,920 distinct values/hour (that is `syslog_talker_hourly`, which already exists and is cheap);
destination+port alone is 106,441. Pairing the two ends is what explodes it — which is exactly why
every existing rollup is source-keyed OR destination-keyed. Dropping to /16 reaches 47,660/hour but
merges unrelated networks, so it answers a question nobody asked.

### The viable shape: aggregate the DECLARED flows, not all traffic

⛔ **A GENERAL ROLLUP ANSWERS EVERY POSSIBLE QUESTION; ONLY A BOUNDED SET IS EVER ASKED.** Live
today: **5 applications, 92 declared flows.** A rollup keyed on (declared flow, device, hour)
is bounded by the DECLARATION, not by the traffic: 92 x 16 devices x 24h = **35,328 rows/day worst
case**, and far less in practice because a flow matches few devices. That is ~1.3 GB/year — about
1/50th of the subnet-grain general rollup, and it answers the question `/applications` actually asks.

⛔ **ITS HONEST COST IS NO RETROSPECTIVE HISTORY.** A flow declared today has no evidence before
today, and changing a declaration starts its history over. That MUST be stated in the UI as its own
state — a flow with no history yet is not a flow with no traffic, the same distinction
`vpnDetections` draws between "insufficient baseline" and "no data". A targeted rollup that rendered
its own youth as absence would be this codebase's signature bug wearing a storage optimisation.

⛔ **UNTIL THAT EXISTS, `/applications` KEEPS SAYING "a rule permitting this flow is in use".** That
wording is already correct and already weaker-by-design; it must not be strengthened on the strength
of a rollup that was refused.

**Status: P2 #6 CLOSED as specified** (the storage decision was the deliverable, and it is "no").
The targeted rollup is a new, better-specified item — argued, sized, and not yet built.

## ⛔ Two gaps the SIX-VENDOR mock fleet exposed (measured 2026-10-03)

Neither is visible on the production fleet, because it holds **5 Fortinet + 11 Palo Alto and
nothing else** — the two vendors with by far the most checks. Both were found within minutes of
seeding mock Check Point / Cisco ASA / Sangfor / Forcepoint devices.

### 1. THE LESS WE KNOW ABOUT A VENDOR, THE HEALTHIER ITS FIREWALLS LOOK

Measured on the 8-device mock fleet:

| device | vendor | gradeable checks | score |
|---|---|---:|---:|
| MOCK-CP-Perimeter-04 | checkpoint | 9 | **78%** |
| MOCK-FP-DC-07 | forcepoint | 9 | **78%** |
| MOCK-SANGFOR-Branch-06 | sangfor | 9 | **78%** |
| MOCK-ASA-Edge-05 | cisco_asa | 11 | 73% |
| MOCK-FGT-Branch-01 | fortinet | 25 | 60% |
| MOCK-FGT-Edge-02 | fortinet | 25 | 40% |
| MOCK-PAN-DC-01 | paloalto | 21 | 38% |

The three top scorers are the three vendors with **ZERO vendor-scoped checks** in
`lib/auditChecksSeed.js` — which carries 18 for `fortinet`, 14 for `paloalto`, 3 for `cisco_asa`
and **none at all** for `checkpoint`, `sangfor` or `forcepoint`. They score highest because they
are measured against 9 generic checks instead of 21-25, not because they are better configured.

⛔ **This is the codebase's signature bug at VENDOR grain.** CLAUDE.md already states it at device
grain — "a firewall nothing can be collected from renders as the healthiest device on the fleet" —
and v2.163.0 built `complianceCoverage.js` precisely so a thin denominator could not be read as a
posture. But `coverageEvidence()` is keyed **per STANDARD, never per DEVICE**: the per-device
`scorePct` is computed from bare counts with no coverage statement attached, so Check Point's
78%-on-9-checks renders identically to a Fortinet 78%-on-25. The guard exists and does not cover
this axis.

**Two separate pieces of work, and they are not the same:**
- **(a) Surface the denominator per device.** ✅ **BUILT v2.225.0** — `buildDeviceCoverage()` /
  `buildDeviceCoverageSet()` / `deviceCoverageEvidence()`, on `/compliance` (both views) and
  `/compliance/[deviceId]`, which carried no coverage statement at all before. The arithmetic is
  unchanged and still pinned by its own untouched test. ⛔ **The device bands had to be SEPARATE
  from the standard ones, which was not foreseen here**: `gradeFor(9)` is `moderate`, so reusing them
  would have graded these three firewalls "moderately evidenced" — the defect wearing the fix's
  clothes. `DEVICE_GRADE_THIN_MAX` is **13**, derived as `cisco_asa`'s full applicable count (the
  lowest ceiling any supported vendor has), so a device at or below it cannot have been broadly
  measured by construction.
- **(b) Write vendor-scoped checks for the three vendors that have none.** ◨ **ATTEMPTED v2.225.0,
  AND THE HONEST RESULT IS THAT IT IS NOT POSSIBLE FROM WHAT WE COLLECT.** The library went 45 → 74;
  of the 29 rows added, **27 are `not_evaluable_from_config`** and only **2 are gradeable** (one
  `admin_access_from_zone` each for checkpoint and forcepoint; **sangfor has zero**). The blocker is
  COLLECTION, not curation: Sangfor's parser extracts hostname, version, interface names and an
  unverified `ssl_vpn.enabled` and nothing else; Check Point returns `{gateway, api_versions,
  administrators}` — management-plane objects, and the adapter itself records that Gaia OS settings
  have no management-API surface; Forcepoint returns an SMC engine identity element. ⛔ **A predicate
  on an uncollected path returns `'no'`, a confident FAIL against the customer's firewall for our
  own blind spot**, so the honest shape is `na` with an operator-readable reason. **Not one of the
  29 rows produced a `fail` on any device.** So (a) is still what stops a thin denominator reading
  as clean, and this row's real remedy has moved to COLLECTING more config — which needs a live
  device for each vendor, the same blocker as the syslog parsers in §2 below. ⛔ **Do not re-read
  "74 checks" as coverage**: mapped is 74, gradeable is 44.

### 2. SYSLOG FOR FOUR VENDORS IS BLOCKED ON EVIDENCE, NOT EFFORT

`detectVendor()` handles **only** `fortinet` and `paloalto`, with a deliberate no-fallback. There
is no parser for `checkpoint`, `cisco_asa`, `sangfor` or `forcepoint`, so syslog from them would be
stored with `vendor NULL` — correct behaviour, and it tests nothing.

⛔ **The parsers may NOT be written from vendor documentation.** Every existing vendor field mapping
was read off REAL captured logs per this repo's "documentation lies" rule, and `scripts/mockSyslog.js`
states the sharper version: *a generator invented from documentation tests the parser against the
same guess the parser was written from, and agrees with itself.* Both halves would be wrong together
and the mock fleet would certify it.

**No source of real lines is currently available**, confirmed 2026-10-03: the production fleet is
5 Fortinet + 11 Palo Alto, and a 6-hour sample of `syslog_events` returned **zero** unparsed rows.
A test asserts `SENDERS` contains only the two parseable vendors, so nobody can quietly add a
fabricated generator for the others.

**The one untried source:** the preserved **335 GB FWA archive**, which ingested from **27**
devices against today's 16 and may hold lines from vendors since removed. If it does, the parsers
become legitimate; if it is the same two vendors, this stays blocked. Checking it needs a grep on
the production box.
