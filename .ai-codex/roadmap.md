# SecVault Roadmap

Living document. ⛔ **FULL BUILT-STATE REVIEW 2026-11-14 (v2.228.3) — ALL 42 OPEN ROWS WERE
RE-MEASURED AGAINST THE CODE, and the live-data ones against production.** This closes the gap the
header had been warning about since 2026-09-22 (v2.162.0), ~66 versions. A row carrying a
`RE-MEASURED 2026-11-14` note has been checked; one with no such note was confirmed STILL OPEN
exactly as written.

**What the review changed, which is the argument for doing it:** one row was already FIXED and
still filed as open (19); **one was mis-filed as housekeeping and is a live credential exposure
(20)**; two were latent and are reachable today (12, 14); one had drifted FURTHER than recorded
(28, 6.8x -> 8.2x); and six carried counts or premises that were simply wrong (10, 17, 44, 47, 50,
51) — including one claim (`DeviceStatusSummary` as `auto-fit`) that was never true at any point in
this repository's history. ⛔ **The error ran in BOTH directions**: rows overstating a problem cost
a session chasing something already fixed, rows understating one left a world-readable dump of
every role's password hash filed as "wasted disk".

**FLEET FIGURES re-measured 2026-11-14** (the previous set was 2026-09-09): **16 active devices**
(paloalto 11, fortinet 5), **81,943,462 syslog events in the last full day**, 67 days of
`syslog_rollup_hourly` history, 1,131 advisories, 1,803 firewall rules, 74 compliance checks, 100
nightly snapshots spanning 118 days. The FWA feature comparison that motivated this product is
still from 2026-09-09 and has NOT been re-measured.

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
| 0 | ⛔ **OUTBOUND ALERTING IS ENTIRELY UNCONFIGURED, SO ALL EIGHT ALERT TYPES ARE INERT. BLOCKED ON A CREDENTIAL ONLY AMRIN HAS — this is a CONFIGURATION decision, not engineering work, and no session can do it.** | Measured on production 2026-11-14, straight after the v2.228.5 deploy: **`notification_dispatch_log` is completely EMPTY — zero rows, every alert type, ever** — and `[notification-dispatch]` logs `finished in 1ms — dispatched 0 alert(s), 0 error(s)` on every 15-minute tick. 1ms is not "gathered and found nothing" (a real gather is ~3s); it is `runNotificationDispatch`'s zero-channel early-out, `if (channels.length === 0) return`. ⛔ **So no enabled `notification_channels` row exists and no fetcher is ever called.** Meanwhile `/work` carried **16 `act_now` items** that same day: 4 patch_now CVEs (**all four KEV-listed** — CVE-2026-24858 9.4, CVE-2026-109618 9.2, CVE-2026-0322 8.6, CVE-2025-61624 5.4, across 8 device-pairs), 1 critical compliance control, 9 licence expiries, 2 tunnels down. Every one of them visible on screen and reaching nobody. ⛔ **The engine, the dedupe/reconcile logic and all eight alert types are BUILT AND CORRECT** — what is missing is one row. ⛔ **It also means no dispatch-path fix can be verified end to end here**: v2.228.5 (row 15) closed a hole where `gatherSegmentation` fed the dispatcher a silent `[]`, and the fix is deployed and unit-verified but dispatches nothing today. That hole was STRUCTURAL — it would have bitten silently the first time anyone added a channel. ⛔ **What it needs:** a Microsoft Teams **Workflows** webhook URL (the legacy Office 365 connector webhooks were retired by Microsoft in May 2026; `lib/notify.js:47` already builds the Workflows-shape Adaptive Card envelope, so a Workflows URL is the one that works and a legacy `webhook.office.com` URL would have been the broken case), **or** a Slack webhook URL, **or** SMTP relay details. ⛔ Verify with the per-channel **Test send** (`POST /api/notification-channels/[id]/test`, `manage_settings`) rather than waiting out a 15-minute poll, and tick at least `work_act_now` and `patch_now_cve`. ⛔ **Asked 2026-11-14 and DEFERRED TO THE BACKLOG BY AMRIN** — do not re-raise unprompted, and do not configure a channel unilaterally: it is outward-facing and the URL is a credential. | [ ] |
| 1 | ✅ **v2.162.0** — **Route / component / DB-integration tests** | 3,460 tests and **zero** of any of those three kinds. The 28-page smoke sweep is the ONLY thing that loads a page. All four defects that reached the live fleet on 2026-09-21 sat in that gap: a 500 reachable only through a route, an auth mechanism nobody had read the library for, a writer broken on the line endings that actually ship. | ✅ |
| 2 | ✅ **v2.163.0** — **Compliance: state the COVERAGE DENOMINATOR, stop printing a bare per-standard %** | `/compliance` shows **"NIST 42%"** computed from **7 checks** — of which 3 are vendor-specific, so ~5 apply per device, and 4 are generic firewall hygiene (`rule-no-any-any-allow`, `rule-logging-enabled-on-rules`, `rule-has-explicit-deny-all`, `rule-no-external-to-internal-access`) wearing a framework's name. Library totals: CIS_V8 44, ISO_27001 35, PCI_DSS 21, SANS 12, NIST 7, out of 45 checks. This is the ONE place the product overclaims, and it is the product's own denominator rule turned inward. | ✅ |
| 3 | ✅ **v2.163.0** — **Compliance: exception / compensating-control workflow** | 151 failing checks fleet-wide and no way to record an accepted risk with an expiry. Every real audit conversation is "yes, and here is why that is mitigated". Without it the 51% score is un-actionable and people stop opening it — the same dynamic that got `new_finding` pulled from Alerts in July. CLAUDE.md already notes critical compliance failures have no acknowledgement mechanism. | ✅ |
| 3b | ✅ **v2.165.0** — **Compliance: say how old the score is** | Found while answering "how often do the checks run". Two of sixteen firewalls were scored on configurations collected 10 and 46 days ago, rendered beside fourteen 12-hour-old ones with nothing distinguishing them. ⛔ The age shown had to be the CONFIG's, not the last run's: the auditor reads the newest `device_configs` row whatever its age and stamps `detected_at = now()`, and TSR_EKC's audit had already run **18 days after** its last successful collection. A "run checks now" button would therefore have put a fresh date on month-old evidence — which is why the panel links to COLLECTION instead. | ✅ |

| 3c | ✅ **v2.166.0** — **Compliance reports: per firewall as well as per framework** | The report could narrow to one FRAMEWORK (a declared param) but not one FIREWALL — the entry was `scope: FLEET` and the route REFUSED a `deviceId` with a 400. Traffic Activity already solved this with `optionalDevice: true`, its own comment citing the compliance report as the precedent it copied; the pattern went one way and never came back. ⛔ Not a filter: every read re-scopes in SQL, so `applicable` becomes "can run on THIS vendor". Verified live — NIST on TSR_EKC reads *5 apply to this firewall's vendor* against the fleet's *7 ran across 16 firewalls*. | ✅ |
### P2 — structural, gets more expensive every month

| # | Item | Why, measured | Done |
|---|---|---|:--:|
| 4 | ✅ **v2.167.0** — **Predicate engine: iterate collections, not one fixed dot-path** | The single-path limit is the ROOT CAUSE of `predicate_type: 'not_evaluable_from_config'`, and `na` is **55 of 404** findings (14%). Anything genuinely per-rule is unanswerable by construction. Fixing this converts a real slice of `na` into actual answers and shrinks the "manual verification" pile. ✅ Built as `rule_property`, the UNIVERSAL quantifier beside `ruleset_property`'s existential one. ⛔ The data was already collected and never looked at: `raw_rule` is the verbatim vendor rule on the table this audit already queries. Live result: `na` 54 → 39, `fail` 153 → 165, and **622 enabled allow rules across nine Palo Altos have no log-forwarding profile**. ⛔ 33 Panorama-pushed rules are UNDECIDABLE, not violations. | ✅ |
| 5 | ✅ **v2.168.0** (foundation) — **RBAC device scoping** | Every role sees the ENTIRE fleet; there is no per-device or per-site grant. Fine for one 27-device organisation, and a hard cap on ever serving an MSP, a holding company, or "the Vietnam team sees Vietnam's firewalls". Architectural, so the cost only grows. ✅ Built DEFAULT-DENY: `user_device_scopes` + `lib/deviceScope.js` + a coverage register that fails the build on an unclassified surface. ⛔ Shipped at **4 aware / 71 blocked / 39 no-device-data** — a scoped account is REFUSED by anything not yet scope-aware, so partial coverage means LESS access, never a leak. Proven live: a 2-device account saw 2 of 16, out-of-scope returned 404, and **0 of 15 other firewalls were named anywhere in the list page response**. ⛔ **v2.168.0 SHIPPED THE REGISTER UNENFORCED** — `isScopeAware()` was never called at runtime, so a scoped account would still have been served the whole fleet on `/compliance`. Fixed in **v2.169.0**: `lib/deviceScopePaths.js` + `middleware.js`, with the scope flag in the JWT beside the role. Verified live — scoped account gets 307/403 on blocked surfaces and 1 of 16 devices on the aware ones, while an unscoped admin is unaffected on all of them. Settings → Users now has the editor. Opening up the remaining 71 surfaces is ongoing work, one at a time, each raising the floor. ⛔ **RE-MEASURED 2026-11-14: 6 aware / 99 blocked / 26 no-device-data** (131 surfaces). `AWARE_FLOOR` is **6** and MATCHES reality, and all six are named individually in `tests/deviceScopeCoverage.test.js`, so demoting any one fails the build rather than only a count drop. ⛔ The row's shipped-at-v2.168.0 figure (4/71/39) is labelled as such and is not stale in itself — but **CLAUDE.md's "measured 2026-11-02 at 6 aware / 91 blocked / 25" is now stale on two of its three numbers**. Stays `◨`: 99 surfaces still refuse a scoped account outright. | ◨ |
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
| 10 | ✅ **DONE v2.164.0** — the page sweep's `& node ... 2>&1` bypassed `Invoke-Native`, so node's TLS warning became a TERMINATING NativeCommandError and the first deploy that actually ran the sweep reported "completed WITH ERRORS" over a 28/28 pass. Four more unrouted redirects remain in `Restore-`/`Uninstall-SecVault.ps1` and `SecVault-Tls.ps1` (openssl), pinned as a SHRINKING allow-list in `tests/installerNativeCalls.test.js` rather than edited blind — those scripts are destructive or unexercised on a normal deploy. openssl is the one worth doing first: it writes progress to stderr routinely. ⛔ **RE-MEASURED 2026-11-14: THE COUNT IS BADLY STALE — 1 remains, not 4.** `tests/installerNativeCalls.test.js:71` now holds `KNOWN_UNROUTED = new Set(['SecVault-Tls.ps1:135'])`; `Restore-`:221 and `Uninstall-`:107/:113 were routed by the v2.175.0 lifecycle audit. ⛔ **And the survivor is not latently dangerous**: `SecVault-Tls.ps1:131-141` hand-rolls the exact protection (`$ErrorActionPreference='Continue'`, verdict from `$LASTEXITCODE` plus files-on-disk, `$prevEap` restored on both paths). Remaining debt is consolidation onto the helper, not a live misreport — so this is lower priority than written. | [ ] |
| 10b | `Update-SecVault.ps1` logs **"Step succeeded"** when the page sweep SKIPS — three deploys reported success for a gate that never ran. Cosmetic now the credentials are set, still dishonest. | [ ] |
| 11 | `drawBarChart` with more rows than fit a page shreds labels and bars onto different pages (`ensureSpace` can only add ONE page). Unreachable today — every call site caps at 15. ⛔ **FIXED, AND IT IS MUCH WORSE THAN “shreds” — STILL LATENT.** Measured with a real `PDFDocument`: 38 rows → 3 pages with the caption alone on its own page; **45 rows → 17 pages (38 bars on one, then ONE BAR PER PAGE ×14, caption on page 16 of 17)**; 60 rows → **47 pages**. Structural: the chart tracks its own local `y`, so once pdfkit auto-flows one label every remaining one triggers another page. ⛔ `ensureSpace` now RETURNS `{broke, fits, measured, needed, available, pageAvailable}` — it still breaks, because a fresh page is the most room there is, but “I broke the page” and “it fits now” are no longer the same answer — and `drawBarChart` bounds its rows on `fits === false`, disclosing a hueless `+ N more not drawn`. ⛔ **`fits` is TRI-STATE: `null` means the need could not be measured, never `false`**, because a caller must not drop content on the strength of a number nobody read; `fits === null` draws everything. Its own test caught `Number(null) === 0` reporting a null height as “fits, needs no space” — the `maxDevices` trap reproduced in page layout. ⛔ Smallest overrunning count is **38**; every caller caps at 10/12/15, so this stays latent. | **[x]** v2.228.12 |
| 12 | Chart captions sit OUTSIDE the height reservation, so the sentence stating a chart's denominator can land on the next page. ⛔ **RE-MEASURED 2026-11-14: REACHABLE TODAY, NOT LATENT — and `drawDonut` is the worse half.** `drawBarChart` reserves `items*(barH+gap)+16` and the bars consume `items*(barH+gap)+6`, leaving **10px** against a 7.5pt caption that runs 3-5 printed lines at `trafficActivity.js:540-543` and `ruleRiskByTrafficPdf.js:149-155`. `drawDonut` reserves `size+24` (144px) while its legend alone can reach `doc.y+145`, so it can overrun BEFORE the caption is drawn at all. Row 11 (one `addPage()`) stays genuinely latent — every call site caps at <=15 rows. ⛔ **FIXED, AND TWO OF THIS ROW'S OWN CLAIMS WERE WRONG.** The 10px slack is right. ⛔ **The “3-5 printed lines” figure is NOT**: measured at contentW 515.28 / 7.5pt, `trafficActivity.js:540` is **1 line (8.67px) and fits the slack**, while `ruleRiskByTrafficPdf.js:149` is **2 lines (17.34px) and split across the page break**. ⛔ **And the call site this row cites was never firing in the real document** — its caller at `ruleRiskByTrafficPdf.js:129` hand-reserves `15*20+60 = 360`, which dominates the chart's own reservation, so the repo's own `comparePdfs` finds that sequence **identical at all 721 cursor positions, before and after**. The defect was live in the HELPER (any new caller) and at `trafficActivity`'s sites. ⛔ `drawDonut` is indeed the worse half — reserves 144 while ring + 10-row legend + the truncation disclosure reach entry+**144.67**, and 12 slices produced **THREE pages** (legend, then the disclosure alone, then the caption alone) — ⛔ **but no current caller passes more than 8 slices against a 10-row legend capacity, so the three-page case is LATENT; what was live at the donut is the caption alone.** ⛔ **Also found and fixed, not in this row:** `drawTimeSeries` had the identical caption defect, and the legend-truncation disclosure was **OVERPRINTED by 2.67px** by the unmeasurable-slice note (y=336 vs y=342) — two hueless 7.5pt greys on top of each other, both of them this product's own “we could not tell you everything” sentences. ⛔ Captions are now measured **through `pdfSafe`**, because `installPdfSafeText` wraps `doc.text` and NOT `heightOfString`: a `⚠` measures 0 width raw and prints as `'!'`, so a raw measurement measures a string nobody draws. That guard is load-bearing on the donut (exact reservation) and belt-and-braces on the bar chart, whose slack absorbs one line — measured, so the test lives on the donut rather than being a guard that cannot fire. ⛔ Document impact swept over all 721 cursor positions: the two cited call sites are byte-identical, four others differ in 1.7–2.5% of positions and the difference IS the fix. **Caveat: synthesised datasets in the right shape, not the live documents** (those need a `pool`). 16 mutations, 13 caught, 3 reported as equivalent/unpinned. | **[x]** v2.228.12 |
| 13 | `drawDonut` has no `opts.format`, unlike `drawBarChart` — a byte-valued donut would print "1.1B" for one gigabyte. ⛔ **FIXED, and reproduced exactly as written**: `drawDonut` ignored `opts.format` entirely, and `fmtCompact(1073741824)` is `'1.1B'` — a gigabyte printed with a count-shaped suffix. It now takes `opts.format` with `drawBarChart`'s **exact** contract (same key, called with the value only, default still `fmtCompact`), so the two helpers cannot drift into two conventions. | **[x]** v2.228.12 |
| 14 | `lib/consoleUrl.js` accepts a zero-padded IPv4 and silently saves a DIFFERENT address (`192.168.010.1` → octal → `192.168.8.1`). ⛔ **CONFIRMED 2026-11-14 BY EXECUTING THE VALIDATOR, not by reading it:** `validateConsoleUrl('http://192.168.010.1:3010', {tlsActive:false})` returns **`{ok:true, url:'http://192.168.8.1:3010'}`** — accepted, silently rewritten, and the only warning emitted is the generic IP-SAN one. `IPV4_RE`/`isIpv4` are applied to the ALREADY-NORMALISED `parsed.hostname`, so the octal octet never reaches a guard. ⛔ **The fix is not a better `IPV4_RE`**: `http://0300.0250.0.1` -> `192.168.0.1` by the same route, and a bare decimal would parse as IPv4 too. Compare the RAW input against `parsed.hostname` and refuse any silent rewrite. This is the most dangerous field in Settings (its own section in CLAUDE.md says so) and the lockout guard runs on the rewritten address. ⛔ **FIXED 2026-11-14.** `typedHostOf()` pulls the host out of the RAW string with no URL parse (parsing is the thing being checked, so deriving the comparison from it would compare the parser with itself) and any disagreement with `parsed.hostname` is REFUSED, naming both addresses. Case is the one allowed difference — hostnames are case-insensitive and lowercasing changes no destination. ⛔ **A better `IPV4_RE` was the wrong fix and the tests say why**: octal (`192.168.010.1`), all-octal (`0300.0250.0.1`), bare decimal (`3232235777`, which `HOST_RE` accepts because it is all alphanumerics), short form (`192.168.1`), hex (`192.168.0x01.1`) and IDN punycode each reach a different address by a different route. All six refused, five legitimate forms still accepted, mutation-verified (removing the refusal fails exactly those six). | [x] |
| 15 | `gatherSegmentation` returned `[]` when called with no opts (the 15-min dispatch path), reported as `{ok:true, count:0}` — so a `violation_active` could show in `/work` as Act now and never reach a channel. Same shape as the bug v2.153.0 fixed. ⛔ **MEASURED BEFORE AND AFTER ON PRODUCTION 2026-11-14, same data, same dispatch options: `segmentation ok=true count=0` → `count=1`.** Both incompleteness guards in `fetchOpenWorkQueue` passed it, because an incomplete source claiming to be complete is what they cannot see. ⛔ Neither obvious fix was available: `omitSources` is refused for any source that CAN reach `act_now` (the reconcile would clear real work as resolved), and throwing would have fired the guard on every poll and silenced the whole alert type. So it now mirrors `gatherApplications` — use a handed-in result, else one COUNT on `segmentation_intents`, probe **fails open**, then evaluate. ⛔ **THE COST WAS MIS-MEASURED FIRST AND IS ~112ms, NOT ~6s.** The initial figure ("dispatch gather 3.8s → 10.3s") compared one run before the fix with one after, at different PostgreSQL cache states — it measured a cold read. Re-measured in one process, alternating both paths three times over the same warm pool: **median 2,906ms free vs 3,018ms self-evaluating**, because `gatherWorkQueue` runs its eleven sources under one `Promise.all` and segmentation's queries overlap the other ten. A cold standalone `evaluateSegmentation()` is 9.8s over 1,803 rules / 16 firewalls / 65-day window — what `/work` pays, not what the poll adds — and 2 counts while nothing is declared. Either way it was unavoidable: `violation_active` is defined by a MEASURED hit count, so the traffic evidence IS the answer. ⛔ A result with no `intents` array now THROWS, and `/work`'s duplicate error channel for this source was removed in the same commit. Live today the one declared intent (`untrust→private`, deny) is `violation_permitted` → `scheduled`, so nothing is being mailed yet — the hole was one measured hit from firing. | **[x]** v2.228.5 |
| 16 | `feedStatus`: an UNLISTED state ranks -1, wins the reduce, matches no branch, and falls through to `FEEDS OK`. The documented "drift makes the pill go loud" property does not exist — it goes green. Latent on today's seven states. ⛔ **CONFIRMED 2026-11-14 BY RUNNING THE REAL FUNCTION, not by reading it** — one synthetic state injected into `feedState()`, everything else untouched: `{state:'ok', ok:true, label:'FEEDS OK'}` beside a clean feed, **and the same when the unlisted feed was the ONLY one**, which is worse than this row claimed. ⛔ **The existing test was the reason it survived**: `tests/feedStatusPill.test.js` asserted `severityOf('some-state-nobody-added-yet') < severityOf('error')` and PASSED — the ranking was correct the whole time and the verdict one function away was not. Mechanism tested, outcome unguarded. ⛔ **FIXED v2.228.6.** Terminal `if (worst !== 'ok')` → state `unknown` / `FEEDS UNKNOWN`, naming the state it could not read; the green return is now unreachable for anything but a literal `ok`. It enumerates no state names, so it cannot drift from `feedState()` the way `STATE_SEVERITY` and the `rated` filter did. ⛔ **Testable only after a refactor**: no `feed_sync_log.status` string can reach an unhandled state (`feedStatusRank` sorts every unrecognised status into rank 1 → `degraded`), so the verdict moved into the pure exported `summarisePill(feeds)` — the `freshnessErrors()` precedent. 2 mutations verified red. | **[x]** v2.228.6 |
| 17 | `feedStatus`: blocked + skipped with nothing rated reports "deliberately skipped", claiming SecVault chose not to collect over feeds a publisher REFUSED. Reachable on a hub-only site (live: `nvd` skipped, `fortinet_psirt` blocked). ⛔ **RE-MEASURED 2026-11-14: REACHABILITY WAS OVERSTATED AND THE LIVE EXAMPLE DOES NOT REACH IT.** The whole block requires `rated.length === 0`, i.e. **all seven** `KNOWN_FEEDS` missing/skipped/blocked; on the hub-only site `cve_hub` and `kev` both succeed, so "nvd skipped, fortinet_psirt blocked" never gets there. The real defect is narrower and still open: the blocked branch is gated `blockedFeeds.length > 0 && skippedFeeds.length === 0`, so ONE skipped feed beside any number of blocked ones falls through to a sentence that names only the skipped ones — blocked feeds are neither counted nor named. ⛔ **FIXED v2.228.6, and the narrowed defect was confirmed by running it**: a synthetic full-coverage cycle (4 blocked, 3 skipped) reported `FEEDS SKIPPED` with the title *"Every advisory feed was deliberately skipped on its most recent cycle (NVD, Fortinet PSIRT, CVE.org)"* — **the four publisher refusals neither counted nor named anywhere on screen**, under a sentence claiming SecVault chose not to collect. ⛔ New state `uncollected` (`NO ADVISORIES`, hueless like either half alone, with its own `PILL_TONE` entry so it is a decision rather than a fallback to danger red) names both groups in separate sentences. ⛔ **The two causes are NEVER summed** — a refusal is not ours to fix and cannot be retried, a skip is a recorded decision; same call `capacityForecast.js` makes between `bytes_not_summable` and `no_log_coverage`. A test fails on a combined total. ⛔ Still reachable only when EVERY known feed is missing/skipped/blocked — one rated feed outranks both, pinned by a test. 2 mutations verified red. | **[x]** v2.228.6 |
| 18 | `docs/SIZING-AND-BACKUP.md` says ~8.4 GB/day archive; measured **4.0**. ⛔ **RE-MEASURED 2026-11-14 AND THE CORRECTION HAD ITSELF DRIFTED.** Docs say 8.4 GB/day, this row said 4.0; production's archive (`E:\SecVaultArchive`) holds **211.32 GB in 46 files**, i.e. **~4.7 GB/day averaged over the retained window and ~5.5 GB/day on recent complete days** (5.49/5.57/5.48/5.48/5.28 for 11-03..11-07). So neither published figure is right. ⛔ **And 8.4 is in FOUR files, not one** — `docs/SIZING-AND-BACKUP.md:50`, `docs/FRESH-INSTALL-CHECKLIST.md:258`, `CLAUDE.md:1758` and `CLAUDE.md:3626` — with three DERIVED figures resting on it in `SIZING-AND-BACKUP.md` alone (`:51` ~380 GB at 45 days, `:55` "add ~35%", `:57` "**Provision 1.5 TB**"). Not a one-cell edit; fix the rate and re-derive all three. ⛔ **FIXED v2.228.9, AND IT WAS FIVE DERIVED FIGURES, NOT THREE** — `SIZING-AND-BACKUP.md`'s 45-day archive (~380 GB → **~245 GiB**), its “add ~35%” rule of thumb (→ **~20%**), its “~35% of total footprint” reduction advice (→ **~23%**), its `SYSLOG_RAW_MESSAGE=all` projection (~2.7 TB → **~2.4 TiB**, which no longer fits the 1.5 TB it tells you to provision), and `FRESH-INSTALL-CHECKLIST.md`'s 60-day archive (≈500 GB → **≈330 GiB**). ⛔ **AND THE FLEET RATE ITSELF WAS WRONG, WHICH THIS ROW DID NOT MENTION AND IS THE DANGEROUS HALF.** The doc said 638/sec · 55.2M/day; re-measured 2026-11-14 over 14 days and all 24 hours it is **810/sec · 70.0M/day — understated 27%**. The archive errors were OVER-cautious, so nobody was ever under-provisioned by them; the fleet rate is the reference figure a reader scales their own estimate against. ⛔ **THE DOCUMENT CONTRADICTED ITSELF ON ONE SCREEN AND NEEDED NO MEASUREMENT TO CATCH.** It stated 55.2M events/day two lines above “Raw syslog per day ~31 GB”, and at the 415 bytes/row the same table declares, 31 GiB/day **is 80.2M events/day**. CLAUDE.md meanwhile said 74M — so three numbers, three values, one fleet. ⛔ **`tests/sizingConsistency.test.js` NOW FAILS THE BUILD ON EXACTLY THAT**: raw/day = events/day × bytes/row, the 30- and 45-day windows are multiples of their dailies, the rule of thumb's percentage matches the two figures above it, the provisioning recommendation covers the derived total, and every table row declares whether it is MEASURED or DERIVED. **M1 of its mutation set restores 55.2M/day and goes red**, i.e. the guard would have caught the original defect. 6 mutations verified. It deliberately checks only the ARITHMETIC — inventing a figure to compare the measurements against would be the fabricated-measurement bug. ⛔ **The 920 GB raw window and the 197 GB “measured” raw total were ALSO extrapolations**: the collector started 2026-09-08 and both were taken 2026-09-16, so 197 GB is **eight days of ingest, not thirty**, and the 30-day window has never been observed on this deployment. The doc's header said nothing was estimated from a datasheet — true, and read as “every number was measured”. ⛔ **FOUR FIGURES COULD NOT BE RE-MEASURED: the VPN dropped mid-task** (db size, raw-partition total, rollup total, bytes/row). They keep their 2026-09-16 dates rather than being restated as current. **Bytes/row matters most** — every derived figure multiplies by it — so re-measure it when the link is up; if it moved, every derived row moves. | **[x]** v2.228.9 |
| 19 | ~~`backfillPaloAltoVersionRanges` still reports `cleaned up 302` every deploy.~~ ⛔ **FIXED, AND THIS ROW WAS THE STALE ONE (re-measured 2026-11-14).** TWO independent fixes landed: the guard now uses `jsonEquivalent(row.affected_version_ranges \|\| [], freshRanges)` instead of `JSON.stringify` (v2.116.1 — the jsonb key-order trap), and the whole repair sits behind `isDone(pool, 'palo-alto-version-ranges', 2)` in the backfill ledger, so it runs once per install. ⛔ **Confirmed from production's own deploy log** (`update-20261113-222055.log`): `palo-alto-version-ranges: already done (rev 2) — skipped`, and no `cleaned up` line anywhere in the run. ⛔ **CLAUDE.md's "Unexplained, left gated but flagged" paragraph is now STALE and says this still happens on EVERY run** — correct it there too. | [x] |
| 20 | ⛔ **NOT HOUSEKEEPING — A LIVE CREDENTIAL EXPOSURE, RE-MEASURED 2026-11-14 AND ESCALATED OUT OF P4.** This row read "Stale `E:\SecVault_Backups` (~4.7 GB) left beside the current backup set", i.e. wasted disk. Measured on production: **two `pg_dumpall` files, 2,420 MB each, written 2026-09-08**, carrying `BUILTIN\Users:(I)(OI)(CI)(RX)` **inherited from the volume root**. A scan of the first file (counts only, values never printed) found **8 `CREATE ROLE` lines with 8 SCRAM password hashes and 128 `CREATE TABLE` statements** — a cluster-wide dump WITH DATA, so it also carries `users.password_hash`, `settings.admin_password_hash` and every `device_credentials` ciphertext. ⛔ **THIS IS ROW 33's EXPOSURE IN A DIRECTORY ROW 33's FIX NEVER LOOKED AT.** v2.225.3 hardened `E:\SecVaultBackup` and verified "0 of 56 files still grant a non-admin principal"; this path differs by ONE UNDERSCORE, appears **nowhere in the repository**, and is therefore never created, pruned or ACL'd by any code — it cannot self-clear, and no future backup run will touch it. ⛔ **The role hashes are CLUSTER-WIDE and shared with the five sibling suite apps**, and they are the PRE-ROTATION `claude_readonly` / `nocvault_readonly` values — so row 52's exposure is sitting in a world-readable file here, not only in git history. ⛔ **Fix is `icacls /inheritance:r` granting SYSTEM + Administrators only** (what `Backup-SecVault.ps1:311` already does for the live directory); deleting the two dumps is a separate, non-reversible decision. ⛔ **EXPOSURE CLOSED 2026-11-14; THE DELETION IS STILL A DECISION.** `icacls /inheritance:r` applied, granting only `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators` `(OI)(CI)F` — the same call `Backup-SecVault.ps1:305-309` makes for the live directory. ⛔ **VERIFIED AT FILE LEVEL, NOT FROM THE EXIT CODE**: both files re-checked individually, **0 of 2 grant any non-admin principal** (`BUILTIN\Users`, `Everyone`, `Authenticated Users`, `INTERACTIVE`), which is the check `Backup-SecVault.ps1` itself performs because a zero exit says icacls RAN, not that the ACL is what was asked for. ⛔ **STILL OPEN for the two dumps themselves** — 4.73 GB of 2026-09-08 pre-migration cluster dumps, outside every retention policy because the path exists nowhere in the repo. Deleting them is not reversible and is the operator's call, not a cleanup. ⛔ **AND THE ROOT CAUSE IS UNFIXED**: nothing prevents the NEXT hand-made directory under `E:\` from inheriting `BUILTIN\Users` read, so a backup written outside `$BackupDir` is exposed by default on this volume. ⛔ **RE-MEASURED 2026-11-15 AND THE EXPOSURE HALF IS GONE — THIS ROW'S CENTRAL CLAIM IS NOW STALE.** `E:\SecVault_Backups` grants **only `BUILTIN\Administrators` and `NT AUTHORITY\SYSTEM`, inheritance broken**; there is no `BUILTIN\Users` ACE on the directory or on either file. Both 2,421 MB dumps are still present (2026-09-08), so what remains is **4.84 GB of wasted disk and two stale copies of every secret at rest, protected exactly as the live database and `.env.local` are** — i.e. housekeeping, which is what this row said before it was escalated. ⛔ **Deleting them is still the operator's call and nothing here should do it unasked.** ⛔ **BUT THE SAME CLASS WAS LIVE IN TWO DIRECTORIES THIS ROW NEVER LOOKED AT, AND ONE OF THEM IS WORSE THAN THIS ONE EVER WAS** — `E:\SecVaultArchive` and `E:\SecVaultSpool`, both inheriting `BUILTIN\Users:(I)(OI)(CI)(RX)` from a volume root that still grants it, the spool additionally `(AD)`/`(WD)` i.e. WRITABLE into the collector's startup replay path. Fixed in **v2.228.14** (`installer/SecVault-Acl.ps1`, applied on every UPDATE because every deployed server already has those directories). See CLAUDE.md's backup section and row 68. ⛔ **The lesson is this row's own, turned one level out**: it recorded "row 33's exposure in a directory row 33's fix never looked at", and the fix for it looked at one directory too. ⛔ **PRODUCTION REMEDIATED 2026-11-15 22:09 local, ahead of the deploy**, with Amrin's go-ahead: the same `icacls` the installer now runs, applied to `E:\SecVaultArchive` and `E:\SecVaultSpool` over WinRM. Verified by re-reading both ACLs (directory clean, SYSTEM retained) AND the pre-existing `syslog-20261001.log.gz`, which lost the inherited ACE as `(OI)(CI)` predicts. ⛔ **And verified by OUTCOME, not just by ACL**: `syslog-20261115.log.gz` was written at **22:09:01** against a clock reading **22:09:03** — the collector appended two seconds after the change, so SYSTEM kept write access and ingest never paused. Collector `Running`, stderr clean. ⛔ The volume root `E:\` is deliberately NOT changed: it still grants `BUILTIN\Users:(OI)(CI)(RX)` and `Everyone:(RX)`, which is the Windows default and not SecVault's to rewrite — the per-directory lockdown is the fix, and v2.228.14 re-applies it on every update so a newly created directory cannot inherit its way back. | [ ] |

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
| 24 | **`versionComparator.parseVersion` returns FABRICATED ZEROS for a version it cannot read**, and says nothing. `parseVersion('fortinet', 'nope')` is `[0,0,…]`, which every conceivable target compares "at or above" — this codebase's most-repeated bug living in a version parser. ⛔ **`upgradePlan.branchOf` and its sibling ARE guarded** (a no-digit test plus an every-component-is-finite test, added 2026-09-27 after a KEV row with `fixed_in: 'Not applicable'` was reported as CLEARED and excluded from `unplannable`). ⛔ **THE REMAINING CALL SITES HAVE NOT BEEN AUDITED**: `lib/engines/versionMatcher.js` (3 sites), `lib/feeds/nvd.js`, `lib/feeds/paloalto.js`, and every adapter's `version_tuple` (`checkpoint/parser.js`, `cisco_asa/index.js`, `fortinet/parser.js`, `fortinet/ssh.js`, `paloalto/parser.js`, `paloalto/ssh.js`, `sangfor/index.js`). The right fix is probably at the source — return `null` for unreadable input and make every caller say what it does about that — but that is a breaking change across a matcher on the CVE path, so measure before moving it. ✅ **PARTIALLY FIXED v2.226.0, and `parseVersion` is deliberately UNCHANGED.** The additive half shipped: `parseVersionReadable()` / `isVersionReadable()`, built from the SAME parsers (all five funnel through `parseForcepointVersion`'s single `Number.isNaN`) rather than a second regex. ⛔ The roadmap said it "says nothing" — it DOES `console.warn`; what is wrong is the RETURN VALUE, which is what callers act on. ONE call site converted, the one where a fabricated zero becomes a vulnerability verdict: `isInRange` now IGNORES an unreadable bound instead of letting it narrow the range, which is CLAUDE.md's own "widen an uncertain bound, never narrow it". ⛔ The two bounds failed in OPPOSITE directions and only one was dangerous: an unreadable MIN never excluded anything, an unreadable MAX excluded EVERY real version, so a live CVE read NOT AFFECTED. ⛔ A range with NO readable bound decides nothing and is now COUNTED by `isUnassessableAdvisory` — measured live, **7 advisories, all `checkpoint`, all carrying a legacy CPE product name ('vsx_ng_with_application_intelligence', 'gold', 'ng', 'next_generation') in BOTH version fields**, all with 0 assessments because no Check Point firewall is deployed. 0 ranges have the mixed readable-min/unreadable-max shape, so **zero live assessments changed**; seven silent not-affecteds became counted gaps. ⛔ **STILL OPEN**: `versionMatcher`'s other 2 sites, `feeds/nvd.js`, `feeds/paloalto.js` and every adapter's `version_tuple`. ⛔ And the min-side readability check is an EQUIVALENT MUTANT today — measured, no test can make it fire, kept for symmetry and recorded as such rather than presented as a working guard. | [x] |
| 25 | **`tests/fixedVersionFromRanges.test.js` still pins EXACT SOURCE TEXT rather than behaviour.** Its section 3 slices `lib/feeds/fortinet.js` around `affected_version_ranges = CASE` and regex-matches the wording of the downgrade guard, so a harmless rename or reformat disarms it silently — a guard that cannot fire, which is the defect this repo names most often. ⛔ Its section 4 (the `cveHub` half) was ALREADY converted after the old four-regex version was demonstrated inert against a real disagreement, and `tests/fixBoundary.test.js` owns that behaviour — so the pattern to follow already exists in the same file. Convert section 3 the same way. ⛔ **DONE — AND THE OLD FORM WAS PROVED INERT, NOT ASSUMED TO BE.** Replayed verbatim against six scratchpad copies of `lib/feeds/fortinet.js`: it stayed GREEN against `THEN advisories.…` → `THEN EXCLUDED.…` and `AND NOT` → `AND NOT NOT` — **one token each, valid SQL each, and each PERFORMS the strict downgrade the arm refuses**, i.e. the 2026-09-25 incident restored. It also stayed green when the guard lines were commented out, and **FAILED on a behaviour-identical hoist** of two jsonb expressions into constants, which changed not one byte of emitted SQL — so it could not fire AND it cried wolf. Now executes the decision from the shared `hasUsableFixBoundary`, reads the protected value back through the real matcher, and asserts the arm over the statement the **real exported `upsertAdvisory`** hands a stub pool (SQL comments stripped first), with the predicate GENERATED by `hasUsableFixBoundarySql` and the invariant that the incoming value may win in exactly ONE place, the `ELSE`. No SQL evaluator was written — that would be a second parser disagreeing with the authoritative one. 6 mutations verified. New finding spun out as row 61. | **[x]** v2.228.12 |
| 26 | ⛔ **AN UN-ENUMERATED OBJECT GROUP RESOLVES TO A CONFIDENT `no-match`, WITH NO `unresolved` SIGNAL.** `lib/engines/objectResolver.js:159,319`. Three cases exit the group branch silently — empty `members`, a cycle, and a chain deeper than `MAX_GROUP_DEPTH` (50) — so `matchesAddress`/`matchesService` fall through to a definitive exclusion built from an object nobody read. The in-code comment justifies it for the CYCLE case only; the same branch covers the other two, where nothing was ever expanded. ⛔ **ROOT CAUSE IS ALREADY WRITTEN DOWN AND THE FIX ALREADY EXISTS ELSEWHERE**: `objectUsage.storeObjects` stores `members: (g && g.members) || []`, so a group the adapter enumerated WITHOUT members is indistinguishable from a genuinely empty one — and the identical defect was fixed in `ruleConsolidation`'s `dimensionOverlap` on 2026-09-26 ("a zero-range non-wildcard extent is `unknown`, NOT `no`"). That fix was never applied to the resolver that `topology.js`, `exposure.js`, `applicationView.js` and `applicationRetire.js` all reuse. **Three wrong outputs reproduced:** (a) Access Path returns `verdict: deny, hasCaveat: false` for traffic a rule permits; (b) `/applications` flips a `violation` to `unspecified` with `unverified: false` and `unverifiedReasons: []` — a hole reported as CLOSED, the direction that file's own header names as dangerous; (c) `applicationRetire`'s "only this application claims it" safety property is defeated with ZERO taints, reducing defence-in-depth to the one independent `not_cleanup_eligible` gate. **Live:** two empty address groups exist today (`TELEMETRY` on OKF(F2) and Vietnam-YCC), neither currently referenced by a rule — latent, one adapter hiccup from real. ⛔ Also a LEAD into unswept ground: the same confident `no-match` very likely produces wrong verdicts on `/topology` and `/exposure`, neither of which was reviewed. ✅ **FIXED v2.226.0.** `groupExpansionBlock()` / `groupUnresolvedLabel()` split the three exits: a true CYCLE stays silent (its members were already accumulated on the first visit, so nothing is lost — the one case the original comment was right about), while MAX_GROUP_DEPTH and a non-enumerable `members` now push `unresolvedNames`. Both the address AND the service branch, which had the identical defect. ⛔ **AN EMPTY ARRAY IS TREATED AS UNKNOWN TOO, AND THE REASON IS UPSTREAM**: all six parsers build group rows with an array either way (`Array.isArray(obj.members) ? obj.members : []`), so `[]` arrives meaning both "enumerated empty" and "never read" and the resolver cannot have the distinction. `objectUsage.storeObjects` now preserves what the adapter gave instead of `|| []` — which changes NOTHING today and is not claimed to; it is the half that would otherwise silently re-flatten a parser fix. ⛔ Live cost measured: **2 empty address groups (TELEMETRY on OKF(F2) and Vietnam-YCC), 0 referencing rules**, so no live verdict moved. 7 mutations verified red. | [x] |
| 27 | ⛔ **7 `rule_scan` COMPLIANCE CHECKS RETURN `pass` WHEN RULE ANALYSIS HAS NEVER RUN.** `lib/engines/configAuditor.js:995-1012`. `evaluateRuleScanCheck` resolves `pass` whenever `ruleFindingsByType` holds nothing for its types, and its `na` guard keys ONLY on `skippedPairwiseFindingTypes(ruleCount)` — the 1000-rule O(n²) cap. A device with a collected ruleset and NO `rule_analysis_results` rows gets nothing from that guard. This is the exact bug the guard's own header describes ("a device with more than 1000 rules scored PASS on both and was CREDITED in the compliance denominator for an analysis SecVault deliberately declined to run") at a SECOND cause it does not cover. **Measured on the 74-check library: `rule_scan` is 7 of every device's 21-27 gradeable checks, 27-33% of the denominator.** TUFF(TUTH3) would go 8/21 = 38% to 13/21 = **62%** — a 24-point lift from an analysis that never ran. Latent on this fleet (all 16 devices hold analysis rows, min 4) but reachable for a newly-added device audited before its first analysis, or one whose analysis has never succeeded. ✅ **FIXED v2.226.0, and it was WIDER than this row said.** Not 7 checks but **9**: 8 `rule_scan` plus `rule-no-external-to-internal-access`, whose verdict also comes entirely from `ruleFindingsByType`. ⛔ **8 of those 9 are `vendor: null`**, i.e. they apply to every firewall of every vendor — and CLAUDE.md records only **10** gradeable vendor-null checks, so a never-analysed firewall collected 8 of its 10 universal gradeable checks as free passes (a Sangfor, with 0 gradeable vendor checks, could not score below 80%). ⛔ The 2026-09-09 guard already WROTE THE SENTENCE — "ran the pass and found nothing, or NEVER RAN THE PASS" — and then tested only the SIZE CAP. The signal cannot be `rule_analysis_results` (zero rows IS the ambiguity); it is `device_risk_history`, the same one `lib/deviceContext.js` already uses. ⛔ THREE states, and an unreadable one fails to `na` with its OWN sentence; an omitted argument is `na`, never a pass. ⛔ The guard applies to the ZERO case only — a present finding is a MEASUREMENT and still fails — and sits AFTER the curated-data branch so a broken check definition stays visible on an unanalysed fleet. ⛔ Live: **0 of 16 firewalls affected today** (all 16 have a completed run), so this is the fresh-install and newly-onboarded case — the v2.94.0 OKF(F2)-at-100/100 shape, in the engine that writes the audit PDF. 8 mutations verified red. | [x] |
| 28 | ⛔ **THE `device_silent` DETECTOR FIRES AT 6.8x ITS RECORDED MEASURED RATE, AND NOTHING RE-MEASURES.** `lib/engines/anomalyDetections.js:131-141` records `alertsPerDay: 0.074`, justified 2026-10-06 on "16 silent device-hours in 9,720 (0.16%), falling in exactly TWO runs". Re-run against production 2026-11-13: **14 alerts over 28 days = 0.500/day**. TFM-MH now flaps on a ~2-hour cycle **12 separate times in 28 days** (39 silent hours of 672), and `SILENCE_MIN_HOURS = 2` sits at the minimum the persistence rule can express — so the "rare AND clustered" measurement that justified it no longer holds. `gatherAnomalies` emits one finding per RUN, so that is 12 separate "TFM-MH stopped sending syslog" notifications about one firewall, which is the `new_finding` noise failure that got an alert type pulled from the feed in July. ⛔ `assertRegisteredDetector` enforces that a measurement EXISTS, not that it still HOLDS — a guard that cannot fire on drift. ⛔ Note TFM-MH's flapping is itself a real collection problem worth chasing separately. ⛔ **RE-MEASURED 2026-11-14 AGAINST PRODUCTION AND IT HAS DRIFTED FURTHER: 8.2x, not 6.8x.** `gatherAnomalies(pool, {days: 28})` returns **17 `device_silent` findings over 28 days = 0.607/day** against the registered `alertsPerDay: 0.074` (`measuredOn: '2026-10-06'`). `assertRegisteredDetector` only checks those fields EXIST, so it cannot fire on drift — the figure is a claim about one afternoon in October that nothing re-tests. The ratio growing between two measurements is itself the argument for re-measuring on a schedule rather than at registration. ⛔ **FIXED 2026-11-14, AND THE FIX IMMEDIATELY FOUND A SECOND DRIFT NOBODY HAD FILED.** `rateDrift()` compares each detector's OBSERVED count against its registered rate on every run. Measured on production: `device_silent` **17 alerts in 28 days against a registered 0.074/day — 8.2x, p=9.6e-11** (this row said 6.8x, so it had drifted further between two measurements), and **`denied_spike` is `drifted_LOW`: 2 alerts where 28 were expected, p=2.9e-10** — a detector registered as firing daily that had almost stopped, which nothing had noticed because nothing re-measured. ⛔ **A POISSON TAIL ON THE COUNT, not a ratio threshold**: the registered 0.074/day comes from TWO observed runs, whose 95% interval spans ~0.24-7.2 events, so no fixed ratio can separate noise from drift — counts 0 through 5 over 28 days all correctly read `indistinguishable`. ⛔ **BOTH DIRECTIONS**, because a detector that quietly stopped is indistinguishable from a healthy fleet. ⛔ **IT REPORTS AND NEVER REFUSES** — a meta-check that could disarm a detector is the guard-that-cannot-fire pattern aimed at the alerting engine itself. ⛔ The measurement AGE is a separate fact (`reviewOverdue`, 90 days, stated as a cadence judgement not a derivation) and may not contaminate the statistical state — **a mutation that seeded the state from it ESCAPED the first draft of the tests**, because the age case used a drifted count and the drift branch overwrote the seed. | [x] |
| 29 | ⛔ **A WINDOW-TRUNCATED SILENCE RUN GETS A NEW `natural_key` EVERY HOUR.** `lib/engines/anomalyDetectionsData.js:115` keys on `run.startAt`, and `loadReportingGrid` generates hours from `now() - 28 days`, so a run whose true start precedes the window has `startAt` clamped to the window's advancing left edge. The dispatcher's reconcile clears every `natural_key` absent from the new list, so each hour a firewall silent for >28 days produces a **false "resolved" on the old key plus a fresh notification on the new one — ~24/day, for ever**. Latent today (no device opens the window silent) but TFM-RN already has a 108-hour run. ⛔ **FIXED v2.228.10, AND “LATENT” WAS THE WRONG WORD — IT IS DEFERRED, BY EXACTLY THE WINDOW LENGTH.** Every silence run that has ever been detected crosses the 28-day boundary eventually and churns for its own duration while it does; TFM-RN's measured 108-hour run would churn for 108 hours. It needs no unusual condition, only time. ⛔ **AND THE CHURN WAS THE SECOND OF THREE CONSEQUENCES, NOT THE ONLY ONE.** With `startAt` clamped to a boundary that advances hourly: (1) `hours` **SHRINKS by one every hour**, so a silence that is not ending renders as one that is getting better, and that figure is the only number the operator gets; (2) the natural_key churned, so the dispatcher's reconcile cleared the previous key as RESOLVED and raised the next as fresh — ~24 false pairs a day; (3) `startAt` was reported as a measured start time when the true start is outside our evidence entirely. ⛔ **THE SAME DEFECT WAS IN `detectSpike` TOO** (`run.startIndex === 0`), which this row did not mention — rarer, since it needs denied traffic elevated continuously across the boundary, but structurally identical, and a fix applied to one of two detectors is a defect waiting to be rediscovered. Both are fixed. ⛔ **A SENTINEL, NOT A GUESSED START.** There is nothing stable to key on inside the window, so a truncated run keys on `start-before-window` — no timestamp of any kind, since the bug WAS a key built from a moving boundary. One alert; when the run finally ages out the key disappears once and reconcile clears it once. `describeSilence` now says **AT LEAST N hours … began before SecVault's evidence window**, and the finding carries `truncated` + `hoursAreLowerBound` so no consumer can render either figure as exact. ⛔ Pinned BEHAVIOURALLY, not by shape: the test judges the same silence an hour apart, asserts the inputs really do move (`startAt` differs, `hours` shrinks) and that the key does not. 5 mutations verified red. | **[x]** v2.228.10 |
| 30 | **The fleet compliance `overall` counts each finding once PER MAPPED STANDARD.** `lib/engines/dashboardSnapshot.js:88-102` sums `pass`/`measurable` across `STANDARDS`, so a check mapped to five frameworks counts five times and one mapped to none is excluded. The per-device page counts each finding once. Measured: 479/1016 = 47% (standard-expanded) against 175/365 = 48% (one row per finding). One point apart today, so nothing looks wrong — but `overall` feeds `computeSecurityScore`'s 30%-weighted compliance component and the nightly snapshot, and the skew moves with the library's standards mapping rather than with the fleet. ⛔ **DONE, AND THE SECOND HALF WAS THE LIVE DANGER.** `overall` now counts each finding ONCE, in (device, check) PAIRS, using the per-device page's own `statusCounts` arithmetic rather than a third definition; the per-standard figures keep their standard-expanded counting, pinned, with the flattening mutation RED. ⛔ **Half 1 measured on the live library: 2.642x expansion** (197 mappings over 74 checks), non-uniform — 4 checks carry 1 standard, 38 carry 2, 6 carry 5 — so the skew does not cancel: a 16-device fleet built from the real mapping scored **51% expanded against 45% per finding**, against the 1 point the reference fleet happens to show. The skew moves with CURATION, not with the fleet. ⛔ **Half 2 was worse than this row said — it could erase a FAILURE:** `{CUSTOM}` (named legitimate in `schema.sql`) or `'{}'` (permitted by `TEXT[] NOT NULL`) made one `pass` + one `fail` report **`overall = 100%`**. Latent in the seed (0 of 74), structural in the schema. ⛔ **Two downstream callers were fixed in the same commit because one contradicted itself ON SCREEN**: `lib/evidence.js` renders the arithmetic beside the score and would have printed `479 ÷ 1016` then `→ 48%`, so `fleetHeadline.js` now hands it the pair counts wrapped in a one-key object (that function unchanged, its null-not-zero discipline untouched); and `complianceReport.js`'s `summaryFromPerDevice` reproduced the old sum ON PURPOSE, arguing a score must not change meaning with its scope — the principle is right and is exactly why it had to change. It also already disagreed with the device PAGE; that was pre-existing and is closed too. ⛔ An absent pair tally yields `null`, never a fallback to the other unit. Two tests that pinned the OLD definition were updated deliberately and say so. 8 mutations verified (one survived first — the exact-.5 operand-order boundary — and was closed). | **[x]** v2.228.12 |
| 31 | ⛔ **`getVpnTunnels()` RETURNS `[]` ON A PARSE FAILURE INTO A DESTRUCTIVE WRITER THAT READS `[]` AS "no tunnels".** `lib/adapters/paloalto/index.js:825`, `paloalto/ssh.js:938`, `fortinet/ssh.js:577` all end `catch { return []; }`. The consumer `lib/engines/vpnTunnels.js:31` is `DELETE FROM vpn_ipsec_tunnels WHERE device_id = $1` then reinsert, and its own header states the opposite meaning: "an empty array legitimately clears the device's tunnels". Producer and consumer disagree about what `[]` means — the `getRules()`-returns-`[]` class one table over. **Live blast radius: 165 rows, 163 `up`** (fortinet/ssh 10, paloalto/api 152, paloalto/ssh 3). A firmware whose output the parser does not recognise wipes every real tunnel for that device and nothing errors; those devices then render as disconnected on the fleet map, which is exactly what the VPN-tunnel-peer edges exist to prevent. ⛔ `connectors.md` does describe this as "best-effort (`[]` on parse doubt)", so the adapter's `[]` was deliberate — **the defect is the contract mismatch with a destructive consumer**, and the preferred fix is a real tri-state (`[]` = none configured, `null` = could not tell, consumer skips the delete on `null`) rather than making the adapters throw.  ✅ **FIXED v2.225.3 — the tri-state, as this row recommended.** `storeVpnTunnels()` now reads an ARRAY as a measurement (`[]` = genuinely none, rows cleared), `null`/`undefined` as NOT MEASURED (DELETE skipped, returning before the transaction opens), and any other shape THROWS — the old `Array.isArray(t) ? t : []` also turned the `undefined` of a method falling off its own end into a wipe. ⛔ **THIS ROW UNDER-COUNTED THE SITES: there are FIVE, not three.** It named `fortinet/ssh.js:577` but not that the same file ALSO swallowed a per-VDOM parse failure to `[]` inside the multi-VDOM loop (so that VDOM counted as a success contributing zero rows), and it missed `fortinet/index.js` entirely. ⛔ **And both Fortinet transports returned a PARTIAL VDOM result as complete**, which is the rule CLAUDE.md already states for `getRules()` ("collect every VDOM or fail") in a second method that rule never looked at — one VDOM failing deleted that VDOM's tunnels. Both now return `null`; the pre-existing every-VDOM-failed branches still THROW, because that is a transport failure rather than an unreadable answer. ⛔ **Residual, stated not hidden:** `cisco_asa`'s `parseVpnSessiondbL2l()` fails closed to `[]` INTERNALLY, so output it cannot parse still arrives as a measured zero; tightening it needs live `show vpn-sessiondb l2l` output to verify against. `tests/vpnTunnelContract.test.js` (27 cases) asserts on the STATEMENTS ISSUED rather than source text, and **re-derives the implementation set from source** — its first draft hardcoded four files and missed the fifth, which was the live-fleet one. 9 mutations verified. | [x] |
| 32 | **`normalizeCountry()`'s ISO map is incomplete, so the fold it exists to perform is a no-op for 17 live codes.** `lib/syslog/vpnAuthStats.js`. Executed over every ISO-2 value in `syslog_vpn_auth_hourly`: **27 of 44 map, 17 return verbatim** (AR BB BE EC EG GE GF HU IL JM KZ LB LC MA MQ TT UZ), and **8 countries are split live** — worst **KZ 230,935 + Kazakhstan 909**, also BE 6 + Belgium 3,829, HU 3 + Hungary 2,782, GE 2 + Georgia 647. Consumers that group on the post-normalisation key therefore still split: the VPN login-locations ranking shows one country as two rows with split counts (and with a top-N limit the smaller row can drop off entirely), and `vpnDetections.js:190`'s country filter shows duplicate options — the exact symptom that file's own comment records as FIXED. ⛔ The map's own comment invites extension ("a country missing from this map still ranks — a visible prompt to extend"), so this is the prescribed remedy, not a redesign. The same-hour "authenticated from both TH and Thailand" false positive stays latent only because every cross-form username found is on `failure` rows and that detection reads successes. ⛔ **DONE — all 17 codes added (44 → 61 entries), `normalizeCountry()`'s logic byte-identical: a data change, not a redesign.** AR Argentina, BB Barbados, BE Belgium, EC Ecuador, EG Egypt, GE Georgia, GF French Guiana, HU Hungary, IL Israel, JM Jamaica, KZ Kazakhstan, LB Lebanon, LC Saint Lucia, MA Morocco, MQ Martinique, TT Trinidad and Tobago, UZ Uzbekistan. ⛔ **Verified against production afterwards: all 42 live ISO codes now map.** ⛔ **A dependent territory keeps its own entry** (`HK: 'Hong Kong'` was the precedent), so GF and MQ are not 'France' — folding a territory into its parent would merge two genuinely different login locations on the page whose job is to say where a session came from. ⛔ **The split was reachable as a FALSE DETECTION, not merely a bad ranking** — measured both ways through the real `buildCountryChangeDetection`: one user seen from `KZ` then `Kazakhstan` two hours apart gave **1 finding unmapped, 0 mapped**, a spelling difference manufacturing a geographic anomaly. ⛔ **`tests/vpnDetections.test.js` used `KZ` as its exemplar of an unmapped code** — the bug as the fixture for the contract — so fixing the bug broke a test whose invariant was never wrong; replaced with `ZZ`, unassigned in ISO 3166-1 and so unable to become valid. ⛔ Residue spun out as row 60 (three map values that do not match the long form the devices send). 19 tests, 8 mutations verified. | **[x]** v2.228.12 |
| 33 | ⛔ **`CREDENTIAL_KEY` WAS READABLE BY EVERY LOCAL USER ON PRODUCTION, AND "ACL IT" HAD BEEN THE DOCUMENTED FIX SINCE v2.133.0 WITH NO CODE BEHIND IT.** `installer/Backup-SecVault.ps1` creates its backup directory with a bare `New-Item` and never set an ACL, while its own header says "the backup directory is as sensitive as the database — it holds the encryption key beside the encrypted credentials. ACL it." **Measured live on production 2026-11-13:** `E:\SecVaultBackup` carried `BUILTIN\Users:(I)(OI)(CI)(RX)` INHERITED from the volume root, over **14 `.env` copies and 28 `.pem` files** (14 retained sets) — so any non-admin local account could read `CREDENTIAL_KEY` (decrypting every row of `device_credentials`, i.e. the whole fleet's firewall passwords), `PG_ADMIN_PASSWORD` (the cluster superuser, shared with five sibling apps) and the console's TLS private key. The 02:30 `SecVaultBackup` task re-registers on every update, so it armed itself. ⛔ **A requirement in prose cannot fail a build, and the sentence reading as though it were handled is precisely what kept anyone from checking** — the guard-that-cannot-fire pattern aimed at this repo's worst secret. ✅ **FIXED v2.225.3**, both halves: production remediated by hand with the user's authorisation (`icacls /inheritance:r` granting only SYSTEM and Administrators `(OI)(CI)F`; verified **0 of 56 files still grant a non-admin principal**, and the task runs as SYSTEM which keeps full control), and the script now does it **on every backup rather than at creation** (every deployed server already HAS the directory, so a create-time fix reaches fresh installs only — the `CREATE TABLE IF NOT EXISTS` trap), **before the dump** (the exposure is created by writing the key there), VERIFYING the resulting ACL rather than trusting icacls' exit code. It WARNS and continues rather than refusing — skipping the backup would trade a conditional read exposure for a CERTAIN loss of recoverability — but clears `$backupComplete`, so the banner cannot claim success and the task result is non-zero. Executed on real Windows PowerShell **5.1.26100.9818** (both the success and the failure path, and idempotent on a second run); `tests/backupScripts.test.js` pins it, 6 mutations verified. | [x] |
| 34 | ~~A SINGLE REJECTED INSERT CHUNK MADE THE COLLECTOR RE-INSERT THE REST OF THE SPOOL FILE ~900 TIMES.~~ **DONE v2.228.16.** `insertEvents()` now reports `failedIndexes` — WHICH records failed, not merely how many chunks did — and `processSpoolFile()` atomically rewrites the spool file with only what is still owed. ⛔ **Shrinking the file did NOT fix the archive half, and the common case is why**: the ordinary failure is the database being briefly away, where EVERY chunk fails and the surviving set is the whole file — nothing shrinks and the ~900 duplicate gzip members would have continued. So a record carries an `archived` marker once it is safely in a member, written ONLY after a successful append, and a replay appends only what is not yet there. ⛔ The decision moved into the requireable `lib/syslog/spoolFile.js` and is EXERCISED against a real temp directory (`tests/spoolFile.test.js`, 23 cases), because `services/collector.js` binds sockets at module load and every guard left in it can only be grepped. 5 mutations verified red. | [x] |
| 35 | **The compressed archive — the only copy of the raw line for ~89% of traffic — has no health signal outside the collector's own stdout, and `archiveStats()`'s docstring claims otherwise.** It says it is used "by the collector's startup banner **and by the ingest-health view**"; a repo-wide grep finds exactly ONE caller, the startup banner. `archiveFailures` is never written to `syslog_ingest_stats` (no column) and never read by `lib/serverHealth.js`, whose only archive involvement is the VOLUME's free bytes. So a full disk, a permission change or an unwritable `SYSLOG_ARCHIVE_DIR` fails every append every 2 seconds with free space reported healthy and no product surface changed. Worse, the periodic ratio line that names `archiveFailures` is gated on `archiveRaw > ARCHIVE_LOG_EVERY_BYTES`, and `archiveRaw` only advances on SUCCESS — so when the archive fails COMPLETELY, the one line naming the failure never prints either. Same incident shape as the `SYSLOG_ARCHIVE_DIR` ENOENT bug this codebase already records, which was fixed at the env-parsing layer while the observability gap it ran through was not. | [ ] |
| 36 | ~~Nothing verifies that any syslog listener actually BOUND, and `spool_backlog` cannot express "could not read".~~ **DONE v2.228.16.** `main()` now AWAITS the bind result, records it in the new `syslog_listener_state` table (a log line is not a health signal), retries an unbound listener every 60s, and no longer prints `collector ready.` over a collector that bound nothing; `lib/serverHealth.js` reads it and the ingest panel's banner no longer says "Check that SecVault-Collector is running" for the one cause where it IS running. `spool_backlog` is nullable with the DEFAULT dropped, and `countReadyFiles()` returns null rather than 0. ⛔ **The UNCONFIRMED reuseAddr suspicion was measured and is neither unconfirmed nor Windows-only**: with two real processes, Windows let the second bind succeed and gave it 0 of 10 datagrams, Linux let it succeed and gave it ALL 10 (libuv maps reuseAddr to SO_REUSEPORT). Either way the bind succeeds and the traffic goes elsewhere, so a bind check over such a socket certifies a deaf collector — `reuseAddr` is gone, and both the refusal and the cost-free restart were re-measured on both platforms. 11 mutations verified red. ⛔ **Residual, stated rather than implied**: a third party setting SO_REUSEADDR can still bind on top of US, and from inside the process that is indistinguishable from a quiet network. | [x] |
| 37 | ⛔ **A WHOLE-CONFIG READ FAILURE IS PERSISTED AS A MASS CONFIG DELETION.** `lib/engines/configDiff.js`'s `detectAndStoreDiff` diffs the two newest `device_configs` rows with no test of whether the NEWER snapshot is usable, and `diffConfigs` treats `null`/`{}`/a partially-parsed tree as a legitimate config — so every section absent from a truncated snapshot is emitted as `removed`. Upstream, Fortinet's `looksLikeConfig` is `/^\s*config\s+\S+/im`, so ONE `config <word>` line anywhere passes and a truncated or scope-restricted dump is stored. **Measured on production:** device TSR_EKM, 2026-08-06 10:26 — `0 added, 142 removed` across six unrelated top-level sections (ssl_vpn 65, fortiguard 45, snmp 12, log_syslogd 10, ntp 8, autoupdate 2) — then `142 added, 0 removed` with an identical breakdown **54 minutes later**. Nothing changed on the device. The operator was shown "somebody wiped the SSL-VPN, FortiGuard, SNMP, NTP and syslog configuration of this firewall", and the false change also drove a CVE re-match, an `auto` backup row and the `config_diff` outbound alert type. Fleet-wide, 3 of 362 rows match the signature (`removed > 20 AND added = 0`); the other two have no matching re-add and may be genuine. ⛔ The lesson was applied to ONE subtree and not the whole: `preserveSystemInfoOnReadFailure` and `cleanupSystemInfoReadFailureDiffs` cover `system_info` only, and `isSystemInfoPath` cannot touch these 142 rows. The exact upstream cause is UNCONFIRMED (truncation is likeliest, but a VDOM-scoped pull or an access-profile change gives the same shape) and the source snapshots are past `CONFIG_RETENTION_DAYS`, so **do not record a mechanism without re-measuring**. **Fix shape:** a wholesale-disappearance guard in `detectAndStoreDiff` — a behaviour change on the collect/store path, so it needs its own verification. ✅ **FIXED v2.226.0.** `detectAndStoreDiff` now refuses to record the change and returns `{suppressed, suppressedReason, lostSections}`, which `collectAndStore` pushes into `result.errors` — a guard that withheld diffs silently would be indistinguishable from a device that stopped changing. Two branches, two sentences: an unusable newest snapshot (reusing `hasUsableConfig`, not a second copy of it), and `lostTopLevelSections()`. ⛔ **THE THRESHOLD IS DERIVED, NOT PICKED: measured across the whole retained history on the reference fleet — 259 consecutive snapshot pairs, 16 firewalls, both vendors — and `max_sections_lost` is 0 for EVERY device.** So one wholly-vanished top-level section is already outside everything this fleet has ever done, and no magic number is needed beyond "any". ⛔ It suppresses the DIFF and never deletes the snapshot, and the reason names the sections and says truncation-or-scope, never "deleted". ⛔ The asymmetry is the argument: a suppressed diff is recovered by the next good pull, a fabricated one has already fired an alert. Upstream cause still UNCONFIRMED and deliberately unnamed. 7 mutations verified red. | [x] |
| 38 | **`collapseObjectArrayIdentityCascades` persists `diffValue()` output without the redaction pass its sibling applies.** Step 1 re-diffs two whole stored objects and splices the result straight into the diff that `collapseHistoricalArrayShiftCascades` UPDATEs into `config_diffs`. Every other persisting `diffValue()` call site redacts first — `diffConfigs`, and `filterDiffForCurrentRules`, which performs the structurally identical re-decomposition and DOES call `redactSecretEntries`. So a secret nested inside an opaque whole-object entry can be promoted into its own named top-level leaf entry, unredacted, and the rewrite happens on every deploy because this repair is NOT ledger-gated. UNCONFIRMED as a live leak: it needs a row that simultaneously has a matching identity in both a whole-element `added` and `removed` entry on one array path AND carries a secret under a pattern-missed key; none found. Partly mitigated in v2.225.3, which made `isSecretPath` match any path SEGMENT rather than the leaf only. `cleanupVolatileConfigDiffs` also runs earlier in the same migrate block and does redact. ⛔ **FIXED v2.230.0, AND IT IS A CONFIRMED LEAK PATH RATHER THAN AN UNCONFIRMED ONE.** Reproduced by calling the real exported function with the shape the row describes: pre-fix output was `[{path:'mgt-config.users.entry[3].phash', old:'LEAKED_OLD', new:'LEAKED_NEW'}]` — a PAN-OS local admin's password hash promoted out of an opaque whole-element entry into its own named leaf, in plaintext, in a table both readonly roles can read. What was unconfirmed was whether a LIVE row has that shape; what is now certain is that the code produces it when one does, and that a historical row written before the deep walk existed is exactly such an input. ⛔ The pass-through entries are redacted too — `redactSecretEntries` is idempotent and fails closed — so the one code path already rewriting a legacy row now REPAIRS it instead of preserving it. ⛔ `tests/configDiffCollapseRedaction.test.js` scans every function composing `{added,removed,modified}` from `diffValue()` output, so a third collapse pass cannot repeat it. | [x] v2.230.0 |
| 39 | ⛔ **`[job-reaper]` DECLARES A STILL-RUNNING JOB FAILED AFTER 30 MINUTES MEASURED FROM `started_at`, NOT FROM ITS LAST PROGRESS REPORT — AND A `device_delete` ON A BUSY FIREWALL CANNOT FINISH IN ONE RUN.** `reapStaleJobs` selects `WHERE status = 'running' AND started_at < now() - 30 min` and never looks at `progress_current`; once reaped, `reportProgress`'s `WHERE id = $1 AND status = 'running'` silently discards every later update, so the UI freezes on a `failed` row while the work continues, and `finishJob` (no terminal-status guard) later overwrites the verdict with no record it was ever reaped. The threshold is then guaranteed to be crossed: `unlinkSyslogEvents` uses `eventBatchSize: 20000` with `eventPauseMs: 200` and `maxBatchesPerTable: 5000`, i.e. **1,000 seconds of pure sleep** before any UPDATE time, and it THROWS at the cap. **Measured on production:** TUM(TUTH1) holds **840,638,199** `syslog_events` rows → **42,032 batches against a 5,000 cap = ~9 consecutive re-runs**; ITC-SK 473M, SMT 436M, OKF(F2) 238M are in the same class. `deviceDeletion.js`'s own DEFAULTS comment sizes the cap against "3.35M events for a single device, measured" and calls 5,000 generous — the busiest live device is **251x** that. The operator is told the worker stopped and that they should re-run, which the index now permits, and `jobQueueInFlight` is held throughout so **no Collect Now anywhere on the fleet can be claimed**. Not yet triggered: `background_jobs` holds 4 rows ever and both past deletes were on devices with no syslog. REFUTED: the duplicate does not run concurrently (`jobQueueInFlight` serialises it). **Fix shape:** reap on last progress rather than `started_at`, add a terminal-status guard to `finishJob`, and re-derive the batch cap against the real fleet. ⛔ **DONE, and the CHURN WAS ONE OF THREE CONSEQUENCES.** `background_jobs` gained `progress_at`, `reportProgress` stamps it, and the reaper keys on `COALESCE(progress_at, started_at)` — the fallback being the one case where the start IS the last sign of life, and never defaulted to `now()`, which would make an abandoned job look alive for ever. ⛔ The other two: `reportProgress` silently discarded every post-reap update (the guard is right; a write that did not land must not report success, so it returns `{applied}`), and `finishJob` had **no terminal-status guard**, erasing the only trace that the reaper had fired wrongly. It still WRITES the result — refusing would be the worse bug, since a real result is the evidence the reap lacked — and appends the earlier verdict, captured in the same statement by a CTE so there is no check-then-act window. ⛔ **THE CAP WAS 336x TOO SMALL, NOT 251x** — re-measured on production 2026-11-15: TUM(TUTH1) holds **1,127,384,476** events (the row recorded 840M; it grew 34%) = **56,370 batches**, against a 5,000 cap derived from a 3.35M device, so the loop threw after **8.9%** of the work on four live firewalls (ITC-SK 1.008B, SMT 935M, OKF(F2) 509M). Re-derived to 2.7x the busiest measured device. ⛔ **`eventBatchSize`/`eventPauseMs` deliberately NOT touched**: both trade against the collector's disk and that trade cannot be measured without rewriting a billion live rows. ~3.1h of pure sleep for that device, with `jobQueueInFlight` held throughout, is recorded rather than guessed at. ⛔ **The unlink is unavoidable by design** — `device_id` is already `ON DELETE SET NULL`, so the batching exists to pay the cost in small committed transactions instead of one catastrophic cascade; do not 'optimise' it onto the FK. 5 mutations verified. | **[x]** v2.228.12 |
| 40 | ⛔ **THE MULTI-HOP SIMULATOR PICKS THE NEXT FIREWALL BY SHARED-SUBNET ADJACENCY ALONE — `neighbors[0]` — IGNORING THE ROUTE'S OWN `next_hop_ip`, AND REPORTS NO AMBIGUITY.** `resolveRoute()` returns `nextHopIp` and the orchestrator uses it only to test `=== null`; the next device is the FIRST entry of the adjacency list, never compared against the next hop the device itself named. `buildAdjacencyGraph`'s own JSDoc says the value is "An array, not a single value … so this never assumes exactly one neighbor" — the orchestrator assumes exactly that, and the entry-device loop `break`s on the first matching interface under the comment "never guess a starting device". **Three live instances measured:** (1) `TUG ethernet1/2` holds `0.0.0.0/0 via 192.168.100.1` but the only adjacent device on that subnet is `HRIS ethernet1/2 = 192.168.100.254` — not the next hop — so any TUG-sourced internet path crosses into HRIS and reports HRIS's verdict; (2) `SMT::tunnel.3` has TWO neighbours, `IDC FW:tunnel.18` and `ITC-SLY:tunnel.4`, both at 169.254.0.2, so the second hop is a coin flip between two Palo Altos; (3) `10.254.254.0/24` is held by FOUR devices all at `.1`, so entry selection is by Map insertion order. This is the damage `tests/topologyAdjacency.test.js` describes — "evaluate the WRONG FIREWALL'S RULESET and return a confident allow/deny for a hop that does not exist" — reached by a path that test does not cover. **Fix shape:** prefer the neighbour matching `next_hop_ip`, and report ambiguity as a `note` rather than resolving it silently — a verdict-affecting change, so it needs its own measurement. | [ ] |
| 41 | **For Fortinet, `applyNat` treats derived per-policy NAT rows as one ordered first-match rulebase, so an `any/any` source-NAT row permanently shadows that device's destination NAT.** `lib/adapters/fortinet/cliParser.js` stamps `sequenceNumber = policy.policyid` on BOTH the destination row (from a VIP in `dstaddr`) and the source row (from `set nat enable`) — a firewall-policy id, not a NAT precedence ordinal. CLAUDE.md states the premise: "FortiOS has no separate ordered NAT rulebase like Palo Alto". Sorting those into one list and returning on first match lets a low-numbered policy's source NAT pre-empt every higher-numbered policy's destination NAT. **Measured:** TSR-TL's source-NAT row at policy 2 is `all/all`, so its only DNAT row (policy 6, `171.99.128.101 → 192.168.3.7`) can never apply — 1 of 1 DNAT rules on that device permanently unreachable, and inbound paths end in "no route known beyond this device" instead of reaching the internal host. Fleet-wide 11 DNAT rows sit after an `any/any` source row (IDC FW 7, TFM-MH 3, TSR-TL 1) but **only the TSR-TL one is a defect** — on Palo Alto the NAT policy genuinely IS first-match across the rulebase, so that ordering is faithful there. **Fix shape:** split the match by `nat_type` for vendors whose NAT is per-policy rather than an ordered rulebase. | [ ] |
| 42 | **`buildExposurePaths` drops a rule whose source or destination resolves to nothing, treating "we could not resolve it" as "not internet-facing", and the counter that would disclose it is incremented AFTER the drop.** `sourceHasPublic` is true only via `isAny` or a resolved non-private range, so a source of object names that resolve to nothing yields `ranges: []` with `unresolvedNames` populated — `matchesAddress`'s `'unresolved'` state — and is `continue`d exactly like a confirmed-internal rule; `unresolvedRules++` sits three lines after the `continue`, so a dropped rule is never even counted, and the counter is read by nothing under `app/` or `components/`. This is the direction `exposure.js` itself calls the worse one ("under-reporting exposure is the more dangerous error"). **Measured: zero live paths today.** 39 enabled allow rules fleet-wide have a fully unresolvable source (PAKFood 21, TSR_EKC 10, TSR-TL 8 — all three devices have no `network_objects` rows at all); of the inbound-or-unverified subset only TSR_EKC qualifies, and TSR_EKC has 0 `device_interfaces` rows so it produces no paths regardless. It bites the first time an inbound rule on an object-less device meets a collected public interface. Distinct from row 26 — these names match no `network_objects` row of any type. ✅ **FIXED v2.226.0.** `unresolvedRules++` moved BEFORE anything can skip the rule (it sat after the `continue`, so a dropped rule was never even counted), and an unresolvable source no longer EXCLUDES the rule: the path is reported with `sourceResolved: false`, exactly as a path on a device with no zone data is reported with `directionVerified: false`. ⛔ `scoreExposure` gets a THIRD branch rather than falling into the `else`, which asserts "restricted to specific ranges, but still includes public space" — a claim about an extent nobody could read. It adds **no points**: not knowing is not evidence, the same call this engine already makes for an unmeasured observation. ⛔ The UI caveat is SEPARATE from "direction unverified" — one is missing zone data, the other missing network objects, and they send an operator to different places. Live: still **0 paths today** as this row measured. 6 mutations verified red. | [x] |
| 43 | **`paloalto/sshParser.js` uses `if (srcTranslated) … else if (dstTranslated)`, so a PAN-OS NAT rule performing BOTH translations is stored as a source-NAT row only and its destination half never reaches `nat_rules`** — which would also hide a published address from `exposure.buildDnatMap`. Found while auditing the topology family; UNMEASURED (nobody counted how many live PAN-OS rules carry both), and the fix belongs with the adapter, not the engine. Measure before acting. | [ ] |
| 44 | ⛔ **~22 SITES RENDER SMALL BODY TEXT IN THE RAW SEVERITY RAMP, AT 3.44–3.64:1 IN THE DEFAULT LIGHT THEME — AND SEVEN OF THEM ARE THE WORDS "NOT MEASURED".** Each sets an INLINE `style={{ color: 'var(--yellow)' }}` or `'var(--sev-high)'` on 12–16px text, so the `--tint-*-fg` remap `StatCard`'s `TEXT_SAFE_VALUE` already performs is bypassed. `app/globals.css` records the numbers itself — "Measured on white: --orange 3.63:1 and --yellow 3.64:1. That clears WCAG 1.4.11's 3:1 for a non-text graphical object and FAILS 1.4.3's 4.5:1 for text." Worst instances: `cvssStyle` paints the CVSS score for the whole 7.0–8.9 HIGH band (the band boundary IS a contrast boundary, since >= 9 gets the passing `--red`), the log-search timeout banner that is the only thing separating "nothing matched" from "we never answered", and the `DeviceTrafficTab` banner naming which sources failed. ⛔ **The sub-class is worse than the contrast miss**: `ServerHealthWidgets.js` prints `These figures are NOT MEASURED, not zero` in amber, and `devices/[id]/page.js` prints `The size of this delete could not be measured` in `--sev-high` on the irreversible delete confirmation — while `components/ui/NotMeasured.js` states the rule being broken ("⛔ NEVER give this a colour from the severity ramp"). The same card uses `--unmeasured` for its VALUES and the severity ramp for the banner explaining them, so the mark is unlearnable. Dark theme passes (7.86–9.04:1); light is the default. ⛔ `tests/designSystemRamp.test.js` cannot see this shape — it matches a `color=` PROP on `<StatCard>` and object literals carrying `label:`+`value:`, not an inline style on arbitrary text, and says so in its own scope note. ⛔ **RE-MEASURED 2026-11-14: 20 unambiguous small-body-text sites** (26 if the six chart/legend config objects count as text), so "~22" is close but the method matters — state which. ⛔ The "seven of them say NOT MEASURED" sub-claim is **exact**, all in `ServerHealthWidgets.js` (`:126` literally `not measured - {d.error}`, `:221` `These figures are NOT MEASURED`). Contrast re-measured on white: `--yellow` **3.64**, `--orange` **3.63** — both clear 1.4.11's 3:1 for graphics and fail 1.4.3's 4.5:1 for text. ⛔ `--red`/`--green`/`--blue` are NOT in scope (4.8/4.8/4.7:1, they pass); `--teal` at 3.84 would fail but sits outside the row's stated band. ⛔ `tests/designSystemRamp.test.js:494` still matches only a `color=` PROP, so an inline `style={{color:'var(--yellow)'}}` is invisible to it. ⛔ **FIXED v2.228.7 — 24 SITES ACROSS 13 FILES, which is more than either figure this row carried (“~22”, then “20 unambiguous”), because BOTH enumerations grepped for the literal `color: 'var(--yellow)'` and neither found `color: h.ingest.backlog > 0 ? 'var(--yellow)' : undefined` — the same failure behind a ternary (`ServerHealthWidgets.js:240` and `:266`). The guard was written FIRST and used to enumerate, so it sees exactly what was fixed.** ⛔ **And the quoted ratios were the BEST case**: `--yellow`/`--orange` measure 3.64/3.63 on white but **3.45/3.44 on `--bg-primary` and 3.30/3.29 on `--surface-subtle`**, where most of these sites actually sit. ⛔ **The split is a question about the SENTENCE, not the hue**: 13 genuine warnings took the contrast-safe counterpart `StatCard`'s `TEXT_SAFE_VALUE` already maps to (`--tint-warn-fg` 5.26–5.80:1, `--tint-orange-fg` 4.88–5.39:1), and **11 sentences saying SecVault could not measure or verify something took `--unmeasured`** (4.62–5.09:1), hueless by construction. The seven `ServerHealthWidgets.js` “not measured” lines and the delete-confirmation sentence are in the second group — and going hueless makes them MORE legible (3.63 → 5.09 on a card), so there was no trade to weigh. ⛔ **The guard is scoped to a CSS-SHAPED OBJECT, not a `style={{...}}` attribute**, because the four `cvssStyle()` helpers RETURN `{ color, fontWeight }` and are applied as `style={cvssStyle(x)}` — an attribute-scoped scan finds none of the worst four. A config row (`{ key, label, color }`) carries no CSS property and is skipped, separating legend data from styles mechanically rather than by a filename list; large text keeps the raw hue at 3:1. ⛔ **A second new guard pins `--tint-*-fg` on a PLAIN surface**, which nothing did: the existing pair test measures each one on its own `--tint-*` wash, so lightening the token to suit the wash would have dropped all 24 sites back under 4.5:1 with that test still green. ⛔ **Verified by RENDERING, not only by the scan** — real `globals.css`, computed `color`, composited ancestor background: 10/10 representative sites pass in both themes, worst **4.62:1 light** and **5.52:1 dark**. The first render pass reported two dark failures (3.16, 1.59) and both were HARNESS artefacts — no `body` background and no alpha compositing, against a `rgba(255,255,255,0.045)` dark `--surface-subtle`. ⛔ `--text-muted` (4.27/4.08) is NOT in scope: already ratcheted by its own test, and darkening it collides with `--unmeasured`. 4 mutations verified red. | **[x]** v2.228.7 |
| 45 | **Four accessibility defects on controls that are the only way to do something.** (a) `NotificationBell.js` renders each notification row as a bare `<div onClick>` with no `role`, no `tabIndex` and no key handler, so the per-alert deep links are MOUSE-ONLY (WCAG 2.1.1, Level A) — and the trigger has no `aria-expanded`/`aria-haspopup` (CONFIRMED live: both absent in the DOM). Mounted on all 30 dashboard pages; the sibling patterns in the same header (`HeaderSearch`, `JobCentre`) get both right. (b) `IdleTimeout.js` sets `role="alertdialog" aria-modal="true"` with NO focus management at all (`grep -c focus` → 0) — nothing moves focus in, confines Tab, restores it, or handles Escape — so `aria-modal` marks everything outside inert while the user's focus point is still out there, making "Stay signed in" unreachable for a screen-reader user. `components/ui/Modal.js` implements all four and documents why. (c) `ReachabilityTab.js` signals a segmentation violation by CELL OUTLINE COLOUR alone with the reason in a `title` on a non-focusable `<td>`; the `<Badge>` inside reads "Allow" on flagged and unflagged cells alike (WCAG 1.4.1). The rest of the repo pairs amber with a `⚠` glyph. (d) Four controls on privilege surfaces have NO accessible name — `LdapRolesPanel.js`'s three "Add a mapping" fields have visible labels that are siblings with no `htmlFor`/`id`, including the group-DN box that decides who becomes an Administrator, and `UsersPanel.js:235`'s per-row role `<select>`. `EntraRolesPanel.js`, written later over the same route, does it correctly, so this is house convention and the older panel predates it. ⛔ **FIXED v2.228.8 — AND THE GUARDS FOUND FOUR MORE INSTANCES THAN THIS ROW LISTED** (`components/ui/Evidence.js`, plus three fields in `components/config/ConditionsManager.js`). The row was compiled by reading; a scan reads every file — which is why the guards were written FIRST and used to enumerate. ⛔ **(a)** The notification rows are now `<Link>`, not `role="button"` + `tabIndex` + `onKeyDown`: these are navigations, and an anchor brings keyboard activation, a focus ring, the announced role and open-in-new-tab with nothing to maintain. The trigger gained `aria-expanded`/`aria-haspopup` and the panel a `role="dialog" aria-label`, matching `JobCentre.js` beside it; the footer button became a Link too, which removed `useRouter` from the file entirely. ⛔ **(b)** `Modal.js`'s private focus trap was EXTRACTED to `components/ui/useFocusTrap.js` and both dialogs now share it — copying it would have left two implementations to disagree. `onEscape` is OPT-IN: `IdleTimeout` deliberately passes none, because there is nothing to close and dismissing it would hide the warning while the session still ended. Its `role`/`aria-modal` also moved from the BACKDROP to the PANEL, which is what the trap must be anchored to. ⛔ **(c)** The risk tier is now in the cell CONTENT (`⚠ Ext→Int` / `⚠ DMZ→Int`) with the glyph `aria-hidden` and the WORDS carrying the meaning, so it is visible, in the accessibility tree, and no longer hover-only on a non-focusable `<td>`; the legend sentence was corrected to stop claiming the outline is the carrier. The marker uses `--tint-danger-fg`/`--tint-warn-fg`, the rule row 44 had just swept. ⛔ **(d)** Six fields bound with `htmlFor`/`id` (three LDAP, three conditions) and the per-row role `<select>` given an `aria-label` that names the **USER** — “Role” alone announces identically on every row, and there is no undo. ⛔ **`Evidence.js` IS A NAMED, REASONED EXEMPTION, NOT A WAIVER (new row 58)** — 3 of 4 mechanisms, missing only Tab confinement. ⛔ **Two first-draft guards were satisfied by a MENTION and mutation testing caught both**: `!/useFocusTrap/` stayed green when the IMPORT was deleted (the identifier survived in the call and a comment), and `/RISK_MARK\[tier\]/` stayed green when the conditional render was disabled (the same identifier appears again as the marker's own text). Prose read as code, inside the suite written to catch guards that cannot fire. 6 mutations verified red after tightening. | **[x]** v2.228.8 |
| 46 | **Two surfaces assert calm or completeness from a read they did not consult.** (a) `SecurityLogWidgets.js` awaits `getThreatCoverage(pool, 24)` into `coverage` and NEVER REFERENCES IT, rendering a plain `No named threats in the last 24 hours.` where its three sibling widgets render `<ThreatEmpty coverage={coverage}/>`. `lib/syslog/threatStats.js` names this exact string as what the guard exists to prevent — "a security dashboard asserting calm because its own aggregation has not run … it was the live state for the first minutes after the rollup shipped". (b) `OverviewComplianceCard.js` draws a 96px compliance donut plus six per-standard donuts with no gradeable-check denominator, calling neither `buildDeviceCoverage()` nor `deviceCoverageEvidence()` — the machinery v2.225.0 added for exactly this, and used one route over on `/compliance/[deviceId]`, whose `DeviceCoverageStrip` docblock says "the figure may never be read before the number of checks it rests on". So a Check Point at 78% off 9 gradeable checks is pixel-identical to a Fortinet at 78% off 25, on the first tab opened for a firewall, and clicking through shows the same score WITH a coverage grade — the two screens disagree about what the number is worth. ⛔ **DONE — both halves reproduced, and a THIRD instance was found in the same file.** (a) `TopThreatsWidget` now renders `<ThreatEmpty coverage={…}/>` like its three siblings. ⛔ **And `DeviceThreatTable` never fetched coverage AT ALL**, although `getDeviceThreatSummary()`'s own comment delegates the no-coverage case to “the widget, not … a NULL here” — so over an unswept rollup every device showed a dash under a fleet-wide `No device reported any threat events in this window.` **A guard delegated in a comment to a caller that never implemented it is the guard-that-cannot-fire pattern with the delegation written down.** Production is 24 of 24 hours swept today, so both are latent and fire after a collector restart or a rollup deploy. ⛔ Both components take `evaluable === true` (never truthy) and are **exported**, because the dangerous input is an ABSENT coverage object that no widget can be made to produce — a `coverage ? … : true` mutation survives every test routed through a widget. ⛔ (b) `OverviewComplianceCard` now renders `DeviceCoverageStrip` from `buildDeviceCoverage()`/`deviceCoverageEvidence()` in BOTH branches, no arithmetic added and no second grading scale; the applicable-count read is the device page's, byte for byte, failing to `null` rather than a zeroed map. Measured on the mock fleet: `MOCK-SANGFOR-Branch-06` scores on **9 gradeable of 19 applicable and is the fleet's highest score**. Added query cost 1.6 ms, in an existing `Promise.all`. ⛔ Residual spun out as row 62 (the strip is handed the BLENDED average, 9 points from the device-wide figure, because the alternative is a second percentage on one screen). 34 tests, 16 targeted mutations RED, one equivalent mutant recorded as such. | **[x]** v2.228.12 |
| 47 | **Three `StatCard` call sites can never show the dashed "not measured" border, and six KPI grids still use the `auto-fit` shape `KpiRow` was built to delete.** `StatCard` takes no `unmeasured` flag — it INFERS one from `color === 'var(--unmeasured)'` — and `ConformanceBoard` (5 tiles) and `VpnDetections` (4) pass `textColor` without `color`, so the attribute is never emitted although both render `<NotMeasured>` as the value. v2.200.0 is explicit that grey alone was judged insufficient (`--unmeasured` and `--text-muted` are four hex digits apart). Nine other call sites pair the two correctly, so the convention exists. `tests/cardSurfaces.test.js` pins the CSS rule and the `:not([data-unmeasured])` exclusion but never whether any caller sets the attribute, so it stays green. Separately, six grids are hand-rolled `repeat(auto-fit, minmax(...))` with 5 or 6 tiles — `ChangeOutcomeBoard` (6), `ConformanceBoard`/`ConsolidationTab`/`RiskyRulesTab` (5 each), `VpnDetections` (4), `DeviceStatusSummary` (3) — against `KpiRow`'s rule that `auto-fit` "cannot be fixed by tuning that number, because it does not know how many tiles there are". `ChangeOutcomeBoard`'s orphan is its QUIETEST tile, which its own ranking rules say must not be given prominence. Known-latent: `KpiRow`'s header already concedes it, and `tests/kpiRow.test.js` gates only three named adopters. ⛔ **RE-MEASURED 2026-11-14 — BOTH COUNTS WERE WRONG AND ONE CLAIM IS PREMISE-WRONG.** StatCard half: **2 sites reproduce, not 3** — `ConformanceBoard.js:1076-1082` (`textColor` with no `color`) and `VpnDetections.js:718-732` (passes NEITHER `color` nor `textColor`, so the row's "textColor without color" wording is wrong for it). Every other `StatCard` call site that also imports `NotMeasured` was swept and is correct; no third site exists, so the original sweep either double-counted or it was fixed with no release note. auto-fit half: **5 of 6 reproduce**. ⛔ **`DeviceStatusSummary` is PREMISE WRONG** — `components/dashboard/DeviceStatusSummary.js:68` is `repeat(3, 1fr)`, explicit, and has been since **v2.10.0** (`730213d`); it was never `auto-fit`. Repo-wide `auto-fit` count is 56. ⛔ **DONE, and a THIRD StatCard site existed that neither sweep listed**: `ConsolidationTab` armed `--unmeasured` only from a standing declaration, so a tile whose `value === null` drew the NotMeasured em-dash inside a SOLID border. ⛔ **The fix is an explicit `unmeasured` prop, and keying it on the tone — the obvious one-liner — would have been WRONG.** `ConformanceBoard`'s “Firewalls not compared” tile is *toned* `--unmeasured` because it COUNTS unmeasured firewalls; that count is a real measurement and dashing it would claim SecVault could not read the number it is printing. No colour string carries both readings. Additive and three-state (`undefined` → the legacy colour inference, which ~40 sites rely on; explicit `true`/`false` wins), so removing the inference would have traded two missing borders for forty. ⛔ **`tests/cardSurfaces.test.js` pinned the CSS rule from both ends and never asked whether a caller could ARM it**, so it stayed green and would have with zero tiles setting the attribute. ⛔ Five boards adopted `KpiRow`; the worst was `ChangeOutcomeBoard`, where auto-fit stranded the SIXTH tile — `indistinguishable`, the verdict that file ranks LAST so it is not prominent — giving it a row to itself and inverting its own ranking on screen. ⛔ `DeviceStatusSummary` premise-wrong CONFIRMED (`repeat(3, 1fr)` since v2.10.0). A test derives each tile count from the source array, so growing `VERDICT_WEIGHT` fails the build rather than stranding a tile. Remaining 51 grids tracked as row 65. 13 mutations verified. | **[x]** v2.228.12 |
| 48 | **Three `.ai-codex/components.md` entries the code contradicts, on the file CLAUDE.md tells every session to read first.** (a) It says `HeadlineStats` "renders THREE SECTIONS" using "`.ov-grid[data-cols=N]`"; the code renders TWO `<section>`s and uses `<KpiRow>`, and `.ov-grid` was retired in v2.220.0 with no surviving CSS rule — `tests/overviewSections.test.js` asserts `!/ov-grid/`, so the build FAILS if a reader follows the index. The file contradicts itself: a later line already records the retirement, and the stale copy is the one filed where a reader would look. (b) It describes `ActiveVpnUsersTable` as a "CLIENT component … search box + 25-per-page pagination" eight lines after correctly recording that it is NO LONGER a client component because that state "AutoRefresh's router.refresh() silently reset mid-read" — so the later line instructs a reader to reintroduce the exact defect that was removed. (c) It names `IpsecTunnelsTable`'s prop `rows`; the signature is `{ tunnels, ... }`, so a call site following the index renders the component's own empty state, reporting a wiring mistake to the operator as a possible vendor collection gap. No live call site is affected today. Nothing in `tests/` validates `components.md` against component source. ⛔ **DONE 2026-11-14.** All three verified: `components.md` was the stale side in every case, and the CODE was right each time. Corrected in place — HeadlineStats renders TWO `<section>`s not three and uses `<KpiRow cols=>` not the retired `.ov-grid` (following the old entry would FAIL `tests/overviewSections.test.js`), the duplicate `ActiveVpnUsersTable` line still called it a CLIENT component while the fuller entry above it explained why it stopped being one, and `IpsecTunnelsTable`'s prop is `tunnels` not `rows`. ⛔ **Zero files under `tests/` reference `components.md`**, which is why all three could drift silently — the index is the one `.ai-codex` file with no guard behind it. | [x] |
| 49 | **Three ramp misuses on the evidence and brand axes.** (a) `ComplianceStandardsBreakdown.toneFor` returns `var(--accent-teal)` for the 75–89 band — `--accent-teal` IS `var(--primary)`, the token reserved for "this is interactive" — so the band ramp reads green → brand-teal → amber → red and a standard scoring 82% is drawn in the same hue as the "Compare devices" link two lines below. (b) `VpnDetections.STATUS_BADGE.measured` is `color: 'success'`, painting the EVIDENCE axis with the severity ramp's green, rendered immediately left of a `danger` findings count — so a credential-spray panel with 130 findings opens with a green chip read first, against CLAUDE.md's "the proof affordance may not borrow from the severity ramp at all". (c) `UserMenu.js:76` is `boxShadow: '0 2px 6px rgba(200,16,46,0.4)'` — `#C8102E`, the RETIRED suite red that `--primary` used to be: the avatar's fill was migrated to `var(--primary)` and the shadow tuned to the old red was not, so a teal circle sits in a red halo on every authenticated page. `tests/loginPage.test.js` is precisely the guard for that literal (`assert.doesNotMatch(src, /#C8102E|200\s*,\s*16\s*,\s*46/i)`) but its scope is the login page only, which is how this survived with the rule written down AND a test for it in the repo. ⛔ **DONE — AND (a) IS MUCH BIGGER THAN A HUE CLASH.** `toneFor` was a LOCAL COPY of a canonical banding: `ComplianceMatrix.scoreColor` (`>80`/`>=60`) is exported “so the per-device page can reuse the same bands instead of re-deriving the cut points” and is used by the matrix, the donut, the compliance PDF, the print page **and `ComplianceScoreWidget` — which `app/(dashboard)/page.js` renders as a SIBLING OF THIS CARD IN ONE GRID over the same five standards.** So **55% was a RED badge in one widget and a YELLOW bar in the other, side by side on one screen.** That file's own header already forbade this one function up (“STANDARDS is imported… never redeclared”). ⛔ **And `toneFor` drove both the bar fill and a 16px/700 NUMBER**, where `--yellow` measures **3.64:1** on `--bg-card` in the default light theme — 16px bold is not large text. Split: raw ramp on the fill (1.4.11, 3:1), `--tint-*-fg` on the text (1.4.3, 4.5:1). ⛔ **That contrast failure slipped past v2.228.7's own guard**, which matches ramp tokens as LITERALS and so cannot see `color: toneFor(pct)` — tracked as row 63. ⛔ (b) `STATUS_BADGE.measured` is hueless, not violet: `--evidence`/`.ev-*` own violet and nothing else may be violet, and this chip opens no drawer. The two gap states already shared `muted`, so the chip had two appearances for three states and spent its colour on the one needing it least; the labels and the hatched panel carry the distinction. ⛔ (c) `UserMenu`'s halo is a neutral shadow, not a re-tinted brand glow, and the retired-hex guard is now REPO-WIDE rather than login-page-only — the generalisation being the actual fix. | **[x]** v2.228.12 |

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

### P4c — raised 2026-11-13 by the five fabricated-answer fixes (rows 24, 26, 27, 37, 42)

Each one is a follow-up the fix UNCOVERED and deliberately did not take on. Every line carries the
measurement that justifies it.

| # | Item | Done |
|---|---|:--:|
| 50 | **All six adapters flatten a group's `members` to `[]`, so "enumerated empty" and "never enumerated" cannot be told apart anywhere downstream.** `checkpoint/parser.js` uses `Array.isArray(obj.members) ? obj.members : []`, `paloalto/sshParser.js` uses `attrs.members !== undefined ? asArray(attrs.members) : []`, and the other four have the same shape. So row 26's resolver fix had to treat an EMPTY array as unknown too, which over-reports uncertainty for a group a device genuinely enumerated as empty. ⛔ `objectUsage.storeObjects` already preserves a non-array (v2.226.0) so a parser fix would not be silently re-flattened — the remaining work is in the SIX PARSERS, which is live-verified vendor code under CLAUDE.md's "verify against live responses" rule, hence its own piece of work. ⛔ Live cost of the current over-reporting is **zero**: 2 empty address groups on the fleet, 0 referencing rules. ⛔ **RE-MEASURED 2026-11-14: "ALL SIX ADAPTERS" IS WRONG, AND THE LIVE COST IS CONFIRMED ZERO.** It is **seven flattening sites across FIVE vendors**; **sangfor has no group parser at all** (`sangfor/index.js:428-430` returns `addressGroups: []` from a stub `getObjects()`), so it cannot flatten `members` — it never produces a group. checkpoint flattens BOTH address and service groups through one function (`parser.js:737`), and paloalto has two separate parsers (XML `parser.js:962/:1002`, SSH `sshParser.js:897/:934`). ⛔ The `storeObjects` half is confirmed FIXED as the row says (`objectUsage.js:359,371,384` preserve a non-array as SQL NULL). ⛔ **Live cost re-measured on production: 414 groups, 0 with NULL members, 2 with an empty array** — both named `TELEMETRY`, on two Fortinets, and **0 firewall rules reference either**. The over-reporting is real and currently costs nothing. | [ ] |
| 51 | **`parseVersion`'s remaining fabricated-zero call sites.** v2.226.0 converted `isInRange` only. Still unaudited: `versionMatcher.js`'s other 2 sites, `lib/feeds/nvd.js`, `lib/feeds/paloalto.js`, and every adapter's `version_tuple` (`checkpoint/parser.js`, `cisco_asa/index.js`, `fortinet/parser.js`, `fortinet/ssh.js`, `paloalto/parser.js`, `paloalto/ssh.js`, `sangfor/index.js`). ⛔ `isVersionReadable()` now exists, so each site is a local decision rather than a breaking contract change. ⛔ Measured 2026-11-13: **0 of the live `device_versions` rows produce a zero-only tuple**, so the device side is latent, not firing. ⛔ **RE-MEASURED 2026-11-14: THE SITE COUNT IS WRONG AND ONLY ONE SITE IS DANGEROUS.** `versionMatcher.js` has **3** remaining sites, not 2. Of them only **`:355`** can turn a fabricated zero into a vulnerability verdict — `isInRange` tests the BOUNDS for readability but never the candidate tuple, so an unreadable device version becomes `[0,0,0,0]`: below every real `min` (silent fleet-wide NOT AFFECTED) and below every `max` on a max-only range (false positive). `:274` and `:291` both fail CLOSED (a zero tuple can never win their `>`/`===` comparisons), so they silently DROP a candidate rather than fabricating one. ⛔ **The 7 adapter `version_tuple` sites are DEAD ENDS today**: the only read of a `version_tuple` column outside `lib/adapters/` is `versionMatcher.js:291`, against a DIFFERENT table (`vendor_recommended_releases`); `:355` re-parses `version_string` and ignores the stored tuple. Fixing them is hygiene, not exposure. ⛔ **Live re-check 2026-11-14: 16 of 16 active devices parse readably, 0 zero-only tuples — `:355` is LATENT, not firing.** ⛔ **THE ONE DANGEROUS SITE IS CLOSED, v2.230.0; THE SEVEN ADAPTER SITES STAY OPEN ON PURPOSE.** `versionMatcher.js:355` now refuses: an unreadable `version_string` SKIPS the device with a recorded error naming the string, exactly as a device with no `device_versions` row already did, and the `continue` runs BEFORE the reconciliation DELETE so a firewall that becomes unreadable keeps the assessments it already had. Both hazard directions were reproduced against the real functions: `isInRange('fortinet',[0,0,0,0],'7.0.0','7.4.4')` is **false** (silent NOT AFFECTED) and `isInRange('fortinet',[0,0,0,0],null,'7.4.4')` is **true** (false positive). ⛔ `:274` was made EXPLICIT rather than changed — its drop was an accident of arithmetic that holds only while the device tuple is non-zero. ⛔ `:291` and the seven adapter `version_tuple` sites remain: measured dead ends, hygiene not exposure, and converting `parseVersion` itself is a breaking contract change across four feeds. ⛔ Re-measured 2026-11-16: still latent, 16 of 16 active devices parse readably. | [x] v2.230.0 |
| 52 | ⛔ **`nocvault_readonly` IS STILL EXPOSED AND ROTATING IT IS A NETVAULT CHANGE.** `lib/schema-grants.sql` carried a hardcoded literal for BOTH readonly roles until 2026-10-16, so the value is in git history on every deployed server. `claude_readonly` was rotated on production and staging on 2026-11-13; `nocvault_readonly` was NOT, because `net-vault/lib/suiteDb.ts` reads `process.env.NOCVAULT_RO_USER \|\| 'nocvault_readonly'` at RUNTIME — it is the Hub's cross-DB read role, so rotating it breaks the Hub across all six staging apps until NetVault's own credential is updated in the SAME sitting. ⛔ `claude_readonly` had no runtime consumer, which is why it could be done alone: the only suite references are LogVault's `.db-readonly.env.example` and its CLAUDE.md, both describing it as access for Claude Code / local development. | [ ] |
| 53 | **Staging's postgres has no inbound firewall rule for 5432, so nothing DB-side can be driven from the dev box.** Measured on the box 2026-11-13: PostgreSQL is **LISTENING on `0.0.0.0:5432`** with `listen_addresses = *`, and `Get-NetFirewallRule -Direction Inbound -Enabled True` returns **no rule whose LocalPort includes 5432**, firewall enabled on all three profiles. A TCP connect from dev gets no answer while port 22 on the same host answers fine — the identical shape CLAUDE.md records for the syslog collector ("binds, reports itself healthy, and receives nothing"). ⛔ **Deliberately NOT created**: opening a six-app shared cluster's postgres to the LAN is a security decision, not a convenience fix. Recorded so the next session does not re-diagnose it as a password problem, which is what the project memory had said. | [ ] |
| 54 | **Fleet-wide compliance EXCEPTIONS view.** `compliance_exceptions` is real and complete (four states, mandatory expiry, owner, compensating control, read-time evaluation), and an exception is visible ONLY if you open the device it sits on — so "2 lapsed fleet-wide" is a real, actionable number nobody can see. ⛔ The engine already exports `describeExceptions`/`summariseExceptions`; this is a route + a page over `listExceptions` widened past one device, not new judgement. ⛔ **It is the third of three and therefore the trigger for the nav change**: when it lands, promote Compliance from a leaf to a GROUP over Dashboard / Controls / Exceptions in the SAME commit — `lib/navRegistry.js` carries the condition and the reason. ⛔ There is NO risk-level column; do not render one. ⛔ **DONE v2.227.0** — `/compliance/exceptions`, built on `listFleetExceptions` + `countFleetFailingChecks`, judgement reused unchanged. The nav promotion shipped in the same commit, as this row required. | [x] |
| 55 | **Refused from the 2026-11-13 compliance-page review, recorded so they are not re-proposed.** A redesign mock proposed six pages; three are not backed by anything. (a) **Remediation progress** (Resolved/In progress/Open) — `audit_findings` is DELETE+reinserted every run and has no workflow column, no owner and no history; a finding stops failing when the FIREWALL changes. (b) **An assessment-run history** (run ids, names, scopes, durations) — no run table exists at any grain; `grep -i 'assessment_run\|compliance_run\|audit_run' lib/schema.sql` returns nothing. (c) **A framework-coverage denominator** ("74 of 230 checks") — nothing publishes a framework's own total, and inventing one is what `COVERAGE_CLAIM` exists to refuse. ⛔ Building any of the three needs a SCHEMA decision first, not a page. ⛔ **Everything else from that review IS built as of v2.227.0**: Controls, fleet Exceptions, the compliance trend (the history was being written nightly and never read), the per-control detail page, the top-failing-controls teaser, status counts on the filter and breadcrumbs. These three are the residue, and they stay refused. | [ ] |
| 56 | ⛔ **THE CENTRAL CVE HUB HAS BEEN FROZEN FOR 22 DAYS, AND ON THIS SITE IT IS THE ONLY SOURCE WITH USABLE VERSION RANGES.** Found 2026-11-14 while verifying the row 16/17 fix against production's live feed rows — not sought. `feed_sync_log` for `cve_hub`, newest run 13:52Z: `[central CVE feed stale] the hub last ingested **527h ago** (threshold 24h)`, `feed_version: 2026-10-02.1`, `inserted: 0`, `feed_rows: 955`. ⛔ **The v2.139.0 staleness guard is working exactly as designed** — it reads `checked_at` rather than `generated_at` precisely so an idempotent republish cannot hide a dead hub, it APPLIES the feed (the advisories did not become wrong) and pushes the verdict into `errors`, which is what turns the run `partial` and puts it on the pill. The guard is not the problem; the hub is. ⛔ **The consequence is a CVE-DISCOVERY OUTAGE, not a cosmetic chip.** CLAUDE.md records that this server cannot reach NVD at all (its sites use internal public ranges overlapping NVD's own address space), that CIRCL's records carry no parseable version bounds, and that stale ⇒ `hubDelivered` false ⇒ the local NVD path runs again. Both halves are visible in the same cycle: `nvd` is `partial` with **59 errors**, every one a network timeout to `services.nvd.nist.gov` followed by a CIRCL fallback whose records are then correctly refused as `[unmatchable]`. So nothing has discovered a new CVE on this deployment since **2026-10-02**. ⛔ **CROSS-REPO: nothing in THIS repo fixes it** — the hub is the `nocvault-eol` project and what has stopped is its scheduled ingest, the same boundary row 22 records. The SecVault-side action is to tell whoever runs the hub; there is no code change here. ⛔ **DIAGNOSED AND FIXED AT SOURCE 2026-11-15, VERIFICATION PENDING — AND "FROZEN" WAS THE WRONG WORD.** The hub was never unreachable: measured live, it answers **200** on `/api/v1/cve-feed/latest` and its pubkey and a correct **401** on the feed without a key, and its hourly ingest function runs on schedule (last attempt 14:10:26Z). Serving, ingesting and publishing are three different things and only the middle one broke. ⛔ Read from its own Neon database (project `square-leaf-46669543`, `cve_ingest_state`): **all 32 targets erroring, 0 never-succeeded, max `consecutive_failures` 81, last success anywhere 2026-10-23T15:10:27Z** — and the errors name themselves. **16 targets: NVD `HTTP 404`, which is what NVD returns for an INVALID API KEY** (not 401, not 403) — the trap `nocvault-eol/CLAUDE.md` already documents, for the second time, because **an env change does not reach a deployed Netlify function until the next build**. 16 targets: `did not respond within 2267-2867ms`, the budget bug below. ⛔ **The key is the single root cause**: every target had succeeded between 10-18 and 10-23, so the tight budget was survivable and the key was not. ⛔ **The PUBLISH side shows no fault** — 5 feed versions ever and none since 10-02 is exactly what an idempotent publish does over a corpus whose content stopped changing, so do not read a still `generated_at` as a broken publisher. ⛔ **The real content figure is worse than either timestamp**: the newest CVE *publication date* in the corpus is **2026-09-22**, so nothing published in 54 days had ever been ingested. ⛔ **Fixed in `nocvault-eol` (5f5e410) + a new NVD key installed by Amrin.** Separately, `cve_ingest_state.last_attempt_at` is stamped per step, so its spread per tick measured the function's reach with no Netlify log: **6 consecutive ticks each touched 1 target, span 0.000s** — `WALL_CLOCK_MS=7000` against a seeded `longestStepMs=4000` made the loop structurally one-step, i.e. a 2-4 day sweep when healthy; and the route's `budgetMs` knob existed, was clamped, was honoured, and this caller never sent a body. ⛔ **This row stays OPEN until `cve_ingest_state` shows a success after the deploy** — the two faults write different `last_error` strings, so one build verifies both independently. ⛔ **AND THE SECVAULT-SIDE ACTION TURNED OUT TO EXIST AFTER ALL** (this row said "there is no code change here"): see row 67. ⛔ **CLOSED 2026-11-16 — BOTH FAULTS CLEARED, MEASURED ON THE HUB'S OWN `cve_ingest_state` AND ON PRODUCTION'S `feed_sync_log`.** The exit criterion this row set for itself ("a success after the deploy") is met and then some: **32 of 32 targets carry `last_error IS NULL`, `max(consecutive_failures) = 0`, err_404 = 0 and err_timeout = 0**, so the invalid NVD key and the one-step budget were two faults and both are gone. `last_success_at` moved **2026-10-23T15:10:27Z → 2026-11-15T22:10:42Z**, and the publisher followed: `feed_version` **2026-10-02.1 → 2026-11-15.4** (first publish in 44 days), `row_count` 955 → **960**, newest CVE `published_at` **2026-09-22 → 2026-10-28**. On production, `cve_hub` went `partial` ("the hub last ingested 548h ago") → **`success`** on both runs since, with no stale error. ⛔ **The corpus is 19 days behind the calendar, not 54** — that is a backlog being worked off by an ingest that is alive again, and is the figure to re-check rather than the fault. | [x] 2026-11-16 |
| 57 | ⛔ **THE HUB'S VERSION-RANGE REPAIRS ARE NOT CONVERGING — 58 ROWS REPAIRED ON THREE CONSECUTIVE RUNS — AND THE FEED SAYS SO ITSELF.** Same production rows as row 56: `[central CVE feed repairs not converging] this feed has repaired advisory version ranges on 3 consecutive runs (58, 58, 58). A repair is a backfill and should converge to zero — a steady count means something is overwriting the repaired rows between cycles, so the fix is not sticking.` ⛔ **This is roadmap row 19's shape in a different place** (`backfillPaloAltoVersionRanges` reporting `cleaned up 302` every deploy for months because its already-clean guard could never fire), and row 19's lesson was that the data was never wrong — the COMPARISON was, which is why nobody looked. Here the opposite may be true: a repair that is genuinely undone every cycle means the advisories driving the priority tree are oscillating. ⛔ **HYPOTHESIS, EXPLICITLY NOT A DIAGNOSIS — do not act on it without measuring.** Row 56 makes `hubDelivered` false, so `runNvdSync` executes AFTER the hub in the same cycle, and its CIRCL fallback returns records with no parseable version bounds; if that path writes over the ranges the hub just repaired, the two findings are one bug and row 56 is its cause. That is a plausible mechanism and nothing has tested it. ⛔ **CLAUDE.md's own rule applies: a confident wrong mechanism is worse than none, because it sends the next session to fix the wrong thing.** What would settle it: snapshot `affected_version_ranges` for the 58 `cve_id`s immediately after a `cve_hub` run and again after the following `nvd` run in the same cycle. If they are unchanged, the overwriter is something else and the hub's own apply rules are the next place to look. ⛔ **THE MECHANISM IS NOW DEMONSTRATED IN PRINCIPLE — the hypothesis above was right about the SHAPE — BUT THESE 58 ROWS ARE STILL UNCONFIRMED (2026-11-15).** Found by reading rather than by the VPN: three of the four advisory writers refuse a fix-boundary downgrade through the shared `lib/feeds/fixBoundary.js` (`cveHub.js`, `fortinet.js`, `paloalto.js`) and **`nvd.js` did not import that module at all** — its arm was a bare `CASE WHEN advisories.vendor = EXCLUDED.vendor THEN EXCLUDED.affected_version_ranges`. ⛔ **The same defect, for the THIRD time**: `paloalto.js` got this guard on 2026-09-27 after `cve_hub` logged `updated=20` on twelve consecutive runs while no advisory row carried an `updated_at` inside a hub window. ⛔ **And `hubIsBetter()`'s WIDENED branch is what makes it a loop rather than a one-off**: it repairs a NON-blank local row when the hub states a fix boundary and we state none, so a writer that strips the boundary guarantees the same row is repaired again next cycle, for ever. ⛔ **PROVEN BY EXECUTION, WITH A NEGATIVE CONTROL** (statement text extracted from the shipping source, `PREPARE`d and run against a real `advisories` table): old code moved `max` **7.4.11 -> 7.4.10** and cleared `exclude_fixed`; new code held `7.4.11`; both let an incoming BETTER boundary win (`7.4.12`). ⛔ **STILL NOT A CONFIRMED CAUSE OF THIS COUNT.** `stats.repaired` is a true `rowCount` delta and `stats.repairedCves` records the ids, so the deciding query is cheap and unchanged from what this row already asks for: compare `repairedCves` across the three runs, then those rows' `updated_at` and source. **`tun0` was down all afternoon, so that is pending.** Note the guard is defensible on its own merits regardless of the answer. Shipped v2.228.13. ⛔ **EVIDENCE STRENGTHENED 2026-11-15 FROM BOTH DATABASES, AND THE DECIDING TEST IS NOW A DEPLOY RATHER THAN A QUERY.** ⛔ First, the query this row asks for is NOT AVAILABLE: `feed_sync_log` has no detail column (`feed_name, status, inserted, updated, errors, duration_ms, started_at, finished_at`), so `repairedCves` is computed in memory and never persisted — only the COUNT survives, as `updated`. Any future session planning to compare id lists across runs should know that before trying. ⛔ What IS measurable, from the hub's Neon DB and production together: the hub holds **443 of 955** advisories with a usable fix boundary; production holds **772 of 1131 LACKING one**, of which **336 are the NVD-dependent vendors** (`cisco_asa` 266, `checkpoint` 70). So 58 is the OVERLAP — rows the hub has a boundary for and production does not — which is exactly `hubIsBetter()`'s widened branch, and explains why the count is stable rather than growing. ⛔ **`cisco_asa` IS THE DISCRIMINATOR AND IT IMPLICATES `nvd.js` STRUCTURALLY**: that vendor has no PSIRT feed, so its only possible writers are `cve_hub` (which by `hubIsBetter`'s own precondition only ever writes ranges that CARRY a boundary) and `nvd.js`. Measured: **69 `cisco_asa` rows + 5 more with `cvss_source='circl'` lack a boundary and were rewritten in a single 2.5-minute feed cycle** (18:01:33-18:04:01 local, 423 rows across all vendors). A row last written by the hub would have a boundary; these do not; for `cisco_asa` nothing else writes. ⛔ And the 25 rows carrying `cvss_source='circl'` prove the CIRCL path is actively writing on a site where NVD itself is unreachable, which is the specific doubt that kept this a hypothesis. ⛔ **STILL NOT CLOSED, BECAUSE THE HONEST CONFIRMATION IS AN OUTCOME.** Production runs the OLD `nvd.js` (2.228.12 / `eb9c13c`); the guard is in 2.228.14 and undeployed. The test is therefore free and decisive: **after the next deploy, `cve_hub`'s `updated` must fall from 58 toward 0 over the following cycles.** If it does not, the overwriter is something else and the hub's own apply rules are the next place to look — exactly as this row originally said. Verify the OUTCOME, not the mechanism. ⛔ **CLOSED 2026-11-16 — THE OUTCOME CAME IN, AND THE MECHANISM WAS CONFIRMED BY WATCHING `nvd` RATHER THAN BY READING IT.** `cve_hub.updated` fell **58 → 58 → 0**: `partial, updated 58` at 00:00 and 00:10 +07, then **`success, repaired 0, unchanged 958`** at 06:00 and 12:00. The overwriter is now named by its own log line: while the hub was stale, `runNvdSync` ran every cycle and reported **`partial, updated 437`**; since the hub recovered it reports **`skipped` — "central CVE feed supplied the corpus this cycle (960 advisories)"**. So the loop was self-sustaining and had TWO stages, which is why it never converged: a stale hub makes `hubDelivered` false → NVD/CIRCL run → they revert the hub's repairs eight seconds later → the next cycle repairs the same 58 rows and pushes a non-converging error → which keeps `errors` non-empty and `hubDelivered` false on its own. ⛔ **ATTRIBUTION IS HONEST AND PARTIAL: the v2.228.13 `nvd.js` fix-boundary guard is NOT provably what closed this.** It was deployed at 00:09:47 +07 (the collector's own `syslog_listener_state` startup row dates the deploy) and the 00:10 `nvd` run under it still updated 437 rows; the following `cve_hub` run repaired 0, which is strong evidence the guard held — but the hub also published a fresh corpus at 05:45 +07 in the same window, so the two cannot be separated from this data. ⛔ **The guard still earns its place**: it is the only thing standing between a future stale hub and the same revert loop, and a healthy hub suppressing `runNvdSync` is a condition, not a fix. | [x] 2026-11-16 |
| 58 | **`components/ui/Evidence.js` declares `aria-modal` with no Tab CONFINEMENT.** Found 2026-11-14 by the guard written for row 45, not by row 45 — which listed four files and missed this one. The drawer is mounted on every answer-first page (the dashboard, `/vulnerability`, `/compliance`, `/analysis`, `/lifecycle`, `/devices`, `/exposure`), so it is the most-used dialog in the product. ⛔ **It is a PARTIAL defect and much milder than `IdleTimeout`'s was**: it has 3 of the 4 mechanisms — Escape closes it, focus moves to the close button on open, focus returns to the opener on close, and it even sets `aria-hidden`/`inert` when shut so a keyboard user cannot tab into an invisible panel. What is missing is only the confinement, so Tab walks out of a dialog that has told assistive technology the page behind it is inert. ⛔ **NOT a drop-in migration to `useFocusTrap`, which is why it was exempted rather than fixed in the same commit**: its focus-in, Escape and opener-restore live in the `EvidenceProvider` rather than the panel — deliberately, because the provider owns the open/close state and the opener identity across pages — so adding the panel-level hook would leave the hook's `document.activeElement` restore racing the provider's `openerRef` restore. Which wins depends on effect-cleanup order, and judging that needs the drawer open in a browser, not a source read. ⛔ Do it with a running app: either move all four mechanisms into the hook at the provider level, or give the hook a confine-only mode and keep the provider's three. `tests/accessibleControls.test.js` names the exemption with this reason, so it cannot quietly become permanent. ⛔ **DONE via the confine-only route, which removes the race BY CONSTRUCTION rather than reasoning about effect-cleanup order.** `useFocusTrap` gained an opt-in `confineOnly` (default `false`, so `Modal` and `IdleTimeout` are behaviour-identical and a test pins that neither passes it); Evidence takes mechanism 3 alone and the provider keeps the other three. The ref is on the `<aside className="ev-drawer">`, not the scrim. ⛔ **The closed drawer was the sharpest hazard and is safe on four pieces of evidence, not one**: `open = !!payload` is the ONLY gate and drives `active`, `data-open`, `aria-hidden` and `inert` alike (pinned); the effect bails before installing any listener while inactive; and both `active: true` and deleting the bail go RED. ⛔ **The imperative half was split out as `installFocusTrap(getPanel, {win, doc})` so the trap is EXERCISED, not read** — what stood there before was five regexes over the hook's own source, the shape of guard this repo has twice seen satisfied by a mention; `getPanel` stays a getter so the live re-read on every key is preserved. 16 behavioural tests replaced it, and the “could not measure” case is covered in two senses (a panel with nothing focusable swallows Tab in BOTH modes; a vanished panel does not throw; and the suite SKIPS with its reason printed if the ES module cannot be loaded, never silently passing). ⛔ **CONFINEMENT MADE A PRE-EXISTING GAP INTOLERABLE, and that fix was taken too** — see row 64: measured in Chromium, PageDown and ArrowDown both left `.ev-body` at `scrollTop 0` with **1,870px of evidence below the fold including “What could not be measured”**, because the scroll container has no focusable descendant and the close button sits outside it. Before the trap a keyboard user could Tab out; shipping confinement alone would have pinned them in front of unreadable content. ⛔ One equivalent mutant recorded rather than quietly dropped. 26 tests, 14 mutations RED. | **[x]** v2.228.12 |
| 59 | **A firewall silent for LONGER than the evidence window produces no anomaly finding at all** — the detector goes quiet exactly as the silence becomes total. Found 2026-11-14 while fixing row 29, by reading `detectSilence`. `if (!list.some((h) => h.reported))` returns `NO_DATA`, and `gatherAnomalies` does `if (r.state !== DETECTOR_STATES.MEASURED) continue;` — so a device that reported for a year and went dark 29 days ago yields **nothing**, while one dark for 27 days yields an alert. ⛔ **THE `NO_DATA` BRANCH IS RIGHT FOR THE CASE IT WAS WRITTEN FOR AND WRONG FOR THE ONE IT ALSO CATCHES.** Its own comment is correct — "a device that has NEVER reported is NOT silent, it is uncollected, and that is a different fact with a different owner" — but the predicate is "did not report IN THIS WINDOW", which collapses *never started* with *stopped reporting, maximally*. ⛔ **Severity is moderated and this was CHECKED rather than assumed**: the device is NOT invisible, because `coverageRegister.js:433` separately says "This firewall sends no syslog to SecVault". What it means is that the surface wired to OUTBOUND alerting emits nothing, so nobody is told without opening `/coverage` — and the two surfaces disagree about the same firewall. (Worth confirming whether the register itself distinguishes *never* from *stopped*; it looks like it may carry the same ambiguity.) ⛔ **The fix is one extra aggregate, on a PERMANENT table**: `MAX(bucket_hour)` over all of `syslog_rollup_hourly` for the device, unbounded by the window. History older than the window with nothing inside it means STOPPED; no history at all means never started. ⛔ **The natural key already exists** — such a run's start is by definition outside the evidence, so `start-before-window` from v2.228.10 is exactly the right key and it cannot churn. ⛔ A new detector state is needed (`stopped_before_window`) rather than reusing `measured`, because `hours` is unknowable from the window and must not be fabricated; the sentence should say "has sent no syslog since <the last hour it did>", which the new aggregate gives for free. ⛔ Reachability on the live fleet is UNMEASURED — the VPN was down when this was written. ⛔ **FIXED v2.230.0.** `loadLastReported` is the unbounded `MAX(bucket_hour)` this row specified, and `detectSilence` now reads three answers where it read two: a Date, an explicit `null` (never reported), and **undefined — nobody asked**, which is its own reason and is never collapsed into either verdict. New state `stopped_before_window`, counted as JUDGED rather than as a coverage gap; `hours` stays **null** and the real span travels as `silentDays`, measured from the permanent table. The `start-before-window` key is reused, so a run that crosses the edge and then falls wholly outside it keeps ONE key and the dispatcher does not resolve-and-re-raise on the day the firewall becomes most silent. ⛔ **Reachability, finally measured (the VPN was down when this row was written): NOT reachable today and on a clock.** 15 of 16 firewalls are current; PAKFood has never reported and is correctly `no_data`; **TFM-RN last reported 2026-11-08 — 8 days dark, so it crosses the 28-day boundary on 2026-12-06**, which is the day the old code would have gone quiet about it. ⛔ The register ambiguity this row asked about is NOT closed and is not in scope here. | [x] v2.230.0 |
| 60 | **Three `normalizeCountry()` map values do not match the long form the devices actually send, so the fold cannot happen for them.** Measured 2026-11-15 by cross-checking all 61 map values against every distinct long-form `src_country` in `syslog_vpn_auth_hourly` (82 of them): `CZ` is mapped to `'Czechia'` while the data holds **`'Czech Republic'`**; `KR` to `'South Korea'` while the data holds **`'Korea, Republic of'`**; `LA` to `'Laos'` while the data holds **`"Lao People's Democratic Republic"`**. ⛔ **All 42 live ISO codes ARE now mapped** (row 32 closed that), so these three are the residue: the map's VALUE is the fold key, and a value that does not byte-match the stored long form splits the country exactly as an unmapped code did. ⛔ **Latent today** — none of `CZ`/`KR`/`LA` currently appears as a two-letter code in the data, so there is nothing to split yet; it fires the first time a device emits one. ⛔ **The convention the v2.228.12 work inferred was right about the MAP and wrong about the DATA**: the map prefers the common English name (`South Korea`, `Czechia`, `Laos`), the devices emit the ISO-official form, and `RU: 'Russian Federation'` — recorded as the map's one "exception" — is the only one that happens to match. The data is authoritative here, which is CLAUDE.md's "documentation lies, verify against live responses" rule applied to our own lookup table. ⛔ **NOT a one-line change, which is why it was recorded rather than done in the same batch:** the map value is simultaneously the fold KEY and the DISPLAY label, so matching the data makes the ranking page read `Korea, Republic of`; `tests/vpnLoginLocations.test.js:190` also uses `'Czechia'` as a fixture; and `tests/vpnAuthStatsCountryMap.test.js` deliberately pins the one-sided fold (only the ISO side is normalised), so folding the long form to a nicer label instead would contradict that pin. Decide between "match the data" and "normalise both sides to a chosen label" — the second is the better product answer and the bigger change. | [ ] |
| 61 | ⛔ **`fixed_in_versions` CAN BE BLANKED BY AN INCOMING RECORD THAT HAS NONE, WHILE `affected_version_ranges` NEXT TO IT IS PROTECTED UNCONDITIONALLY.** Found 2026-11-15 while converting row 25's test. `lib/feeds/fortinet.js:1151-1155`: the preserve-existing arm is gated on `$17::boolean` (the `degraded` flag), so a NON-degraded `advisory_page` record carrying `fixed_in_versions: []` falls to `ELSE EXCLUDED.fixed_in_versions` and erases a non-empty list — while the `affected_version_ranges` arm three lines above refuses the same downgrade for ALL records via `hasUsableFixBoundarySql`. ⛔ `[]` is the ORDINARY CSAF outcome, not an edge case: `fortinet.js:767` records the "Upgrade to X.Y.Z" instruction as "a bonus (not required)". ⛔ **`lib/feeds/cveHub.js:528-537` already refuses exactly this and names the cost in its own comment** — "real fixed versions from the Fortinet CSAF feed would be blanked by a hub row that has none, flipping `is_fixed_recommended` and silently moving a CVSS>=7 advisory from scheduled to monitor" — so the rule is written down in one feed and absent from the other. ⛔ **`lib/feeds/paloalto.js:562-563` IS WORSE: it has NO empty-value guard at all** — `fixed_in_versions = CASE WHEN advisories.vendor = EXCLUDED.vendor THEN EXCLUDED.fixed_in_versions ELSE advisories.fixed_in_versions END` takes the incoming value unconditionally on any same-vendor upsert. ⛔ **MEASURED POPULATION AT RISK (production, 2026-11-15):** non-empty `fixed_in_versions` by vendor — **paloalto 320 of 370**, fortinet 8 of 317, checkpoint 3 of 77, cisco_asa 0 of 357, sangfor 0 of 5, forcepoint 0 of 5. So the ungated path guards the vendor holding **40x more** of the data than the half-gated one. ⛔ **Reachability is UNMEASURED and is the decision:** nobody has counted how often either feed actually re-upserts an advisory with an empty list where a non-empty one is stored. Measure that before changing the SQL — a guard added on a path that never fires is cost without benefit, and `cveHub`'s existing refusal may already be absorbing the hub-sourced case. ⛔ **FIXED v2.228.15, AND IN ALL THREE WRITERS RATHER THAN THE ONE THIS ROW NAMES.** Re-measured 2026-11-15: `fortinet.js` guarded this column only behind `$17::boolean` (`degraded`), and **`paloalto.js` and `nvd.js` did not guard it at all** (`THEN EXCLUDED.fixed_in_versions`, unconditional on a vendor match). `cveHub.js` was the only correct one in the codebase. Fixing only the row's named site would have been the one-of-three trap row 20 records. ⛔ **PROVEN REPRODUCIBLE BY EXECUTING THE REAL STATEMENT** (extracted from the shipping source, `PREPARE`d, run against a live `advisories` table) **with the pre-fix arm as a negative control**: a healthy NON-degraded record carrying `[]` turned `["7.4.11"]` into `[]` under the old arm and left it untouched under the new one; under BOTH, an incoming `["7.4.12"]` still wins, so the guard is one-directional and the vendor keeps authority where it has better data. ⛔ **ONE SHARED PREDICATE, `hasFixedVersionsSql` in `lib/feeds/fixBoundary.js`**, now used by all four writers including `cveHub.js`, whose inline copy was migrated so "names a real release" cannot mean two things in two files. It WALKS the array rather than trusting `jsonb_array_length > 0`, because a list of empty strings names no release either — the reasoning `max: null` already carries for a boundary. SQL-only on purpose: nothing decides this column in JS, so a JS twin would be an unused definition free to drift. ⛔ **A GUARD FOR THE NEXT WRITER, AND ITS FIRST DRAFT WAS SATISFIED BY A MENTION.** `tests/fixBoundary.test.js` scans every `lib/feeds/*.js` that sets this column and requires the shared predicate — but asking `code.includes(...)` passed on the IMPORT LINE alone, so deleting the guard from `paloalto.js`'s CASE left the suite GREEN (verified by mutation). It now requires the predicate INSIDE the `fixed_in_versions = CASE ... END` arm, and a companion assertion fails if fewer than four writers are found at all, so the scan cannot go vacuous. 3 mutations verified red. | [x] v2.228.15 |
| 62 | **`deviceCoverageEvidence()`'s drawer states a formula its newest caller does not use, and the engine cannot express "no single figure".** Raised 2026-11-15 by the row 46 work, which hit it and reported rather than reaching outside its files. `OverviewComplianceCard`'s headline donut is a **BLENDED AVERAGE of the five per-standard scores** — recorded in that file as a deliberate, user-decided product choice — while `deviceCoverageEvidence()`'s drawer prints `score = round(100 x pass / (pass + fail + warning))`, which is the DEVICE-WIDE figure. Measured on `secvault_mock`: on `MOCK-SANGFOR-Branch-06` the two differ by **9 points** (blend 87%, device-wide 78%). ⛔ **All three options are imperfect and the least-bad was taken, deliberately**: passing the device-wide score would put a SECOND compliance percentage on the same screen as the donut, which CLAUDE.md forbids ("counts and a hueless grade, never a rival percentage"); passing `scorePct: null` is read by the engine as **"nothing gradeable"** and retitles the drawer; so the blend is passed and the drawer's formula line under-describes it. ⛔ **The drawer is the one surface an operator opens specifically to see where a figure came from**, so a formula that does not describe the number above it is a small instance of exactly what that drawer exists to prevent — which is why this is recorded rather than left. ⛔ **Fix:** `lib/engines/complianceCoverage.js` needs to separate "the caller's headline is not a simple pass-rate" from "nothing is gradeable" — a third state, not a null — and omit or restate the formula line in that case. Additive; no score moves. ⛔ Note the same engine is used correctly by `/compliance/[deviceId]`, whose headline IS the device-wide pass rate, so this is a property of the new caller, not a defect in the engine. | [ ] |
| 63 | ⛔ **`tests/designSystemRamp.test.js`'s "a severity-ramp hue is never the `color` of small body text" IS BLIND TO A HUE RETURNED BY A HELPER — AND THAT IS HOW A 3.64:1 TEXT FAILURE SURVIVED THE v2.228.7 SWEEP THAT GUARD SHIPPED WITH.** Found 2026-11-15 by the row 47/49 work, in the guard written three commits earlier. `RAMP_ON_TEXT` matches the ramp tokens as LITERALS in the value expression, so `color: toneFor(s.scorePct)` — a local function returning `var(--yellow)` — passed it with `RAMP_TEXT_ALLOWED` empty and the suite green. Measured: `ComplianceStandardsBreakdown` painted a **16px/700** score in `--yellow`, **3.64:1 on `--bg-card`** in the default light theme, and 16px bold is NOT large text. Fixed in that file by hand; the GUARD is still blind. ⛔ **This is the same class of limitation as `tests/sizingConsistency.test.js` being unable to catch two inputs that cancel** (roadmap row 18): both guards check exactly what they claim and the gap is in what they CANNOT see, which is worth writing down beside them rather than leaving a reader to assume coverage. ⛔ **Fix shape:** resolve single-file helpers — a function declared in the same module whose every `return` is a ramp literal, applied to `color:` — and treat that as the literal. ⛔ **Do NOT make it follow arbitrary call chains**: a scan that reports a hue three modules away will fire on correct code, and a guard that cries wolf gets waived, which is how the check stops happening. Keep the named-exemption convention so an intentional case is a decision with a reason. | [ ] |
| 64 | **A scrollable region whose only focusable controls sit OUTSIDE the scroller cannot be scrolled by keyboard, and the evidence drawer was one.** Found 2026-11-15 while fixing row 58, and measured in Chromium against the real `app/globals.css` rules: `.ev-body` is the drawer's scroll container while the close button lives in `.ev-head` outside it, so with focus where the provider puts it there was **no scrollable ancestor for the browser to act on** — PageDown AND ArrowDown both left `scrollTop` at **0** with **1,870px of evidence below the fold, including "What could not be measured"**. Fixed for `.ev-body` (`tabIndex={0}`, `role="region"`, `aria-label`): scrollTop 0 → 348 on one PageDown. ⛔ **It was pre-existing, and adding Tab confinement is what made it intolerable** — before, a keyboard user could at least Tab out of the drawer; shipping the trap without this would have turned "focus escapes a modal dialog" into "pinned in front of content you cannot read". ⛔ **Only `.ev-*` was checked.** `app/globals.css` has several other `overflow-y: auto` / `overflow: auto` containers; sweep them for the same shape — a scroller with no focusable descendant — and fix the ones that have it. Each is cheap; the point is that nothing systematically looks for them. | [ ] |
| 65 | **51 hand-rolled `repeat(auto-fit, minmax(...))` KPI grids remain, against `KpiRow`'s rule that `auto-fit` "cannot be fixed by tuning that number, because it does not know how many tiles there are".** Measured 2026-11-15: 56 repo-wide before the row 47 work, 5 adopted (`ChangeOutcomeBoard` 6, `ConformanceBoard`/`ConsolidationTab`/`RiskyRulesTab` 5, `VpnDetections` 4), so **51 left**. ⛔ **Not all 51 are defects** — `auto-fit` is correct for a genuinely open-ended set, and `DeviceStatusSummary` was reported as an offender for three releases while being `repeat(3, 1fr)` since v2.10.0, so the list must be re-derived per candidate rather than migrated wholesale. ⛔ **The ones that matter carry a FIXED tile count from an array literal and a RANKING**, which is where orphaning inverts meaning: `ChangeOutcomeBoard`'s stranded sixth tile was `indistinguishable`, the verdict that file ranks LAST precisely so it is not prominent, and the layout gave it a row to itself. Triage by (fixed count) × (does order mean anything), not by grepping for the shape. | [ ] |
| 66 | **`ruleRiskByTrafficPdf.js:129` hand-reserves a chart's height in the CALLER, and v2.228.12 made it redundant with 0.66px of margin.** `ensureSpace(doc, layout, 15 * 20 + 60)` is a second, hand-maintained copy of the chart's height arithmetic, and its own comment claims it includes "its caption". ⛔ **It is WHY that document was correct** — it dominated the chart's own (then caption-less) reservation, which is why `comparePdfs` finds that call-site sequence identical at all 721 cursor positions before and after the fix. Now that `drawBarChart` reserves for its own caption the chart needs **337.34** against the caller's 360, i.e. **0.66px of margin after `sectionTitle`**. ⛔ **It will silently disagree the day `barH`, the gap or that caption changes** — two copies of one piece of arithmetic, which is the shape this repo records going wrong in `ComplianceMatrix.scoreColor` (row 49) and `STANDARDS`. ⛔ Either remove it, now that the chart reserves correctly for itself, or keep it and change its comment to say it is belt-and-braces rather than the primary guard. Not touched in v2.228.12 because the file was outside the agent's partition and the change is a judgement about which guard is primary. Trivial either way; the point is that it must be a decision. | [ ] |
| 67 | ⛔ **`checked_at` CANNOT CARRY CONTENT, AND A LIVE INGEST HID A DEAD CORPUS FOR THREE WEEKS — FIXED v2.228.13, RECORDED BECAUSE THE REASONING MATTERS MORE THAN THE FIX.** Raised and closed 2026-11-15 by the row 56 work, which had declared "there is no code change here". `feedFreshness`' docblock argues correctly that `generated_at` cannot carry LIVENESS (an idempotent republish leaves it still on a quiet week); **the converse was never guarded** — `checked_at` says the hub is ingesting and says nothing about whether the corpus is GROWING. Measured on the live hub: `generated_at` 2026-10-02 (44d), `checked_at` 2026-10-23 (23d), newest CVE *publication date* in the corpus **2026-09-22 (54d)**. So between 10-02 and 10-23 `checked_at` advanced hourly, this feed reported **`fresh`**, and no newly published CVE had arrived. ⛔ `corpusAdvance()` reads `generated_at` from the **SIGNED BODY** (`checked_at` is a header), so it cannot be set independently of the feed it describes. ⛔ Threshold 14 days, a **STATED CADENCE not a derivation**, labelled as such like A6's `reviewOverdue`. ⛔ `superseded` when freshness is already bad, enforced in the function rather than documented, so one fault never yields two errors. ⛔ Reports, never refuses — but it DOES push into `errors`, which makes `hubDelivered` false and re-enables local NVD discovery, deliberately and for a stronger reason than the stale branch has. ⛔ **The WIRING was the unguarded part and that was measured**: with the composition inline, deleting `...corpusAdvanceErrors(advance)` left **all 44 tests green**, so the composition is now the pure exported `syncErrors()` and dropping either contributor goes red. ⛔ One shared `CLOCK_SKEW_TOLERANCE_MS` instead of two copies of `-5 * 60 * 1000`. 49 tests, 8 mutations verified. | [x] v2.228.13 |
| 68 | **`Backup-SecVault.ps1` holds a second copy of the directory-lockdown logic, and its guard is what blocks unifying them.** Raised 2026-11-15 by the v2.228.14 work, which deliberately did NOT migrate it. `installer/SecVault-Acl.ps1` is now the shared definition used by both installer scripts for the spool and the archive; the backup script keeps its own inline `icacls` block. ⛔ **Not laziness — `tests/backupScripts.test.js` pins that block by TEXT**: `'/inheritance:r'` as a literal, `$aclCheck = Invoke-Native`, and its ORDER relative to the `pg_dump` and the `CREDENTIAL_KEY` copy. Dot-sourcing the helper breaks all three, and weakening a guard that protects `CREDENTIAL_KEY` to accommodate a refactor is the wrong trade. ⛔ **So the work is the GUARD, not the script**: convert those assertions to behavioural ones (the v2.228.14 helper was verified by execution on staging PS 5.1 — 18 assertions — which is the shape to copy), then route the backup script through the shared function and delete the copy. ⛔ Until then the two copies can drift, and the one in `Backup-SecVault.ps1` is the one guarding the directory that holds `CREDENTIAL_KEY`, `PG_ADMIN_PASSWORD` and the TLS private key — so **if either is changed, change both in the same commit**. | [ ] |

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
| 69 | ⛔ **THE OS/FIRMWARE BRANCH LIFECYCLE FEED — BUILT v2.229.0.** SecVault knew every firewall's running version and matched advisories against it, so it could say "this firewall is affected by CVE-X"; it could not say that the BRANCH that version belongs to left vendor support in 2022, which makes the advisory's own "upgrade to 10.0.12" instruction name a release on a branch the vendor no longer commits to. The hub's third signed corpus (`/api/v1/os-feed`, 54 cycles: PAN-OS 27, Cisco IOS-XE 19, FortiOS 8) closes it. ⛔ **NO NEW CLIENT AND NO NEW ENV VARS** — `lib/feeds/hubFeed.js` now holds the pinned key, the verifier and the transport for BOTH hub feeds, and `CVE_HUB_URL`/`CVE_HUB_LICENSE_KEY`/`CVE_HUB_PUBLIC_KEY` govern both because they describe one publisher. ⛔ **THE SHARED KEY WAS MEASURED, NOT ASSUMED**: the OS feed's REAL published signature over its real 23,538-byte body verifies against the key already pinned in SecVault's source, and a one-bit flip is rejected — the fixture `tests/fixtures/osFeedSigned.js` keeps that proof offline and permanent. ⛔ **FOUR STATES, NEVER THREE**: `extended_end_date` is a separate date, so `extended_only` is its own state with its own claim (`EXTENDED_CLAIM`) — the first draft said "cannot be fixed on this branch" of an extended-support firewall and a test caught it. ⛔ **CONFIDENCE DECIDES THE BAND**: PAN-OS is the vendor's own table (`high` → `reported` → may reach `act_now`); every FortiOS and Cisco IOS-XE row is endoflife.date (`low` → `unmeasured` → `verify`), however bad it looks. ⛔ **`cisco_asa` IS NOT MAPPED TO IOS-XE** — an ASA runs ASA Software; the corpus covers IOS-XE because a machine-readable source existed, not because it covers this product's firewall. ⛔ **FIVE UNKNOWN CAUSES, NEVER SUMMED.** ⛔ **NO PRIORITY-BAND CHANGE**: the branch state is a second axis beside `priority_band`, like `approval_state` beside `rule_change_requests.status`. 143 tests, **20 mutations verified red**, and the whole path exercised against real Postgres (54 stored, idempotent re-apply, a PAN-OS 10.0 device classifying `eol`). ⛔ **AND THE LAST UNVERIFIED STEP IS NOW MEASURED (2026-11-17): the authenticated HTTP pull from production runs** — four consecutive `os_hub` cycles `success`, `stored 54 / refused 0 / removed 0`, `os_branch_cycles` at 54 rows / `feed_version 2026-11-16.1` with 26 `lts` NULL preserved, and dbcheck 123 ok/4 failed → **127 ok / 0 failed**, the four failures having been only the undeployed table. | [x] v2.229.0 |
| 70 | **The work queue has TWO `TYPE_LABEL` maps and they were already out of step before this release.** Found 2026-11-16 while adding `os_lifecycle`. `components/work/WorkQueueBoard.js` and `components/work/WorkQueueFilters.js` each carry their own map and each falls through to the RAW TYPE on a miss, so a missing entry renders a snake_case identifier in the UI rather than failing visibly — which `WorkQueueBoard`'s own comment already records happening to `application_flow` for a release. ⛔ Measured today: the Board map covers 12 types; the Filters map covers 10, of which **`device` and `conformance` are not types any gather emits**, while `tunnel`, `collection_gap`, `ingest_drop`, `coverage_gap` and `licence_unknown` are emitted and absent from it. So the filter dropdown shows raw identifiers for five real sources. ⛔ **Both maps got `os_lifecycle` in v2.229.0 and the drift was left**, deliberately: closing it means fixing ~6 existing labels, which is a user-visible change outside that commit's subject. ⛔ **Fix shape — a GUARD, not six edits**: assert that every `type` a gather can emit has an entry in BOTH maps, derived from the gathers rather than from a third hand-written list, and fail the build on a map entry naming a type nothing emits. That is what stops the next source shipping with a snake_case label. ⛔ **FIXED v2.230.0, AND THE DRIFT WAS WORSE THAN THIS ROW RECORDED.** Measured against the sixteen types `workQueueData.js` emits: the board was missing THREE (`ingest_silent`, `tunnel_stale`, `tunnel_unknown`) and the filter dropdown was missing NINE while offering four options — `application`, `ingest`, `device`, `conformance` — that **no source has ever produced**, against `WorkQueueFilters`' own header rule that an option which can only ever return nothing is indistinguishable from a broken filter. ⛔ One shared `components/work/workItemTypes.js`, and the guard is the fix: `tests/workQueueTypeLabels.test.js` derives the types from the PRODUCER (comments stripped) and fails BOTH ways — a type with no label, and a label for a type nothing emits. One-ended it would have passed over half of this. ⛔ The fallback to the raw type STAYS: a renderer that threw would take the queue down over a cosmetic gap. | [x] v2.230.0 |

## ⛔ Deferred from the v2.236.0 bug sweep (four reviewers, 2026-11-19)

Fixed in v2.236.1: the SD-ID consumption bug, generic daemon app-names, RT_IDP byte zeros, the
`FW:` free-prose 5-tuple, `protocol="http"`, the prototype read on the filter-action letter, the
dead `CONTENT_FILTERING_BLOCKED` rule, `tenant-id` in `vdom`, the unbounded epoch, `tz_assumed`
across three parsers, `pri=` severity, the SonicWall date roll-over and zone-suffix drop, the IPv6
interface fabrication, lax `Number()`, the gcat=6 over-reach, the auth vocabulary, the CEF
precedence regression, the credential holes in both device routes and `CredentialForm`, the
engine-worker skip gate, Test Connectivity, `NEVER_ACT_NOW_SOURCES`, the compliance-controls
denominator, the fleet-headline amber chip and the `syslog_rollup_hourly` seq scan.

⛔ **v2.237.0 WIDENED THE FEATURE AND CLOSED THE TWO ROWS THAT MADE IT UNSAFE TO WIDEN.** Every
MANAGED vendor now offers `mgmt_method = 'syslog'` too, so a FortiGate nobody holds credentials for
can be added log-only — which is what v2.236.0's own note predicted ("untrue otherwise the day
somebody owns a Fortinet they have no credentials for — which is the common case this unlocks
next"). ⛔ That is exactly what made rows 1 and 2 stop being cosmetic: while only `juniper` and
`sonicwall` could be log-only, the vendor column was an ACCIDENTAL TELL, because neither has an
adapter and a reader could infer the state. A log-only FortiGate offers no inference at all — its
row is pixel-identical to a FortiGate that was assessed and came back clean.

**Still open, deliberately — none blocks a deploy:**

1. ✅ **CLOSED v2.237.0** — no surface MARKED a device as monitoring-only.
   `components/devices/MonitoringOnlyMark.js` is the one marker (hueless `--unmeasured`, a WORD not
   just a glyph), `deviceInventory.js` and `deviceContext.js` now project `mgmt_method` and derive
   `monitoringOnly` from `isMonitoringOnly()`, and it renders on `/devices` and on all six
   per-device pages. ⛔ **In the NAME cell, not the vendor cell**: `vendor` is priority 3 and
   hideable from the ColumnChooser, so a marker there is defeated by a saved view or a pasted URL,
   while `name` is `required: true`. ⛔ Derived from the METHOD, never from
   `VENDOR_META.monitoringOnly`, which answers the different question "could SecVault ever manage
   this brand" — a test pins both directions. ⛔ The projection itself is pinned by reading the SQL
   the real function issues **with comments stripped**, because both queries carry a `--` comment
   naming the column and a naive scan is satisfied by the prose justifying the thing it checks.
   Verified live on the mock fleet: two log-only FortiGates marked, beside a genuinely-broken ASA
   carrying the same em-dashes and no marker.
2. **PARTIALLY CLOSED v2.237.0 — `coverageRegisterData.js` STILL does not project `mgmt_method`.**
   `deviceInventory.js` and `deviceContext.js` now do (row 1). The coverage register does not, so it
   still cannot draw the blocked-vs-skipped distinction and still ranks a log-only firewall
   **#1 fleet-wide** above every genuinely broken device, with cell text reading as collection
   failures. ⛔ **The blast radius grew with v2.237.0**: any vendor can now reach that #1 slot, not
   only the two adapter-less ones. ⛔ It was left out deliberately rather than folded in — the fix
   is not a projection but a RANKING SEMANTICS change on a page whose whole job is ranking by
   consequence, and that deserves its own commit and its own measurement rather than riding along
   with a capability change.
⛔ **FOUND BY A FIVE-AGENT SWEEP OF v2.237.0 AND FIXED IN IT** (so they are recorded as closed
rather than open): the PUT monitoring-only refusal threw `ReferenceError: method is not defined`
and became a 500 — the same shape as the v2.236.0 `NextResponse` bug one route over, a guard
crashing on the branch it exists to serve; `PUT {mgmt_method:'syslog'}` on an already-collected
firewall stranded its version, ruleset, config, CVE assessments and compliance findings as FROZEN
evidence that every engine kept asserting (measured: a converted FortiGate scores **97, band
"excellent"**) and is now refused 409 via the testable `refuseMonitoringOnlyConversion()`;
`PUT …/snmp` was the third `setCredential` caller and the only one with no monitoring-only guard;
`POST /api/devices` stored a client-supplied `mgmt_port` for a method declaring `defaultPort: null`;
Forcepoint-plus-syslog could never be saved because the SMC test-before-save gate keyed on the
VENDOR's connection shape rather than on whether SecVault would connect at all; the port field
rendered a literal `"null"` placeholder; the explanatory paragraph was not `FULL_WIDTH`; the
prefilled address vanished on a vendor change; the per-device header dropped the marker on a failed
context read while keeping the vendor badge; the discovered-list hint named an Access Method
selector that is not rendered for `juniper`/`sonicwall`; and both minute-scale poll loops reached
`getAdapter` for a log-only managed-vendor firewall, logging ~150 false "could not build adapter"
warnings per device per day.

⛔ **AND THE SWEEP FOUND THE TEST GUARDS WERE THE WEAKEST PART, WHICH IS THE DURABLE LESSON.**
Sixteen mutations had been verified red before the review and the review still found five INERT
assertions in the same file: the marker was rendered in isolation and **never asserted to be
MOUNTED** (deleting both call sites left the suite green — the entire visible half of the release);
`aria-hidden` was matched anywhere in the markup, so moving it to the OUTER span passed while
removing the whole marker from the accessibility tree; "hueless" was an 8-token blocklist that
missed the good half of the ramp, so a GREEN-tinted "Logs only" chip passed; the title asserted the
claim and not the imported remedy; and the `securityScore === null` fixture pinned pre-existing
never-assessed behaviour rather than anything to do with `mgmt_method`. All five are closed, plus a
`/noPort/` scan that was satisfied by `const noPort = false;`. **A mutation round proves the
mutations you thought of; it says nothing about the assertion you never wrote.**

**Still open from that sweep, deliberately:**

- ✅ **CLOSED v2.237.1** — `/alerts` could print an unqualified all-clear over a fleet the
  detectors never looked at.
  `AnomalyPanel`'s `anyUnjudged` reads only `insufficient_baseline` and `no_data` and has **no fleet
  denominator**, while `loadReportingGrid` selects only devices that already have a
  `syslog_rollup_hourly` row — so a firewall that has never produced one is in NO bucket at all.
  Measured: with **zero** firewalls judged the panel renders a plain card, no coverage pill, no
  `<details>`, and the sentence "No firewall stopped reporting and none exceeded its normal
  denied-traffic level in the last 28 days." ⛔ v2.236.4 made this worse in three ways: the gate is
  now the sole safety argument for collapsing the section, it also decides whether the disclosure
  exists at all, and the all-clear is now the only sentence on screen. ⛔ Live today in partial
  form — PAKFood sends no syslog, and every monitoring-only firewall is invisible to the gate, so
  13-of-16 judged renders identically to 16-of-16. `Coverage` also prints "judged 15 firewalls", a
  numerator with no denominator, under its own comment saying a reader "needs the denominator".
- ✅ **CLOSED v2.237.1** — an unregistered detector was silently dropped from the closed bar while
  the comment, the fallback branch and the test title all claimed the opposite. `detectors` is now
  the registered set UNION whatever the findings and `states` actually carry, so the
  `${mine.length} ${detector}` fallback is reachable and the test asserts the NAME rather than only
  the count. ⛔ The old note, kept because the shape recurs: `describeAnomalies` iterates
  `Object.keys(DETECTOR_LABEL)`, so a detector outside the registry contributes rows INSIDE the
  disclosure while the load-bearing bar says only "1 observation"; the `${mine.length} ${detector}`
  fallback is unreachable dead code, and the test named "names an unregistered detector rather than
  dropping it" asserts only the observation count. A6 exists to register new detectors, so this is
  on the next one's path.
- **`<h2>` inside `<summary>`** (`AnomalyPanel`) is not a valid content model — `<summary>` takes
  phrasing content or one heading element, and it is wrapped in a `<div>` with a `<p>`. Browsers
  render it, but name-from-content flattening very likely drops the section from the document
  outline. The cited precedent (`.wq-item`) contains **no heading**, so this is not the house
  pattern it reads as.
- **`/logs` for an Operator resolves `activeNavHref` to `null`**, so every sidebar row renders
  inactive while `sectionIsActive` still lights Investigate — the row-grain version of "the sidebar
  claiming you are nowhere" that v2.236.3 was written to prevent. Not a regression (the row was
  never rendered for that role), but v2.236.3's new docblock asserts "nothing goes dark", and there
  is no ancestor to fall through to because group items are flat.
- **`executiveSummary`'s "Firewalls reachable"** keeps a log-only firewall in the denominator and
  can never put it in the numerator, so the PDF that leaves the building shows a reachability
  REGRESSION the month one is added, and `dashboardSnapshot` persists it into every future delta.
  Same root as `lib/evidence.js`'s "Not reachable" drawer row. ⛔ Deliberately NOT changed here:
  `monitoring_only` is now counted separately by `getDeviceCounts` so the partition is available,
  but moving a published metric's denominator is the kind of change CLAUDE.md wants documented
  before the code, not folded into a capability commit.
- **`complianceControls`' numerator and denominator use different device sets.**
  `VENDOR_SCOPE_SQL` excludes `mgmt_method IS DISTINCT FROM 'syslog'`; `FINDINGS_SQL` does not, and
  `notEvaluated = Math.max(0, applicable - answered)` clamps the contradiction away instead of
  reporting it `inconsistent` the way `complianceCoverage` does. Only reachable via a converted
  device, which v2.237.0 now refuses — so it is latent rather than live, and it should still be
  made consistent.
- `vpnTunnelHealth.tunnelSupport(vendor, 'syslog')` classifies six vendors in one identical state
  three different ways (`support_unknown` / `unsupported` / null). Every answer degrades toward
  unclaimable, so nothing is over-claimed, but the honest bucket for all of them is "never connected
  to" and no existing state says that.

2b. ✅ **CLOSED v2.237.3** — a firewall absent from the evidence ENTIRELY was neither judged nor
   counted by either anomaly detector. `loadReportingGrid` gated its device list on
   `EXISTS (… syslog_rollup_hourly …)` and `loadDeniedSeries` derived its devices from a
   window-bounded `reporting` CTE, so a firewall that has never produced a rollup row (or is dark
   for the whole window) was missing from the numerator AND the denominator. ⛔ **It was a RECORDED
   residual of v2.237.1, not an unknown** — `AnomalyPanel.js` wrote it down ("13-of-16 judged reads
   exactly like 16") and writing a gap down does not close it. ⛔ Measured on production
   2026-11-24: 17 active, `measured` 15, `no_data` **0** — PAKFood and the newly-added logs-only
   StarUnion. ⛔ Fixed in BOTH detectors, because one of two is the v2.228.10 trap. Counted, never
   alerted: a firewall that never started is uncollected, not silent. 4 mutations verified red.

2c. ✅ **CLOSED v2.237.3** — `runRuleVersionPullJob` wrote a FAILED `device_connectivity_history`
   row for a logs-only firewall, so its header read "Failing — config collection 0% succeeding"
   and "Every poll in the last 3 days failed" about a device 20 minutes old that SecVault never
   contacts. `collectAndStore` skipped it correctly and the loop then recorded the skip as an
   unreachable poll — the doctrine implemented in the adapter layer and defeated one function
   later. v2.237.0 guarded `vpn-session-poll` and `snmp-poll` and missed the third loop, which is
   the only one that writes reachability. ⛔ Found by the user testing the feature on production
   the day it shipped.

2d. ✅ **CLOSED v2.237.4** — **onboarding a firewall raised a false silence alert.**
   `syslog_rollup_hourly.device_id` is stamped at INGEST, so a rollup row cannot predate the
   device row — every hour before a firewall was added is silent by construction, and
   `detectSilence` read the lot as one run. Measured on production 2026-11-24, 48 minutes after
   the fleet's first logs-only device was added: *"StarUnion stopped sending syslog — AT LEAST 671
   hours"*, about a firewall created at 14:28 that was sending as the alert was generated.
   ⛔ **It would have been DISPATCHED** — `device_silent`'s alert type is in
   `notificationDispatch.js`'s ALERT_TYPES, so with channels configured, onboarding a firewall
   emails an outage alert about it; this deployment has none. ⛔ **Not a regression from 2b** — the
   device had rollup rows by then, so the old `EXISTS` admitted it too; it needed a firewall to be
   ADDED to show itself, which had not happened here in months. ⛔ Each device's grid now starts at
   `date_trunc('hour', LEAST(created_at, now()))`, and `gridStartsAtBirth` travels with it so a run
   at index 0 is NOT flagged `truncated`: v2.228.10's moving window edge and a fixed recorded
   creation time must not share an answer. ⛔ A gap between creation and the first log is still
   reported — SecVault was listening and nothing came. 6 mutations verified red, **two of which
   survived the first round**: hardcoding the flag at the call site and when reading the column
   both left the suite green, because the tests drove the detector and the SQL and not the WIRING
   between them.

2e. ◨ **IN PROGRESS v2.237.7 — a VOLUME-COLLAPSE detector.** `device_silent` asks only "did ANY
   event arrive this hour", so a 99.999% fall that keeps dribbling is invisible to it: TFM-MH went
   from ~5.9M events/day to ~30 on 2026-11-08 and was still dark 16 days later, with management
   collection succeeding and every reachability signal green. ⛔ **`detectVolumeCollapse` is
   written, tested (15 cases, 8 mutations red) and DELIBERATELY NOT REGISTERED** — no entry in
   `DETECTORS`, no alert type, no `EVIDENCE` — because `assertRegisteredDetector` requires a
   measured rate AND sensitivity and v2.237.6 is the argument for not guessing either. ⛔ **The
   baseline is anchored in PERMANENT history, and that was measured rather than preferred**: swept
   over 77 days, a 14-day trailing baseline had ALREADY cleared on TFM-MH while it was still dark,
   and 28 days only defers the same failure to ~2026-12-06. ⛔ An early threshold sweep reported
   **0.03-0.04 alerts/day flagging TFM-MH and TFM-RN**; both halves are superseded below — the rate
   is 0.017/day and the TFM-RN firing was a defect in this detector. ⛔ A day the FLEET was not collecting
   is excluded, never zeroed, or a deploy gap flags all 17 firewalls. ⛔ Partitioned against
   `device_silent`: a fully dark firewall is that detector's.

   ⛔ **MEASURED v2.237.8, AND THE MEASUREMENT CHANGED A SHIPPED CONSTANT AND FOUND A REAL DEFECT.**
   `scripts/a6Harness.js --detector collapse` drives the REAL detector over 78 days of live daily
   rollups (16 devices, 930 device-days). ⛔ **The paragraph above said "0.03-0.04 alerts/day,
   flagging TFM-MH and TFM-RN — the two real incidents"; that was wrong on both halves.** The rate
   is **0.017/day — ONE alert in 930 device-days** — and TFM-RN was a DEFECT, not an incident this
   detector should report.
   ⛔ **THE DEFECT: THE FULLY-DARK HAND-OFF GUARD TESTED THE WINDOW'S SUM WHILE THE VERDICT TESTED
   ITS MEDIAN.** TFM-RN reported NOTHING from 2026-11-09 to 11-17 (nine days, no rollup rows) and a
   window straddling the boundary — `[758646, 0, 0]` — sums to 758,646 while its median is 0. So
   the guard passed, the detector fired, and the finding claimed **`recent: 0 events/day`**:
   `device_silent`'s exact claim, made by the detector built for the case where silence does NOT
   apply. It also CHURNED, producing TWO onsets (11-08 and 11-16) for ONE outage, because the
   walk-back crossed the dark stretch. Fixed to `rec <= 0`, which strictly subsumes the sum test;
   TFM-RN now produces nothing and every configuration yields exactly one alert. ⛔ **The durable
   lesson is narrower than "handle zeros": A GUARD MUST TEST THE SAME STATISTIC ITS VERDICT DOES** —
   two statistics for one question disagree exactly at the boundary, which is the only place the
   question is hard. In `gotchas.md`.
   ⛔ **`COLLAPSE_SUSTAIN_DAYS` MOVED 2 → 3 ON THE INTERVAL'S LOWER BOUND.** At 2 days sensitivity
   is 92% (840/915) with a 95% Wilson lower bound of **89.85%**, so it cannot be SHOWN to clear the
   >=90% bar while its point estimate reads like a pass; at 3 days it is **93% (826/885, lower bound
   91.5%)** at the same 0.017/day. 5 days scores identically and detects two days later. ⛔ Ranking
   on the bare percentage picks 2 — the same error v2.237.6 corrected for `denied_spike`, met again
   two releases later on a different detector, 0.15 points from passing.
   ⛔ **`COLLAPSE_DROP_RATIO` IS A STATED JUDGEMENT AND IS LABELLED AS ONE.** 0.95, 0.99 and 0.999
   produce the IDENTICAL alert, rate and sensitivity at every sustain, because the one real collapse
   is a 99.999% fall that clears every bar and nothing else comes close — the fleet does not
   discriminate it. 0.99 is kept on the argument that a hundred-fold fall is not a plausible traffic
   change while a twenty-fold one is reachable by a branch closing. Same class as `reviewOverdue`'s
   90 days, not a derivation dressed as a measurement.
   ⛔ **SENSITIVITY MAGNITUDES ARE MULTIPLES OF THE BAR, NOT ABSOLUTE FRACTIONS — the first draft
   got this wrong in a way that read as a 42% detector.** Planting a fixed `[0.001, 0.01, 0.05]`
   against three bars put every cell where the planted remainder EQUALLED the bar's remainder
   exactly on the threshold, and a threshold at its own boundary is a coin toss: those cells read
   25-43% while every cell a factor of ten inside read 91-93%, for the same detector. Confirmed on a
   flat synthetic canvas at **51% (486/944)** at the bar and **944/944** inside it.
   ⛔ **SPECIFICITY IS MEASURED ON A FLAT SYNTHETIC CANVAS, AND READING THE REAL-SERIES ROWS AS A
   FAILURE WAS THE SECOND DRAFT'S MISTAKE.** A plant lands ON TOP OF real variation, so a day whose
   natural volume was already a tenth of the device's median (TFM-RN's 2026-10-26 was 98,374 against
   ~1.6M, 6%) plus a ten-times-the-bar plant is a genuine hundred-fold fall — the detector is RIGHT
   to fire, because the series it was handed really did collapse. ~9 of ~900 live device-days have
   that shape. On the flat canvas a ten-times-outside plant fires **0 of 944 in every
   configuration**, so the ratio guard is sound.
   ⛔ **`COLLAPSE_SUSTAIN_DAYS` IS A WINDOW LENGTH, NOT A RUN, AND ITS OWN COMMENT SAID
   "consecutive" UNTIL IT WAS EXERCISED.** The verdict is the window's median, so a MAJORITY must be
   down: at 3 days `[1M, 10, 10]` fires on two collapsed days, and a recovery takes two days to
   clear. The hysteresis is wanted; it is a weaker guarantee than "three consecutive days" and may
   not be described as one. ⛔ Found because a test asserting *"two days is the declared sustain"*
   went on passing when the constant moved to 3 — a test that passed for the wrong reason. Both
   directions are now pinned against the constant rather than a literal.
   ⛔ **LOADER AND REGISTRATION LANDED v2.237.9, AND THE LIVE RESULT IS THE HEADLINE: 42 ANOMALY
   FINDINGS BECAME 5.** `loadDailyVolumes` (180 days, 586ms, every ACTIVE firewall from `devices`),
   the `gatherAnomalies` pass, `describeCollapse` + `COLLAPSE_CLAIM`, and all four alert-type
   registries. **TFM-MH's 39 silence findings became ONE** collapse finding keyed
   `anomaly_volume_collapse:<id>:2026-11-08`, reading *"has been sending since 2026-11-08 about 35
   events a day, against 5,472,037 a day before that — a fall of 99.999%"* and naming the 39
   absorbed runs as symptoms. ⛔ 6 outcome tests + 5 mutations verified red (suppression removed,
   key on today, the `!collapsed` gate, the count zeroed, the NO_DATA reasons re-merged).
   ⛔ **AND VERIFYING IT ON PRODUCTION FOUND ONE MORE FALSE SENTENCE.** `detectVolumeCollapse`'s
   `NO_DATA` branch collapsed two facts — zero JUDGEABLE days, and judgeable days that are all
   zero — and gave both *"this device has never reported"*. **StarUnion was added to the inventory
   that day, so its only gridded day was TODAY**, always partial and therefore never judgeable: the
   detector said a firewall that was actively sending syslog had never reported. Split, with the new
   reason naming the recency. Both remain `NO_DATA` because neither can be judged; only one is a
   statement about the firewall.
   **REMAINING: the operator CLOSE path.** The loader and registration are done.
   ⛔ **Superseded note — the original wording of this item:** — `gatherAnomalies` drives each
   detector with its own loader rather than iterating `DETECTORS`, so registering alone wires
   nothing and would leave a registered detector that cannot fire. The loader needs the daily grid
   `COLLAPSE_SQL` already proves (3.5s on production), and ⛔ **it must count a never-reporting
   firewall in the denominator** — the harness's `devs` CTE reads `DISTINCT device_id FROM hourly`,
   which omits PAKFood entirely; that is fine for a measurement and is exactly the v2.237.3 hole if
   it reaches the engine. **Then the operator CLOSE path** — decided 2026-11-24 with the user: the
   finding is LONG-LIVED, cleared only by recovery, an explicit close, or the firewall being
   removed. Modelled on `compliance_exceptions` (the measurement stays true and visible; the
   operator records that it is expected), NOT a "mark as done", which `/work`'s own rule forbids.
   ⛔ Until that path lands a collapse finding clears ONLY on recovery, which is every other anomaly
   finding's behaviour — do not describe it as closeable before it is.
   ⛔ **AND THE CASE FOR IT IS STRONGER THAN THIS ROW SAID, MEASURED ON PRODUCTION AFTER THE v2.237.8
   DEPLOY.** The argument everywhere above is that `device_silent` CANNOT see a dribbling firewall.
   `gatherAnomalies` against the live fleet says something worse: it CAN, **38 times**, and says the
   wrong thing each time. Of 42 findings fleet-wide, **38 are `device_silent` on TFM-MH alone** —
   it reports in only 8-20 hours of each day at 20-44 events, so every gap is a separate silence run
   with its own natural key. Each one is titled *"TFM-MH stopped sending syslog"* about a firewall
   that has not stopped sending syslog. ⛔ **This is also the whole of the `device_silent`
   rate drift**: `drifted_high`, 39 alerts in 28 days against a registered 0.074/day (p=0), and 38
   of the 39 are one firewall in a state this detector is the wrong one for. So the collapse
   detector does not only ADD a finding — it REPLACES 38 wrong ones with one correct one, and the
   drift notice resolves itself when it does. ⛔ Note the drift check behaved exactly as designed
   here: it reported, it refused nothing, and the figure it published was true.

3. **`lib/evidence.js:135` `deviceCountEvidence`** reports a never-probed device as a measured
   "Not reachable" with an empty "what could not be measured" — while `deviceInventoryEvidence` in
   the same file handles the identical column correctly with a separate `Never probed` row.
4. ◨ **PARTLY CLOSED v2.237.2** — the `DiscoveredDeviceActions` half is done, and writing the
   behavioural test is what found a live defect the source scans could not see.
   `tests/discoveredDeviceNotes.test.js` mounts the component with `react-dom/server` (via
   `next/dist/build/swc`, no devDependency) and reads the WORDS for every shape a discovered row
   can take. ⛔ **The defect was a HOLE BETWEEN two notes, which no per-note assertion could have
   found.** Both notes split on "is the detected vendor manageable", which assumes a vendor was
   detected: `discovered_devices.observed_vendor` is NULLABLE ("NULL = never identified", its own
   schema comment), so a third shape had `manageable` false *and* `vendor` falsy and rendered
   NEITHER note. ⛔ Measured on production 2026-11-24 minutes after the v2.237.1 deploy: of seven
   rows, the one still `new` and still sending (`10.248.40.254`, "StarUnion", 48 observed hours,
   last seen an hour earlier) has `observed_vendor IS NULL` — **so the only row anybody was going
   to click was the one the release said nothing on.** Fixed with a third hueless note naming the
   vendor gap and the logs-only remedy; 8 mutations verified red, and the test asserts the
   PARTITION (every shape yields exactly one note or a reasoned zero, with the vendor table derived
   from `VENDOR_SLUGS` so a new vendor cannot be silently omitted the way `null` was).
   ⛔ **STILL OPEN: `tests/monitoringOnly.test.js`'s DeviceForm gate**, which an agent proved stays
   green with the gate removed by keeping the identifier count. `DeviceForm` is a much larger client
   component with far more imports to stub, so it is its own sitting.
5. **`$replyDirection` is written and nothing reads it** — the 53 `m=713` SonicWall rows still
   attribute traffic to the firewall's own WAN address in `syslog_talker_hourly`.
6. ✅ **CLOSED v2.237.0** — `ACCESS_METHODS` was `['smc','api','ssh']` while `juniper` and
   `sonicwall` stored `'syslog'`, so its own comment ("the only `devices.mgmt_method` values that
   may be stored") was FALSE rather than merely stale. ⛔ **It survived because the only consumer,
   `tests/vendorRegistryParity.test.js`, looped over the MANAGED half of `VENDOR_META`** and so
   never asked a monitoring-only vendor's method about the list — a guard that could not fire over
   the single value it did not know. The loop now covers every slug and asserts the other direction
   too (no entry that no vendor offers). ⛔ Recorded while closing it: **nothing at runtime reads
   this constant** — `POST /api/devices` validates against the per-vendor `accessMethods` map — so
   it is a contract for the test to enforce, not a gate, and a route must not be "simplified" into
   reading it, because a method legal for one vendor is not legal for another.
7. ✅ **CLOSED v2.236.2** — `AdvisoriesTab.js` and `CvePostureTab.js` hardcoded a six-vendor
   filter that **omitted Sophos**, a supported vendor since v2.233.0. Reported from production the
   day after the v2.236.1 deploy made it live. The `defaultValue` residual closed with it: with
   `sophos` now an option, `?vendor=sophos` no longer filters the SQL while the control reads
   "All vendors".
   ⛔ **THE LIST IS DERIVED, NOT EXTENDED.** `MANAGED_VENDOR_SLUGS` (vendorMeta.js) is
   `VENDOR_SLUGS` minus the monitoring-only partition, and `tests/cveVendorFilter.test.js` asserts
   it equals `Object.keys(VENDOR_CPES)` — the registry in the OTHER module system, so the check
   cannot pass by being self-consistent. Adding Sophos as a seventh literal would have left the
   eighth vendor to rediscover this.
   ⛔ **JUNIPER AND SONICWALL ARE EXCLUDED ON PURPOSE** and a test pins that from both ends. They
   carry no adapter, no version parser and no CPEs, so no `advisories` row can ever name them; an
   option for them could only ever return "no results", which reads as *this firewall has no
   vulnerabilities* — the failed-read-as-a-fact rule wearing a dropdown. They are reported as
   never-assessed by the `monitoring_only` work-queue source instead, which is where that fact
   belongs.
