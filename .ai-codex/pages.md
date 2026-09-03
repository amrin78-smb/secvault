# SecVault Page Index

Dense lookup table of every `page.js` route under `app/`. Format per line:
`[client|server] /route — ComponentName — purpose`

"client"/"server" = presence/absence of a `'use client'` directive as the first line of the file.
Route paths omit route groups `(auth)`/`(dashboard)` per Next.js App Router convention.
Query-param tab state (`?tab=...`) is noted inline rather than as separate route lines — this app
uses that pattern extensively (mostly server-driven `?tab=`, one client-driven exception noted below).

---

## Auth

[client] /login — LoginPage — local-admin username/password form; calls `signIn('local', ...)`, redirects to `/` on success. No LDAP option in the UI (LDAP auth works server-side but has no login-page entry point — known gap, see CLAUDE.md).

## Dashboard

[server] / — DashboardPage — **TABBED since v2.66.0** (`?tab=overview|security|rules|compliance|fleet`, default `overview`). Twelve widgets in one grid had become a wall. `HeadlineStats` and the last-feed-sync footer sit OUTSIDE the tabs so fleet posture and feed freshness are never a tab away; everything else is per-tab. `AutoRefresh` polls every 60s.
  - Tab list + URL whitelist live in `lib/dashboardTabs.js` (pure CJS, unit-tested) — NOT inline here. Adding a tab = one array entry + one case in `page.js`.
  - `overview` = CVE Severity, ComplianceScoreWidget, RulesetOverview, TopRiskyDevices, RecentCriticalAlerts, QuickActions.
  - `security` = CVE Severity, VulnerabilityTrends, TopRiskyDevices, RecentCriticalAlerts, RiskByCategory.
  - `rules` = RulesetOverview, RiskByCategory, TopRiskyDevices.
  - `compliance` = ComplianceScoreWidget, ComplianceStandardsBreakdown.
  - `fleet` = DeviceStatusSummary, VendorDistribution, FleetSystemHealth, LicenceExpiryWidget, ConfigChangesWidget, + full-width RecentActivityFeed.
  - ⛔ Only the ACTIVE tab renders, so each 60s refresh now runs one tab's queries instead of all twelve widgets'. A widget appearing on two tabs is deliberate (Overview answers "what needs attention now" across domains; the specialised tab answers depth), not duplication to factor out.
  - ⛔ No Live Traffic tab: it needs the Phase 8 syslog collector (`services/collector.js`), which does not exist. See `lib/dashboardTabs.js` for the one-line addition and `tests/dashboardTabs.test.js` for the test that must be deleted alongside it.

## Devices

[server] /devices — DevicesPage — fleet device inventory table (name/vendor/address/version/patch-now-scheduled-monitor counts/last collected/connectivity status), sortable via `?sort=name|cve_count|last_collected`; Add Device link + per-row Collect Now/Test/Delete (all `canWrite`-gated); delete confirm via `?confirmDelete=<id>` + Server Action `deleteDeviceAction` (admin-gated, redirects `?error=forbidden` for non-admin).
[client] /devices/new — NewDevicePage — blank Add Device form (`DeviceForm`); POSTs `/api/devices`, redirects to the new device's detail page on success.
[server] /devices/[id] — DeviceDetailPage — per-device shell: identity strip (status dot/name/vendor badge) + tab bar at top (`?tab=overview|cve|rules|config|admins|manage`, `manage` admin-only both as link and content). `overview` (default) = Device Details card (mgmt IP/hostname/version/model/build/serial) + always-fetched SNMP Monitoring card (stat tiles + `SnmpTrendMini` 30-point trend, "Detected in config" nudge) + `OverviewCveCard`/`OverviewExposureCard`/`OverviewRuleHygieneCard`/`OverviewConfigChangesCard`/`OverviewComplianceCard`. `cve` = `CVETable`. `rules` = top-20-by-sequence table + links to full Rules/Analysis/VPN pages. `config` = link out to `/devices/[id]/changes`. `admins` = `summarizeAdminAccounts()` table (username/privilege/2FA/source-restricted). `manage` (admin-only) = Device Actions (`DeviceActions` Collect/Test + Delete), Rotate Credentials (`CredentialForm`), Zone Classification (`ZoneClassificationPanel`, zones fetched server-side and passed as prop so Collect Now's `router.refresh()` updates it).
[server] /devices/[id]/rules — DeviceRulesPage — full paginated (50/page) `firewall_rules` table for one device; filters: search (name/IP/port ILIKE), action (comma-list via `= ANY`), enabled, nat, zone (jsonb `@>`), sort (sequence|hits); CSV export link.
[server] /devices/[id]/changes — DeviceChangesPage — `config_diffs` timeline (each row: `DiffViewer` + `AcknowledgeButton`/ack badge+note, admin-gated) and `config_backups` table (label/size/download link) + `BackupActions` (admin-gated, create manual backup).
[server] /devices/[id]/snmp — DeviceSnmpPage — full unlimited-history SNMP page: stat tiles + `SnmpMetricsCharts` (CPU/Memory + Sessions, two charts) + `SnmpConfigForm` (admin-gated: enable toggle, host/port, saved-profile picker, manual v1/v2c/v3 entry w/ cleartext-ack gate) + "detected in config" nudge + CSV export.

## Vulnerability / CVE

[server] /vulnerability — VulnerabilityPage — tabbed shell (`?tab=posture|advisories`, default `posture`); renders `CvePostureTab` or `AdvisoriesTab`; "Assess Now" button (admin-gated, `AssessNowButton`) shown only on `posture` tab.
[server] /vulnerability/cve/[cveId] — CveDetailPage — one advisory's fleet view: CVSS/published/vendor + description + table of affected devices (current version/fixed-in/priority band/is-fixed-recommended) sourced from `device_cve_assessments`.
[server] /vulnerability/advisories/[cveId] — AdvisoryDetailPage — advisory record detail: KEV badge+date, CVSS score/vector, description, affected-version-ranges table, fixed-in-versions badges, applicability-condition count + link to conditions page, affected-devices list, external NVD link.
[server] /vulnerability/advisories/[cveId]/conditions — AdvisoryConditionsPage — CRUD UI (`ConditionsManager`, admin-gated) for this one advisory's `advisory_conditions` applicability predicates (config_key_exists/config_value_equals/config_value_matches/feature_enabled/port_exposed/admin_access_from_zone), with per-device test capability.

## Rule Analysis

[server] /analysis — FleetAnalysisPage — fleet-wide "Rule Health" table: one row per active device with per-severity (`rule_analysis_results`) finding counts + `computeRiskScoreFromCounts()` risk band/score badge, links into each device's `/devices/[id]/analysis`.
[server] /devices/[id]/analysis — DeviceAnalysisPage — 13-tab rule-analysis workspace for one device via `?tab=summary|rules|findings|cleanup|optimization|reorder|risk|risky-rules|objects|tracking|reachability|access-path|relationships` (default `summary`). `summary` = clickable StatCard grid (Total/Allowed/Denied/Inactive/NAT/Any-to-Any/Logging-Disabled, most linking into filtered `/rules` or `?tab=findings`) + severity StatCards + `RuleStatsBarChart`/`FindingsBarChart`. `findings` = filterable (severity/finding_type, 12 types) findings table. Other tabs render one dedicated component each (`CleanupTab`, `OptimizationTab`, `ReorderTab`, `RiskTab`, `RiskyRulesTab`, `ObjectsTab`, `TrackingTab`, `ReachabilityTab`, `AccessPathTab` — added 2026-08-02, object/IP/port-resolved query tool, see `lib.md`'s `objectResolver.js` entry — `RuleRelationshipTab`). "Run Analysis" button admin-gated; CSV export always available.

## Compliance

[server] /compliance — CompliancePage — `?view=cards|table` toggle (default `cards`). `cards` = ONE selected device's `StandardCard` donut grid (PCI-DSS/ISO 27001/CIS v8/NIST/SANS) via `?device=<id>` + `DeviceSelect` dropdown (defaults to first active device alphabetically, never a fleet aggregate), plus Network Details (device's collected rule zones) and `ZoneClassificationBanner` when the zone-dependent check is `na`. `table` = fleet-wide device×standard `ComplianceMatrix` comparison ("Compare Devices"); actions: Export CSV, **Download PDF Report** (added 2026-08-02, `<a href="/api/compliance/report/pdf">`, fleet-wide — the `cards` view's own per-device Export CSV/Print Report stay separate, that view already has `/compliance/[deviceId]/print` for a single device).
[server] /compliance/[deviceId] — DeviceCompliancePage — one device's `StandardCard` donut-grid summary (same 5 standards) + Network Details card + `ZoneClassificationBanner`; actions: View All Checks, Export CSV, Print Report, Run Audit (admin-gated).
[server] /compliance/[deviceId]/standards — ComplianceStandardsPage — full browsable per-standard tabbed table (`StandardTabs`) of every `audit_findings` row for one device, with `matched_rule_ids` resolved to real rule rows for rule_scan-backed checks.
[server] /compliance/[deviceId]/checks/[findingId] — ComplianceCheckDetailPage — single compliance check detail page (description/result/remediation + `RuleEvidenceTable` if rule_scan-backed); a stale `findingId` from a superseded audit run renders a friendly "recomputed since" EmptyState instead of a raw 404.
[server] /compliance/[deviceId]/print — CompliancePrintPage — chrome-free printable report: all 4(5) standards' full findings in one continuous scroll (no tabs, unlike the live page), plain-text status/severity coloring; `PrintReportButton` triggers `window.print()`.

## VPN

[server] /vpn — VpnFleetPage — fleet table of VPN status per active device (`summarizeVpnConfig()`, config-derived from latest `device_configs.config_parsed`) + latest polled active-session count/timestamp (Fortinet-only capability) + CSV export.
[server] /devices/[id]/vpn — DeviceVpnPage — one device's VPN config summary card (SSL-VPN/remote-access: source interface/port/idle-timeout/min-TLS, enabled/disabled/unknown badge, low-confidence badge for doc-derived vendors) + `VpnSessionTrendChart` (session-count history) + CSV export.

## Topology

[server] /topology — TopologyPage — top-level nav entry (added 2026-08-02, between VPN and Settings). `?view=query|map` toggle (same pattern as `/compliance`'s `?view=cards|table`), default `query` renders `<PathQueryTab />` (fleet-wide, no props); `map` (added 2026-08-02) renders `<FleetMap />`, a visual diagram of every active device + inferred link. See `components.md`'s `topology/` entry and `lib.md`'s `topology.js` engine entry.

[server] /lifecycle — LifecyclePage — top-level nav entry (added 2026-08-03, between Topology and Settings). Fleet-wide device lifecycle & health: support/licence expiry sorted soonest-first (the renewal-planning view), HA state across every pair, and signature freshness. Reads `device_licenses`/`device_ha_status`/`device_disk_usage`/`device_content_versions` and bands them via `lib/engines/deviceHealth.js` at render time (status is never stored). Devices with no collected data are listed as "Not collected" rather than omitted — the same fleet-coverage honesty as the Fleet Map. Palo Alto only as of this add; Fortinet devices legitimately show no data.

## Alerts

[server] /alerts — AlertsPage — fleet-wide chronological event feed merging open `patch_now` CVE assessments + unacknowledged `config_diffs` (⛔ `new_finding`/rule-level findings deliberately removed 2026-07-20 — those live in Rule Analysis's Cleanup/Optimization/Reorder tabs instead). Filters: `type` (patch_now|config_diff), `status` (open|all), `device_id`; paginated 25/page; inline `AlertAckControl` (admin-gated) per row.

## Settings

[client] /settings — SettingsPage — client-side-tabbed shell (`General|Users|Credential Profiles|Updates|About`; `?tab=` read once on mount as a deep-link convenience only, then pure client state — a deliberate, documented exception to this app's usual server-driven `?tab=` convention). `General` = feed-poll-interval form + change-password form. `Users` = `UsersPanel` (self-gates via its own `GET /api/users` 403). `Credential Profiles` = `CredentialProfilesPanel` (admin-only render). `Updates` = `UpdatePanel` (admin-only render). `About` = static product/version/port/runtime/database table. Role (`isAdminUser`) resolved client-side via `GET /api/auth/session` (fails closed to non-admin), since this page has no server-passed session prop.

---

## Notes / CLAUDE.md contradictions found

- **CLAUDE.md's top-level File Structure tree** (under "File Structure") still lists `cve/` and
  `advisories/` as separate directories directly under `app/(dashboard)/`. The real routes were
  merged into `app/(dashboard)/vulnerability/` (with `vulnerability/cve/[cveId]`,
  `vulnerability/advisories/[cveId]`, and `vulnerability/advisories/[cveId]/conditions`) — CLAUDE.md
  itself acknowledges this merge in prose (the 2026-07-19 "sixth pass" bug-sweep entry references
  "the brand-new Vulnerability page merge"), but the file-structure tree diagram was never updated
  to match, and the earlier "UI vendor-scoping gap" Known Issues entry still cites the old
  `app/(dashboard)/advisories/page.js` / `app/(dashboard)/cve/page.js` paths by name.
- No other contradictions found — the device-detail tab list (`overview|cve|rules|config|admins|manage`),
  the 12-tab `devices/[id]/analysis` list, the Compliance page's cards-as-default view, and the
  Settings page's client-side-tab mechanism all match CLAUDE.md's documentation exactly.
