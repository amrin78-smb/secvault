// lib/auditChecksSeed.js
//
// Phase 7 compliance check library — curated data, seeded/updated by
// lib/migrate.js's main() (mirrors lib/migrate.js's seedDefaultAdmin()
// pattern: an idempotent upsert function, NOT a raw .sql seed file, so this
// stays hand-editable JS the same way advisory_conditions is hand-edited via
// the admin UI — see CLAUDE.md's "Advisory Conditions Are Data, Not Code").
//
// Every row's predicate_config is evaluated by lib/engines/applicability.js's
// evaluatePredicate() — the SAME evaluator advisory_conditions uses — via
// lib/engines/configAuditor.js. See CLAUDE.md's "tri-state -> four-state
// polarity problem" for the pass_when field these rows all carry.
//
// ── Groundedness of predicate paths — read before editing ──────────────────
//
// Per CLAUDE.md ("verify all field names against live responses... never
// assume field names from documentation alone") the ideal grounding is a
// live device. None is reachable from this build, so the next-best grounding
// used here is this repo's OWN parser code (not vendor CLI docs from
// memory):
//
//   Fortinet: as of 2026-07-19, lib/adapters/fortinet/index.js's getConfig()
//   collects 11 named sections — the original 5 ({global, interfaces,
//   ssl_vpn, snmp, admins}) PLUS 6 more added in this change ({ntp, dns,
//   log_syslogd, password_policy, fortiguard, autoupdate_schedule}) — built
//   by lib/adapters/fortinet/cliParser.js's parseFullConfiguration() (SSH)
//   and the matching cmdb-endpoint set in fortinet/index.js (REST API). Each
//   of the 6 new sections is a flat {key: value} object of that FortiOS
//   config block's direct settings. This closes the ntp/dns/logging/
//   password-policy/fortiguard gap that used to leave 5 checks below
//   permanently 'warning' — see the 5 upgraded checks (fortinet-ntp-configured,
//   fortinet-dns-configured, fortinet-logging-enabled,
//   fortinet-password-min-length, fortinet-fortiguard-updates-enabled) for
//   the live predicates now in place. Two other Fortinet checks
//   (fortinet-ips-internet-facing-policies, fortinet-unused-interfaces-shutdown)
//   remain 'not_evaluable_from_config' for structural reasons UNRELATED to
//   config collection — see reason (b) below — and are not fixed by this or
//   any future config-collection change.
//
//   ⚠️ The exact field paths used by the 5 upgraded checks below
//   (ntp.ntpsync, dns.primary, log_syslogd.status,
//   password_policy.minimum-length, autoupdate_schedule.status) are
//   doc-derived from standard FortiOS CLI/REST field-naming conventions —
//   they follow the SAME "flat {key:value} per section" shape the SSH/REST
//   adapters were built to produce, but have NOT yet been confirmed against
//   a live FortiGate's actual config_parsed output. Per CLAUDE.md's
//   "documentation lies, verify against live systems" rule, treat these as
//   best-effort until the next live Fortinet SSH collect in this deployment
//   confirms or corrects them (grep engine.log for [Fortinet Debug] /
//   [Fortinet SSH Debug]). If the real field names differ, only this file
//   (plus lib/adapters/fortinet/{ssh.js,cliParser.js,index.js,api.js,parser.js})
//   needs updating — the predicate engine itself (applicability.js) does not.
//
//   Palo Alto: lib/adapters/paloalto/sshParser.js's parseConfig() (SSH) sets
//   parsed.tree to the FULL parsed brace-tree from `show` (root-anchored,
//   confirmed live 2026-07-16 on a PA-440 and a PA-3220 — see CLAUDE.md's
//   "Palo Alto SSH — RESOLVED"), and lib/adapters/paloalto/parser.js's
//   parseConfig() (XML API) roots parsed at result.config, i.e. also the
//   full config tree. So unlike Fortinet, EVERY PAN-OS config section is at
//   least reachable in principle — the risk here is not "the section was
//   never collected" but "the exact schema key name is a best guess". Two
//   paths are taken directly from CLAUDE.md/task-confirmed real samples
//   (`mgt-config.users`, `deviceconfig.system.ntp-servers.primary-ntp-server`,
//   `rulebase.security.rules`); every other PAN-OS path below follows the
//   SAME schema-naming convention as those confirmed paths but is NOT itself
//   independently live-verified — flagged inline as best-effort.
//
//   Check Point / Sangfor / Forcepoint: added 2026-11-12, and their grounding
//   notes are DELIBERATELY NOT REPEATED HERE — they live in the section header
//   immediately above the checkpoint-* rows at the bottom of CHECKS, next to
//   the rows they govern, because the conclusion they reach differs from the
//   two paragraphs above in a way a reader must not skim past. For those three
//   vendors the adapter does not collect the SECTION a hardening concept would
//   live in (Check Point's Management API exposes management-plane objects and
//   no Gaia OS settings; Sangfor's parser extracts hostname, version,
//   interface names and one unverified SSL-VPN flag and nothing else;
//   Forcepoint's config_parsed is an SMC engine IDENTITY element). Fortinet's
//   and Palo Alto's best-effort paths above are guessed LEAF NAMES inside
//   sections that provably ARE collected, which is a correctable risk; a
//   predicate on an absent section is a guard that can only ever fire wrong,
//   so those concepts are `not_evaluable_from_config` instead. Read that
//   section header before adding a row for any of the three.
//
// ── predicate_type: 'not_evaluable_from_config' — a deliberate, non-hacky use
//    of evaluatePredicate()'s own documented default case ───────────────────
//
// evaluatePredicate()'s switch has a `default: return 'unknown';` for any
// predicate_type it doesn't recognize — this is EXISTING, documented
// behaviour ("never throws... unknown predicate type... returns 'unknown'"),
// not something this file adds to applicability.js. Some concepts in the
// spec below genuinely cannot be answered from device_configs.config_parsed
// at all, for two different reasons:
//   (a) the config section needed was never collected by the adapter — this
//       was Fortinet's ntp/dns/logging/password-policy/fortiguard gap
//       described above, and it is why those 5 checks are STILL the
//       reference example of reason (a) in this comment even though, as of
//       2026-07-19, they are no longer 'not_evaluable_from_config'
//       themselves (the gap they illustrate is now closed for them
//       specifically; reason (a) remains valid in general for any future
//       section that isn't collected yet), or
//   (b) the fact is inherently per-rule (e.g. "IPS profile on internet-facing
//       policies") and the predicate engine only supports ONE fixed
//       dot-path per check, not "for every rule in the ruleset" — a
//       fundamentally different query shape belonging to a future
//       ruleAnalysis.js-style finding type, not this predicate engine. This
//       is the reason fortinet-ips-internet-facing-policies remains
//       not_evaluable_from_config even after this change — no amount of
//       additional flat-section config collection fixes a per-rule fact.
//       fortinet-unused-interfaces-shutdown is a related-but-distinct case:
//       it needs traffic/hit-count telemetry a static config snapshot never
//       has, regardless of which sections are collected.
// For both cases, resolving the check to config_key_exists on some
// currently-absent path would return 'no' (a confident FAIL) — which
// misrepresents "we cannot tell" as "the device is non-compliant".
//
// ⛔ CORRECTED 2026-08-25. This paragraph used to say the predicate_type
// 'not_evaluable_from_config' deliberately fell through to
// evaluatePredicate()'s default case to produce 'unknown' -> 'warning'.
// That is no longer true, and it was the wrong bucket. A `warning` is a
// fact about the DEVICE -- we collected a config, asked a real question of
// it, and the answer was indeterminate -- so it COUNTS toward the score.
// These checks are a fact about SECVAULT: the question cannot be posed at
// all, and nothing an operator changes on the firewall makes it answerable.
// Scoring a customer down for our own coverage gap is the same error as
// hit_count's old NOT NULL DEFAULT 0 (see CLAUDE.md's Critical Rule on a
// failed read never being a measurement). Across the 16-device fleet, 43 of
// 61 warnings were this.
//
// configAuditor.evaluateCheck() now SHORT-CIRCUITS this predicate_type to
// 'na' at the top of the function, before the pass_when guard -- so it is
// excluded from the score denominator, while still being written and shown
// to the operator as a manual-verification item. `pass_when` on these rows
// is therefore a never-consulted placeholder. `reason` IS surfaced in the
// finding detail (it stopped being evaluator-only on the same date), so
// write it for an operator to read, not just a future maintainer.
//
// seedAuditChecks() is idempotent and re-runnable via ON CONFLICT ... DO
// UPDATE (not DO NOTHING) — editing this file and re-running lib/migrate.js
// updates the library in place, matching how this codebase treats curated
// data elsewhere.

'use strict';

const CHECKS = [
  // ─────────────────────────────────────────────────────────────
  // Shared concepts (8), one row per vendor — tailored predicate_config per
  // vendor since Fortinet's and Palo Alto's config_parsed shapes share
  // nothing (see file header). Do NOT collapse these into vendor:null rows.
  // ─────────────────────────────────────────────────────────────

  {
    checkId: 'fortinet-admin-access-untrusted-zone',
    name: 'Admin access not permitted from untrusted/WAN zone',
    description:
      'Administrative GUI/CLI/API access should not be reachable from the WAN or any untrusted zone.',
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS', 'NIST', 'SANS'],
    vendor: 'fortinet',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'admin_access_from_zone',
      // Best-effort: 'wan1' is FortiGate's conventional default WAN
      // interface name, not a value read from real device output. The
      // generic deep-scan (applicability.js's scanAdminZone) also only
      // finds this if the zone string surfaces under a key path containing
      // 'admin'/'management' somewhere above it — not independently
      // verified against this adapter's actual `admins`/`interfaces`
      // shapes. Flagged unverified.
      zone: 'wan1',
      pass_when: 'no',
    },
    remediationGuidance:
      'Remove ping/https/ssh/http from the allowaccess list on any interface with role "wan", or restrict admin access to a dedicated management VDOM/interface.',
  },
  {
    checkId: 'paloalto-admin-access-untrusted-zone',
    name: 'Admin access not permitted from untrusted/WAN zone',
    description:
      'Administrative GUI/CLI/API access should not be reachable from the untrust zone.',
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS', 'NIST', 'SANS'],
    vendor: 'paloalto',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'admin_access_from_zone',
      // 'untrust' is PAN-OS's standard external-zone naming convention.
      // Same deep-scan caveat as the Fortinet row above — best-effort.
      zone: 'untrust',
      pass_when: 'no',
    },
    remediationGuidance:
      'Ensure no security policy or interface management-profile permits ssh/https/http-based admin services from the untrust zone.',
  },

  {
    checkId: 'fortinet-ssh-mgmt-untrusted-iface',
    name: 'SSH management disabled on untrusted interfaces',
    description:
      "SSH should not be present in an untrusted interface's allowaccess list.",
    standards: ['CIS_V8', 'ISO_27001', 'SANS'],
    vendor: 'fortinet',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'config_value_matches',
      // Best-effort / index assumption: getByPath has no "find the WAN
      // interface" operator, only fixed array indices, so this targets
      // interfaces[0] specifically. On many factory-default FortiGate
      // configs the first `config system interface` entry IS the WAN
      // interface, but this is NOT guaranteed and is not verified against
      // a real device's interface ordering. Flagged unverified.
      path: 'interfaces[0].allowaccess',
      pattern: '\\bssh\\b',
      pass_when: 'no',
    },
    remediationGuidance:
      'Remove "ssh" from the allowaccess list on WAN-facing interfaces; manage the device only from a trusted internal interface or VPN.',
  },
  {
    checkId: 'paloalto-ssh-mgmt-disabled',
    name: 'SSH management disabled on untrusted interfaces',
    description:
      'PAN-OS has a global SSH management-service kill switch (deviceconfig.system.service.disable-ssh) rather than a strictly per-zone one; this check verifies it is engaged. This is DELIBERATELY coarser than the concept name (it disables SSH mgmt everywhere, not just from untrust) — flagged, not a bug — because per-interface management-profile resolution needs following a named profile reference the predicate engine cannot chase in one fixed path.',
    standards: ['CIS_V8', 'ISO_27001', 'SANS'],
    vendor: 'paloalto',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'feature_enabled',
      // Real, well-known PAN-OS hardening CLI knob: `set deviceconfig
      // system service disable-ssh yes`. Doc-derived naming convention
      // (same 'deviceconfig.system.*' root as the live-verified
      // deviceconfig.system.panorama path in CLAUDE.md), not itself
      // independently live-verified.
      path: 'deviceconfig.system.service.disable-ssh',
      pass_when: 'yes',
    },
    remediationGuidance:
      'If SSH management access is not required at all, set "disable-ssh yes" under deviceconfig system service. If it IS required, restrict it via an interface management-profile scoped to trusted zones only instead of relying on this global switch.',
  },

  {
    checkId: 'fortinet-https-only-not-http',
    name: 'HTTPS management only, not HTTP',
    description: 'Plain HTTP admin access should be disabled in favor of HTTPS.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'fortinet',
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'config_value_matches',
      // Same interfaces[0]-index caveat as the SSH check above.
      path: 'interfaces[0].allowaccess',
      pattern: '\\bhttp\\b',
      pass_when: 'no',
    },
    remediationGuidance: 'Remove "http" from the allowaccess list on every interface; keep only "https".',
  },
  {
    checkId: 'paloalto-https-only-not-http',
    name: 'HTTPS management only, not HTTP',
    description: 'Plain HTTP admin access should be disabled in favor of HTTPS (mirrors the SSH check above).',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'paloalto',
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'feature_enabled',
      path: 'deviceconfig.system.service.disable-http',
      pass_when: 'yes',
    },
    remediationGuidance: 'Set "disable-http yes" under deviceconfig system service; use HTTPS exclusively for the admin GUI.',
  },

  {
    checkId: 'fortinet-ntp-configured',
    name: 'NTP configured',
    description:
      'NTP synchronization is enabled ("config system ntp" -> "set ntpsync enable") so device ' +
      'time is accurate for reliable log correlation and certificate validity checks.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'fortinet',
    severity: 'low',
    predicateConfig: {
      predicate_type: 'feature_enabled',
      // Doc-derived, NOT yet live-verified — see the "Groundedness" header
      // comment's 2026-07-19 update. 'ntpsync' is the standard FortiOS
      // `config system ntp` CLI key for the sync on/off switch.
      path: 'ntp.ntpsync',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Enable NTP synchronization via "config system ntp" / "set ntpsync enable"; accurate time is required for reliable log correlation and certificate validity checks.',
  },
  {
    checkId: 'paloalto-ntp-configured',
    name: 'NTP configured',
    description: 'An NTP server should be configured for accurate log timestamps.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'paloalto',
    severity: 'low',
    predicateConfig: {
      predicate_type: 'config_key_exists',
      // Live-confirmed shape per CLAUDE.md's Palo Alto SSH resolution notes
      // and this task's own instructions — the one path in this file taken
      // directly from a live-verified example, not a guess.
      path: 'deviceconfig.system.ntp-servers.primary-ntp-server',
      pass_when: 'yes',
    },
    remediationGuidance: 'Configure at least a primary NTP server under Device > Setup > Services.',
  },

  {
    checkId: 'fortinet-dns-configured',
    name: 'DNS configured',
    description:
      'A primary DNS resolver is configured ("config system dns" -> "set primary <ip>") for ' +
      'hostname resolution (FortiGuard, URL filtering, updates, etc.).',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'fortinet',
    severity: 'low',
    predicateConfig: {
      predicate_type: 'config_key_exists',
      // Doc-derived, NOT yet live-verified — see the "Groundedness" header
      // comment's 2026-07-19 update. 'primary' is the standard FortiOS
      // `config system dns` CLI key for the primary DNS server IP.
      path: 'dns.primary',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Configure at least a primary DNS server via "config system dns" / "set primary <ip>".',
  },
  {
    checkId: 'paloalto-dns-configured',
    name: 'DNS configured',
    description: 'A DNS server should be configured for hostname resolution (URL filtering, updates, etc.).',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'paloalto',
    severity: 'low',
    predicateConfig: {
      predicate_type: 'config_key_exists',
      // Best-effort: follows the SAME 'deviceconfig.system.*' naming
      // convention as the live-verified ntp-servers path, but this exact
      // key was not itself captured in a live sample. Flagged unverified.
      path: 'deviceconfig.system.dns-setting.servers.primary',
      pass_when: 'yes',
    },
    remediationGuidance: 'Configure at least a primary DNS server under Device > Setup > Services.',
  },

  {
    checkId: 'fortinet-logging-enabled',
    name: 'Logging enabled / syslog configured',
    description:
      'Remote syslog forwarding is enabled ("config log syslogd setting" -> "set status enable") ' +
      'so security events are forwarded off-box for incident response and several of the ' +
      'standards this check maps to.',
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS', 'SANS'],
    vendor: 'fortinet',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'feature_enabled',
      // Doc-derived, NOT yet live-verified — see the "Groundedness" header
      // comment's 2026-07-19 update. 'status' is the standard FortiOS
      // `config log syslogd setting` CLI key for the on/off switch.
      path: 'log_syslogd.status',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Enable remote syslog via "config log syslogd setting" / "set status enable"; centralized logging is required for incident response and several of the standards this check maps to.',
  },
  {
    checkId: 'paloalto-logging-enabled',
    name: 'Logging enabled / syslog configured',
    description: 'A syslog server profile should be configured so security events are forwarded off-box.',
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS', 'SANS'],
    vendor: 'paloalto',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'config_key_exists',
      // ⛔ Path fixed 2026-07-18, LIVE-VERIFIED (not doc-derived guessing —
      // this was actually wrong before): the original path,
      // 'shared.server-profile.syslog', does not exist on either real Palo
      // Alto device in this deployment — confirmed directly against real
      // device_configs rows. The REAL syslog server-profile location,
      // confirmed on BOTH a real SSH-collected device (IDC FW,
      // shared.log-settings.syslog.<profile-name>.server.<server-name> —
      // brace-tree object-keyed-by-name shape) and a real XML/API-collected
      // device (ITC-SLY, shared.log-settings.syslog.entry.server.entry[] —
      // fast-xml-parser entry/array shape), is 'shared.log-settings.syslog'
      // — one level shallower than assumed, and under 'log-settings', not
      // 'server-profile'. config_key_exists only needs the key to be
      // present (regardless of which of the two real shapes it takes), so
      // this single path is correct for both transports.
      path: 'shared.log-settings.syslog',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Configure a syslog server profile under Device > Server Profiles > Syslog and attach it via a log forwarding profile.',
  },

  {
    checkId: 'fortinet-password-min-length',
    name: 'Password policy: minimum length configured',
    description:
      'A minimum admin-password length is present under "config system password-policy" / ' +
      '"set minimum-length <n>". NOTE: like fortinet-session-timeout below, config_key_exists ' +
      'only proves this field is PRESENT, not that it enforces a strict/non-default value — a ' +
      'full-configuration dump typically prints this field even at its factory default, so this ' +
      'check will usually pass trivially. A stricter check would need a numeric-threshold ' +
      'predicate type this engine does not have.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'fortinet',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'config_key_exists',
      // Doc-derived, NOT yet live-verified — see the "Groundedness" header
      // comment's 2026-07-19 update. 'minimum-length' is the standard
      // FortiOS `config system password-policy` CLI key. Presence-only
      // check — see description's caveat above (mirrors the identical
      // caveat already documented on fortinet-session-timeout).
      path: 'password_policy.minimum-length',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Set "config system password-policy" / "set minimum-length <n>" to a strong minimum (e.g. 12+); note this check only confirms the field is present, not that its value is strict.',
  },
  {
    checkId: 'paloalto-password-min-length',
    name: 'Password policy: minimum length configured',
    description: 'A minimum admin-password length should be enforced under mgt-config.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'paloalto',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'config_key_exists',
      // Best-effort, but rooted under the SAME 'mgt-config' top-level key
      // CLAUDE.md confirms was live-verified (mgt-config.users) — the
      // sub-path 'password-complexity.minimum-length' itself is not
      // independently confirmed.
      path: 'mgt-config.password-complexity.minimum-length',
      pass_when: 'yes',
    },
    remediationGuidance: 'Set a minimum password length under Device > Setup > Management > Minimum Password Complexity.',
  },

  {
    checkId: 'fortinet-session-timeout',
    name: 'Session timeout configured',
    description: 'An admin idle-session timeout should be configured under system global.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'fortinet',
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'config_key_exists',
      // Grounded: 'admintimeout' is a real, well-known `config system
      // global` key (idle admin session timeout, minutes) — this section
      // IS collected by this adapter. Note this check only proves the key
      // is PRESENT, not that it is set to a strict value: a "full
      // configuration" dump typically prints this field even at its
      // factory default, so this check will usually pass trivially. A
      // stricter check would need a numeric-threshold predicate type this
      // engine does not have.
      path: 'global.admintimeout',
      pass_when: 'yes',
    },
    remediationGuidance: 'Set "config system global / set admintimeout <n>" to a short idle timeout (e.g. 5-15 minutes).',
  },
  {
    checkId: 'paloalto-session-timeout',
    name: 'Session timeout configured',
    description: 'An admin idle-session timeout should be configured under mgt-config.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'paloalto',
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'config_key_exists',
      // Best-effort, rooted under the live-verified 'mgt-config' key.
      path: 'mgt-config.idle-timeout',
      pass_when: 'yes',
    },
    remediationGuidance: 'Set an idle timeout under Device > Setup > Management > Idle Timeout.',
  },

  // ─────────────────────────────────────────────────────────────
  // Fortinet-specific (10)
  // ─────────────────────────────────────────────────────────────

  {
    checkId: 'fortinet-sslvpn-not-wan-exposed',
    name: 'SSL-VPN not exposed to WAN unless required',
    description: 'SSL-VPN source-interface should not include a WAN-facing interface unless remote access is an intended use case.',
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS'],
    vendor: 'fortinet',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'config_value_matches',
      // Grounded: 'source-interface' is a real `config vpn ssl settings`
      // key, and ssl_vpn IS one of the 5 sections this adapter collects.
      path: 'ssl_vpn.source-interface',
      pattern: 'wan',
      pass_when: 'no',
    },
    remediationGuidance:
      'If SSL-VPN remote access is not a required use case for this device, remove WAN interfaces from source-interface; if it is required, ensure MFA and a restrictive portal are also configured.',
  },
  {
    checkId: 'fortinet-sslvpn-idle-timeout',
    name: 'SSL-VPN idle timeout configured',
    description:
      'An explicit SSL-VPN idle timeout ("config vpn ssl settings" -> "set idle-timeout <minutes>") ' +
      'reduces the exposure window of an abandoned remote-access session.',
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS'],
    vendor: 'fortinet',
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'config_key_exists',
      // Doc-derived, NOT yet live-verified — see the "Groundedness" header
      // comment's 2026-07-19 update. 'idle-timeout' is the standard
      // FortiOS `config vpn ssl settings` CLI key (minutes). Presence-only
      // — same caveat as fortinet-password-min-length/fortinet-session-timeout
      // above: proves the field is set, not that its value is a
      // strict/non-default number, since a full-configuration dump
      // typically prints this field even at its factory default. A
      // stricter check would need a numeric-threshold predicate type this
      // engine does not have. A live Fortinet SSH device now exists in
      // this deployment (2026-07-19, see CLAUDE.md's Live Validation
      // Status) — confirm this path against its actual
      // config_parsed.ssl_vpn on the next collect.
      path: 'ssl_vpn.idle-timeout',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Set an explicit SSL-VPN idle timeout via "config vpn ssl settings" / "set idle-timeout <minutes>" rather than relying on the factory default.',
  },
  {
    checkId: 'fortinet-sslvpn-min-tls-1-2',
    name: 'SSL-VPN minimum TLS version is 1.2 or higher',
    description:
      'The SSL-VPN portal should reject TLS 1.0/1.1 ("config vpn ssl settings" -> "set ' +
      'ssl-min-proto-ver") — both are deprecated, broken-cipher-suite protocol versions.',
    standards: ['CIS_V8', 'PCI_DSS'],
    vendor: 'fortinet',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'config_value_matches',
      // Doc-derived, NOT yet live-verified — see the "Groundedness" header
      // comment's 2026-07-19 update. 'ssl-min-proto-ver' is the standard
      // FortiOS `config vpn ssl settings` CLI key, with values
      // tls1-0/tls1-1/tls1-2/tls1-3. Matches tls1-2 or tls1-3 (either is
      // acceptable) via a pattern rather than a single config_value_equals,
      // since either passing value should PASS this check, not just one.
      // A live Fortinet SSH device now exists in this deployment
      // (2026-07-19, see CLAUDE.md's Live Validation Status) — confirm
      // this path against its actual config_parsed.ssl_vpn on the next
      // collect.
      path: 'ssl_vpn.ssl-min-proto-ver',
      pattern: 'tls1-[23]',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Set "config vpn ssl settings" / "set ssl-min-proto-ver tls1-2" (or tls1-3) to reject TLS 1.0/1.1 connections to the SSL-VPN portal.',
  },
  {
    checkId: 'fortinet-fortiguard-updates-enabled',
    name: 'FortiGuard updates enabled',
    description:
      'FortiGuard signature/engine auto-updates are enabled on a schedule ("config system ' +
      'autoupdate schedule" -> "set status enable").',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'fortinet',
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'feature_enabled',
      // Doc-derived, NOT yet live-verified — see the "Groundedness" header
      // comment's 2026-07-19 update. 'status' is the standard FortiOS
      // `config system autoupdate schedule` CLI key for the on/off switch.
      // (Read from the autoupdate_schedule config_parsed section, not the
      // sibling `config system fortiguard` section, which this check's
      // config_parsed key name — autoupdate_schedule — deliberately mirrors.)
      path: 'autoupdate_schedule.status',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Enable FortiGuard signature/engine auto-updates via "config system autoupdate schedule" / "set status enable".',
  },
  {
    checkId: 'fortinet-ips-internet-facing-policies',
    name: 'IPS profile applied to internet-facing policies',
    description:
      'Every enabled allow policy arriving from an external zone should carry an IPS sensor that ' +
      'is actually active. FortiOS only applies a UTM profile when utm-status is enabled, so both ' +
      'the sensor and utm-status must be present on the policy — a named sensor on a policy with ' +
      'UTM switched off inspects nothing. Evaluated per policy against the collected ruleset.',
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS'],
    vendor: 'fortinet',
    severity: 'high',
    // ⛔ The old reason named `firewall_rules.raw_rule` as being "outside"
    // what the engine could read. It was outside what the PREDICATE ENGINE
    // could read; the column was already selected by this very audit's own rule
    // query. 36 of 181 live FortiOS policies carry `ips-sensor`.
    // ⛔ No Panorama equivalent on FortiOS, so no undecidable_when_key: a
    // policy without `ips-sensor` genuinely has no IPS sensor.
    predicateConfig: {
      predicate_type: 'rule_property',
      subject: 'an ACTIVE IPS sensor',
      applies_to: { action: 'allow', enabled_only: true, src_zone_role: 'external' },
      // ⛔ BOTH FIELDS, NOT JUST THE SENSOR NAME. On FortiOS a UTM profile only
      // applies when `set utm-status enable`, and `show` omits fields left at
      // their default — which for utm-status is disable. `ips-sensor` alone
      // says a sensor is NAMED, not that it is ACTIVE, so requiring only it
      // would pass a policy whose IPS is configured and switched off: a false
      // all-clear on an internet-facing rule. Live: 36 policies carry
      // `ips-sensor`, 45 carry `utm-status`.
      require_all_path: ['ips-sensor', 'utm-status'],
      pass_when: 'yes',
    },
    remediationGuidance:
      'Manually verify an IPS sensor is attached to every policy whose destination interface is internet-facing.',
  },
  {
    checkId: 'fortinet-default-admin-active',
    name: "No default 'admin' username still active",
    description: "The factory-default 'admin' account should be renamed or disabled.",
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS', 'SANS'],
    vendor: 'fortinet',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'config_value_equals',
      // Heuristic / index assumption: admins is a flattened array
      // (cliParser.flattenEntries), and getByPath only supports fixed
      // indices — there's no "does this array contain an entry named
      // 'admin'" operator. Targeting index 0 is a best-effort guess: the
      // original factory admin account is very commonly left as the FIRST
      // `config system admin` entry even when additional named accounts
      // are added later, but this is not guaranteed and is not verified
      // against a real device's admin-entry ordering.
      path: 'admins[0].name',
      value: 'admin',
      pass_when: 'no',
    },
    remediationGuidance: "Rename or disable the default 'admin' account; use named, individually-attributable admin accounts instead.",
  },
  {
    checkId: 'fortinet-https-port-changed',
    name: 'HTTPS admin port changed from default 443',
    description:
      'Informational hardening check only — running on the default HTTPS admin port (443) is ' +
      'not itself a vulnerability, so this is seeded at severity "info" and pass_when is set so a ' +
      'device still on the default merely surfaces as a low-impact FYI, not a real compliance gap.',
    standards: ['CIS_V8'],
    vendor: 'fortinet',
    severity: 'info',
    predicateConfig: {
      predicate_type: 'config_value_equals',
      // Grounded: 'admin-sport' is a real `config system global` key.
      path: 'global.admin-sport',
      value: '443',
      pass_when: 'no',
    },
    remediationGuidance:
      'Optional hardening: change the HTTPS admin port from 443 to reduce automated/opportunistic scanning noise. Not required for compliance.',
  },
  {
    checkId: 'fortinet-unused-interfaces-shutdown',
    name: 'Unused interfaces administratively shut down',
    description:
      'NOT EVALUABLE with current data: "unused" requires traffic/hit-count evidence this ' +
      'predicate engine (which only sees a static config snapshot) does not have — the same class ' +
      'of gap Phase 5\'s ruleAnalysis.js documents for FortiOS SSH hit-count unavailability.',
    standards: ['CIS_V8'],
    vendor: 'fortinet',
    severity: 'low',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason: '"unused" requires traffic/hit-count data not present in a static config_parsed snapshot.',
      pass_when: 'yes',
    },
    remediationGuidance: 'Manually review interfaces with no assigned traffic and administratively shut them down.',
  },
  {
    checkId: 'fortinet-admin-2fa-required',
    name: 'Admin two-factor authentication required',
    description:
      'Administrator accounts should require two-factor authentication ("config system admin" -> ' +
      '"set two-factor <method>") in addition to a password, so a leaked/guessed admin password ' +
      'alone is not sufficient to reach the management plane.',
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS'],
    vendor: 'fortinet',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'feature_enabled',
      // Same index-0-only limitation as fortinet-default-admin-active above:
      // admins is a flattened array and getByPath only supports fixed
      // indices, so this can only ever check the FIRST admin entry, not
      // "every admin has 2FA enabled" — a real gap, not an oversight.
      // UNLIKE most other Fortinet paths in this file, this one is
      // LIVE-CONFIRMED, not doc-derived: a direct production DB query on
      // 2026-07-19 (this same day) read a real device's admins[0] and found
      // `"two-factor": "disable"` and `"accprofile": "super_admin"` — i.e.
      // both the key name 'two-factor' and its FortiOS enable/disable string
      // vocabulary are confirmed from an actual config_parsed row, not
      // inferred from CLI documentation. This is stronger grounding than
      // this file's usual "doc-derived, not yet live-verified" caveat.
      path: 'admins.0.two-factor',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Enable "set two-factor <method>" (FortiToken/email/SMS) under "config system admin" for every administrator account — this check only confirms the first configured admin, so manually verify the rest.',
  },
  {
    checkId: 'fortinet-password-policy-enabled',
    name: 'Password policy enforcement enabled',
    description:
      'Verifies "config system password-policy" -> "set status enable" itself — i.e. that the ' +
      'password-policy block is actually ENFORCED, not just present. This is a STRONGER check than ' +
      'fortinet-password-min-length above: that check only proves a "minimum-length" field is ' +
      'present in the config dump (which, per its own documented caveat, is often true even when the ' +
      'policy is fully disabled, since a full-configuration dump typically prints the field at its ' +
      'factory default regardless). Without "status enable" here, minimum-length and every other ' +
      'complexity setting in the same block goes unenforced.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'fortinet',
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'feature_enabled',
      // Doc-derived, NOT yet live-verified (unlike the two-factor field on
      // fortinet-admin-2fa-required directly above, which IS live-confirmed
      // as of 2026-07-19). 'status' is the standard FortiOS `config system
      // password-policy` CLI key for the master enable/disable switch,
      // following the same naming convention as this file's other
      // '<section>.status' feature_enabled checks (log_syslogd.status,
      // autoupdate_schedule.status).
      path: 'password_policy.status',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Enable password policy enforcement via "config system password-policy" / "set status enable" — without this, minimum-length and other complexity settings in the same block are not actually applied.',
  },

  // ─────────────────────────────────────────────────────────────
  // Palo Alto-specific (6)
  // ─────────────────────────────────────────────────────────────

  {
    checkId: 'paloalto-zone-protection-external',
    name: 'Zone protection profiles applied to all external zones',
    description: "The 'untrust' zone should have a zone-protection-profile attached (flood/reconnaissance protection).",
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'paloalto',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'config_key_exists',
      // Best-effort: zones are name-keyed objects in the brace tree
      // (`network { zone { untrust { ... } } }`), unlike Fortinet's
      // flattened interfaces array — so a fixed path is safe here as long
      // as the zone is actually named "untrust" (standard PAN-OS
      // convention, not verified against a specific device's naming).
      path: 'network.zone.untrust.zone-protection-profile',
      pass_when: 'yes',
    },
    remediationGuidance: 'Create a zone protection profile (flood protection, reconnaissance protection) and attach it to every internet-facing zone.',
  },
  {
    checkId: 'paloalto-security-profiles-internet-facing',
    name: 'Security profiles (AV/IPS/URL) applied to internet-facing rules',
    description:
      'Every enabled allow rule arriving from an external zone should carry a security profile — ' +
      'either a profile group or individually attached AV/IPS/URL profiles. Evaluated per rule ' +
      'against the collected ruleset. Rules pushed from Panorama are reported as unjudgeable ' +
      'rather than failed, because a profile group attached there is not visible on this firewall.',
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS'],
    vendor: 'paloalto',
    severity: 'high',
    // ⛔ WAS 'not_evaluable_from_config' UNTIL v2.167.0, AND THE REASON GIVEN
    // WAS ACCURATE BUT NO LONGER TRUE: the predicate engine could only follow
    // one fixed dot-path, so "every rule" was unaskable. `rule_property` is that
    // missing question shape. The data never moved -- 1,063 of 1,586 live Palo
    // Alto rules already carried `profile-setting` in `firewall_rules.raw_rule`.
    predicateConfig: {
      predicate_type: 'rule_property',
      subject: 'a security profile',
      applies_to: { action: 'allow', enabled_only: true, src_zone_role: 'external' },
      // PAN-OS expresses this two ways and both are compliant: a profile GROUP
      // (88 live rules) or individually-attached profiles (975).
      require_any_path: ['profile-setting.group', 'profile-setting.profiles'],
      // ⛔ A PANORAMA-PUSHED RULE CANNOT BE JUDGED FROM THE FIREWALL'S OWN
      // CONFIG. 33 live rules carry `@_panorama`; a profile group attached in
      // Panorama is invisible here, so reading their silence as "no profile"
      // would manufacture findings out of a place SecVault cannot see.
      undecidable_when_key: '@_panorama',
      undecidable_reason: 'it is pushed from Panorama, where its profile may be attached',
      pass_when: 'yes',
    },
    remediationGuidance: 'Manually verify AV/IPS/URL-filtering profiles (or a security profile group) are attached to every rule permitting internet-bound traffic.',
  },
  {
    checkId: 'paloalto-mgmt-not-from-untrusted',
    name: 'Management interface not accessible from untrusted zones',
    description: 'The MGT interface should be restricted to an explicit permitted-IP allowlist.',
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS', 'NIST'],
    vendor: 'paloalto',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'config_key_exists',
      // Grounded convention: 'permitted-ip' is a real, well-known PAN-OS
      // hardening CLI key (`set deviceconfig system permitted-ip <cidr>`)
      // restricting MGT-interface source IPs; rooted under the
      // live-verified 'deviceconfig.system' path. The key's exact presence
      // is not itself independently live-verified.
      path: 'deviceconfig.system.permitted-ip',
      pass_when: 'yes',
    },
    remediationGuidance: 'Restrict MGT-interface access to a specific administrator source-IP allowlist via "set deviceconfig system permitted-ip".',
  },
  {
    checkId: 'paloalto-threat-prevention-license',
    name: 'Threat prevention license enabled',
    description:
      'NOT EVALUABLE with current data: license status is reported by the operational command ' +
      '"request license info", not part of the running-config tree captured by getConfig().',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'paloalto',
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason: 'License status comes from "request license info" (an op command), not the config tree getConfig() collects.',
      pass_when: 'yes',
    },
    remediationGuidance: 'Verify the Threat Prevention license is active and not expired via Device > Licenses.',
  },
  {
    checkId: 'paloalto-log-forwarding-profiles',
    name: 'Log forwarding profiles configured on security rules',
    description:
      'Every enabled allow rule should carry a log-forwarding profile, or its sessions never ' +
      'reach the syslog/SIEM target. Evaluated per rule against the collected ruleset. Rules ' +
      'pushed from Panorama are reported as unjudgeable rather than failed.',
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS'],
    vendor: 'paloalto',
    severity: 'medium',
    // ⛔ NO ZONE DEPENDENCY, DELIBERATELY. Log forwarding is expected on every
    // enabled allow rule, not only internet-facing ones -- an unlogged internal
    // session is just as absent from the SIEM. That also makes this the one of
    // the three converted checks that can be answered on EVERY firewall rather
    // than only on those whose zones an operator has classified.
    predicateConfig: {
      predicate_type: 'rule_property',
      subject: 'a log-forwarding profile',
      applies_to: { action: 'allow', enabled_only: true },
      require_any_path: ['log-setting'],
      // ⛔ A PANORAMA-PUSHED RULE CANNOT BE JUDGED FROM THE FIREWALL'S OWN
      // CONFIG. 33 live rules carry `@_panorama`; a profile group attached in
      // Panorama is invisible here, so reading their silence as "no profile"
      // would manufacture findings out of a place SecVault cannot see.
      undecidable_when_key: '@_panorama',
      undecidable_reason: 'it is pushed from Panorama, where its profile may be attached',
      pass_when: 'yes',
    },
    remediationGuidance: 'Manually verify a log forwarding profile is attached to every security rule so allowed/denied sessions reach the syslog/SIEM target.',
  },
  {
    checkId: 'paloalto-default-rules-not-allow-all',
    name: 'Default security rules not left in allow-all state',
    description: "The implicit intrazone-default rule should not be overridden to a broad explicit allow.",
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'paloalto',
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'config_value_matches',
      // Best-effort / uncertain-existence: PAN-OS only writes an explicit
      // rulebase.default-security-rules.* entry into the running-config
      // when an operator has overridden the factory default action/logging
      // — an unmodified device may have NO node at this path at all. That
      // is handled correctly here: config_value_matches's own semantics
      // return 'no' (not 'unknown') when the path is absent, which for
      // pass_when:'no' resolves to PASS — i.e. "never explicitly
      // overridden to an open allow" reads as compliant, which is the
      // intended interpretation, not a lucky accident of missing data.
      path: 'rulebase.default-security-rules.intrazone-default.action',
      pattern: '^allow$',
      pass_when: 'no',
    },
    remediationGuidance: 'If the intrazone-default rule has been overridden, ensure its action, log-setting and scope are deliberate and narrowly scoped rather than a broad allow.',
  },

  // ─────────────────────────────────────────────────────────────
  // Cisco ASA-specific (3) — first ASA coverage in this file, added
  // 2026-07-19. Grounding note: unlike Fortinet/Palo Alto, lib/adapters/
  // cisco_asa/parser.js's parseRunningConfig() is a small, fully-read,
  // flat-object parser (not a generic brace/CLI tree) — every field path
  // below (telnet_sources, http_server_enabled, usernames) was confirmed by
  // directly reading that function's source, not inferred from ASA CLI
  // documentation. Still NOT live-verified against a real ASA (see
  // CLAUDE.md "Live Validation Status" — no Tier-1 vendor besides Palo Alto
  // SSH has a confirmed live connection yet), so treat the SHAPE as
  // grounded-in-code but the actual field VALUES on a live device as
  // unverified, same posture as every other pre-live-connect check here.
  //
  // getByPath() array-index note (relevant to the telnet check below): a
  // dot-path segment like `telnet_sources.0` is tokenized by getByPath's
  // regex as the literal string '0' (not the number 0, since it never
  // reaches a `[digit]` bracket token) — but `current['0']` on a JS array
  // resolves identically to `current[0]`, because array elements are just
  // string-keyed properties under the hood and JS coerces the numeric
  // string back to the same slot. Confirmed by reading getByPath()'s
  // implementation directly (lib/engines/applicability.js) rather than
  // assumed. So `config_key_exists` with a bare `arrayField.0` path DOES
  // correctly resolve 'yes' only when index 0 exists (non-empty array) and
  // 'no' when the array is empty — no bracket syntax (`arrayField[0]`)
  // needed, and no separate config_value_matches/pattern workaround needed
  // either, since telnet_sources entries are always non-empty trimmed
  // config-line strings when present (parser.js pushes `trimmed`, never an
  // empty string), so "path resolves" and "path resolves to a non-empty
  // value" are the same condition here.
  // ─────────────────────────────────────────────────────────────

  {
    checkId: 'cisco-asa-telnet-disabled',
    name: 'Telnet management disabled',
    description:
      'Telnet is a cleartext management protocol — any configured `telnet <source> ...` line is a ' +
      'real compliance finding, not just a hardening suggestion, since credentials and session ' +
      'traffic cross the network in plain text.',
    standards: ['CIS_V8', 'PCI_DSS', 'ISO_27001'],
    vendor: 'cisco_asa',
    severity: 'critical',
    predicateConfig: {
      predicate_type: 'config_key_exists',
      // parsed.telnet_sources is an array (empty when no `telnet ...` source
      // lines exist at all — see parser.js's parseRunningConfig). An empty
      // array IS defined (not undefined), so config_key_exists on the bare
      // array path would always resolve 'yes' regardless of contents — that
      // would be wrong. Targeting index 0 specifically is what makes this
      // correct: 'yes' only when at least one telnet source line actually
      // exists. See the array-index note in this section's header comment
      // for why config_key_exists (not config_value_matches) is sufficient
      // and correct here.
      path: 'telnet_sources.0',
      pass_when: 'no',
    },
    remediationGuidance:
      'Remove all `telnet <source> <mask> <interface>` lines from the running-config; use SSH exclusively for remote CLI management.',
  },
  {
    checkId: 'cisco-asa-http-server-disabled',
    name: 'HTTP server (ASDM) not left unnecessarily enabled',
    description:
      'The ASA\'s built-in HTTP server ("http server enable", used for ASDM and the REST API) ' +
      'expands the management-plane attack surface when left on without a real need for it.',
    standards: ['CIS_V8', 'PCI_DSS'],
    vendor: 'cisco_asa',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'feature_enabled',
      // parsed.http_server_enabled is a plain JS boolean (parser.js sets it
      // to `true` on a literal `http server enable` line match, otherwise
      // it stays at its `false` default — there is no separate
      // enable/disable string form to worry about here, unlike Fortinet's
      // CLI-string config values). evaluatePredicate's feature_enabled case
      // does `String(value).toLowerCase()` before checking membership in
      // TRUTHY_FEATURE_VALUES/FALSY_FEATURE_VALUES — String(true) ->
      // 'true', String(false) -> 'false', and both 'true'/'false' are
      // explicitly listed in those arrays (confirmed by reading
      // applicability.js directly), so a real boolean resolves correctly
      // without any string-vocabulary mismatch.
      path: 'http_server_enabled',
      pass_when: 'no',
    },
    remediationGuidance:
      'Disable "http server enable" unless ASDM/REST-API management access is a required use case; if it is required, restrict source access via "http <ip> <mask> <interface>" entries scoped to a trusted management subnet only.',
  },
  // ─────────────────────────────────────────────────────────────
  // Rule-scan checks (7) — added alongside the compliance rule-evidence
  // drill-down UI. A SECOND kind of check, distinct from every row above:
  // predicate_type: 'rule_scan' is evaluated by lib/engines/configAuditor.js
  // directly against a device's CURRENT rule_analysis_results (Phase 5
  // findings), NOT against device_configs.config_parsed via
  // applicability.js's evaluatePredicate() — see configAuditor.js's own
  // header comment on evaluateRuleScanCheck() for why. No pass_when field:
  // every check below is a fixed-polarity "this bad pattern should not
  // exist anywhere in the ruleset" check, so zero matching rules is always
  // PASS and any match is always FAIL — there's no meaningful inverse
  // reading the way admin_access_from_zone/feature_enabled checks need one.
  // vendor: null on all of them, since firewall_rules/rule_analysis_results
  // are already vendor-normalized by collectAndStore — no per-vendor
  // duplication needed here, unlike the shared-concept block at the top of
  // this file.
  //
  // Unlike every check above (whose predicate paths are grounded in this
  // repo's OWN parser code, per this file's Groundedness header), these are
  // grounded in something stronger for the security-relevant subset: they
  // simply REUSE detection logic lib/engines/ruleAnalysis.js already runs
  // and stores — no new predicate evaluation risk, just a new lens
  // (standards mapping) on findings this codebase was already computing.
  //
  // Real, cited sources for the standards tags below (not guessed
  // regulatory-clause paraphrasing — see this file's own commit history for
  // the web research this was grounded in):
  //   - SANS Institute, "Firewall Checklist" (Krishni Naidu),
  //     https://www.sans.org/media/score/checklists/FirewallChecklist.pdf —
  //     a real, publicly published, numbered SCORE checklist. Item numbers
  //     cited below refer to this document as fetched 2026-07-18.
  //   - NIST SP 800-41 Rev. 1, "Guidelines on Firewalls and Firewall
  //     Policy," https://csrc.nist.gov/pubs/sp/800/41/r1/final — cited
  //     where its documented themes (formal change-control ruleset review,
  //     continuous log/alert monitoring) apply directly, as an ADDITION to
  //     this app's existing 'NIST' standard tag (which otherwise points at
  //     SP 800-53) rather than as a confusing second NIST-labeled standard
  //     key.
  {
    checkId: 'rule-no-any-any-allow',
    name: 'No unrestricted (any-source/any-destination) allow rules',
    description:
      'No enabled rule permits traffic with an unrestricted source AND destination — an ' +
      '"allow any-any" rule defeats least-privilege network segmentation. Reuses ' +
      'ruleAnalysis.js\'s existing any_any finding (critical severity) rather than a second ' +
      'detection pass. A textbook control across every network-security standard; also the ' +
      'first item ManageEngine Firewall Analyzer\'s own comparable NIST-mapped report checks ' +
      '("All inbound and outbound traffic not specifically permitted should be blocked").',
    standards: ['PCI_DSS', 'CIS_V8', 'ISO_27001', 'NIST', 'SANS'],
    vendor: null,
    severity: 'critical',
    predicateConfig: {
      predicate_type: 'rule_scan',
      finding_types: ['any_any'],
    },
    remediationGuidance:
      'Replace the any-any rule with explicit source/destination/service scoping for the traffic actually required; add an explicit deny-and-log rule at the end of the policy for everything else.',
  },
  {
    checkId: 'rule-no-risky-services',
    name: 'No rules expose known-risky cleartext or high-risk services',
    description:
      'No enabled rule permits a service ruleAnalysis.js\'s risky-service list flags (telnet, ' +
      'FTP, RDP, SMB/NetBIOS, TFTP, SNMP v1/v2c, VNC, rlogin/rsh, and others — see ' +
      'lib/engines/ruleAnalysis.js\'s DEFAULT_RISKY_PORTS for the full list). Directly grounded ' +
      'in the SANS Firewall Checklist\'s explicit block-list for these exact services: Telnet ' +
      '(item 45), FTP (item 44), TFTP (item 34), rlogin/rsh (item 37, TCP 512-514), NetBIOS/SMB ' +
      '(items 53-55, 62), and SNMP (items 57-58) — plus item 70\'s recommendation to use SSH ' +
      'instead of Telnet for remote management.',
    standards: ['PCI_DSS', 'CIS_V8', 'SANS'],
    vendor: null,
    severity: 'high',
    predicateConfig: {
      predicate_type: 'rule_scan',
      finding_types: ['risky_service'],
    },
    remediationGuidance:
      'Remove or restrict rules permitting cleartext/high-risk services; where remote access is genuinely required, use an encrypted equivalent (SSH instead of Telnet, SFTP instead of FTP) restricted to specific management source addresses.',
  },
  {
    checkId: 'rule-logging-enabled-on-rules',
    name: 'Logging enabled on active rules',
    description:
      'No enabled rule has logging disabled. Reuses ruleAnalysis.js\'s log_disabled finding. ' +
      'Grounded in the SANS Firewall Checklist\'s explicit logging items ("Enable logging and ' +
      'review for attack patterns," item 16; "Log traffic from non-internal IPs," item 78) and ' +
      'NIST SP 800-41 Rev. 1\'s guidance that firewall logs and alerts "should be continuously ' +
      'monitored to identify threats" — a rule with logging off produces no evidence for either ' +
      'goal, regardless of whether the traffic it matches was legitimate.',
    standards: ['PCI_DSS', 'ISO_27001', 'NIST', 'SANS'],
    vendor: null,
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'rule_scan',
      finding_types: ['log_disabled'],
    },
    remediationGuidance:
      'Enable logging on every active rule, at minimum for denied/dropped traffic and any rule permitting access to sensitive assets — un-logged allow rules leave no audit trail for incident response.',
  },
  {
    checkId: 'rule-no-shadowed-rules',
    name: 'No rules are fully shadowed by an earlier rule',
    description:
      'No enabled rule is completely shadowed by an earlier rule with the same action, making it ' +
      'permanently unreachable. Reuses ruleAnalysis.js\'s shadow finding. A shadowed DENY rule is ' +
      'the more dangerous case in practice — it reads as a documented control in the policy but ' +
      'never actually fires.',
    standards: ['CIS_V8'],
    vendor: null,
    severity: 'high',
    predicateConfig: {
      predicate_type: 'rule_scan',
      finding_types: ['shadow'],
    },
    remediationGuidance:
      'Remove the shadowed rule, or reorder/narrow the earlier covering rule so the shadowed rule can take effect as intended.',
  },
  {
    checkId: 'rule-no-redundant-rules',
    name: 'No exact-duplicate rules',
    description:
      'No enabled rule exactly duplicates an earlier rule (identical zones, addresses, services, ' +
      'and action). Reuses ruleAnalysis.js\'s redundant finding. Duplicate rules add no security ' +
      'value and make the policy harder to audit and maintain — the same "keep the ruleset lean ' +
      'and auditable" discipline the SANS checklist\'s rule-review items (25-26) and NIST SP ' +
      '800-41 Rev. 1\'s formal change-control/periodic-review guidance both describe, applied here ' +
      'to an automatically detectable subset of that discipline.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: null,
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'rule_scan',
      finding_types: ['redundant'],
    },
    remediationGuidance: 'Remove the duplicate later rule to simplify the policy and reduce audit overhead.',
  },
  {
    checkId: 'rule-no-overly-permissive-rules',
    name: 'No rules are broader than necessary',
    description:
      'No enabled rule uses an unrestricted ("any") value on a field where the rest of the rule ' +
      'is specific, a common sign the rule is broader than the traffic it was actually written ' +
      'for. Reuses ruleAnalysis.js\'s overly_permissive finding.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: null,
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'rule_scan',
      finding_types: ['overly_permissive'],
    },
    remediationGuidance:
      'Narrow the "any" field(s) to the specific addresses/services/zones the rule is actually intended to cover.',
  },
  {
    checkId: 'rule-stale-unused-rules-reviewed',
    name: 'No stale unused rules left unreviewed',
    description:
      'No enabled rule has gone unused (zero hit count) beyond the configured review window. ' +
      'Reuses ruleAnalysis.js\'s unused finding. Periodic removal of rules no longer matching any ' +
      'real traffic is the SANS Firewall Checklist\'s ruleset-review discipline (items 25-26) and ' +
      'a widely-cited PCI DSS firewall-hygiene expectation, applied here to the automatically ' +
      'detectable subset (hit-count evidence, where the collecting adapter/transport supports it — ' +
      'some vendors cannot report hit counts over SSH at all, a documented limitation ' +
      'which this check inherits: an SSH-collected device with no hit-count support will report ' +
      'every rule as unused, same caveat ruleAnalysis.js itself documents).',
    standards: ['PCI_DSS', 'CIS_V8', 'SANS'],
    vendor: null,
    severity: 'low',
    predicateConfig: {
      predicate_type: 'rule_scan',
      finding_types: ['unused'],
    },
    remediationGuidance:
      'Review rules with zero hit count over the configured window; remove or re-justify each one. On vendors/transports without reliable hit-count data, verify manually before relying on this signal.',
  },

  // ─────────────────────────────────────────────────────────────
  // ruleset_property checks (2) — added 2026-07-18, found missing during a
  // direct comparison against ManageEngine Firewall Analyzer's real
  // compliance report for the SAME two real devices in this deployment.
  // Both are POSITIVE existence checks against a device's current
  // firewall_rules (see lib/engines/configAuditor.js's evaluateRulesetPropertyCheck()
  // for the evaluator) — a different question shape from every rule_scan
  // check above ("a bad pattern should not exist" vs "a required pattern
  // SHOULD exist"), which is why these need a distinct predicate_type
  // rather than just another rule_scan finding_types entry.
  // ─────────────────────────────────────────────────────────────
  {
    checkId: 'rule-has-explicit-deny-all',
    name: 'Explicit deny-all rule present',
    description:
      'At least one enabled rule should explicitly deny unrestricted (any-source/any-destination/' +
      'any-service) traffic, rather than relying purely on the device\'s implicit default-deny. ' +
      'An explicit catch-all deny is auditable and loggable in a way an implicit default is not — ' +
      'this is the same concept ManageEngine Firewall Analyzer\'s own NIST-mapped report checks ' +
      '("2.1 Explicit Deny rule") and ISO-mapped report checks ("13.1.2 Explicit deny rule"), ' +
      'confirmed by direct comparison against a real compliance report for a real device in this ' +
      'deployment — SecVault had no equivalent check before this.',
    standards: ['NIST', 'ISO_27001', 'PCI_DSS', 'CIS_V8'],
    vendor: null,
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'ruleset_property',
      property: 'has_explicit_deny_all',
    },
    remediationGuidance:
      'Add an explicit deny-all rule (any source, any destination, any service) at the end of the policy, with logging enabled, rather than relying solely on the implicit default-deny.',
  },
  {
    checkId: 'rule-blocks-icmp',
    name: 'Unwanted ICMP traffic blocked',
    description:
      'At least one enabled rule should explicitly deny ICMP traffic (or a defined subset of it), ' +
      'rather than leaving ICMP unaddressed by the ruleset. This is the same concept the SANS ' +
      'Firewall Checklist calls out explicitly (item 73: block ICMP echo requests/replies, and the ' +
      'broader item 15 category ManageEngine Firewall Analyzer\'s own SANS-mapped report checks) — ' +
      'confirmed by direct comparison against a real compliance report for a real device in this ' +
      'deployment — SecVault had no equivalent check before this. Deliberately coarse (any ICMP-named ' +
      'service on a deny rule counts, not specifically echo/echo-reply types) — this predicate engine ' +
      'has no ICMP-type-level granularity today.',
    standards: ['SANS', 'CIS_V8'],
    vendor: null,
    severity: 'low',
    predicateConfig: {
      predicate_type: 'ruleset_property',
      property: 'blocks_icmp',
    },
    remediationGuidance:
      'Add a rule denying ICMP (or at minimum echo-request/echo-reply) from untrusted zones, to reduce network reconnaissance surface.',
  },
  {
    checkId: 'rule-no-external-to-internal-access',
    name: 'No unrestricted External-to-Internal zone access',
    description:
      'No enabled allow rule should permit traffic directly from a zone classified External to a ' +
      'zone classified Internal — network segmentation between untrusted and trusted networks is a ' +
      'core requirement across every major framework (e.g. PCI-DSS Requirement 1\'s network security ' +
      'controls between the CDE and other networks; NIST/CIS network segmentation guidance). Unlike ' +
      'every other check in this file, this one depends on data an admin must explicitly supply — ' +
      'see lib/engines/zoneClassification.js: SecVault never guesses which zone is External/Internal/' +
      'DMZ from its name alone (an earlier feature, the Compliance page\'s Network Details card, ' +
      'already tried and rejected automatic name-pattern classification for this exact reason). A ' +
      'device whose zones haven\'t been classified yet resolves NA for this check, never a false ' +
      'PASS — see evaluateExternalToInternalExposure()\'s own header comment in configAuditor.js for ' +
      'why the plain rule_scan "zero matches is pass" shape every other check here uses would be ' +
      'actively wrong for this one specifically.',
    standards: ['PCI_DSS', 'NIST', 'CIS_V8'],
    vendor: null,
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'ruleset_property',
      property: 'no_external_to_internal_access',
    },
    remediationGuidance:
      'Review each matched rule: if the External-to-Internal path is genuinely required (e.g. a VPN ' +
      'termination or partner link), narrow it to the minimum required source/destination/service and ' +
      'ensure it is monitored; otherwise remove or restrict it, and route legitimate External-facing ' +
      'access through a DMZ zone instead of directly into Internal.',
  },

  {
    checkId: 'cisco-asa-local-admin-accounts-present',
    name: 'Local admin account inventory (informational)',
    description:
      'NOT EVALUABLE as a real pass/fail concept with current data. parsed.usernames captures local ' +
      'account NAMES ONLY — parser.js deliberately never stores password hashes, and it has no ' +
      'privilege-level, role, or last-used data either (an ASA "username X password Y privilege 15" ' +
      'line only contributes the name). "At least one local account exists" is not itself a finding: ' +
      'local admin accounts are normal and often necessary (e.g. a break-glass account alongside ' +
      'centralized AAA), so resolving this to a real pass/fail would need a threshold or an ' +
      'allowlist this engine has no data to support — inverting "exists" into a fail would be exactly ' +
      'the kind of misleading confident-answer this file\'s own philosophy (see header comment) exists ' +
      'to avoid. Kept as an honest not_evaluable_from_config rather than a low-value or misleading ' +
      'real check.',
    standards: ['CIS_V8'],
    vendor: 'cisco_asa',
    severity: 'low',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'parsed.usernames has names only (no privilege/role/password data) — "local accounts exist" is not a meaningful pass/fail without a threshold or allowlist this engine cannot express.',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Manually review the local account list (device_configs.config_parsed.usernames) periodically: remove unused accounts, confirm remaining accounts are individually attributable, and prefer centralized AAA (RADIUS/TACACS+) over local accounts where possible.',
  },

  // ═════════════════════════════════════════════════════════════
  // Check Point / Sangfor / Forcepoint (29) — the three vendors that had
  // ZERO vendor-scoped checks until this change, added 2026-11-12.
  //
  // Those three firewalls were not healthier than the other three; they were
  // THINLY MEASURED. A Check Point, Sangfor or Forcepoint device scored only
  // against the vendor:null rule_scan/ruleset_property rows, so every
  // vendor-specific hardening concept this library tracks (admin access,
  // management services, NTP, DNS, logging, password policy, session
  // timeout) was simply absent from its assessment — invisible, because an
  // absent check looks exactly like a concept nobody cares about.
  //
  // ── WHAT EACH ADAPTER ACTUALLY PUTS IN config_parsed ──────────────────
  //
  // Read off the adapter source, per this file's Groundedness header (never
  // from vendor CLI/API documentation from memory). No live Check Point
  // management server, Sangfor NGAF or Forcepoint SMC exists in this
  // deployment, so adapter source IS the best available grounding — and the
  // mock fleet is NOT a second source: its Check Point config_parsed is a
  // 3-key toy object no adapter produces, so writing a predicate against it
  // would be testing one guess against another.
  //
  //   checkpoint — lib/adapters/checkpoint/index.js:597-601 builds exactly
  //     { gateway, api_versions, administrators }.
  //       · `gateway` is a show-gateways-and-servers object. ALWAYS present
  //         on a successful collection (index.js:523-540 throws rather than
  //         storing a gateway-less snapshot). Fields this repo itself reads
  //         off it: name/uid/type/ipv4-address (parser.js:359-374),
  //         version|os-version|software-version, build-number|build,
  //         hardware (parser.js:392-439), and the `policy` sub-object
  //         (parser.js:469-499). ⛔ It is a management-API VIEW at the
  //         DEFAULT details-level (index.js:157-159 passes no
  //         'details-level'), NOT a full device configuration — so "the key
  //         is absent" never licenses the conclusion "the setting is not
  //         configured" the way it does for a full PAN-OS config tree.
  //       · `api_versions` and `administrators` are INDEPENDENTLY try/caught
  //         (index.js:544-547, 566-579) — either can be `null` on an
  //         otherwise successful collection.
  //       · `administrators`, when non-null, is parseAdministratorObjects()
  //         output (parser.js:798-817): a fixed nine-key record per account
  //         — name, uid, authentication_method, email, phone_number,
  //         must_change_password, expiration_date, permissions_profile,
  //         comments. `show-administrators` is a real documented Management
  //         API command, corroborated against Check Point's own forum JSON
  //         examples and the check_point.mgmt.cp_mgmt_administrator Ansible
  //         module (generated from the same API schema) — but UNVERIFIED
  //         against a live management server (index.js:548-565 says so).
  //       · ⛔ These are MANAGEMENT-PLANE objects. Gaia OS settings on the
  //         gateway itself (clock/NTP, DNS resolver, the web UI, SSH, the OS
  //         password policy, admin session timeout) have NO management-API
  //         surface at all — index.js:552-556 states this in the adapter:
  //         "Check Point management-server 'administrator' objects are
  //         management-plane users, not Gaia OS accounts on the gateway
  //         itself — there is no API surface for the latter from the
  //         management server."
  //
  //   sangfor — lib/adapters/sangfor/index.js:377-383 builds exactly
  //     { source_command, line_count, sections, collected_via }, where
  //     `sections` is parseConfigSections() output
  //     (lib/adapters/sangfor/parser.js:527-567) and extracts FOUR things
  //     and nothing else: `hostname`, `version`, `interfaces` (interface
  //     NAMES only — parser.js:541-547) and a tri-state
  //     `ssl_vpn.enabled` (parser.js:549-560). hostname/version/interfaces
  //     are ABSENT when nothing matched; `ssl_vpn` is always present with
  //     `enabled` true|false|null, and its own parser comment flags the
  //     detection regex as a never-live-verified guess with null as "the
  //     expected, common state".
  //     ⛔ Sangfor is this codebase's least-verified vendor: no live NGAF has
  //     ever been connected AND, unlike every other vendor here, there is no
  //     documentation trail to check field names against either, and no
  //     captured CLI sample exists anywhere in this codebase
  //     (.ai-codex/connectors.md). Everything below is therefore
  //     not_evaluable_from_config — see the Sangfor sub-header.
  //
  //   forcepoint — lib/adapters/forcepoint/index.js:309-315 returns
  //     { ...parseConfig(redactedEngineElement).parsed,
  //       smc_vpn_gateway_configured, smc_administrators }, and
  //     parseConfig() (lib/adapters/forcepoint/parser.js:297-303) sets
  //     `parsed` to the REDACTED ENGINE ELEMENT ITSELF — so config_parsed is
  //     root-anchored on SMC's engine element, plus exactly two
  //     SecVault-written `smc_`-prefixed fields.
  //       · smc_vpn_gateway_configured: tri-state true|false|null from
  //         detectVpnGatewayConfigured() (parser.js:619-628).
  //       · smc_administrators: summarizeAdministrators() output
  //         (parser.js:655-664) — { name, superuser, enabled } per account,
  //         SERVER-WIDE (not per-engine), or `null` when the fetch failed
  //         (index.js:289-299).
  //       · Engine-element fields this repo itself reads: software_version,
  //         version, attributes.version, engine_version, dynamic_package,
  //         model, type, name (parser.js:43-94) and internal_gateway
  //         (parser.js:619-628). ⛔ Every one is DOC-DERIVED from the
  //         smc-python client and explicitly unverified against live
  //         hardware (parser.js:56-60). The element is security-relevant
  //         only in the sense that it identifies the engine; it carries no
  //         field this repo can name that expresses a hardening setting.
  //
  // ── WHY SO MANY OF THESE ROWS ARE not_evaluable_from_config ───────────
  //
  // ⛔ A predicate on a path the adapter never collected does not answer
  // "unknown" — evaluatePredicate() maps an unresolved path to 'no' for
  // config_key_exists, config_value_equals, config_value_matches AND
  // feature_enabled (lib/engines/applicability.js:178-216). With
  // pass_when:'yes' that is a CONFIDENT FAIL, i.e. SecVault's own collection
  // gap written down as a fact about the customer's firewall — the same error
  // as hit_count's old NOT NULL DEFAULT 0. Flipping pass_when to dodge it
  // just inverts the lie into a confident PASS, which on a compliance report
  // is the worse direction (a hole reported as closed). There is no
  // path-lookup predicate whose miss resolves to 'unknown', so for a concept
  // whose SECTION is not collected at all the only honest encoding is
  // not_evaluable_from_config — `na`, excluded from the score denominator by
  // configAuditor.evaluateCheck()'s short-circuit, still WRITTEN and still
  // shown to the operator with its `reason`.
  //
  // ⛔ This is a stricter bar than the Fortinet rows at the top of this file,
  // deliberately, and the difference is WHICH part is a guess. Fortinet's
  // `ntp.ntpsync` is a guessed LEAF NAME inside a section the adapter
  // demonstrably collects; "checkpoint NTP" would be a guessed SECTION that
  // provably is not collected and cannot be. A guessed leaf inside a real
  // section is a correctable best-effort; a predicate on an absent section is
  // a guard that can only ever fire wrong.
  //
  // ⛔ The two REAL predicates below both use `admin_access_from_zone`, which
  // is the one predicate type that is SAFE BY CONSTRUCTION here: it
  // deep-scans for the zone string under any key containing 'admin' or
  // 'management' and returns found ? 'yes' : **'unknown'**
  // (applicability.js:229-233) — never 'no'. So a wrong zone literal or an
  // unexpected config shape degrades to `warning` ("we asked a real question
  // of a config we did collect and could not tell"), never to a fabricated
  // FAIL. `warning` — not `na` — is the correct bucket for them per
  // CLAUDE.md's "whose limitation is it?": the scan really does run against a
  // real collected config, so the indeterminacy is the device's/the curated
  // zone name's, and it counts toward the score exactly as the two existing
  // rows for this same concept (fortinet/paloalto) already do.
  //
  // ⛔ port_exposed was CONSIDERED FOR THE SAME REASON AND REFUSED. It is
  // equally miss-safe, but its hit side is not: PORT_KEY_NAMES is
  // port|ports|listen_port|dst_port (applicability.js:33) and a match on ANY
  // such key anywhere — a service object's port, an SMC element's listener —
  // would resolve 'yes' and, with pass_when:'no', assert "a cleartext
  // management port is exposed on this firewall". A fabricated FAIL from an
  // affirmative false positive is worse than the gap it would close.
  // ═════════════════════════════════════════════════════════════

  // ── Check Point (10) ────────────────────────────────────────────────────

  {
    checkId: 'checkpoint-admin-access-untrusted-zone',
    name: 'Admin access not permitted from untrusted/External zone',
    description:
      'Administrative access to the gateway or its management server should not be reachable from ' +
      'the External (untrusted) zone. Evaluated by deep-scanning the collected management-plane ' +
      'config for the zone name under any admin/management-named key.',
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS', 'NIST', 'SANS'],
    vendor: 'checkpoint',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'admin_access_from_zone',
      // Best-effort zone literal: 'External' is Check Point's own topology
      // vocabulary (and the same spelling this repo already uses in
      // rule-no-external-to-internal-access below), not a value read off a
      // live management server — no Check Point server has ever been
      // connected to this codebase. Safe to get wrong in only one direction:
      // applicability.js:229-233 returns 'unknown' (-> warning) when the
      // scan finds nothing, NEVER 'no', so a wrong literal or an unexpected
      // gateway-object shape can never manufacture a FAIL. Same deep-scan
      // caveat as the fortinet/paloalto rows for this concept at the top of
      // this file.
      zone: 'External',
      pass_when: 'no',
    },
    remediationGuidance:
      'On the management server, ensure no access rule or gateway management setting permits ssh/https/API administration from the External zone; restrict administration to a dedicated management network reached over VPN.',
  },
  {
    checkId: 'checkpoint-ssh-mgmt-untrusted-iface',
    name: 'SSH management disabled on untrusted interfaces',
    description:
      'NOT EVALUABLE from the data this adapter collects. SSH administration of a Check Point ' +
      'gateway is a Gaia OS setting on the appliance, and lib/adapters/checkpoint/index.js:597-601 ' +
      'stores only management-plane objects ({gateway, api_versions, administrators}) — the gateway ' +
      'object carries identity, version and policy fields (parser.js:359-439, 469-499) and no ' +
      'interface or management-access list at all. The adapter says so itself at index.js:552-556: ' +
      'there is no API surface for Gaia OS settings from the management server. A predicate on a ' +
      'guessed interface path would resolve to a confident FAIL on every Check Point device.',
    standards: ['CIS_V8', 'ISO_27001', 'SANS'],
    vendor: 'checkpoint',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'SSH administration is a Gaia OS setting on the gateway. SecVault collects this device through the Security Management Server API, which exposes management-plane objects only (gateway, API versions, administrators) and no per-interface management-access list.',
      // Never consulted (configAuditor.evaluateCheck() short-circuits this
      // predicate_type to 'na' before the pass_when guard) — recorded as the
      // polarity this concept WOULD carry, so the intent survives if the
      // adapter ever gains the data.
      pass_when: 'no',
    },
    remediationGuidance:
      'Verify manually on the gateway (Gaia CLI/WebUI): confirm SSH administration is reachable only from a trusted management network, e.g. via Gaia "set net-access ssh" plus an allowed-clients list, and never from an External-facing interface.',
  },
  {
    checkId: 'checkpoint-https-only-not-http',
    name: 'Management web access over HTTPS only (no plaintext HTTP)',
    description:
      'NOT EVALUABLE from the data this adapter collects. The Gaia Portal\'s HTTP/HTTPS listener is ' +
      'an OS-level setting on the appliance, not a management-API object, and nothing in ' +
      'config_parsed ({gateway, api_versions, administrators}, index.js:597-601) reports it.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'checkpoint',
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'The Gaia Portal web listener is an OS-level setting on the gateway; the Security Management Server API SecVault collects through exposes no field reporting whether plaintext HTTP administration is enabled.',
      pass_when: 'no',
    },
    remediationGuidance:
      'Verify manually on the gateway: confirm the Gaia Portal is served over HTTPS only and that any plaintext HTTP listener is disabled or redirects.',
  },
  {
    checkId: 'checkpoint-ntp-configured',
    name: 'NTP time synchronisation configured',
    description:
      'NOT EVALUABLE from the data this adapter collects. Gaia\'s clock/NTP configuration has no ' +
      'representation in the management-plane objects this adapter stores (index.js:597-601). ' +
      'Accurate time matters here specifically because every log line, rule hit and audit finding ' +
      'SecVault correlates is timestamped by the device.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'checkpoint',
    severity: 'low',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'Clock/NTP settings live in Gaia on the gateway, not in the Security Management Server objects SecVault collects (gateway, API versions, administrators).',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Verify manually on the gateway: confirm at least one reachable NTP server is configured and the clock is in sync (Gaia "show ntp active" / "show ntp servers").',
  },
  {
    checkId: 'checkpoint-dns-configured',
    name: 'DNS resolver configured',
    description:
      'NOT EVALUABLE from the data this adapter collects. The gateway\'s DNS resolver is a Gaia OS ' +
      'setting with no management-API representation in config_parsed (index.js:597-601).',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'checkpoint',
    severity: 'low',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'DNS resolver settings live in Gaia on the gateway, not in the Security Management Server objects SecVault collects.',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Verify manually on the gateway: confirm a reachable DNS resolver is configured (Gaia "show dns primary"), since signature updates and FQDN-based objects depend on it.',
  },
  {
    checkId: 'checkpoint-logging-enabled',
    name: 'Traffic logging enabled',
    description:
      'NOT EVALUABLE from the data this adapter collects, for TWO independent reasons. (1) Check ' +
      'Point logging is decided per rule by each rule\'s Track setting, which lives in the ' +
      'RULEBASE, not in device_configs.config_parsed — and a per-rule fact cannot be expressed as ' +
      'the one fixed dot-path this predicate engine evaluates. (2) Gateway-level log-server ' +
      'assignment is not among the gateway-object fields this repo reads (parser.js:359-439, ' +
      '469-499). The rule grain IS already covered for every vendor by the vendor-null ' +
      'rule-logging-enabled-on-rules check in this same library, which reads the collected ' +
      'firewall_rules rows directly — so this concept is measured for Check Point, just not here.',
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS', 'SANS'],
    vendor: 'checkpoint',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'Check Point logging is a per-rule Track setting in the rulebase, which this predicate engine cannot query (it evaluates one fixed path in the config snapshot), and gateway-level log-server assignment is not among the fields collected. The rule-level question is answered instead by the fleet-wide "Logging enabled on rules" check.',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Review the per-rule findings of the fleet-wide "Logging enabled on rules" check for this device, and confirm on the management server that the gateway has a log server assigned and is actually delivering logs to it.',
  },
  {
    checkId: 'checkpoint-password-min-length',
    name: 'Administrator password policy enforces a minimum length',
    description:
      'NOT EVALUABLE from the data this adapter collects. parseAdministratorObjects() ' +
      '(lib/adapters/checkpoint/parser.js:798-817) captures nine fields per administrator — name, ' +
      'uid, authentication_method, email, phone_number, must_change_password, expiration_date, ' +
      'permissions_profile, comments — and NO password-policy field of any kind; the Gaia OS ' +
      'password policy for appliance accounts is a separate surface with no management-API ' +
      'representation at all.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'checkpoint',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'The administrator records SecVault collects carry no password-policy fields, and the Gaia OS password policy is not exposed through the Security Management Server API.',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Verify manually: confirm a minimum password length and complexity policy is enforced for SmartConsole administrators (or that they authenticate against an external directory), and separately for Gaia OS accounts on each appliance.',
  },
  {
    checkId: 'checkpoint-session-timeout',
    name: 'Administrative session timeout configured',
    description:
      'NOT EVALUABLE from the data this adapter collects. Neither the SmartConsole session timeout ' +
      'nor the Gaia CLI/WebUI idle timeout appears in config_parsed ({gateway, api_versions, ' +
      'administrators}, index.js:597-601).',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'checkpoint',
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'Administrative session/idle timeouts are not among the management-plane objects SecVault collects for this vendor.',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Verify manually: confirm an idle timeout is enforced for SmartConsole sessions and for Gaia CLI/WebUI sessions on each appliance.',
  },
  {
    checkId: 'checkpoint-access-policy-installed',
    name: 'Assigned access policy is actually installed on the gateway',
    description:
      'NOT EVALUABLE as a safe pass/fail, and the reason is worth reading: a gateway whose policy ' +
      'package is assigned but NOT installed is enforcing something other than the policy SecVault ' +
      'collected and analysed, which would make every rule finding, segmentation verdict and ' +
      'compliance result for it describe a policy the device is not running. This repo DOES read ' +
      'the field — lib/adapters/checkpoint/parser.js:487-499 tests ' +
      'gateway.policy["access-policy-installed"] === false explicitly — but the SAME adapter ' +
      'documents that some management versions OMIT the installed-policy field from ' +
      'show-gateways-and-servers (which is exactly why index.js:296-300 exists, to fetch the ' +
      'gateway\'s own element as a second source for it). Every path-lookup predicate maps an ' +
      'absent path to \'no\' (applicability.js:178-216), so pass_when:\'yes\' would FAIL every ' +
      'gateway whose management version simply did not return the field, and pass_when:\'no\' would ' +
      'PASS every one of them — a confident wrong answer in either direction, with no third option ' +
      'available from this engine. Recorded honestly instead.',
    standards: ['CIS_V8', 'ISO_27001', 'NIST'],
    vendor: 'checkpoint',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'Whether the assigned policy package is currently installed is reported inconsistently across Check Point management versions, and this engine cannot distinguish "not installed" from "the management server did not report it" — both would resolve to a definite pass or a definite fail depending only on which polarity was chosen.',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Verify in SmartConsole that this gateway\'s access policy shows as installed and that its installation date matches the last policy change; an assigned-but-uninstalled policy means the appliance is enforcing an older rulebase than the one SecVault analysed.',
  },
  {
    checkId: 'checkpoint-administrator-inventory',
    name: 'Administrator account inventory (informational)',
    description:
      'NOT EVALUABLE as a real pass/fail concept with current data — the same judgement, for the ' +
      'same reason, as cisco-asa-local-admin-accounts-present above. config_parsed.administrators ' +
      '(lib/adapters/checkpoint/parser.js:798-817) gives per-account name, authentication method, ' +
      'permissions profile, must-change-password and expiry, which is a genuinely useful inventory ' +
      '— but "administrator accounts exist" is not a finding, and the predicate engine evaluates ' +
      'ONE fixed dot-path, so "every administrator has an expiry" or "no administrator uses ' +
      'internal authentication" cannot be expressed without pinning an arbitrary array index and ' +
      'grading the whole fleet on whichever account happened to be first. A positional predicate ' +
      'dressed as a fleet-wide control is worse than an honest gap. Note also that ' +
      '`administrators` is independently try/caught (index.js:566-579) and is `null` when the API ' +
      'user lacks rights to read it — and config_key_exists treats null as PRESENT, so even a ' +
      'bare existence predicate here would report \'yes\' for a failed read.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'checkpoint',
    severity: 'low',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'The collected administrator inventory is per-account, and this engine evaluates one fixed path — a per-account rule such as "every administrator has an expiry date" cannot be expressed without grading the device on an arbitrary single account.',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Review the collected administrator list on this device\'s configuration snapshot: remove unused accounts, confirm each is individually attributable, prefer an external directory over internal passwords, and set expiry dates on contractor accounts.',
  },

  // ── Sangfor (9) ─────────────────────────────────────────────────────────
  //
  // ⛔ EVERY SANGFOR ROW IS not_evaluable_from_config, AND THAT IS THE
  // RESULT, NOT A SHORTFALL. lib/adapters/sangfor/parser.js's
  // parseConfigSections() (lines 527-566) extracts FOUR things from the
  // running-config dump and nothing else: hostname, version, a list of
  // interface NAMES, and a tri-state ssl_vpn.enabled whose own parser
  // comment (lines 549-560) flags the detection regex as a never-verified
  // guess with `null` as "the expected, common case". None of the four is a
  // hardening setting. Sangfor is also this codebase's least-verified
  // vendor: no live NGAF has ever been connected, no captured NGAF CLI
  // sample exists anywhere in this repository, and — uniquely among the six
  // — there is no documentation trail to check a field name against either.
  //
  // So there is nothing here to write a real predicate against, and padding
  // this block with plausible-looking paths would manufacture a confident
  // FAIL on every Sangfor device for every concept (applicability.js maps an
  // unresolved path to 'no'). What these rows DO buy is visibility: nine
  // named, operator-readable manual-verification items, each excluded from
  // the score denominator, where previously the gap was invisible and a
  // thinly-measured Sangfor rendered as a clean one.
  //
  // Sangfor devices are still graded on the eleven vendor-null
  // rule_scan/ruleset_property checks, which read the collected
  // firewall_rules rows and do not depend on config_parsed at all.

  {
    checkId: 'sangfor-admin-access-untrusted-zone',
    name: 'Admin access not permitted from untrusted/WAN zone',
    description:
      'NOT EVALUABLE from the data this adapter collects. The admin_access_from_zone predicate ' +
      'deep-scans for a zone name under any key containing "admin" or "management" ' +
      '(lib/engines/applicability.js:116-133); Sangfor\'s config_parsed is ' +
      '{source_command, line_count, sections, collected_via} (index.js:377-383) where `sections` ' +
      'holds only hostname, version, interface names and ssl_vpn (parser.js:527-567) — there is no ' +
      'admin- or management-named key anywhere in it, on any device, ever. The scan could ' +
      'therefore never return true: it would be a guard that cannot fire, permanently reporting ' +
      '`warning` and quietly scoring every Sangfor device down for SecVault\'s own blind spot.',
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS', 'NIST', 'SANS'],
    vendor: 'sangfor',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'The configuration SecVault can read from this vendor contains no administrative-access settings at all, so the question cannot be posed — not even inconclusively.',
      pass_when: 'no',
    },
    remediationGuidance:
      'Verify manually on the device: confirm management access (web console, SSH, API) is permitted only from a trusted internal network or over VPN, and never from a WAN/untrusted interface.',
  },
  {
    checkId: 'sangfor-ssh-mgmt-untrusted-iface',
    name: 'SSH management disabled on untrusted interfaces',
    description:
      'NOT EVALUABLE from the data this adapter collects. sections.interfaces is a list of ' +
      'interface NAMES only (lib/adapters/sangfor/parser.js:541-547) — no address, no role, and ' +
      'no per-interface management-service list — so there is nothing to test even for the ' +
      'interfaces SecVault can see.',
    standards: ['CIS_V8', 'ISO_27001', 'SANS'],
    vendor: 'sangfor',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'SecVault collects interface names only for this vendor — no per-interface management-service settings — so whether SSH is reachable on an untrusted interface cannot be determined from the snapshot.',
      pass_when: 'no',
    },
    remediationGuidance:
      'Verify manually on the device: confirm SSH administration is bound to a trusted management interface only and disabled on every WAN-facing interface.',
  },
  {
    checkId: 'sangfor-https-only-not-http',
    name: 'Management web access over HTTPS only (no plaintext HTTP)',
    description:
      'NOT EVALUABLE from the data this adapter collects. No management-service settings are ' +
      'extracted from the Sangfor running-config at all (parser.js:527-567 extracts hostname, ' +
      'version, interface names and ssl_vpn).',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'sangfor',
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'No management-service settings are extracted from this vendor\'s configuration, so whether plaintext HTTP administration is enabled cannot be determined.',
      pass_when: 'no',
    },
    remediationGuidance:
      'Verify manually on the device: confirm the management web console is served over HTTPS only and plaintext HTTP administration is disabled.',
  },
  {
    checkId: 'sangfor-ntp-configured',
    name: 'NTP time synchronisation configured',
    description:
      'NOT EVALUABLE from the data this adapter collects — no NTP section is extracted from the ' +
      'Sangfor running-config (parser.js:527-567). Worth verifying by hand regardless: every ' +
      'syslog event SecVault ingests from this device is timestamped by the device.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'sangfor',
    severity: 'low',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'No NTP settings are extracted from this vendor\'s configuration snapshot.',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Verify manually on the device: confirm at least one reachable NTP server is configured and the clock is in sync.',
  },
  {
    checkId: 'sangfor-dns-configured',
    name: 'DNS resolver configured',
    description:
      'NOT EVALUABLE from the data this adapter collects — no DNS section is extracted from the ' +
      'Sangfor running-config (parser.js:527-567).',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'sangfor',
    severity: 'low',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason: 'No DNS settings are extracted from this vendor\'s configuration snapshot.',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Verify manually on the device: confirm a reachable DNS resolver is configured, since signature updates and FQDN-based policy objects depend on it.',
  },
  {
    checkId: 'sangfor-logging-enabled',
    name: 'Traffic logging enabled',
    description:
      'NOT EVALUABLE from the data this adapter collects — no logging section is extracted from ' +
      'the Sangfor running-config (parser.js:527-567). The RULE grain is covered for every vendor ' +
      'by the fleet-wide rule-logging-enabled-on-rules check, which reads collected firewall_rules ' +
      'rows rather than config_parsed, so this concept is partly measured for Sangfor — just not ' +
      'at the device-wide level.',
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS', 'SANS'],
    vendor: 'sangfor',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'No device-wide logging settings are extracted from this vendor\'s configuration snapshot; the per-rule question is answered instead by the fleet-wide "Logging enabled on rules" check.',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Verify manually on the device: confirm traffic and security logging is enabled and forwarded to a syslog destination, and review the per-rule findings of the fleet-wide "Logging enabled on rules" check for this device.',
  },
  {
    checkId: 'sangfor-password-min-length',
    name: 'Administrator password policy enforces a minimum length',
    description:
      'NOT EVALUABLE from the data this adapter collects. No administrator or password-policy ' +
      'section is extracted from the Sangfor running-config (parser.js:527-567), and the ' +
      'adapter\'s redaction pass deliberately blanks the remainder of any line carrying a ' +
      'password/secret keyword before the config is stored (parser.js redactConfig) — so even a ' +
      'policy line would not survive into config_parsed with a readable value.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'sangfor',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'No administrator or password-policy settings are extracted from this vendor\'s configuration snapshot.',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Verify manually on the device: confirm a minimum password length and complexity policy is enforced for administrator accounts, or that administrators authenticate against an external directory.',
  },
  {
    checkId: 'sangfor-session-timeout',
    name: 'Administrative session timeout configured',
    description:
      'NOT EVALUABLE from the data this adapter collects — no administrative session/idle-timeout ' +
      'setting is extracted from the Sangfor running-config (parser.js:527-567).',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'sangfor',
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'No administrative session-timeout setting is extracted from this vendor\'s configuration snapshot.',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Verify manually on the device: confirm an idle timeout is enforced for web-console and SSH administrative sessions.',
  },
  {
    checkId: 'sangfor-sslvpn-posture',
    name: 'SSL VPN posture reviewed',
    description:
      'NOT EVALUABLE, and this is the one Sangfor concept where SecVault does see SOMETHING — ' +
      'which is exactly why it needs stating rather than omitting. ' +
      'lib/adapters/sangfor/parser.js:549-560 sets a tri-state sections.ssl_vpn.enabled, and its ' +
      'own comment flags the detection regex as a best-effort guess never confirmed against any ' +
      'live Sangfor CLI output, with `null` ("could not determine") as the expected, common case. ' +
      'Two things stop it becoming a check. First, "SSL VPN is enabled" is not itself a ' +
      'compliance failure — remote access is a normal, often required function — so there is no ' +
      'honest polarity to grade it on; what matters is the authentication, encryption and access ' +
      'scope behind it, none of which is collected. Second, grading a device on an unverified ' +
      'single-line regex would put SecVault\'s confidence where it has none.',
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS'],
    vendor: 'sangfor',
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'SecVault detects only whether an SSL VPN line appears to be present, from an unverified pattern, and nothing about its authentication, encryption or access scope — and "SSL VPN is enabled" is not itself a pass or a fail.',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Verify manually on the device: if SSL VPN is in use, confirm multi-factor authentication is required, TLS 1.2 or later is enforced, an idle timeout is set, and the resources reachable through the tunnel are scoped to what each user group needs.',
  },

  // ── Forcepoint (10) ─────────────────────────────────────────────────────

  {
    checkId: 'forcepoint-admin-access-untrusted-zone',
    name: 'Admin access not permitted from untrusted/External zone',
    description:
      'Administrative access to the engine or its SMC should not be reachable from the External ' +
      '(untrusted) zone. Evaluated by deep-scanning the collected engine element and SMC ' +
      'administrator records for the zone name under any admin/management-named key.',
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS', 'NIST', 'SANS'],
    vendor: 'forcepoint',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'admin_access_from_zone',
      // Best-effort zone literal, and deliberately the SAME spelling as the
      // Check Point row above: 'External' is this repo's own zone
      // vocabulary (see rule-no-external-to-internal-access below), not a
      // value read off a live SMC — none has ever been connected (every
      // Forcepoint field mapping in lib/adapters/forcepoint/parser.js
      // carries that same standing caveat). Unlike a path-lookup predicate
      // this cannot misfire downward: applicability.js:229-233 returns
      // 'unknown' (-> warning) when the scan finds nothing, never 'no'.
      // Reachable in principle because config_parsed is root-anchored on the
      // full SMC engine element (forcepoint/parser.js:297-303) and also
      // carries smc_administrators (index.js:314), whose key name itself
      // satisfies the scan's admin/management key test.
      zone: 'External',
      pass_when: 'no',
    },
    remediationGuidance:
      'In the SMC, confirm no access rule or engine management setting permits ssh/https/API administration from the External zone, and that SMC administration itself is reachable only from a trusted management network.',
  },
  {
    checkId: 'forcepoint-ssh-mgmt-untrusted-iface',
    name: 'SSH management disabled on untrusted interfaces',
    description:
      'NOT EVALUABLE from the data this adapter collects. config_parsed is root-anchored on the ' +
      'SMC engine element (lib/adapters/forcepoint/parser.js:297-303), and the only fields this ' +
      'repository can name on that element are identity and version fields — software_version, ' +
      'version, attributes.version, engine_version, dynamic_package, model, type, name ' +
      '(parser.js:43-94) and internal_gateway (parser.js:619-628) — every one of them doc-derived ' +
      'from the smc-python client and explicitly unverified against live hardware ' +
      '(parser.js:56-60). No field reporting per-interface management services can be named, so a ' +
      'predicate here would be a guessed path returning a confident FAIL.',
    standards: ['CIS_V8', 'ISO_27001', 'SANS'],
    vendor: 'forcepoint',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'The SMC engine element SecVault collects is an identity and version record; no field reporting per-interface management services can be identified in it without a live SMC to confirm the schema against.',
      pass_when: 'no',
    },
    remediationGuidance:
      'Verify manually in the SMC: confirm engine SSH administration is permitted only from a trusted management network and disabled on External-facing interfaces.',
  },
  {
    checkId: 'forcepoint-https-only-not-http',
    name: 'Management web access over HTTPS only (no plaintext HTTP)',
    description:
      'NOT EVALUABLE from the data this adapter collects. Forcepoint engines are administered ' +
      'through the SMC rather than a per-engine web UI, and no field in the collected engine ' +
      'element can be named that reports a plaintext management listener ' +
      '(lib/adapters/forcepoint/parser.js:43-94, 297-303, 619-628).',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'forcepoint',
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'No field reporting a plaintext management listener can be identified in the SMC engine element SecVault collects.',
      pass_when: 'no',
    },
    remediationGuidance:
      'Verify manually: confirm the SMC is reached over TLS with a trusted certificate and that no plaintext management listener is enabled on the engines or the SMC.',
  },
  {
    checkId: 'forcepoint-ntp-configured',
    name: 'NTP time synchronisation configured',
    description:
      'NOT EVALUABLE from the data this adapter collects — no NTP/clock field can be named in the ' +
      'SMC engine element (lib/adapters/forcepoint/parser.js:43-94, 297-303). Worth verifying by ' +
      'hand: engine timestamps are what SecVault correlates log evidence against.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'forcepoint',
    severity: 'low',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'No NTP/clock field can be identified in the SMC engine element SecVault collects.',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Verify manually in the SMC: confirm the engine and the SMC itself synchronise to a reachable NTP source and their clocks agree.',
  },
  {
    checkId: 'forcepoint-dns-configured',
    name: 'DNS resolver configured',
    description:
      'NOT EVALUABLE from the data this adapter collects — no DNS field can be named in the SMC ' +
      'engine element (lib/adapters/forcepoint/parser.js:43-94, 297-303).',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'forcepoint',
    severity: 'low',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason: 'No DNS field can be identified in the SMC engine element SecVault collects.',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Verify manually in the SMC: confirm a reachable DNS resolver is configured for the engine, since dynamic update retrieval and FQDN-based elements depend on it.',
  },
  {
    checkId: 'forcepoint-logging-enabled',
    name: 'Traffic logging enabled',
    description:
      'NOT EVALUABLE from the data this adapter collects, for two reasons. Forcepoint logging is ' +
      'decided per rule by each rule\'s log level — lib/adapters/forcepoint/parser.js:277-280 ' +
      'reads rule.options.log_level when normalising a rule — which is a per-rule fact this ' +
      'predicate engine cannot express (it evaluates one fixed dot-path). And engine-level log ' +
      'server assignment is not among the engine-element fields this repository can name. The ' +
      'rule grain IS covered for every vendor by the fleet-wide rule-logging-enabled-on-rules ' +
      'check, which reads the collected firewall_rules rows.',
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS', 'SANS'],
    vendor: 'forcepoint',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'Forcepoint logging is a per-rule log level, which this predicate engine cannot query, and engine-level log server assignment is not among the fields collected. The per-rule question is answered instead by the fleet-wide "Logging enabled on rules" check.',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Review the per-rule findings of the fleet-wide "Logging enabled on rules" check for this device, and confirm in the SMC that the engine has a Log Server assigned and is delivering records to it.',
  },
  {
    checkId: 'forcepoint-password-min-length',
    name: 'Administrator password policy enforces a minimum length',
    description:
      'NOT EVALUABLE from the data this adapter collects. summarizeAdministrators() ' +
      '(lib/adapters/forcepoint/parser.js:655-664) keeps exactly three fields per SMC ' +
      'administrator — name, superuser, enabled — and no password-policy field; and by design ' +
      'the admin elements are passed through redactEngineElement() first ' +
      '(index.js:289-299, parser.js:380-414), so any password or secret-shaped field is already ' +
      '"<redacted>" before this function sees it.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'forcepoint',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'The SMC administrator records SecVault collects carry only a name, a superuser flag and an enabled flag — no password-policy fields — and secret-shaped fields are redacted before storage by design.',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Verify manually in the SMC: confirm a minimum password length and complexity policy is enforced for SMC administrators, or that they authenticate against an external directory (RADIUS/LDAP).',
  },
  {
    checkId: 'forcepoint-session-timeout',
    name: 'Administrative session timeout configured',
    description:
      'NOT EVALUABLE from the data this adapter collects — no SMC or engine administrative ' +
      'session/idle-timeout field can be named in the collected engine element or administrator ' +
      'records (lib/adapters/forcepoint/parser.js:43-94, 297-303, 655-664).',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'forcepoint',
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'No administrative session-timeout field can be identified in the SMC data SecVault collects.',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Verify manually in the SMC: confirm an idle timeout is enforced for SMC administrator sessions and for engine CLI access.',
  },
  {
    checkId: 'forcepoint-dynamic-update-package',
    name: 'Dynamic Update (signature) package installed',
    description:
      'NOT EVALUABLE as a safe pass/fail. `dynamic_package` is Forcepoint/Stonesoft terminology ' +
      'for the installed signature/Dynamic Update package version, and this repository does read ' +
      'it — lib/adapters/forcepoint/parser.js:49-67 lists it as a last-resort version candidate ' +
      'and warns in its own comment that mistaking it for the firmware version was a real bug. ' +
      'But that same comment states the SMC field names are unverified against live hardware and ' +
      'asks for them to be revisited once a real engine element is captured in the [SMC Debug] ' +
      'log. Because every path-lookup predicate maps an absent path to \'no\' ' +
      '(lib/engines/applicability.js:178-216), a check on this path would report "no signature ' +
      'package installed" on every engine whose SMC version simply names the field something ' +
      'else — a fabricated critical finding from a field-name mismatch. The honest encoding is ' +
      'this, until one live engine element confirms the name.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'forcepoint',
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'The field reporting the installed Dynamic Update package has not been confirmed against a live SMC, and this engine cannot distinguish "no package installed" from "the field is named differently on this SMC version".',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Verify manually in the SMC: confirm the engine holds a current Dynamic Update package and that automatic update downloads are working. This becomes gradeable as soon as one live engine element is captured in the SMC debug log and the field name is confirmed.',
  },
  {
    checkId: 'forcepoint-administrator-inventory',
    name: 'Administrator account inventory (informational)',
    description:
      'NOT EVALUABLE as a real pass/fail concept with current data — the same judgement as ' +
      'cisco-asa-local-admin-accounts-present and checkpoint-administrator-inventory. ' +
      'config_parsed.smc_administrators (lib/adapters/forcepoint/parser.js:655-664) gives name, ' +
      'superuser and enabled per account, which is worth reading, but "administrator accounts ' +
      'exist" is not a finding and "no account is an unnecessary superuser" is a per-account rule ' +
      'this one-fixed-path engine cannot express without pinning an arbitrary array index. Two ' +
      'further cautions recorded here so a future author does not have to rediscover them: the ' +
      'list is SMC-SERVER-WIDE rather than per-engine (parser.js:630-654 — SMC has no "which ' +
      'engine does this administrator belong to" concept to resolve against), so it would grade ' +
      'every engine on one shared fact; and it is `null` when the fetch fails ' +
      '(index.js:289-299), which config_key_exists reports as PRESENT.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'forcepoint',
    severity: 'low',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'The collected administrator inventory is per-account and SMC-server-wide rather than per-engine, so a per-account rule such as "no unnecessary superusers" cannot be expressed as a per-device check by this engine.',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Review the collected SMC administrator list: remove unused accounts, confirm each is individually attributable, grant superuser only where genuinely required, and prefer an external directory over internal SMC passwords.',
  },
];

/**
 * Idempotent upsert of the curated audit_checks library. Re-runnable: editing
 * this file and re-running lib/migrate.js updates existing rows in place
 * (ON CONFLICT ... DO UPDATE, not DO NOTHING).
 *
 * @param {import('pg').Pool} pool
 * @returns {Promise<{count: number}>}
 */
async function seedAuditChecks(pool) {
  for (const check of CHECKS) {
    await pool.query(
      `INSERT INTO audit_checks
         (check_id, name, description, standards, vendor, severity, predicate_config, remediation_guidance)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)
       ON CONFLICT (check_id) DO UPDATE SET
         name = EXCLUDED.name,
         description = EXCLUDED.description,
         standards = EXCLUDED.standards,
         vendor = EXCLUDED.vendor,
         severity = EXCLUDED.severity,
         predicate_config = EXCLUDED.predicate_config,
         remediation_guidance = EXCLUDED.remediation_guidance,
         updated_at = now()`,
      [
        check.checkId,
        check.name,
        check.description,
        check.standards,
        check.vendor || null,
        check.severity,
        JSON.stringify(check.predicateConfig),
        check.remediationGuidance,
      ]
    );
  }
  return { count: CHECKS.length };
}

module.exports = { seedAuditChecks, CHECKS };
