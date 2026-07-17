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
//   Fortinet: lib/adapters/fortinet/index.js's getConfig() collects ONLY 5
//   named sections — {global, interfaces, ssl_vpn, snmp, admins} — built by
//   lib/adapters/fortinet/cliParser.js's parseFullConfiguration() (SSH) and
//   the matching cmdb-endpoint set in fortinet/index.js (REST API). Whole
//   swaths of real FortiOS config — `config system ntp`, `config system
//   dns`, `config log syslogd setting`, `config system password-policy`,
//   `config system fortiguard` / `config system autoupdate` — are NEVER
//   extracted into config_parsed by either transport, even though they exist
//   in the raw device. Checks that need one of those sections are seeded
//   with predicate_type 'not_evaluable_from_config' (see below) rather than
//   a path that would silently and wrongly resolve to a hard FAIL.
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
// ── predicate_type: 'not_evaluable_from_config' — a deliberate, non-hacky use
//    of evaluatePredicate()'s own documented default case ───────────────────
//
// evaluatePredicate()'s switch has a `default: return 'unknown';` for any
// predicate_type it doesn't recognize — this is EXISTING, documented
// behaviour ("never throws... unknown predicate type... returns 'unknown'"),
// not something this file adds to applicability.js. Some concepts in the
// spec below genuinely cannot be answered from device_configs.config_parsed
// at all, for two different reasons:
//   (a) the config section needed was never collected by the adapter
//       (Fortinet's ntp/dns/logging/password-policy/fortiguard gaps above), or
//   (b) the fact is inherently per-rule (e.g. "IPS profile on internet-facing
//       policies") and the predicate engine only supports ONE fixed
//       dot-path per check, not "for every rule in the ruleset" — a
//       fundamentally different query shape belonging to a future
//       ruleAnalysis.js-style finding type, not this predicate engine.
// For both cases, resolving the check to config_key_exists on some
// currently-absent path would return 'no' (a confident FAIL) — which
// misrepresents "we cannot tell" as "the device is non-compliant". Naming
// the predicate_type 'not_evaluable_from_config' intentionally lands on
// evaluatePredicate()'s default case, producing 'unknown' -> 'warning', the
// status this file's own four-state mapping reserves for exactly this
// situation ("something was collected, but this specific value couldn't be
// resolved"). `reason` is not read by the evaluator; it documents to a human
// (or a future adapter change) why this check cannot pass or fail today.
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
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS', 'NIST'],
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
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS', 'NIST'],
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
    standards: ['CIS_V8', 'ISO_27001'],
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
    standards: ['CIS_V8', 'ISO_27001'],
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
      'NOT EVALUABLE with current data: config system ntp is not one of the 5 sections ' +
      '(global, interfaces, ssl_vpn, snmp, admins) lib/adapters/fortinet/index.js\'s ' +
      'getConfig() collects (SSH or REST). This check will read "warning" for every ' +
      'Fortinet device until the adapter is extended to fetch it.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'fortinet',
    severity: 'low',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason:
        'config system ntp is not collected by lib/adapters/fortinet/index.js getConfig() (SSH: ' +
        'cliParser.parseFullConfiguration; REST: the same 5-section list) — adapter enhancement needed.',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Verify NTP is configured manually via the CLI ("show system ntp") until this adapter collects it automatically; accurate time is required for reliable log correlation.',
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
      'NOT EVALUABLE with current data: config system dns is not one of the 5 sections this ' +
      'adapter collects. See the fortinet-ntp-configured check for the identical gap.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'fortinet',
    severity: 'low',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason: 'config system dns is not collected by lib/adapters/fortinet/index.js getConfig().',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Verify DNS servers are configured manually ("show system dns") until this adapter collects it automatically.',
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
      'NOT EVALUABLE with current data: config log syslogd setting is not one of the 5 sections ' +
      'this adapter collects. Given this concept\'s severity, extending the adapter to collect it ' +
      'is a good follow-up — flagged here rather than silently guessed at.',
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS'],
    vendor: 'fortinet',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason: 'config log syslogd setting is not collected by lib/adapters/fortinet/index.js getConfig().',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Verify remote syslog is configured manually ("show log syslogd setting") until this adapter collects it automatically; centralized logging is required for incident response and several of the standards this check maps to.',
  },
  {
    checkId: 'paloalto-logging-enabled',
    name: 'Logging enabled / syslog configured',
    description: 'A syslog server profile should be configured so security events are forwarded off-box.',
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS'],
    vendor: 'paloalto',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'config_key_exists',
      // Best-effort: standard PAN-OS schema location for syslog server
      // profile objects. Not independently live-verified.
      path: 'shared.server-profile.syslog',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Configure a syslog server profile under Device > Server Profiles > Syslog and attach it via a log forwarding profile.',
  },

  {
    checkId: 'fortinet-password-min-length',
    name: 'Password policy: minimum length configured',
    description:
      'NOT EVALUABLE with current data: config system password-policy is not one of the 5 ' +
      'sections this adapter collects.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'fortinet',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason: 'config system password-policy is not collected by lib/adapters/fortinet/index.js getConfig().',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Verify a minimum password length is enforced manually ("show system password-policy") until this adapter collects it automatically.',
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
  // Fortinet-specific (6)
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
    checkId: 'fortinet-fortiguard-updates-enabled',
    name: 'FortiGuard updates enabled',
    description:
      'NOT EVALUABLE with current data: config system fortiguard / config system autoupdate ' +
      'schedule are not collected by this adapter.',
    standards: ['CIS_V8', 'ISO_27001'],
    vendor: 'fortinet',
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason: 'config system fortiguard / autoupdate schedule are not collected by lib/adapters/fortinet/index.js getConfig().',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Verify FortiGuard signature/engine auto-updates are enabled manually ("show system autoupdate schedule") until this adapter collects it automatically.',
  },
  {
    checkId: 'fortinet-ips-internet-facing-policies',
    name: 'IPS profile applied to internet-facing policies',
    description:
      'NOT EVALUABLE via this predicate engine: IPS-sensor assignment is a per-policy field ' +
      '(firewall_rules.raw_rule, not device_configs.config_parsed) — the applicability engine only ' +
      'supports one fixed dot-path per check, not "for every internet-facing rule". A future ' +
      'ruleAnalysis.js-style finding type is the right home for this, not audit_checks.',
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS'],
    vendor: 'fortinet',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason: 'IPS-sensor assignment is per-policy (firewall_rules.raw_rule), outside device_configs.config_parsed.',
      pass_when: 'yes',
    },
    remediationGuidance:
      'Manually verify an IPS sensor is attached to every policy whose destination interface is internet-facing.',
  },
  {
    checkId: 'fortinet-default-admin-active',
    name: "No default 'admin' username still active",
    description: "The factory-default 'admin' account should be renamed or disabled.",
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS'],
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
      'NOT EVALUABLE via this predicate engine: profile-setting assignment lives per-rule inside ' +
      'rulebase.security.rules.<rule-name>.profile-setting (CLAUDE.md confirms a real captured rule ' +
      'with a nested profile-setting sub-block) — but there is no fixed dot-path that means "every ' +
      'internet-facing rule"; that is a for-each-rule query, the same shape gap as the Fortinet IPS ' +
      'check above.',
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS'],
    vendor: 'paloalto',
    severity: 'high',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason: 'Security-profile assignment is per-rule (rulebase.security.rules.<name>.profile-setting); no fixed path covers "every rule".',
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
      'NOT EVALUABLE via this predicate engine: log-setting assignment is per-rule, the same ' +
      'for-each-rule shape gap as the two checks above.',
    standards: ['CIS_V8', 'ISO_27001', 'PCI_DSS'],
    vendor: 'paloalto',
    severity: 'medium',
    predicateConfig: {
      predicate_type: 'not_evaluable_from_config',
      reason: 'Log-forwarding-profile assignment is per-rule (rulebase.security.rules.<name>.log-setting); no fixed path covers "every rule".',
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
