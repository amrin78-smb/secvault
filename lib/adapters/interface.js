// Base interface — all vendor adapters implement these methods.
// A concrete adapter's constructor takes { device, pool } — the device row from
// the `devices` table, and the shared pg pool (needed for credStore decryption).
//
// NormalizedRule shape (returned by getRules()):
// {
//   rule_name, rule_id_vendor, sequence_number, enabled, action,
//   src_zones, dst_zones, src_addresses, dst_addresses, services,
//   applications, schedule, expiry_date, log_enabled, comment,
//   hit_count, raw_rule
// }
class FirewallAdapter {
  constructor({ device, pool }) {
    if (new.target === FirewallAdapter) {
      throw new Error('FirewallAdapter is abstract and cannot be instantiated directly');
    }
    this.device = device;
    this.pool = pool;
  }

  // → { ok: bool, latency_ms, message }
  async testConnectivity() {
    throw new Error('testConnectivity() not implemented');
  }

  // → { version_string, version_tuple, build, model }
  async getVersion() {
    throw new Error('getVersion() not implemented');
  }

  // → NormalizedRule[]
  async getRules() {
    throw new Error('getRules() not implemented');
  }

  // → { raw: string, parsed: object }
  async getConfig() {
    throw new Error('getConfig() not implemented');
  }

  // OPTIONAL — do not throw a default implementation; the base class simply
  // omits this method, and lib/adapters/index.js's collectAndStore() checks
  // `typeof adapter.getObjects === 'function'` before calling it. Most
  // vendors don't implement this yet — see CLAUDE.md's "Network Object
  // Catalog" section for per-vendor status.
  //
  // → { addresses: NamedAddress[], addressGroups: NamedGroup[], services: NamedService[], serviceGroups: NamedGroup[] }
  //   NamedAddress: { name: string, type?: string, value: string|null }  -- value: CIDR/range/fqdn, or null if unresolvable
  //   NamedService: { name: string, value: string|null }                -- value: e.g. "tcp/443", or null if unresolvable
  //   NamedGroup:   { name: string, members: string[] }                 -- members: names of other objects/groups (this codebase does not resolve nested groups further than storing the member NAME — analyzeObjectUsage() walks the nesting itself)
  //
  // Must degrade gracefully per sub-category (try/catch each of the 4 fetches
  // internally) rather than throwing whole on one sub-fetch's failure —
  // unlike getRules()/getConfig(), a PARTIAL object catalog (e.g. addresses
  // collected, service objects failed) is still useful data, not a
  // "silently wrong" risk the way an empty getRules() result would be (there
  // is no destructive DELETE-then-nothing consequence here the way there is
  // for firewall_rules — see CLAUDE.md's getRules() fail-loud rule, which
  // does NOT apply to this method).

  // OPTIONAL — SNMP monitoring (added 2026-07-21, see CLAUDE.md's "SNMP
  // Monitoring" section). Same optional-capability pattern as getObjects()/
  // getVpnSessionSummary(): the base class omits this method, and
  // services/engine-worker.js's snmp-poll job checks
  // `typeof adapter.getSnmpMetrics === 'function'` before calling it — most
  // vendors don't implement this yet.
  //
  // Uses a SEPARATE credential (device_credentials credential_type='snmp',
  // parsed by lib/adapters/snmpCredential.js's parseSnmpCredential) from the
  // adapter's own management-plane credential (SSH/REST/SMC) — SNMP is
  // read-only monitoring, never used for rule/config collection, so it is
  // never gated on or mixed with testConnectivity()/getRules()'s auth.
  // Target host/port: this.device.snmp_host (falls back to mgmt_ip for
  // every vendor EXCEPT Forcepoint, where snmp_host is REQUIRED — see
  // CLAUDE.md's Forcepoint SNMP exception) and this.device.snmp_port
  // (default 161).
  //
  // → {
  //     cpuPercent: number|null, memoryPercent: number|null,
  //     sessionCount: number|null, uptimeSeconds: number|null,
  //     raw: object,            // every OID's raw response, for debugging
  //     lowConfidence?: boolean, // true when OIDs are doc-derived/unverified
  //     targetHost: string,      // the host actually polled — surfaced in UI
  //   }
  //
  // MAY throw (missing credential, snmp_host unset for Forcepoint, timeout,
  // auth failure) — the engine-worker job's existing per-device try/catch
  // treats a getSnmpMetrics() failure exactly like any other polling
  // failure: logged and skipped, never fatal to the job or other devices.
  // MUST NOT guess a metric value when an OID genuinely didn't resolve —
  // return null for that field, per this codebase's "no confident-looking
  // wrong answer" discipline (see the applicability tri-state rule in
  // CLAUDE.md).

  // OPTIONAL — Device lifecycle & health (added 2026-08-03). Same
  // optional-capability pattern as everything else in this section: the base
  // class omits all three, and collectAndStore() checks
  // `typeof adapter.getLicenses === 'function'` (etc) before calling.
  // Implemented ONLY by paloalto (BOTH transports) as of this add — every
  // command was live-verified against the real fleet before its parser was
  // written. Fortinet is deliberately deferred: `get system status` exposes no
  // licence/support surface, and while `Mode: Standalone` is confirmed on all
  // five units there is no HA-ENABLED FortiGate anywhere to verify a peer
  // parser against (same discipline that deferred Fortinet API topology).
  //
  // → { licenses: LicenseEntry[] }
  //   LicenseEntry: { feature, description, serial, issuedAt, expiresAt,
  //                   expiresRaw, expired, authcode }
  //     issuedAt/expiresAt: 'YYYY-MM-DD' or null. ⛔ expiresAt null is
  //     AMBIGUOUS on its own and expiresRaw is what disambiguates it: raw
  //     'Never' = a genuinely perpetual licence; any other raw = the vendor
  //     string did not parse and the expiry is UNKNOWN. Never collapse those
  //     two into one state — see lib/engines/deviceHealth.js's licenseStatus().
  //     expired: the DEVICE's own verdict (boolean), or null if unreported.
  //
  // → HaStatus | null
  //   HaStatus: { enabled, mode, groupId, localState, peerState, peerMgmtIp,
  //               peerSerial, peerConnectionStatus, configSyncState,
  //               lastNonfunctionalReason, versionCompatOk, versionCompat, raw }
  //     { enabled: false } is a POSITIVE, storable fact ("this device is
  //     standalone"). Returning null means "could not determine" — the caller
  //     stores nothing and leaves the previous row intact, so standalone and
  //     never-collected stay distinguishable.
  //     versionCompatOk is TRI-STATE: true = all components reported Match,
  //     false = at least one Mismatch, null = the device reported no
  //     compatibility block at all. Never default null to true.
  //     lastNonfunctionalReason carries only genuine fault reasons (e.g.
  //     'Link down'); a deliberate 'User requested' suspension is kept out of
  //     it and preserved in raw instead, so it can't read as a fault.
  //
  // → { filesystems: FilesystemEntry[] }
  //   FilesystemEntry: { filesystem, mountedOn, sizeRaw, usedRaw, availRaw, usePercent }
  //     Sizes stay as the device's own human-readable strings ('21G'); only
  //     usePercent is numeric. This replaces SNMP as the disk source for
  //     vendors implementing it — no lowConfidence caveat, it comes from the
  //     same management API/CLI as everything else.
  //
  // Content/signature versions are NOT a method here: they ride along on
  // getVersion()'s already-fetched system info as `contentVersions`
  // ({ component, version, releasedAt }[]), issuing no extra device command.

  // OPTIONAL — Topology collection (added 2026-08-02, for
  // lib/engines/topology.js's multi-hop cross-device path simulation, see
  // CLAUDE.md's Topology section). Same optional-capability pattern as
  // getObjects()/getSnmpMetrics(): base class omits all three methods below,
  // lib/adapters/index.js's collectAndStore() checks
  // `typeof adapter.getInterfaces === 'function'` (etc) before calling.
  // Phase 1 (2026-08-02): implemented ONLY by paloalto/fortinet — the two
  // vendors with a live device in this deployment to verify real command
  // output against, per CLAUDE.md's "verify against live responses before
  // writing any parser" rule. A device whose adapter lacks these methods
  // simply has zero device_interfaces/device_routes/nat_rules rows — the
  // multi-hop engine treats that identically to "device exists but we don't
  // know its interfaces," never a fatal error, same as every other optional
  // capability's absence.
  //
  // → { interfaces: NamedInterface[] }
  //   NamedInterface: { name: string, ipAddress: string|null, zone: string|null, vdom: string|null, enabled: boolean }
  //     ipAddress: CIDR string ("10.1.1.1/24") -- the interface's OWN address+mask, not a route.

  // → { routes: RouteEntry[] }
  //   RouteEntry: { destinationCidr: string, nextHopIp: string|null, interfaceName: string|null, protocol: string|null, metric: number|null, vdom: string|null }
  //     nextHopIp: null means directly-connected/local (no next hop -- the destination IS this device's own subnet).

  // → { rules: NatRuleEntry[] }
  //   NatRuleEntry: {
  //     sequenceNumber: number|null, enabled: boolean, natType: 'source'|'destination'|'static',
  //     originalSrcAddresses: string[]|null, originalDstAddresses: string[]|null, originalServices: string[]|null,
  //     translatedSrcAddresses: string[]|null, translatedDstAddresses: string[]|null, translatedServices: string[]|null,
  //   }
  //   original_*/translated_* arrays use the EXACT SAME shape as NormalizedRule's
  //   src_addresses/dst_addresses/services above (literal IPs or object names) --
  //   deliberate, so lib/engines/objectResolver.js's resolveAddressField()/
  //   matchesAddress() work UNCHANGED against nat_rules rows, zero new
  //   address-matching logic for NAT. translatedSrcAddresses/translatedDstAddresses
  //   are expected to resolve to a single concrete literal IP (NAT translates to
  //   ONE address per session) -- lib/engines/topology.js's applyNat() only acts
  //   on a literal it can parse, never guesses from an object reference.
  //
  // All three MAY throw (same treatment as getSnmpMetrics()) -- collectAndStore()
  // catches per-method, logs, and leaves that table's rows for the device
  // untouched rather than wiping them on a transient failure (unlike getRules()'s
  // fail-loud DELETE+reinsert contract -- topology data has no destructive-empty
  // risk the way a wiped ruleset does).
}

module.exports = { FirewallAdapter };
