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
}

module.exports = { FirewallAdapter };
