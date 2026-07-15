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
}

module.exports = { FirewallAdapter };
