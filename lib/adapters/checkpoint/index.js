// lib/adapters/checkpoint/index.js
// CommonJS ONLY — required (eventually) by services/engine-worker.js (plain
// node, CommonJS).
//
// Check Point adapter. Talks to the Check Point MANAGEMENT SERVER's Web API
// (the device row's mgmt_ip points at the management server, not the gateway —
// the gateway itself is located by matching device name/IP inside
// show-gateways-and-servers).
//
// See CLAUDE.md — in particular the Pool Warning: testConnectivity() and any
// function touching credStore/DB must always receive and use `this.pool`, even
// though it looks like a pure connectivity check. Removing pool builds clean
// and silently breaks credential decryption at runtime.

const { FirewallAdapter } = require('../interface');
const credStore = require('../../credStore');
const api = require('./api');
const parser = require('./parser');

const PAGE_LIMIT = 500;
// Defensive cap on pagination loops — mirrors the defensive caps used in the
// Forcepoint adapter against misbehaving/huge management servers.
const MAX_PAGES = 100;

let loggedFirstGateway = false;
let loggedFirstRulebasePage = false;

class CheckpointAdapter extends FirewallAdapter {
  constructor({ device, pool }) {
    super({ device, pool });
  }

  // Builds the management server connection descriptor, decrypting the stored
  // credential via credStore. Always uses this.pool — never omit it
  // (CLAUDE.md Pool Warning).
  //
  // Credential plaintext is a JSON string: {"username":"...","password":"..."}
  // OR {"api_key":"..."}. Parsed defensively — if it isn't valid JSON, the
  // whole string is treated as an api_key.
  async _getConn() {
    const plaintext = await credStore.getCredential(this.device.id, 'rest_api', this.pool);
    if (!plaintext) {
      throw new Error(
        `No Check Point REST API credential found for device ${this.device.id} — save credentials before connecting.`
      );
    }

    let credentials;
    try {
      const parsed = JSON.parse(plaintext);
      if (parsed && typeof parsed === 'object') {
        if (parsed.api_key) {
          credentials = { apiKey: String(parsed.api_key) };
        } else if (parsed.username) {
          credentials = {
            username: String(parsed.username),
            password:
              parsed.password === undefined || parsed.password === null
                ? ''
                : String(parsed.password),
          };
        } else {
          // Valid JSON object, but neither "api_key" nor "username". Do NOT
          // fall back to treating the raw string as an api_key here: the string
          // is a JSON blob that almost certainly contains the operator's
          // password under a misspelled key, and it would then be sent to the
          // management server in the api-key field. Fail with an actionable
          // error instead. Only the KEY NAMES are echoed — never any value.
          throw new Error(
            'Check Point credential JSON has no recognizable fields — expected ' +
              '{"username","password"} or {"api_key"}. Found keys: ' +
              JSON.stringify(Object.keys(parsed))
          );
        }
      } else {
        // Valid JSON but not an object (a bare number/string/array) — treat it
        // as a raw api_key string, which is a shape operators do paste.
        credentials = { apiKey: plaintext };
      }
    } catch (err) {
      // Re-throw our own actionable error; only a genuine JSON.parse failure
      // falls through to the raw-api_key interpretation.
      if (err instanceof SyntaxError === false) throw err;
      // Not JSON at all → a bare API key string. This is a legitimate shape, so
      // it is accepted; if it is actually a password the management server will
      // reject it with a normal authentication error.
      // NOTE: the SyntaxError is deliberately swallowed, never logged — its
      // message embeds a snippet of the input, which is the decrypted secret.
      credentials = { apiKey: plaintext };
    }

    return {
      host: this.device.mgmt_ip,
      port: this.device.mgmt_port || 443,
      credentials,
      allowSelfSignedSsl: this.device.allow_self_signed_ssl !== false,
    };
  }

  // Follows show-gateways-and-servers offset pagination (total/to), returning
  // the accumulated objects array.
  async _fetchGatewaysAndServers(session) {
    const objects = [];
    let offset = 0;

    for (let pageCount = 0; pageCount < MAX_PAGES; pageCount++) {
      const page = await session.request('show-gateways-and-servers', {
        'details-level': 'full',
        limit: PAGE_LIMIT,
        offset,
      });

      const pageObjects = (page && Array.isArray(page.objects) && page.objects) || [];
      objects.push(...pageObjects);

      const total = page && typeof page.total === 'number' ? page.total : null;
      const to = page && typeof page.to === 'number' ? page.to : null;
      if (pageObjects.length === 0 || total === null || to === null || to >= total) {
        break;
      }
      offset = to;
    }

    return objects;
  }

  // Follows show-access-rulebase offset pagination (total/to). Requests
  // 'show-hits': true for hit counts; if that fails (older management
  // versions), retries without it and continues.
  async _fetchAccessRulebasePages(session, layerUid) {
    const pages = [];
    let offset = 0;
    let includeHits = true;
    let fetches = 0;

    while (fetches < MAX_PAGES) {
      fetches++;

      const body = {
        uid: layerUid,
        'details-level': 'standard',
        'use-object-dictionary': true,
        limit: PAGE_LIMIT,
        offset,
      };
      if (includeHits) {
        body['show-hits'] = true;
      }

      let page;
      try {
        page = await session.request('show-access-rulebase', body);
      } catch (err) {
        if (includeHits) {
          console.warn(
            `[CheckPoint] show-access-rulebase with show-hits failed (${err.message}) — retrying without hit counts`
          );
          includeHits = false;
          continue;
        }
        throw err;
      }

      if (!loggedFirstRulebasePage) {
        // Per CLAUDE.md "External API Integrations": log raw responses on
        // first-connect paths so parser.js field mappings can be verified
        // against the live system.
        console.log(
          '[CheckPoint Debug] show-access-rulebase first page:',
          JSON.stringify(page, null, 2)
        );
        loggedFirstRulebasePage = true;
      }

      pages.push(page);

      const total = page && typeof page.total === 'number' ? page.total : null;
      const to = page && typeof page.to === 'number' ? page.to : null;
      if (total === null || to === null || to >= total) {
        break;
      }
      offset = to;
    }

    if (fetches >= MAX_PAGES) {
      console.warn(
        `[CheckPoint] show-access-rulebase pagination stopped at the ${MAX_PAGES}-page cap — ruleset may be truncated`
      );
    }

    return pages;
  }

  // Finds the gateway for this device (see parser.findGateway for matching
  // rules) and logs the raw object once for field-name verification.
  async _findGateway(session) {
    const objects = await this._fetchGatewaysAndServers(session);
    const gateway = parser.findGateway(objects, this.device);

    if (gateway && !loggedFirstGateway) {
      console.log('[CheckPoint Debug] Gateway object:', JSON.stringify(gateway, null, 2));
      loggedFirstGateway = true;
    }

    return gateway;
  }

  // → { ok: bool, latency_ms, message } — must never throw.
  async testConnectivity() {
    const startedAt = Date.now();
    try {
      const conn = await this._getConn();
      await api.withSession(conn, async (session) => {
        try {
          await session.request('show-api-versions', {});
        } catch (err) {
          // Login itself succeeded — that already proves connectivity +
          // credentials. show-api-versions failing (permissions, old version)
          // is worth a warning but not a failed test.
          console.warn(
            `[CheckPoint] show-api-versions failed after successful login: ${err.message}`
          );
        }
      });
      return { ok: true, latency_ms: Date.now() - startedAt, message: 'Connected' };
    } catch (err) {
      return { ok: false, latency_ms: null, message: err.message };
    }
  }

  // → { version_string, version_tuple, build, model }
  async getVersion() {
    const conn = await this._getConn();
    return api.withSession(conn, async (session) => {
      const gateway = await this._findGateway(session);
      if (!gateway) {
        throw new Error(
          'No gateway object found in show-gateways-and-servers for this device (and no gateway-type fallback available)'
        );
      }
      return parser.parseGatewayVersion(gateway);
    });
  }

  // → NormalizedRule[]
  async getRules() {
    const conn = await this._getConn();
    return api.withSession(conn, async (session) => {
      const pkgResponse = await session.request('show-packages', { 'details-level': 'full' });
      const packages =
        (pkgResponse && Array.isArray(pkgResponse.packages) && pkgResponse.packages) || [];
      if (packages.length === 0) {
        throw new Error('No policy packages found on the Check Point management server');
      }
      if (packages.length > 1) {
        console.warn(
          `[CheckPoint] ${packages.length} policy packages found — using the first ("${
            packages[0].name || packages[0].uid
          }")`
        );
      }
      const pkg = packages[0];

      const layers = Array.isArray(pkg['access-layers']) ? pkg['access-layers'] : [];
      if (layers.length === 0) {
        throw new Error(
          `Policy package "${pkg.name || pkg.uid}" has no access layers — nothing to collect`
        );
      }
      if (layers.length > 1) {
        console.warn(
          `[CheckPoint] Package "${pkg.name || pkg.uid}" has ${layers.length} access layers — using the first ("${
            layers[0].name || layers[0].uid
          }")`
        );
      }

      const layer = layers[0];
      const layerUid = layer && typeof layer === 'object' ? layer.uid : layer;
      if (!layerUid) {
        throw new Error(
          `First access layer of package "${pkg.name || pkg.uid}" has no uid — cannot query rulebase`
        );
      }

      const pages = await this._fetchAccessRulebasePages(session, layerUid);
      return parser.parseRulebasePages(pages);
    });
  }

  // → { raw: string, parsed: object }
  // parsed = { gateway, api_versions } — feeds the Phase 6 dot-path predicate
  // engine, which walks parsed config by dot-path.
  async getConfig() {
    const conn = await this._getConn();
    return api.withSession(conn, async (session) => {
      const gateway = await this._findGateway(session);

      let apiVersions = null;
      try {
        apiVersions = await session.request('show-api-versions', {});
      } catch (err) {
        console.warn(`[CheckPoint] show-api-versions failed during getConfig: ${err.message}`);
      }

      const parsed = {
        gateway: gateway || null,
        api_versions: apiVersions,
      };

      return { raw: JSON.stringify(parsed, null, 2), parsed };
    });
  }
}

module.exports = { CheckpointAdapter };
