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
const { parseApiCredential } = require('../credentials');
const api = require('./api');
const parser = require('./parser');

const PAGE_LIMIT = 500;
// Defensive cap on pagination loops — mirrors the defensive caps used in the
// Forcepoint adapter against misbehaving/huge management servers.
const MAX_PAGES = 100;

let loggedFirstGateway = false;
let loggedFirstRulebasePage = false;
let loggedFirstPolicyResolution = false;
let loggedFirstSimpleGateway = false;

class CheckpointAdapter extends FirewallAdapter {
  constructor({ device, pool }) {
    super({ device, pool });
  }

  // Builds the management server connection descriptor, decrypting the stored
  // credential via credStore. Always uses this.pool — never omit it
  // (CLAUDE.md Pool Warning).
  //
  // Credential plaintext is a JSON string: {"username":"...","password":"..."}
  // OR {"api_key":"..."}, or (legacy) a bare API-key string.
  //
  // Parsing is delegated to the shared lib/adapters/credentials.js helper so
  // Check Point behaves identically to the other API vendors. That helper
  // preserves the protection this adapter's hand-rolled parser was fixed to
  // provide: VALID JSON WITH UNRECOGNIZED KEYS THROWS. It must never degrade to
  // "treat the whole blob as an api_key", which would send the operator's
  // password to the management server in the api-key field. It also never echoes
  // the plaintext (nor JSON.parse's SyntaxError, whose message embeds its input)
  // into an error — adapter errors surface in engine.log AND in the
  // /api/devices/[id]/test response body.
  async _getConn() {
    const plaintext = await credStore.getCredential(this.device.id, 'rest_api', this.pool);
    if (!plaintext) {
      throw new Error(
        `No Check Point REST API credential found for device ${this.device.id} — save credentials before connecting.`
      );
    }

    const { apiKey, username, password } = parseApiCredential(plaintext, 'Check Point');
    const credentials = apiKey ? { apiKey } : { username, password };

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

  // Fetches the gateway's own element (show-simple-gateway / show-simple-cluster)
  // as a second source for the installed-policy field, which some management
  // versions omit from show-gateways-and-servers. Never throws — a failure here
  // just means this resolution route produced nothing.
  async _showGatewayElement(session, gateway) {
    const selector = gateway.uid
      ? { uid: gateway.uid }
      : gateway.name
      ? { name: gateway.name }
      : null;
    if (!selector) return null;

    // Cluster objects reject show-simple-gateway and vice versa; try the likely
    // one first based on the object's type, then the other. Both failing is
    // normal on older versions and is not an error.
    const type = typeof gateway.type === 'string' ? gateway.type.toLowerCase() : '';
    const commands = type.includes('cluster')
      ? ['show-simple-cluster', 'show-simple-gateway']
      : ['show-simple-gateway', 'show-simple-cluster'];

    for (const command of commands) {
      try {
        const result = await session.request(command, {
          ...selector,
          'details-level': 'full',
        });
        if (result && typeof result === 'object') {
          if (!loggedFirstSimpleGateway) {
            console.log(
              `[CheckPoint Debug] ${command} response (policy-resolution route 2):`,
              JSON.stringify(result, null, 2)
            );
            loggedFirstSimpleGateway = true;
          }
          return result;
        }
      } catch (err) {
        console.warn(
          `[CheckPoint] ${command} lookup failed (${err.message}) — trying remaining policy-resolution routes`
        );
      }
    }

    return null;
  }

  // Resolves WHICH policy package belongs to THIS device's gateway.
  //
  // ⛔ A Check Point management server manages many gateways, each able to run a
  // different policy package. show-packages returns them all, so a positional
  // pick (packages[0]) stores ANOTHER DEVICE'S RULES against this device — and
  // rule hygiene, shadow analysis and CVE applicability all then compound that
  // error downstream. This function therefore only ever returns a package it can
  // justify, and throws otherwise. Storing nothing is recoverable; storing the
  // wrong gateway's ruleset silently is not.
  //
  // Runs inside the caller's existing session — it must NOT open its own
  // (session lifecycle is owned by api.withSession).
  async _resolvePolicyPackage(session, packages, pkgResponse) {
    const objects = await this._fetchGatewaysAndServers(session);
    const gateway = parser.findGatewayByIdentity(objects, this.device);

    if (!loggedFirstPolicyResolution) {
      // CLAUDE.md "External API Integrations": every field path used below is
      // doc-derived and unverified. Dump the raw shapes once so the real ones can
      // be confirmed on first live connect. No credential/sid is present in these.
      loggedFirstPolicyResolution = true;
      console.log(
        '[CheckPoint Debug] Policy resolution — gateway matched by identity:',
        JSON.stringify(gateway, null, 2)
      );
      console.log(
        '[CheckPoint Debug] Policy resolution — show-packages raw response:',
        JSON.stringify(pkgResponse, null, 2)
      );
    }

    const deviceLabel = `"${this.device.name}" (mgmt_ip ${this.device.mgmt_ip || 'unset'})`;

    // Route 1: the installed-policy field on the gateway object itself.
    let policyName = gateway ? parser.extractInstalledPolicyName(gateway) : null;
    let source = policyName ? 'show-gateways-and-servers' : null;

    // Route 2: the gateway's own element, for versions that omit policy above.
    if (!policyName && gateway) {
      const element = await this._showGatewayElement(session, gateway);
      if (element) {
        policyName = parser.extractInstalledPolicyName(element);
        if (policyName) source = 'show-simple-gateway/cluster';
      }
    }

    if (policyName) {
      const match = parser.matchPackageByNameOrUid(packages, policyName);
      if (match) {
        console.log(
          `[CheckPoint] Device ${deviceLabel}: gateway "${gateway.name || gateway.uid}" reports ` +
            `installed policy "${policyName}" (via ${source}) — collecting that package's rulebase.`
        );
        return match;
      }
      // Name resolved but nothing on the server answers to it — most likely a
      // field-name mismatch (we read something that isn't the package name).
      // Treat as UNRESOLVED and fall through; never soften it into a guess.
      console.warn(
        `[CheckPoint] Device ${deviceLabel}: gateway reports installed policy "${policyName}" ` +
          `(via ${source}) but no policy package on the management server has that name or uid ` +
          `(packages: ${parser.describePackages(packages)}). Ignoring it and trying other routes.`
      );
    }

    // Route 3: installation-targets. Only conclusive when exactly one package
    // targets this gateway.
    if (gateway) {
      const targeted = parser.findPackagesTargetingGateway(packages, gateway);
      if (targeted.length === 1) {
        console.log(
          `[CheckPoint] Device ${deviceLabel}: exactly one policy package ` +
            `("${targeted[0].name || targeted[0].uid}") lists gateway ` +
            `"${gateway.name || gateway.uid}" in its installation-targets — collecting that package.`
        );
        return targeted[0];
      }
      if (targeted.length > 1) {
        console.warn(
          `[CheckPoint] Device ${deviceLabel}: ${targeted.length} policy packages list this gateway ` +
            'as an installation target — not conclusive, trying remaining routes.'
        );
      }
    }

    // Route 4: a single package on the whole server is unambiguous regardless of
    // whether we could identify the gateway — there is nothing else it could be.
    if (packages.length === 1) {
      console.warn(
        `[CheckPoint] Device ${deviceLabel}: could not resolve the policy package from the gateway ` +
          `object, but the management server has exactly ONE policy package ` +
          `("${packages[0].name || packages[0].uid}") — it is unambiguous, using it.`
      );
      return packages[0];
    }

    // Multiple packages and no evidence tying one to this device. Fail loudly.
    const reason = gateway
      ? `gateway "${gateway.name || gateway.uid}" was found, but no known field on it reports an ` +
        'installed access policy (tried policy.access-policy-name, installed-policy, policy) and ' +
        'installation-targets did not single out one package'
      : "no gateway object on the management server matched this device's name or mgmt_ip " +
        `(candidates: ${parser.describeGatewayCandidates(objects)})`;

    throw new Error(
      `Cannot determine which policy package is installed on the Check Point gateway for device ` +
        `${deviceLabel}: ${reason}. The management server has ${packages.length} policy packages: ` +
        `${parser.describePackages(packages)}. Refusing to guess — importing another gateway's ` +
        `ruleset would silently corrupt this device's rule analysis, shadow findings and CVE ` +
        `applicability. Fix: make the SecVault device name exactly match the gateway object name ` +
        `on the management server, or grant the API user permission to read the gateway's policy ` +
        `details, then re-run the collection.`
    );
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

      const pkg = await this._resolvePolicyPackage(session, packages, pkgResponse);

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
      if (!gateway) {
        // Same "nothing at all was found" case getVersion() already refuses to
        // proceed on (see the throw above in getVersion()) — a bare name/IP
        // mismatch with zero gateway-type objects on the server at all, not the
        // documented "first gateway" fallback (that path already returned a
        // gateway above and is untouched). Without this throw, getConfig() used
        // to persist { gateway: null, api_versions } as if the pull had
        // succeeded — a near-empty snapshot with no error surfaced anywhere,
        // and one that can also trigger spurious "config changed" diffs on
        // later pulls as candidate objects on the server vary run to run.
        const objects = await this._fetchGatewaysAndServers(session);
        throw new Error(
          `No gateway object found in show-gateways-and-servers for device "${this.device.name}" ` +
            `(mgmt_ip ${this.device.mgmt_ip || 'unset'}), and no gateway-type fallback is available ` +
            `(candidates on the management server: ${parser.describeGatewayCandidates(objects)}). ` +
            'Refusing to store a near-empty config snapshot as a successful collection — fix the ' +
            "SecVault device name or mgmt_ip to match a gateway object's name/ipv4-address on the " +
            'management server, then re-run the collection.'
        );
      }

      let apiVersions = null;
      try {
        apiVersions = await session.request('show-api-versions', {});
      } catch (err) {
        console.warn(`[CheckPoint] show-api-versions failed during getConfig: ${err.message}`);
      }

      const parsed = {
        gateway,
        api_versions: apiVersions,
      };

      return { raw: JSON.stringify(parsed, null, 2), parsed };
    });
  }
}

module.exports = { CheckpointAdapter };
