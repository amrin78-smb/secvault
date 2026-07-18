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
let loggedFirstObjectsPage = false;

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

  // Generic offset-pagination helper (total/to), shared by every "show-*"
  // list endpoint that follows this Check Point Mgmt API convention —
  // show-gateways-and-servers (below) and the object-catalog endpoints used
  // by getObjects() (show-hosts / show-networks / show-address-ranges /
  // show-groups / show-services-tcp / show-services-udp /
  // show-service-groups). Same bounded-pagination discipline as
  // _fetchAccessRulebasePages (page-count cap, stop on empty page or
  // to>=total).
  async _fetchAllPages(session, command, extraBody) {
    const objects = [];
    let offset = 0;

    for (let pageCount = 0; pageCount < MAX_PAGES; pageCount++) {
      const page = await session.request(command, {
        'details-level': 'full',
        limit: PAGE_LIMIT,
        offset,
        ...(extraBody || {}),
      });

      const pageObjects = (page && Array.isArray(page.objects) && page.objects) || [];
      objects.push(...pageObjects);

      const total = page && typeof page.total === 'number' ? page.total : null;
      const to = page && typeof page.to === 'number' ? page.to : null;
      if (pageObjects.length === 0 || total === null || to === null || to >= total) {
        return objects;
      }
      offset = to;

      // ⛔ BUG FIXED 2026-07-18, found in a bug-sweep pass: unlike its
      // sibling _fetchAccessRulebasePages(), this loop had no warning when
      // the MAX_PAGES cap was hit — a catalog exceeding PAGE_LIMIT *
      // MAX_PAGES objects (or a server-side pagination bug that never lets
      // to reach total) silently returned an incomplete object catalog with
      // zero log signal. Logged here, at the point the loop is ABOUT to
      // exceed the cap on its next iteration, so it only fires when pages
      // genuinely remain outstanding — never on a clean, fully-paginated
      // fetch that happens to finish near the cap.
      if (pageCount + 1 >= MAX_PAGES) {
        console.warn(
          `[CheckPoint] _fetchAllPages: hit MAX_PAGES (${MAX_PAGES}) for "${command}" with more objects outstanding (offset=${offset}, total=${total}) — catalog truncated.`
        );
      }
    }

    return objects;
  }

  // Follows show-gateways-and-servers offset pagination (total/to), returning
  // the accumulated objects array.
  async _fetchGatewaysAndServers(session) {
    return this._fetchAllPages(session, 'show-gateways-and-servers', {});
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

  // Finds the gateway for this device (see parser.findGatewayByIdentity for
  // matching rules) and logs the raw object once for field-name verification.
  // ⛔ Bug fixed 2026-07-19 (a confirmed-still-open item per CLAUDE.md's own
  // Known Limitations): this used to call parser.findGateway(), which falls
  // back to "the first gateway-type object" (with only a console.warn) when
  // no identity match is found — the exact same class of silent-wrong-data
  // bug already fixed for policy-package resolution
  // (parser.findGatewayByIdentity(), used by _resolvePolicyPackage()) but
  // never applied here. On a name/IP mismatch, getVersion()/getConfig()
  // could silently report ANOTHER gateway's version/config for this device.
  // Now uses the SAME strict identity matcher policy resolution already
  // uses — null means "no match", full stop, no fallback — and the two call
  // sites below throw with candidate names listed, matching
  // _resolvePolicyPackage()'s established error style.
  async _findGateway(session) {
    const objects = await this._fetchGatewaysAndServers(session);
    const gateway = parser.findGatewayByIdentity(objects, this.device);

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
        const objects = await this._fetchGatewaysAndServers(session);
        throw new Error(
          `No gateway object in show-gateways-and-servers matches device "${this.device.name}" by ` +
            `name or mgmt_ip (candidates on the management server: ${parser.describeGatewayCandidates(objects)}). ` +
            'Refusing to guess — reporting another gateway\'s version would silently misattribute ' +
            "it to this device. Fix: make the SecVault device name exactly match the gateway " +
            'object\'s name on the management server, then re-run the collection.'
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
        // Same "no identity match at all" case getVersion() already refuses to
        // proceed on (see the throw above in getVersion()) — _findGateway() no
        // longer has a "first gateway" fallback to fall back TO (that fallback
        // was itself the bug fixed 2026-07-19 — see _findGateway()'s own
        // comment). Without this throw, getConfig() used to persist
        // { gateway: null, api_versions } as if the pull had
        // succeeded — a near-empty snapshot with no error surfaced anywhere,
        // and one that can also trigger spurious "config changed" diffs on
        // later pulls as candidate objects on the server vary run to run.
        const objects = await this._fetchGatewaysAndServers(session);
        throw new Error(
          `No gateway object found in show-gateways-and-servers for device "${this.device.name}" ` +
            `(mgmt_ip ${this.device.mgmt_ip || 'unset'}) ` +
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

      // ⛔ Bug fixed 2026-07-19, found in a follow-up bug sweep: this used to
      // store `gateway`/`api_versions` completely unredacted — the ONLY
      // adapter of the six with no secret-redaction pass at all (every other
      // adapter, including API/JSON ones like Fortinet's REST transport and
      // Palo Alto's XML transport, redacts defensively even when it's
      // unverified whether the vendor API itself already blanks secrets —
      // "fail closed"). device_configs.config_raw/config_parsed are GRANT
      // SELECT'd to claude_readonly/nocvault_readonly, the same roles
      // CLAUDE.md bars from device_credentials. Not confirmed exploitable
      // (no live Check Point server has been examined for what these
      // responses actually carry), but the same defensive posture every
      // sibling adapter already applies.
      const parsed = {
        gateway: parser.redactSecrets(gateway),
        api_versions: parser.redactSecrets(apiVersions),
      };

      return { raw: JSON.stringify(parsed, null, 2), parsed };
    });
  }

  // → { addresses, addressGroups, services, serviceGroups }
  //
  // OPTIONAL capability (see lib/adapters/interface.js) feeding the
  // Unused/Duplicate Objects feature (lib/engines/objectUsage.js). Unlike
  // getRules()/getVersion()/getConfig(), Check Point's object catalog is
  // SERVER-WIDE, not gateway/policy-scoped (CLAUDE.md's Check Point rows) —
  // this simply enumerates whatever address/service objects and groups are
  // defined on the management server this device's mgmt_ip/credentials point
  // at, with no gateway-identity resolution needed.
  //
  // Each of the 4 sub-categories (and, within "addresses", each of the 3
  // source object types) is fetched+parsed inside its own try/catch,
  // degrading independently to [] on failure — per the interface contract,
  // this method must never throw whole on one sub-fetch's failure the way
  // getRules() does; a partial object catalog is still useful, and there is
  // no destructive DELETE-then-nothing risk here.
  async getObjects() {
    const conn = await this._getConn();
    return api.withSession(conn, async (session) => {
      const addresses = [];
      const addressGroups = [];
      const services = [];
      const serviceGroups = [];

      try {
        const hosts = await this._fetchAllPages(session, 'show-hosts', {});
        addresses.push(...parser.parseHostObjects(hosts));
      } catch (err) {
        console.warn(
          `[CheckPoint] getObjects: show-hosts failed (${err.message}) — host addresses omitted`
        );
      }

      try {
        const networks = await this._fetchAllPages(session, 'show-networks', {});
        addresses.push(...parser.parseNetworkObjects(networks));
      } catch (err) {
        console.warn(
          `[CheckPoint] getObjects: show-networks failed (${err.message}) — network addresses omitted`
        );
      }

      try {
        const ranges = await this._fetchAllPages(session, 'show-address-ranges', {});
        addresses.push(...parser.parseAddressRangeObjects(ranges));
      } catch (err) {
        console.warn(
          `[CheckPoint] getObjects: show-address-ranges failed (${err.message}) — address ranges omitted`
        );
      }

      try {
        // 'details-level': 'full' (already the default extraBody passed by
        // _fetchAllPages) is requested specifically so group members come
        // back as inline objects with a `name` field, avoiding a second
        // per-member lookup call — this is an UNVERIFIED ASSUMPTION (no live
        // Check Point management server exists in this deployment to confirm
        // it against; see CLAUDE.md's Live Validation Status section).
        // parser.extractMemberName() tolerates the other case (a bare uid
        // string) by falling back to the uid itself rather than dropping the
        // member, so a wrong assumption here degrades to uid-named members,
        // not missing ones.
        const groups = await this._fetchAllPages(session, 'show-groups', {});
        addressGroups.push(...parser.parseGroupObjects(groups));
      } catch (err) {
        console.warn(
          `[CheckPoint] getObjects: show-groups failed (${err.message}) — address groups omitted`
        );
      }

      try {
        const tcp = await this._fetchAllPages(session, 'show-services-tcp', {});
        services.push(...parser.parseTcpServiceObjects(tcp));
      } catch (err) {
        console.warn(
          `[CheckPoint] getObjects: show-services-tcp failed (${err.message}) — TCP services omitted`
        );
      }

      try {
        const udp = await this._fetchAllPages(session, 'show-services-udp', {});
        services.push(...parser.parseUdpServiceObjects(udp));
      } catch (err) {
        console.warn(
          `[CheckPoint] getObjects: show-services-udp failed (${err.message}) — UDP services omitted`
        );
      }

      try {
        const svcGroups = await this._fetchAllPages(session, 'show-service-groups', {});
        serviceGroups.push(...parser.parseGroupObjects(svcGroups));
      } catch (err) {
        console.warn(
          `[CheckPoint] getObjects: show-service-groups failed (${err.message}) — service groups omitted`
        );
      }

      if (!loggedFirstObjectsPage) {
        // Per CLAUDE.md "External API Integrations": log a raw-shape summary
        // on first connect so parser.js's field mappings can be verified.
        loggedFirstObjectsPage = true;
        console.log(
          '[CheckPoint Debug] getObjects collected counts:',
          JSON.stringify({
            addresses: addresses.length,
            addressGroups: addressGroups.length,
            services: services.length,
            serviceGroups: serviceGroups.length,
          })
        );
      }

      return { addresses, addressGroups, services, serviceGroups };
    });
  }
}

module.exports = { CheckpointAdapter };
