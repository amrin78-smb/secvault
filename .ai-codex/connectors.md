# SecVault Vendor Connector Reference

**Read this before touching ANY file under `lib/adapters/`.** Dense, code-verified reference for
all 6 Tier-1 firewall integrations — not prose documentation. Every claim below was checked against
the current code on 2026-07-23, not copied from CLAUDE.md's historical narrative (CLAUDE.md documents
a long bug-fix history and can be stale — this file is the current-state cross-check).

## Shared architecture (read once, applies to every vendor)

- **Contract**: `lib/adapters/interface.js` — `FirewallAdapter` base class. Required:
  `testConnectivity()`, `getVersion()`, `getRules()`, `getConfig()`. Optional (base class simply
  omits them; callers check `typeof adapter.X === 'function'`): `getObjects()`,
  `getSnmpMetrics()`, `getVpnSessionSummary()`.
- **Dispatch**: `lib/adapters/index.js` — `ADAPTERS[vendor][mgmt_method] → AdapterClass`,
  `DEFAULT_METHOD[vendor]` fallback when `devices.mgmt_method` is null/unrecognized
  (`getAdapter()`). CommonJS only — required by `services/engine-worker.js` under plain node.
- **Persistence pipeline**: `lib/adapters/index.js:collectAndStore(device, pool)` — the ONLY place
  `device_versions`/`firewall_rules`/`device_configs` are written. Order: `getVersion()` (isolated
  try/catch) → `getRules()` inside a `BEGIN`/`DELETE firewall_rules`/`INSERT`/`COMMIT` transaction
  (rollback on any insert failure, so a partial ruleset never lands) → Phase 5 rule analysis (only if
  rules collection succeeded) → `getConfig()` → Phase 6 diff/backup + Phase 7 compliance audit (only
  if config collection succeeded) → `getObjects()` if implemented (runs LAST, after config, so it can
  read back `device_configs` via `getLatestConfigParsed()` instead of a second live call) → object
  usage analysis (only if object collection succeeded).
- **⛔ THE CENTRAL RULE, every vendor**: `getRules()` must **THROW** on a genuine retrieval
  failure, **NEVER return `[]`**. `collectAndStore()` DELETEs a device's `firewall_rules` before
  reinserting — an empty array from a *failed* pull silently wipes the real ruleset and cascades
  away its Phase 5 findings while reporting success. `[]` is reserved exclusively for "a real config
  was retrieved and it genuinely contains zero rules." This exact bug has been found and fixed at
  least once in nearly every adapter (Sangfor, Fortinet both transports, Forcepoint, Palo Alto SSH) —
  never reintroduce it.
- **Shared credential helpers**:
  - `lib/adapters/credentials.js:parseApiCredential(plaintext, label)` — REST/API vendors
    (`credential_type='rest_api'`). Accepts `{"api_key":"..."}`, `{"username","password"}`, or a
    bare non-JSON string (legacy raw token). Every error is secret-free — never echoes the
    plaintext, and never re-throws `JSON.parse`'s own `SyntaxError` (which embeds input).
  - `lib/adapters/sshClient.js:runCommands()` / `parseJsonCredential()` — SSH vendors
    (`credential_type='ssh'`, JSON `{"username","password","enable_password"?}`). Shell-channel
    (not exec) expect-loop; `DEFAULT_PROMPT_REGEX = /[>#$%]\s*$/` has **no `m` flag** deliberately
    — with `m`, any line of output ending in a prompt-like char (e.g. Cisco's `banner motd ####`
    delimiter) would falsely match mid-buffer and silently truncate a multi-MB config read.
    `enablePassword` is checked for embedded `\r`/`\n` before being written to the shell — refuses
    rather than risking command injection into a privileged root shell.
  - `lib/adapters/snmpCredential.js:parseSnmpCredential()` — `credential_type='snmp'`, always a
    SEPARATE credential from the management-plane one, never gated on/mixed with it. v1/v2c
    (`{"version","community"}`) or v3 (`{"version":"v3","username","authProtocol","authPassword",
    "privProtocol","privPassword"}`, requires auth-before-priv).
- **`node-fetch@2` + Next.js webpack gotcha** (bit both Palo Alto's `api.js` and Check Point's
  `api.js`): `node-fetch`'s package.json declares both `"main"` (CJS) and `"module"` (ESM); Next.js's
  bundler resolves `"module"` even for a plain `require()`, so the raw import is the ESM namespace
  object, not the callable — must unwrap via `fetchModule.default || fetchModule`. Reproduces only
  inside the built Next.js runtime, not under plain `node script.js` — easy to "fix" once and have it
  silently regress in a copy-pasted new adapter.
- **Every adapter constructor takes `{ device, pool }`** — `this.pool` must be threaded into every
  function that touches `credStore` even when it looks like a pure connectivity check (removing it
  builds clean, breaks credential decryption silently at runtime — CLAUDE.md's "Pool Warning").

---

## Forcepoint (`forcepoint`)

**Files**: `lib/adapters/forcepoint/{index.js, smc.js, parser.js}`

**Auth / endpoint**: SMC-only, by design (never SSH to Forcepoint engines). Base URL
`https://<smc_host>:<smc_port||8082>` (`smc.js:smcRequest`). Auth header `SMC-API-KEY: <apiKey>`
(no session/cookie flow) — `credential_type='smc_api'`, plaintext is a **raw string**, not JSON
(unlike every other vendor's REST credential). Self-signed accepted by default
(`device.allow_self_signed_ssl !== false`).

**What is collected**: `testConnectivity`, `getVersion`, `getRules`, `getConfig`, `getObjects` all
implemented (`index.js`). `getVpnSessionSummary` **not implemented** (absent entirely).
`getSnmpMetrics` implemented but bypasses the SMC entirely (see quirk below).

**Parsing entry point**: rules → `parser.js:parsePolicy(policyElement, networkElements,
serviceElements)`, called from `index.js:getRules()`. Config `parsed` → `parser.js:parseConfig
(engineElement)`, called from `index.js:getConfig()` — this function does **not** redact itself,
caller must redact first (see below).

**Known quirks**:
1. **HATEOAS href-following is load-bearing, not stylistic.** `smc.js:getElement(conn, href)` and
   `fetchAllPages(conn, path, {cap})` (follows `page.paging.next`) are the only ways this adapter
   reaches a resource — never constructs a URL from an element ID. `getConfig()` re-fetches the full
   engine element via `smc.getElement(conn, engine.href)` even when a cached copy exists, "the href
   is always authoritative." Engine list capped at `MAX_ENGINES = 100`, one-shot warn on cap.
2. **Engine identity resolution is name-exact, throw-on-ambiguity.** `parser.js:findEngineByIdentity
   (engines, device)`, called via `index.js:_resolveEngine()`, matches `device.name` case-
   insensitively and EXACTLY against `engine.name` — no substring/fuzzy match, no IP fallback (SMC
   host addresses the SMC server, not the engine — name is the only identity signal available).
   Returns `null` on no match; `_resolveEngine()` then throws, naming candidates via
   `parser.js:describeEngineCandidates()`. This resolver is used by `getVersion`, `getRules`, AND
   `getConfig` — no positional `engines[0]` fallback survives anywhere in the current code.
3. **Policy resolution is also identity-based, never `policies[0]`.** `getRules()` reads the policy
   via the *matched engine's own* `fw_policy.href`/`policy.href` reference. No href on the engine →
   throw, explicitly refusing "to fall back to a positionally-picked policy from the server's full
   policy list." A no-href-arg `smc.js:getPolicy(conn)` form still exists (lists `/api/elements/
   fw_policy` positionally) but is **dead code from `index.js`'s perspective** — never called for
   engine-scoped rule collection; don't be misled into thinking it's the live path.
4. **`getRules()` throws on true failure, `[]` only for an honestly-empty policy.**
   `parser.js:parsePolicy()` checks field *presence* (`hasOwnProperty`) separately from resolved
   content for both known field names (`rules` / `fw_ipv4_access_rules`) — throws only when NEITHER
   field exists on the element at all; returns `[]` when a known field is present but empty.
5. **Redaction: `parser.js:redactEngineElement(value, depth)`**, keyword pattern
   `/secret|password|passwd|psk|private[-_]?key|community|credential|token|api[-_]?key|phash|
   pre[-_]?shared|keytab/i` (widened 2026-07-19 after `phash`/`pre-shared`/`keytab` were found
   missing in an audit — this is the SAME class of gap that caused a real production secret leak
   documented in CLAUDE.md's config-diff section). Called in `index.js:getConfig()` **before**
   `parser.parseConfig()` and before the object leaves the adapter — confirmed to run before
   persistence, not after.
6. **SNMP is the one deliberate, documented exception to "never touch anything but the SMC."**
   `getSnmpMetrics()` requires `device.snmp_host` explicitly — **throws if unset, no fallback to
   `smc_host` or `mgmt_ip`**. Does not call `_getConn()`/`smc.js`/`_resolveEngine()` at all; uses a
   completely separate `credential_type='snmp'`. Every other method still goes exclusively through
   the SMC. OIDs are from STONESOFT-FIREWALL-MIB (Forcepoint NGFW's legacy Stonesoft branding) —
   `lowConfidence: true` is hardcoded unconditionally for this vendor, unlike Cisco ASA/Fortinet.
7. **`{any: true}` ref resolution.** SMC's convention for an unrestricted src/dst/service is the
   object `{any: true}`, not a string — `parser.js:resolveRef()` special-cases this to the literal
   string `'any'`. Without this, `String({any:true})` → `"[object Object]"`, which
   `ruleAnalysis.js`'s `isAny()` never matches, silently defeating `any_any`/`overly_permissive`/
   `shadow`/`redundant`/`reorder_candidate` detection on a genuine Forcepoint allow-any rule. This
   was a real bug, fixed.
8. **Live Validation Status: NOTHING in this adapter has been confirmed against a real SMC.** Every
   field name (engine version field precedence, `rules` vs `fw_ipv4_access_rules`, network/service
   element sub-type shapes, SNMP OIDs) is doc-derived. `[SMC Debug]` one-shot logs exist on
   `getEngines()`/network/service element fetches specifically so the first live connection can
   correct `parser.js`.
9. `getObjects()` deliberately does NOT fail-loud like `getRules()` — each of network/service
   fetch+parse is independently try/caught, degrading to `[]` per sub-array (no destructive
   DELETE-then-nothing risk for the object catalog the way there is for `firewall_rules`).

---

## Fortinet (`fortinet`)

**Files**: `lib/adapters/fortinet/{index.js, api.js, ssh.js, cliParser.js, parser.js}` — two adapter
classes, `FortinetAdapter` (REST, `mgmt_method='api'`, default) and `FortinetSshAdapter`
(`mgmt_method='ssh'`).

**Auth / endpoint**:
- REST: `https://<mgmt_ip>:<mgmt_port||443>`, `credential_type='rest_api'` via `parseApiCredential`.
  Two live auth modes: **token** (`Authorization: Bearer <token>`, stateless) when the stored
  credential resolves to an API key; **session** (`POST /logincheck` with `secretkey=<password>`,
  cookie + `X-CSRFTOKEN` header on every non-GET) when it resolves to username+password. Session
  success is judged by presence of a real `ccsrftoken` cookie, NOT HTTP status (`/logincheck`
  returns 200 even on rejected login). Session always closed via `_withSession()`'s `finally` →
  `api.logoutSession()`, logout errors swallowed (never mask the real result).
- SSH: port `mgmt_port||22`, `credential_type='ssh'` via `parseJsonCredential`. No enable/privileged
  mode — FortiOS has none. Prompt regex narrowed to `/#\s*$/` (FortiOS never shows `>`/`$`/`%`).
  Pager disabled via `config system console` / `set output standard` / `end`.

**What is collected**: Both transports implement all 4 required methods plus `getObjects`,
`getSnmpMetrics`, AND `getVpnSessionSummary` (Fortinet is the only vendor with all 7 methods on
both transports).

**Parsing entry point**: REST rules → `parser.js:parsePolicies()`. SSH rules →
`cliParser.js:policiesFromConfigText()` converts CLI text into REST-cmdb-shaped objects, then feeds
the **same** `parser.parsePolicies()` — one shared normalizer for both transports. REST config
`parsed` → assembled inline in `index.js:getConfig()`, each section run through
`parser.redactSecretFields(parser.extractResults(...))`. SSH config `parsed` →
`cliParser.js:parseFullConfiguration(redactedText)` — this function explicitly REQUIRES
already-redacted input (documented in its own header).

**Known quirks**:
1. **VDOM scoping is explicit and required on both transports, exactly as CLAUDE.md claims —
   confirmed.** REST: `api.js:withVdom(path, vdom)` appends `?vdom=<name>`; every VDOM-sensitive
   cmdb/monitor call takes an explicit `vdom` param — omitting it returns only the admin token's
   default VDOM. SSH: rule/object/VPN-poll calls send literal `config vdom` / `edit <vdom>` /
   `<cmd>` / `end` batches.
2. **VDOM-enumeration-failure behavior is ASYMMETRIC between transports for `getRules()` — this is
   the one real nuance to know.** REST's `_discoverVdoms()` never throws on enumeration failure —
   it returns `null` ("assume single implicit VDOM"), and `getRules()` degrades to the
   single-implicit-VDOM request on that `null`. This is a deliberate, reasoned tradeoff (older
   firmware / VDOM-scoped tokens routinely can't enumerate VDOMs; REST has no independent signal
   that the box IS multi-VDOM), NOT a silent-partial-ruleset bug — CLAUDE.md explicitly flags this
   as "investigated, found NOT a bug." SSH is stricter because it has an independent positive
   signal: `get system status`'s `vdom_mode` field (`cliParser.isMultiVdom()`). If `vdom_mode`
   confirms multi-VDOM but the VDOM-listing command then fails, SSH's `_getRulesMultiVdom()`
   **throws explicitly** rather than falling back to a single-VDOM pull — "we KNOW multi-VDOM is
   enabled but cannot list the VDOMs... falling back here would reintroduce the exact bug this code
   exists to fix." Per-VDOM rule-fetch failure (enumeration succeeded, one VDOM's fetch fails) has
   **no try/catch on either transport** — throws whole, by design.
3. **`getRules()` never returns `[]` on failure on either transport** — REST's `_getRulesForVdom()`
   throws if the cmdb response has no `results` array (comment explicitly cites the old bug: "this
   returned `[]` — a false success... collectAndStore would DELETE every stored rule and report
   `rulesCount: 0`"). SSH's `cliParser.policiesFromConfigText()` returns `null` (not `[]`) when no
   policy block is found — `null` vs `[]` is load-bearing there too, and `ssh.js` converts `null`
   into a thrown Error.
4. **Hit counts: REAL on REST, UNMEASURED (NULL) on SSH.** REST fetches real per-policy hit counts via
   `GET /api/v2/monitor/firewall/policy`, fetched per-VDOM (policy IDs are only unique within a
   VDOM). SSH passes `[]` as stats — `diagnose firewall iprope show ...` (the CLI equivalent) is
   "an undocumented, firmware-specific debug format," deliberately not attempted. Every
   SSH-collected rule has `hit_count: null` (UNMEASURED). Until 2026-08-25 it was `0`, which Phase 5
   read as `unused`, so an SSH-collected FortiGate flagged EVERY rule unused; `ruleAnalysis.js` now
   requires a measured zero. Use REST if you need real unused-rule findings for this device.
5. **Redaction**: `cliParser.js:redactConfig(text)` — stateful line-scanner tracking `config`/`end`
   block-path context (for context-sensitive secrets, e.g. SNMP community only under `config system
   snmp community`) plus multi-line quoted-value (PEM key) handling; fails closed on parse error
   (redacts the whole line). Used by BOTH the SSH text redaction AND the REST raw-config-backup text
   redaction (`index.js:getConfig()` calls the same function on the `/monitor/system/config/backup`
   text). REST's structured `parsed` JSON gets a SECOND, independent pass:
   `parser.js:redactSecretFields()` (key-name-based, depth-capped 12, fails closed). SSH's `parsed`
   inherits redaction from the text pass alone (single-layered) since
   `parseFullConfiguration()` is only ever called on already-redacted text. Both confirmed to run
   **before** the return from `getConfig()`, i.e. before persistence.
6. **Concurrent admin session cap** — mentioned repeatedly in comments as the reason session
   logout is mandatory in `_withSession()`; no hard number given in code, just "a FortiGate caps
   concurrent admin sessions" (relevant if a future change adds parallel per-VDOM fetches).
7. **`network_objects` has no VDOM column** — an identically-named object catalog entry across two
   VDOMs on the same device silently collapses to whichever was inserted last. Documented, accepted
   simplification, not a bug.
8. **VPN session-count header regex bug, live-confirmed and fixed 2026-07-23**: SSH's
   `cliParser.countActiveVpnSessions()` originally only matched `SSL VPN Login Users:` (space) but a
   real device sent `SSL-VPN Login Users:` (hyphen) — silently broke the feature on every poll until
   fixed. Returns `null` (not `0`) if the header isn't found at all — callers must not treat that as
   a confirmed zero.
9. **Topology collection (added 2026-08-02, `getInterfaces()`/`getRoutingTable()`/`getNatRules()`,
   SSH transport only, live-verified against TSR-TL)**: `get system interface physical` — one
   `==[<name>]` block per interface, `ip: <ip> <mask>` line converted to CIDR via the existing
   `ipMaskToPrefixLength()` (already used for `getObjects()`); unconfigured interfaces report
   `0.0.0.0` and are skipped. `get router info routing-table all` — primary routes start at column 0
   with a one-letter code (`C`/`S`/`O`/`B`/`R`) + optional `*`; ECMP/backup continuation lines are
   indented and start with `[`, naturally excluded (only the first/primary path per destination is
   kept). `getNatRules()` derives NAT from `show firewall policy` + `vip` + `ippool` (FortiOS has no
   separate ordered NAT rulebase like Palo Alto — NAT is a per-policy `set nat enable` flag plus VIP
   objects referenced from `dstaddr`) by reusing the EXISTING `policiesFromConfigText()`/
   `entriesFromConfigText()` config-tree parsers, no bespoke text parsing needed. Destination NAT via
   a VIP resolves cleanly (VIPs bind to a real physical `extintf`). Source NAT resolves to the egress
   interface's own IP ONLY when `dstintf` names a real `device_interfaces` entry — **live-confirmed
   that every policy on this device uses an SD-WAN virtual interface (`"virtual-wan-link"`) as
   `dstintf`**, which has no IP of its own (SecVault has no visibility into which physical WAN link
   an SD-WAN policy actually egresses through at any moment) — that case reports
   `translatedSrcAddresses: null` (`natUnresolved` downstream in `topology.js`), never a guessed WAN
   link. An explicit `ippool` reference is also resolved when present (empty on this device).

---

## Palo Alto (`paloalto`)

**Files**: `lib/adapters/paloalto/{index.js, api.js, ssh.js, sshParser.js, parser.js}` — two adapter
classes, `PaloaltoAdapter` (XML API, `mgmt_method='api'`, default) and `PaloaltoSshAdapter`
(`mgmt_method='ssh'`).

**Auth / endpoint**:
- XML API: single endpoint `https://<mgmt_ip>:<mgmt_port||443>/api/`, operation selected via query
  params. Auth key passed as `key=` query param. `credential_type='rest_api'` via
  `parseApiCredential`. Username+password is exchanged for a key via PAN-OS's own **native**
  keygen endpoint `GET /api/?type=keygen&user=<user>&password=<pass>` (`api.js:generateApiKey()`) —
  this is a first-class PAN-OS auth mode, not a shim. The minted key is cached for the LIFE OF THE
  ADAPTER INSTANCE (`_apiKeyPromise`) so one collect cycle (getVersion+getRules+getConfig) doesn't
  put the password on the wire 3-4 times; never persisted beyond the instance.
- SSH: port `mgmt_port||22`, `credential_type='ssh'` via `parseJsonCredential`. No enable mode (role
  is bound to the account; a read-only "superreader" can enter `configure` and `show` but not
  commit/edit). Prompt regex is STRICTER than the shared default:
  `/[\w.-]+@[\w.-]+(?:\([^\n()]*\))?\s*[>#]\s*$/` — requires the full `user@host>` shape, because a
  loose regex against a multi-MB config dump risks a chunk-boundary false-match and silent
  truncation; a mismatched prompt fails LOUD (command timeout) instead, which is the correct
  trade-off here.

**What is collected**: Both transports implement all 4 required + `getObjects` + `getSnmpMetrics`.
Neither implements `getVpnSessionSummary`.

**Parsing entry point**: XML API rules → `parser.js:parseRules(rulesResult)` (falls back to
`parser.js:parseRulesDeep()` for the any-vsys search — see quirk below). XML API config `parsed` →
`parser.js:parseConfig(configResult, systemInfoResult)`. SSH rules →
`sshParser.js:parseSecurityRules(configText)` (brace-tree parser). SSH config `parsed` →
`sshParser.js:parseConfig(redactedText, systemInfo)`.

**Known quirks (verified against current code, 2026-07-23)**:

1. **QUIRK #1 — keygen password-in-URL: risk is CONFIRMED PRESENT AT THE HTTP LAYER but MITIGATED
   IN THIS CODEBASE, not unmitigated.** `api.js:generateApiKey()` does send the password as a
   `password=` query-string parameter (`GET /api/?type=keygen&user=...&password=...`) — this is
   how PAN-OS's own keygen endpoint works, not something SecVault chose. **However, `index.js`
   never logs the constructed request URL anywhere** (checked every `console.log` call in both
   `api.js` and `index.js` — none echo the URL). The shared request core `api.js:panFetchXml()`
   builds every possible error string through `redactSecrets(text, secrets)`
   (→ `scrubUrlSecretParams()`, a name-anchored regex `/([?&](?:key|password|user)=)[^&\s"'<>)\]]*/gi`
   that redacts by PARAMETER NAME, not by matching the literal secret text — so it can't be defeated
   by URL re-encoding differing from what was predicted) PLUS literal/percent-encoded/
   form-encoded secret-string matching (`secretForms()`). The keygen call additionally passes
   `echoBody: false`, so the response body (which contains the freshly minted key — itself a
   credential) is **never** quoted into any error message either. Net: the password does travel in
   the URL on the wire (inherent to PAN-OS, would appear in a network-level packet capture or an
   upstream proxy's own access log — outside SecVault's control), but nothing SecVault itself
   writes to `engine.log` or the `/api/devices/[id]/test` HTTP response can leak it. This exact
   class of bug (body-read errors leaking `?...&key=<APIKEY>`) HAS happened once in this file
   before and was fixed — the current redaction discipline is the fix holding, not first-line
   prevention.
2. **QUIRK #2 — running-config redaction before persistence: CONFIRMED on both transports.**
   XML API: `index.js:getConfig()` calls `parser.redactConfigXml(raw)` and
   `parser.redactConfigTree(configResult)` **before** `parser.parseConfig()` builds `parsed` and
   before the `{raw, parsed}` object is returned — i.e. before `collectAndStore()` ever persists it.
   SSH: `ssh.js:getConfig()` calls `sshParser.redactConfig(configText)` first, THEN builds `parsed:
   sshParser.parseConfig(redacted, systemInfo)` from the REDACTED text — the parsed tree is built
   FROM already-redacted input, not redacted after the fact. Both redaction functions are
   keyword/tag-based (`SECRET_TAGS`/`SECRET_TOKENS` — `phash`, `password`, `pre-shared-key`,
   `snmp-community-string`, `private-key`, etc.) and fail closed. `device_configs`/`config_backups`
   are `GRANT SELECT`'d to `claude_readonly`/`nocvault_readonly` — this is why redaction cannot be
   optional or deferred.
3. **Palo Alto SSH does NOT return `set`-format config despite running the documented command
   sequence to request it.** `configure` → `set cli config-output-format set` → bare `show` reliably
   retrieves the FULL config tree, but on real firmware (11.1.13-h5, 2 devices) it comes back as the
   classic curly-brace tree regardless. `sshParser.js` has a real tokenizer/recursive-descent parser
   for this grammar — do not attempt to "fix" the command sequence to force `set` output; it's been
   tried and doesn't work on this firmware line.
4. **Panorama-managed device fallback**: when NO `rulebase.security.rules` container (bare,
   `vsys.entry`, `shared`, or `pre-/post-rulebase`) is found anywhere in the SSH-parsed tree,
   `ssh.js:getRules()` falls back to the operational command `show running security-policy`
   (`EFFECTIVE_POLICY_COMMAND`, a DIFFERENT command needing no `configure`/set-format step),
   parsed by `sshParser.js:parseEffectiveSecurityPolicy()`. This returns the MERGED effective
   policy (local + Panorama pre/post-rulebase). **Documented, real limitations of this fallback
   path**: `enabled` is always `true` (a disabled rule isn't part of the enforced policy, so it
   never appears — no way to distinguish "doesn't exist" from "exists but disabled"); `log_enabled`
   defaults to `true` (no logging-state field in this output); `hit_count` is always `0` (hit-count
   enrichment needs the brace-tree this fallback never builds); NAT/schedule/expiry/comment are
   always false/null. Only used when the primary container search finds ZERO containers — if it
   finds ≥1, this fallback is never attempted, even if that container turns out empty (that's an
   honest `[]`, not a failure). **This SSH-transport version IS live-verified** (33/33 rules
   confirmed against a real captured device output).
   — **XML/API transport equivalent — LIVE-VERIFIED 2026-08-25, and the original guess was
   WRONG.** The 2026-07-23 version assumed `show running security-policy` returns structured XML
   over the API. It does not. PAKFood (PAN-OS 11.1.13-h5, the fleet's only Panorama-managed
   firewall) returns the CLI's plain brace text wrapped in a single `<member>` element, so
   `parser.parseEffectiveSecurityPolicy()` — which deep-walks for `@_name`+`action` entries —
   matched nothing and returned `null` on every device. The fallback ran on every pull and could
   never succeed; on the API transport it was dead code. Because `collectAndStore` DELETEs before
   reinserting, PAKFood's 33 real rules (collected fine on the SSH transport until 2026-08-03)
   were WIPED by the first API-transport pull.

   `index.js:getRules()` now tries three tiers at that same trigger point (after BOTH the
   default-vsys and any-vsys config-get xpaths return zero rules), best-data-first, and names the
   winning tier in its `engine.log` line:
   1. **`api.showPushedSharedPolicy()`** — `<show><config><pushed-shared-policy/></config></show>`,
      clean structured XML that `parser.parseRulesDeep()` extracts UNMODIFIED. **33 rules live**,
      with real OBJECT NAMES (`VLAN4-10.248.4.0_24`) and complete application lists. Preferred.
   2. **the `<member>` CLI text** through `sshParser.parseEffectiveSecurityPolicy()`, the SSH
      transport's ALREADY live-verified text parser. **35 rules live.** Same "the API returns the
      CLI text verbatim" precedent `getNatRules()` already relies on.
   3. the original doc-derived XML shape, kept only in case a future PAN-OS returns it. Never
      observed working on any real device.

   Tiers 1 and 2 disagree on COUNT (33 vs 35) because they are different questions — tier 2's
   merged effective policy includes rules tier 1's pushed-policy view does not. Tier 1 wins on
   data quality, which is why it is first. The SSH transport's documented limitations (no
   disabled-rule visibility, no real logging state, no hit counts, no NAT) apply to tiers 2 and 3;
   tier 1 carries real object names but still no hit counts.

   ⛔ The durable lesson, and it is CLAUDE.md's own rule: "verify all field names against live
   responses before writing any parser — documentation lies." The 2026-07-23 parser was written
   shape-agnostically *specifically* to survive a wrong guess, and that discipline did work — it
   failed closed to `null` instead of inventing rules. But no amount of defensive parsing can make
   a guessed format correct, and the real format was not among the shapes considered plausible.
5. **XML API's default xpath is single-vsys only** (`vsys1`, hardcoded as `DEFAULT_VSYS`). Zero
   rules from that xpath is ambiguous — could be genuinely empty OR a multi-vsys device whose rules
   live under vsys2/vsys3. `index.js:getRules()` only tries the predicate-free any-vsys fallback
   (`api.getSecurityRulesAnyVsys()` → `parser.parseRulesDeep()`) when the primary path returns
   zero — never regresses the working single-vsys case.
6. **Hit-count enrichment (both transports) is ADDITIVE and can never affect the returned ruleset**
   — wrapped separately, never throws past its own boundary, leaves every rule at `hit_count: null`
   (UNMEASURED) on any failure. ⛔ It defaulted to `0` until 2026-08-25, and the API-transport
   command was itself malformed (missing `<vsys>` wrapper, rejected by PAN-OS on every call), so
   every Palo Alto rule reported zero hits forever and Phase 5 called them all `unused`. Fixed and
   live-verified against all 10 API devices. SSH specifically gates on `containersFound === 1` before even attempting vsys-name
   resolution (a 2026-07-18 fix — the vsys-name walker was less shape-tolerant than the container
   search and could silently misattribute one vsys's hit counts to another vsys's identically-named
   rule on a genuinely multi-vsys device). Both transports skip enrichment entirely (not
   best-effort) whenever the ruleset came from a multi-vsys/any-vsys result, since rule names are
   unique per-vsys, not globally — merging by name alone risks a WRONG (not just missing) count,
   judged worse than no count.
7. **`getObjects()` makes NO new device call on either transport** — reads back the already-committed
   `device_configs.config_parsed` for THIS pull via `getLatestConfigParsed()` (works because
   `getObjects()` runs after `getConfig()` in `collectAndStore()`'s pipeline) and does a bounded
   depth-first search for `address`/`address-group`/`service`/`service-group` container keys —
   doc-derived field shapes, not yet live-verified for this specific object-catalog slice (the
   brace-tree grammar itself IS live-confirmed for rules, but not specifically exercised against
   real address/service objects).
8. **Live Validation Status**: SSH transport's brace-tree parsing of `rulebase.security.rules` is
   LIVE-CONFIRMED against 2 real devices (15/15 and 33/33 rules extracted correctly, including edge
   cases like unspaced list brackets and nested `profile-setting` blocks). `show system info` field
   names ARE live-confirmed (`hostname`, `sw-version`, `model`, `serial`). Hit-count response shape
   on BOTH transports is doc-derived, NOT live-verified — `[PaloAlto Debug]`/`[PaloAlto SSH Debug]`
   one-shot logs exist specifically to confirm this on next live connect. XML/API transport's rule
   collection has separately worked live on real devices (confirms the XML API path independently of
   the SSH-specific brace-tree bug history).
9. **Topology collection, SSH transport (added 2026-08-02, `getInterfaces()`/`getRoutingTable()`/
   `getNatRules()`, live-verified against HRIS)**: `show interface all`'s logical-interface table
   is column-padded with 2+ spaces (split on `/\s{2,}/`, not plain whitespace — the "zone" column can
   be entirely empty, collapsing 7 tokens to 6, handled explicitly). `show routing route`'s "flags"
   column can hold MULTIPLE space-separated codes (e.g. `"A S"`, `"A C"`) — parsed by classifying
   tokens positionally (destination/nexthop/metric fixed, then consume flag-shaped tokens, then the
   next token is the interface) rather than a fixed column count; host (`H`) routes are dropped
   (self-route to the interface's own `/32`, no path-decision value). `show running nat-policy` shows
   the COMPILED policy — a bidirectional static NAT rule appears as TWO separate blocks (one
   `source <ip>`/`translate-to "src: ..."` for the outbound direction, one `destination
   <ip>`/`translate-to "dst: ..."` for the return direction) — each parsed as its own independent
   `nat_rules` row; `lib/engines/topology.js` never needs to know they're a matched pair.
10. **Topology collection, API transport (added 2026-08-03, `getInterfaces()`/`getRoutingTable()`/
    `getNatRules()`, live-verified against ITC-SLY — the one live PAN-OS API-transport device in
    this fleet)**: `show interface all`'s CLI-to-XML mapping does NOT follow this file's usual
    "every token becomes a nested tag" rule — `<show><interface><all/></interface></show>` is
    REJECTED ("needs to have non NULL value"); the working form is
    `<show><interface>all</interface></show>` (the final token becomes a VALUE, not a further
    nested tag). Response is clean structured XML (`<ifnet><entry>` with `name`/`zone`/`ip` fields
    directly) — no column-position parsing needed at all, unlike the SSH transport. `show routing
    route` uses the standard nested-tag form and is likewise clean structured `<entry>` XML.
    **`show running nat-policy`'s XML response is confirmed BYTE-IDENTICAL in format to the SSH
    transport's plain text** (same brace-delimited blocks inside a single `<member>` text
    element) — `paloalto/index.js`'s API-transport `getNatRules()` reuses
    `sshParser.parseNatPolicyOutput()` directly rather than a second parser.
    **⛔ Real bug found via this live capture, fixed in the SHARED `sshParser.js` (affects BOTH
    transports)**: a `dynamic-ip-and-port` (PAT/overload) NAT rule's `translate-to` string
    includes the egress INTERFACE NAME between `"src:"` and the IP
    (`"src: ethernet1/2 118.174.183.36(*) (dynamic-ip-and-port) ..."`), unlike the `static-ip`
    shape (`"src: 27.254.123.18 (static-ip) ..."`) this parser was originally verified against —
    the original regex required the IP immediately after `"src:"` and silently produced ZERO NAT
    rows for every PAT/overload rule (the single most common real-world NAT type) until fixed to
    skip any token lazily before matching the first dotted-quad.
11. **Device lifecycle & health (added 2026-08-03, `getLicenses()`/`getHaStatus()`/`getDiskUsage()`
    + `getVersion()`'s new `contentVersions`, BOTH transports, all live-verified across 11 real
    devices before any parser was written)**:
    - **Command syntax is per-command, with NO general rule** — verified individually, and the
      "obvious" form fails in both directions. Licences need the NESTED form
      `<request><license><info></info></license></request>`; the value form
      `<request><license>info</license></request>` is REJECTED (`code="17" ... is unexpected`) —
      the exact opposite of `showInterfacesAll()` above, which needs the value form. HA uses
      `<show><high-availability><state></state></high-availability></show>`, disk uses
      `<show><system><disk-space></disk-space></system></show>`.
    - **Licence output formats DIFFER between transports** (the only one of these that does): the
      API returns structured `<licenses><entry>` XML (`parser.parseLicensesXml()`), the SSH CLI
      returns repeated `License entry:` text blocks with a literal question mark in `Expired?:`
      (`sshParser.parseLicenseInfoOutput()`). Dates are human strings in BOTH
      (`"September 16, 2027"`), and `"Never"` is a real value for perpetual licences.
    - **Disk returns plain `df -h` text on the API too** (in CDATA), byte-identical to the CLI, so
      `sshParser.parseDiskSpaceOutput()` serves both transports (same documented reuse as
      `parseNatPolicyOutput`).
    - ⛔ **HA does NOT. It has THREE different response shapes and this cost a real bug.** The CLI
      returns an indented text block; the API returns `<enabled>no</enabled>` plus a near-empty
      `<group>` for a STANDALONE device; and the API returns a fully STRUCTURED tree
      (`<group><local-info>/<peer-info>`) for an HA-ENABLED device. The first API sample available
      was a standalone device, so reusing the text parser for the API "worked" in testing and would
      have silently stored NOTHING for every real HA pair on that transport — caught only because
      devices were later switched from SSH to API and the enabled-state was re-verified.
      **Verify per-device-STATE, not just per-command**: a command that parses correctly against one
      device can return a structurally different response from another device in a different state.
      `parser.parseHaStateXml()` now handles the API; `sshParser.parseHaStateOutput()` the CLI.
    - The API exposes MORE than the CLI text: per-component `*-compat` verdicts including
      `url-compat`, which has no equivalent in the CLI's Version Compatibility block (live: IDC FW
      reports `url-compat: Mismatch` — its URL DB is `20260803.20149` vs the peer's
      `0000.00.00.000`), and it splits the peer's last error into `last-error-state` +
      `last-error-reason` rather than one prose label, giving a cleaner signal for the
      suspended-vs-fault distinction. ⚠️ `<DLP>` is NOT a compat verdict despite looking like one —
      it holds `Match` in `local-info` but a version string in `peer-info`; only keys ending
      `-compat` are read.
    - The XML response carries no HA group NUMBER (the CLI prints `Group 33:`), so `group_id` is
      null on the API transport rather than invented.
    - ⚠️ **Do NOT read HA state from the group header line.** Live samples show three different
      suffixes for the same healthy condition — `Group 33: Master`, `Group 48: Active`, and
      `Group 63: ` (empty). The authoritative value is `Local Information: → State:`. A standalone
      device returns the literal string `HA not enabled`.
    - ⚠️ **Two distinct peer-reason labels, deliberately treated differently**:
      `Last non-functional state reason` (live: `Link down`) is a genuine fault signal and
      populates `device_ha_status.last_nonfunctional_reason`; `Last suspended state reason: User
      requested` is a deliberate admin action on an otherwise healthy pair and is kept OUT of that
      column (retained in `raw`) so it can never read as a fault.
    - Fleet reality at time of build: 6 of 11 Palo Altos are Active-Passive pairs (IDC FW, SMT,
      ITC-SK, PAKFood, TUFF(TUTH3), TUM(TUTH1)); the rest standalone. PAN-OS reports its own
      `Version Compatibility:` Match/Mismatch block, so cross-pair version-mismatch detection is
      parsing, not computation.
    - ⛔ **Fortinet licences ARE implemented (2026-08-04). An earlier version of this note claimed
      Fortinet had no licence surface — that was WRONG**, and the mistake is worth recording: the
      conclusion came from probing only `get system status`, which genuinely has no licence lines.
      One command returning nothing does NOT establish that a vendor lacks the data. Three other
      commands carry it, all live-verified on TSR-TL/TSR_EKC before any parser was written:
      - `diagnose autoupdate versions` — Fortinet's OWN documented CLI licence command. Per-component
        FortiGuard UPDATE contracts (`Contract Expiry Date:`) plus signature versions and last-update
        timestamps, so content freshness comes from the same output.
      - `diagnose test update info` — the **System contracts** block (`SPRT`/`HDWR`/`ENHN`/`COMP`/
        `FMWR`), i.e. the SUPPORT and HARDWARE entitlements. Available nowhere else on the CLI, and
        the actual renewal-planning data. Its second group of DATABASE codes (APDB/AVDB/ETDB/...) is
        deliberately skipped — `diagnose autoupdate versions` already reports those same contracts
        against readable component names, so emitting both double-counts 30+ rows per device.
      - `get system fortiguard` — query-based services (webfilter, antispam, outbreak prevention)
        that are not downloaded databases and therefore never appear in autoupdate's list.
      ⚠️ `Contract Expiry Date: n/a` means **NOT LICENSED** — a distinct state from unknown; the raw
      string is preserved so `deviceHealth` can tell them apart, exactly like Palo Alto's `Never`.
      ⚠️ Dates are `Tue Jul 24 2029`, sometimes carrying a time (`Mon May 6 16:00:00 2024`) — a
      different shape from Palo Alto's `September 16, 2027`, so `parseFortiDate()` is its own parser.
      FortiOS reports no expired yes/no verdict, so `expired` stays null and the date decides.
    - **Fortinet HA remains deferred**: `Mode: Standalone` is confirmed on all 5 units, but no
      HA-ENABLED FortiGate exists in this deployment to verify a peer parser against — same
      discipline that deferred Fortinet API-transport topology.

---

## Check Point (`checkpoint`)

**Files**: `lib/adapters/checkpoint/{index.js, api.js, parser.js}`

**Auth / endpoint**: `mgmt_ip` is the **Security Management Server's** IP, not a gateway's —
confirmed explicitly in file-header comments; the gateway is located by matching device
name/IP against `show-gateways-and-servers` results. Base URL
`https://<mgmt_ip>:<mgmt_port||443>/web_api/<command>`. Session-based: `POST login` with
`{user,password}` or `{"api-key":apiKey}` → `sid`, sent as `X-chkp-sid` header on every subsequent
call. `credential_type='rest_api'` via the shared `parseApiCredential`.

**What is collected**: `testConnectivity`, `getVersion`, `getRules`, `getConfig`, `getObjects` all
implemented. `getSnmpMetrics` implemented (added 2026-07-30/commit 0e4e2d9, v2.25.0 — generic
MIB-II/HR-MIB only, `snmp_host` required, no `mgmt_ip` fallback, same exception class as
Forcepoint; see `lib/adapters/checkpoint/index.js:613`). `getVpnSessionSummary` **not implemented**
(Management API has no VPN tunnel/session-status endpoint at all — researched 2026-07-30; live
state needs SmartView Monitor/Log Server/gateway access this adapter doesn't have).

**Parsing entry point**: rules → `parser.js:parseRulebasePages(pages)` (merges every page's
`objects-dictionary` into a uid→object map, flattens sectioned rulebase, normalizes each rule).
Config `parsed` is NOT a single parser function — built inline in `index.js:getConfig()` as
`{ gateway: parser.redactSecrets(gateway), api_versions: parser.redactSecrets(apiVersions) }`.

**Known quirks**:
1. **QUIRK #4 — gateway/policy resolution is fully identity-based with no positional fallback
   ANYWHERE — confirmed across getVersion/getRules/getConfig, not just rules.**
   `parser.js:findGatewayByIdentity(objects, device)` matches on `ipv4-address === device.mgmt_ip`
   OR case-insensitive name equality, AND requires `isGatewayLikeType(type)` (regex
   `/gateway|cluster/i`) so a management/log-server object sharing an IP can't be mismatched for
   the gateway. Called via one wrapper, `index.js:_findGateway(session)`, used by BOTH
   `getVersion()` and `getConfig()`. Policy-package resolution
   (`index.js:_resolvePolicyPackage()`) tries 4 identity/evidence-based routes in strict order
   (installed-policy field on the gateway object → same via a direct `show-simple-gateway`/
   `show-simple-cluster` call → the single package whose install-targets name this gateway,
   ONLY if exactly one → the single package on the whole server, ONLY if exactly one) — **never**
   `packages[0]`. All failure paths **throw**, naming candidates via
   `parser.js:describeGatewayCandidates()`/`describePackages()` (capped at 12 shown + "+N more").
   The OLD fallback-permitting `parser.findGateway()` function was fully **removed** from the
   codebase, not just unused — confirmed no positional fallback survives.
2. **`getRules()` throws on true failure** (no policy packages on server, unresolved package,
   0 access layers, missing layer uid, network errors) — never returns `[]` for those cases. One
   softer nuance INSIDE the parser: `parser.parseRulebasePages()` lets an individual malformed
   *page* contribute 0 rules (loudly `console.warn`'d) without failing the whole call — a
   documented, deliberate fix so one bad page doesn't nuke the entire pull, but this is
   fundamentally different from the adapter method itself silently returning `[]`.
3. **Redaction: `parser.js:redactSecrets(value, depth)`** — CONFIRMED PRESENT (this is the one
   adapter that historically had NO redaction pass at all, per CLAUDE.md — the fix has landed).
   Keyword pattern `/secret|password|passwd|psk|private[-_]?key|community|credential|token|
   api[-_]?key/i`, depth-capped at 20, fails closed (`'<redaction-error>'`/
   `'<redaction-depth-exceeded>'` rather than raw data on internal error). Called synchronously
   inside `getConfig()` before `parsed`/`raw` are constructed and returned — before persistence.
   **Caveat**: redaction is only applied in `getConfig()` — `getRules()`'s `raw_rule` field stores
   the raw rule object unredacted (rules don't typically carry secrets, but this is unguarded if a
   rule extension field ever did).
4. **Session lifecycle**: `api.js:withSession(conn, fn)` — one fresh login/logout PER top-level
   adapter method call (not cached across `getVersion()`+`getRules()`+`getConfig()` in the same
   collect cycle — each opens its own session). `finally` block always calls `logout()`, which
   itself never throws (a logout failure is only warned, never masks the real result of the work
   done inside the session).
5. **Pagination**: shared `index.js:_fetchAllPages()` (gateways-and-servers + all `getObjects()`
   catalog endpoints) and a sibling `_fetchAccessRulebasePages()` (rulebase-specific, has
   `show-hits` retry logic for older management versions that reject that flag). Both capped at
   `MAX_PAGES=100` × `PAGE_LIMIT=500`, and **both now warn on hitting the cap** (a 2026-07-18 fix —
   the generic helper originally warned, the rulebase-specific one didn't, silently truncating a
   large ruleset with zero log signal).
6. **`getObjects()` is server-wide, not gateway-scoped, by deliberate design** — unlike
   getRules/getVersion/getConfig, the object catalog has no gateway-identity resolution at all; it
   dumps every host/network/range/group/service on the whole management server the credential
   reaches. Each of the 7 endpoint calls is independently try/caught (degrades per-category, never
   throws whole) — explicit contrast in comments with `getRules()`'s all-or-nothing throw.
7. **Group-member resolution assumes `details-level: full` returns inline objects, not bare uid
   strings** — this specific assumption is UNVERIFIED (no live Check Point server in this
   deployment). `parser.extractMemberName()` tolerates either shape, falling back to the uid string
   itself rather than dropping a member.
8. Check Point rules have no zone concept at the API level — `src_zones`/`dst_zones` are always `[]`.
   `hit_count` requires `show-hits: true` in the rulebase request; retried without it automatically
   if the server rejects the flag (older management versions).

---

## Cisco ASA (`cisco_asa`)

**Files**: `lib/adapters/cisco_asa/{index.js, parser.js}` (no separate `ssh.js` — transport logic
lives directly in `index.js` on top of the shared `lib/adapters/sshClient.js`).

**Auth / endpoint**: SSH shell channel, port `mgmt_port||22`, `credential_type='ssh'` via
`parseJsonCredential` — JSON `{"username","password","enable_password"?}`. Enable/privileged mode
IS supported: `_getSession()` passes `enablePassword`; the shared `sshClient.runCommands()` sends
literal `enable`, waits for a password prompt (or accepts if the session is already privileged),
sends the enable password, waits for the prompt again. `terminal pager 0` is sent as an init
command to disable `--More--` pagination.

**What is collected**: `testConnectivity`, `getVersion`, `getRules`, `getConfig`, `getObjects`,
`getSnmpMetrics`, `getVpnSessionSummary` all implemented (the last one added 2026-07-30, `show
vpn-sessiondb summary` — see the cross-vendor table above). `webvpn.enabled`/`webvpn.enabled_interface`
(see quirk #7 below) remains a separate, minimal, presence-only config-level VPN signal — distinct
from the live active-session count `getVpnSessionSummary` now provides.

**Parsing entry point**: rules → `parser.js:parseAccessListConfig(text)` (iterates `access-list `
lines from `show running-config access-list`, delegates single-ACE parsing to
`parser.js:parseExtendedAce()`). Config `parsed` → `parser.js:parseRunningConfig(text)`, called on
the ALREADY-redacted text. Objects → `parser.js:parseObjects(text)`, called on **unredacted**
`show running-config` text (object/group defs carry no secrets).

**Known quirks**:
1. **Redaction: `parser.js:redactConfig(text)`** (line-by-line via `redactLine()`), confirmed to
   run in `getConfig()` **before** `parser.parseRunningConfig()` — `parsed` is built from the
   already-redacted text too, described in-code as "defence in depth." A first-match-wins ordered
   list of ~15 regexes covers: `enable password`, `passwd`, `username ... password`, SNMP community
   (both `snmp-server host ... community` and bare `snmp-server community`, host-form checked
   first), IKEv1 PSK (`crypto isakmp key`), failover IPsec PSK, IKEv1/v2 pre-shared-key, LDAP login
   password, OSPF/NTP MD5 keys, key-chain `key-string`, indented AAA-server sub-mode `key` (RADIUS/
   TACACS+ shared secret — requires leading whitespace to avoid colliding with `key-exchange`/
   `key-chain`), and **`radius-common-pw`** (explicitly noted as found missing in a follow-up sweep
   and then added). SNMPv3 `snmp-server user ... auth <alg> <key> priv ... <key>` is handled
   separately (two secrets, one line). `redactLine()` fails CLOSED — any exception redacts the
   entire line rather than risk leaking a fragment.
2. **`getRules()` throws (never `[]`) on a rejected/unprivileged CLI response** —
   `parser.looksLikeCliError()` gates this explicitly; the comment states the reason precisely:
   a rejected response would otherwise parse as "zero ACEs," and the caller would then DELETE all
   previously stored rules and report success. Hit-count enrichment (`show access-list`) is the
   ONE part of this flow allowed to fail silently — wrapped separately, only degrades `hit_count`
   to 0, never aborts `getRules()`.
3. **The `ip` protocol token has NO special "any protocol" handling in this adapter.** It's stored
   verbatim as `proto: 'ip'`, lowercased, like any other protocol string — there is no
   alias/normalization logic here at all. This matters for cross-file consistency: this codebase's
   `any_any`/`external_exposure`/compliance deny-all detection treats a literal `ip` token
   specially (Cisco convention for "all IP protocols"), but that handling lives ELSEWHERE
   (`ruleAnalysis.js`, `configAuditor.js`) — a future change to how `ip` is interpreted must be
   made in those consumer files, not here, since this parser just passes the raw token through.
4. **ACL parsing is `extended`-only** — `standard`/`webtype`(clientless VPN)/`ethertype` ACLs are
   skipped with a once-per-ACL warning, not parsed at all.
5. **`usernames[]` captures names ONLY, by explicit design** — password hash, privilege level, and
   any other trailing tokens on a `username ... password ...` line are never extracted. No
   privilege-level or 2FA/source-restriction data exists for this vendor anywhere in this codebase
   (confirmed — `adminAccountSummary.js` sets those fields to `null` for ASA, never guessed).
6. **`getObjects()` only captures NAMED references inside object-groups** —
   `network-object object NAME` / `group-object NAME` for network groups,
   `service-object object NAME` / `group-object NAME` for service groups. INLINE literals
   (`network-object host 1.2.3.4`, `network-object 10.0.0.0 255.255.255.0`) are deliberately
   skipped — "no backing named object, nothing to add as a member." Triple-layered to never throw
   (outer try/catch around the whole SSH run, inner try/catch around parsing, plus the
   CLI-error/format guard) — always resolves to the empty-catalog shape on any failure.
7. **`webvpn.enabled`/`webvpn.enabled_interface`** is a minimal, presence-only VPN signal (a
   `webvpn` block containing an `enable <interface>` sub-line) — deliberately does NOT parse
   `tunnel-group`/`group-policy`/AnyConnect image/certificate config. No `getVpnSessionSummary()`
   exists for this vendor at all.
8. **SNMP OIDs**: MIB-II `sysUpTime.0`; CISCO-PROCESS-MIB `cpmCPUTotal5minRev` (walked table,
   already 0-100%); CISCO-MEMORY-POOL-MIB `ciscoMemoryPoolUsed`/`Free` (summed for percent);
   CISCO-FIREWALL-MIB `cfwConnectionCurrentInUse` at a SPECIFIC instance suffix `.5.40.6` (not a
   walk) for current global connections. Doc-derived (cross-checked against Cisco's own MIB
   reference + oidref.com, not a live device) but `lowConfidence` is hardcoded `false` — the ONE
   vendor where SNMP confidence is asserted high despite no live test, because the sourcing was
   considered strong enough. Each table walk is independently try/caught so one failed walk doesn't
   discard already-obtained scalars (uptime, session count).
9. **ASA prompt regex** (`/[>#]\s*$/`, set as `promptRegex` override) is a NARROWER character class
   than the shared default (`/[>#$%]\s*$/` — ASA never shows `$`/`%`), but shares the critical
   no-`m`-flag property with the shared default, which is what actually prevents mid-config
   truncation on a `banner motd ####`-style line.

---

## Sangfor (`sangfor`)

**Files**: `lib/adapters/sangfor/{index.js, parser.js}` (no separate `ssh.js`).

**This is explicitly the codebase's least-verified, lowest-confidence adapter — no live NGAF
device exists anywhere in this deployment's history. Every parsing choice is defensive/best-effort
by design, not an oversight.**

**Auth / endpoint**: SSH, `credential_type='ssh'` via `parseJsonCredential`. Command-dialect
fallback pattern: tries an ORDERED array of candidate commands per operation (e.g.
`VERSION_COMMANDS = ['show version', 'display version']`,
`CONFIG_COMMANDS = ['show running-config', 'display current-configuration', 'show configuration']`)
via a shared `_tryCommands()` helper, since "Sangfor CLI syntax varies by firmware line
(Cisco-flavored on some, Huawei-flavored on others)."

**What is collected**: `testConnectivity`, `getVersion`, `getRules`, `getConfig`,
`getSnmpMetrics` implemented. `getObjects()` **exists as a real function but is an unconditional
empty-array stub** (see quirk below) — it IS callable (so `collectAndStore()`'s
`typeof adapter.getObjects === 'function'` check is true), it just never attempts parsing.
`getVpnSessionSummary` not implemented at all — researched 2026-07-30 (Sangfor community forum,
NGAF User Manuals v8.0.6/v8.0.35/v8.0.47): no documented CLI command for VPN/session state was
found with reasonable confidence, and the v8.0.47 manual states the CONSOLE/CLI interface is
"for development, test, and debugging only" — VPN and admin-account management are web-GUI-first
by design on this vendor, a stronger and more specific reason than "just unverified yet" for why
this vendor's CLI surface is less discoverable-by-documentation than Fortinet/Cisco/Palo Alto.
Admin-account collection was researched on the same pass and skipped for the identical reason.

**Parsing entry point**: rules → `parser.js:parseRulesFromConfig(text)` — two-pass: groups lines
into blocks starting at a header regex (`policy`/`rule`, optionally prefixed
firewall/security/acl/ip/nat/access/app) until a block-exit boundary, then extracts fields per
block, skipping blocks with no recognizable action keyword. Config `parsed` →
`parser.js:parseConfigSections(text)`, called on the ALREADY-redacted text.

**Known quirks**:
1. **`getObjects()` is a deliberate, explicitly-justified stub**, not a gap waiting to be filled
   casually:
   ```js
   async getObjects() {
     return { addresses: [], addressGroups: [], services: [], serviceGroups: [] };
   }
   ```
   The surrounding comment is unusually explicit: object-catalog definitions need an
   unverifiable block-header keyword (`ip address-set` / `object-group network` / `address-object`
   / ...) that "no two vendors agree on, and Sangfor's own NGAF CLI has no captured sample anywhere
   in this codebase" — contrasted against the *rule* parser's field keywords, which only describe
   how policies REFERENCE objects (which has SOME grounding from rule text), not how objects are
   DEFINED (zero grounding). Do not "improve" this without first getting a real
   `[Sangfor Debug]` config dump from a live device — inventing block syntax here would fabricate
   unused/duplicate object findings as confidently as real ones.
2. **`getRules()` throws (never `[]`) on true retrieval failure** — if `_getConfigText()` succeeds
   but resolves to `null` (every candidate command in `CONFIG_COMMANDS` failed/produced nothing),
   `getRules()` throws explicitly rather than returning `[]`, with the same "false success would
   silently wipe firewall_rules via collectAndStore's DELETE" reasoning as every other vendor. The
   ONLY legitimate `[]` path: config WAS retrieved but `parseRulesFromConfig()` found zero
   recognizable rule blocks (logged via warning, explicitly distinguished in-code from a
   communication failure).
3. **Redaction covers BOTH `getConfig()`'s raw text AND each rule's `raw_rule.text`** —
   `parser.js:redactConfig(text)` is called at TWO separate construction points: once in
   `index.js:getConfig()` before `{raw, parsed}` is returned, and once per-block inside
   `parseRulesFromConfig()` when building `raw_rule: {source, text: redactConfig(blockText)}`. This
   second one is a real historical-bug fix — `raw_rule` previously escaped redaction (CLAUDE.md
   documents this) since `firewall_rules` is whole-table `GRANT SELECT`'d to the readonly roles.
   Field EXTRACTION for rules always runs on the UNREDACTED `block.lines`/`blockText` (redaction is
   keyword-based and would corrupt legitimate tokens like a service object literally named
   "community-web" if applied before extraction) — only the persisted snapshot is redacted, not the
   parsing input. This asymmetry is intentional, not a bug.
4. **VPN detection is explicitly the SAME "low confidence, defensible guess" class as
   `getObjects()`'s stub is deliberately NOT** — `sections.ssl_vpn.enabled` is a genuine tri-state
   (`true`/`false`/`null`), from a single regex `/^\s*(?:ssl[\s-]?vpn)\s+(enable|disable)/im`.
   `null` is explicitly documented as the EXPECTED, COMMON case ("undetected"), not a failure
   signal — treat it as such in any UI/engine code that reads this field.
5. **`hit_count` is a static literal `null` (UNMEASURED) for every rule, unconditionally** — no attempt at
   hit-count extraction exists anywhere in the parser (unlike Fortinet-SSH, where the limitation is
   at least documented as "the CLI command format is undocumented"; here there's simply no code
   path for it at all).
6. **Per-instance config-text cache** (`_configText`/`_configCommand`, populated by
   `_getConfigText()`) avoids dumping the running config over SSH twice per collect cycle (once for
   `getRules()`, once for `getConfig()`) — held UNREDACTED in memory on purpose (redaction is
   applied at each egress point instead: the `[Sangfor Debug]` preview log, `getConfig()`'s `raw`,
   and each rule's `raw_rule.text`), same caching shape as Palo Alto SSH's `_configText`/
   `_systemInfo` caches.
7. **SNMP is restricted to standard RFC 1213 (MIB-II) / RFC 2790 (HOST-RESOURCES-MIB) OIDs ONLY** —
   explicit in-code refusal to invent a plausible-sounding Sangfor-proprietary enterprise MIB
   ("exactly the 'guessing ungrounded syntax' CLAUDE.md's live-verification rule warns against").
   `sessionCount` is always `null` — no generic MIB-II/HOST-RESOURCES-MIB equivalent for firewall
   session count exists, and no Sangfor-proprietary MIB is known. `lowConfidence: true` is
   hardcoded unconditionally, same as Forcepoint and Palo Alto (both transports).

---

## Cross-vendor summary table

| Vendor | Transport(s) | credential_type | testConn | getVersion | getRules | getConfig | getObjects | getSnmpMetrics | getVpnSessionSummary | getRules() [] on failure? |
|---|---|---|---|---|---|---|---|---|---|---|
| forcepoint | SMC REST | `smc_api` (raw string) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (SMC-bypass exception) | ✗ (researched 2026-07-30 — no SMC monitoring endpoint found) | never — throws |
| fortinet | REST + SSH | `rest_api` / `ssh` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (2026-07-31 also returns per-user `sessions[]` → `vpn_active_sessions`: SSH `cliParser.parseVpnSslMonitorSessions` merges the `get vpn ssl monitor` Login-Users + Sessions tables by index — header-offset column slicing, per-VDOM `gateway`; REST `restSslVpnSessionToNormalized` off `/api/v2/monitor/vpn/ssl`. Additive/best-effort, count unchanged) | never — throws |
| paloalto | XML API + SSH | `rest_api` / `ssh` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (added 2026-07-30, GlobalProtect current-user only, both transports — doc-derived; 2026-07-31 also returns per-user `sessions[]` → `vpn_active_sessions`, additive, best-effort — XML via `parser.normalizeGlobalProtectUsers`, SSH via `sshParser.parseGlobalProtectSessions`; count is unchanged/authoritative, session detail never breaks it). 2026-07-31: a device with NO GlobalProtect gateway (SSH: no header line / XML: no `<entry>` and not confirmed-empty) now returns a clean `active_session_count 0` + `raw.no_globalprotect_gateway=true` instead of THROWING — the old throw WARN-spammed the poll log every cycle for non-GP devices (e.g. "TFM-RN"); `looksLikeCliError` still surfaces a genuinely rejected command) | never — throws (SSH has a Panorama fallback before throwing) |
| checkpoint | Mgmt API | `rest_api` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (added 2026-07-30, generic MIB-II/HR-MIB only, `snmp_host` required, no mgmt_ip fallback — same exception class as Forcepoint) | ✗ (researched 2026-07-30 — Management API has no VPN tunnel/session-status endpoint at all; live state needs SmartView Monitor/Log Server/gateway access this adapter doesn't have) | never — throws |
| cisco_asa | SSH | `ssh` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (added 2026-07-30, `show vpn-sessiondb summary`, sums each VPN-type row's Active column — doc-derived; 2026-07-31 also runs `show vpn-sessiondb anyconnect` in the SAME session → per-user `sessions[]` via `parser.parseVpnSessiondbDetail` (Public/Assigned IP, Bytes Rx/Tx, `0h:05m:12s`/`1d`-duration parse, Group Policy→gateway). Additive/best-effort, count unchanged) | never — throws |
| sangfor | SSH | `ssh` | ✓ | ✓ | ✓ | ✓ | stub (always empty) | ✓ (MIB-II/HR-MIB only) | ✗ (researched 2026-07-30 — no documented Sangfor CLI surface found with reasonable confidence; VPN/admin management is web-GUI-first per Sangfor's own manual) | never — throws |

All 6 vendors additionally use a SEPARATE `credential_type='snmp'` for `getSnmpMetrics()`, never
mixed with the management-plane credential.

**Palo Alto SSH `show session info` — LIVE-VERIFIED 2026-08-05** (v2.55.0, against TUG, the only remaining `mgmt_method='ssh'` PAN-OS device; the other 10 moved to API). Session count had been returned as `null` on this transport because the text output had never been captured and this codebase does not write parsers against guessed formats. Confirmed shape is `Label:<whitespace>Value`; `parseSessionInfoOutput` reads **`Number of allocated sessions`** as the active count. ⛔ NOT the sum of the per-protocol "active X sessions" lines — on the live capture TCP+UDP+ICMP = 6052 vs allocated 6058, because those lines omit several session classes, so summing under-reports. Also captures `Number of sessions supported` and `Session table utilization` into `raw`. Best-effort: it shares the CPU/memory session but a failure there never fails the whole metric read.

**Optional `getPerformanceMetrics()`** (added 2026-08-04, v2.50.0) — same return shape as
`getSnmpMetrics()` (`{cpuPercent, memoryPercent, sessionCount, uptimeSeconds, raw, lowConfidence}`)
but read over the management transport the device is ALREADY configured for, so it needs no `snmp`
credential, no `snmp_host`, and no per-device `snmp_enabled` opt-in. Implemented by **paloalto (both
transports)** via `show system resources` + `show session info`, and **fortinet (SSH only)** via
`get system performance status`. `services/engine-worker.js`'s `snmp-poll` job PREFERS this method
and falls back to `getSnmpMetrics()` only for devices without it; rows land in the same
`snmp_metric_snapshots` table. Not implemented for checkpoint/cisco_asa/forcepoint/sangfor or
fortinet's REST transport — no live device to verify real command output against, per CLAUDE.md's
"verify against live responses before writing any parser" rule.

⚠️ Because this opens real management sessions, the `snmp-poll` job is no longer a lightweight UDP
poll: it is now mutually exclusive with BOTH `vpn-session-poll` and `rule-version-pull` (whichever
starts first wins, the others skip that tick). FortiOS caps concurrent admin sessions, so
overlapping fleet-wide runs previously produced intermittent failures in both jobs.

**Optional `getVpnTunnels()`** (IPSec site-to-site tunnel status → `vpn_ipsec_tunnels`, added 2026-07-31,
a SEPARATE method + command from `getVpnSessionSummary`; engine-worker calls it in its own try/catch so a
tunnel-pull failure never fails the session poll). Shape `{name, peer, status, ike_version, bytes_in,
bytes_out, raw}`. ⛔ **THE ANSWER IS TRI-STATE SINCE 2026-11-13**: an ARRAY is a measurement (`[]` = genuinely no tunnels up, and clearing the rows is correct), `null`/`undefined` is NOT MEASURED and `storeVpnTunnels()` SKIPS the delete, and any other shape THROWS. Implemented for **paloalto** (`show vpn ipsec-sa`, both
transports — SSH `sshParser.parseIpsecTunnels` tabular dedupe, XML `parser.normalizeIpsecTunnels`),
**fortinet** (`diagnose vpn tunnel list` SSH `cliParser.parseIpsecTunnelList` + `/api/v2/monitor/vpn/ipsec`
REST, VDOM-aware), **cisco_asa** (`show vpn-sessiondb l2l` → `parser.parseVpnSessiondbL2l`). All doc-derived,
`[Vendor Debug]`-logged on first use, best-effort. ⛔ **AND "BEST-EFFORT" USED TO MEAN `[]` ON PARSE
DOUBT, WHICH DELETED THE DEVICE'S TUNNELS.** All **five** implementations degraded a parse/normalization
failure to an empty array, `storeVpnTunnels()` read that as a measured zero, and `topology.js`'s
`buildVpnEdges()` then drew the firewall with NO TUNNELS AT ALL — a confident wrong answer rather
than a gap, from a vendor shape the normalizer did not expect. Each now returns `null` with a named
`[Vendor]` warning, so the last-known rows are kept and age into `stale` via
`vpnTunnelHealth.classifyFreshness()` (120 min). That is also what already happened when the pull
THREW, so a parse failure and a transport failure finally behave alike.
⛔ **Fortinet additionally refused its own PARTIAL VDOM result.** The multi-VDOM loop returned the
tunnels of whichever VDOMs answered whenever at least one did, so one VDOM's monitor failing deleted
that VDOM's tunnels and reported the rest as the device's complete set — the defect CLAUDE.md
already names for `getRules()` ("collect every VDOM or fail"), in a second method that rule never
looked at. It returns `null` now; the pre-existing every-VDOM-failed branch still THROWS, because
that is a transport failure rather than an unreadable answer.
⛔ **What is NOT fixed, stated rather than implied:** `cisco_asa`'s `parseVpnSessiondbL2l()` fails
closed to `[]` INTERNALLY, so CLI output it cannot make sense of still arrives as an empty array and
is stored as a measured zero. Tightening that needs live `show vpn-sessiondb l2l` output to verify
against (no ASA on the reference fleet reports tunnels), and guessing the shapes it should refuse is
the "documentation lies" trap. Not implemented for forcepoint/
checkpoint/sangfor (same no-endpoint findings as their `getVpnSessionSummary` column). Also 2026-07-31:
`vpnSummary.summarizePaloAlto` now surfaces GlobalProtect **gateway/portal names** (config inventory,
`extractEntryNames`, both transports) instead of only the opaque found-at path.

**`getConfig()` config_parsed additions (2026-07-30)**: Check Point now includes `administrators`
(`show-administrators`, doc-derived) alongside `{gateway, api_versions}`. Forcepoint now includes
`smc_vpn_gateway_configured` (tri-state, from the engine element's `internal_gateway` field) and
`smc_administrators` (SMC-wide admin list) alongside the existing engine-element shape — both
`smc_`-prefixed to avoid colliding with a real unprefixed field on the spread engine element, both
independently try/caught (a fetch failure degrades that one field to `null`/absent, never fails the
whole collect). Both vendors' new admin-account data flows through the same redaction pass as the
rest of their config before being persisted.

## CLAUDE.md contradictions / staleness found

None found that materially change guidance — every specific claim CLAUDE.md makes about the 4
mandatory quirks above (PAN-OS keygen redaction, PAN-OS config redaction ordering, Fortinet VDOM
fail-loud behavior, Check Point identity-based resolution) was independently confirmed accurate
against the current code. Two precision notes worth flagging for future readers:
- CLAUDE.md's own text sometimes describes the PAN-OS keygen situation only as "the password
  travels in the URL query string" without stating plainly that SecVault's own logging/error paths
  already prevent that from becoming a SecVault-side leak — this file states that distinction
  explicitly (quirk #1 under Palo Alto) so it isn't mistaken for an open vulnerability.
- CLAUDE.md documents the Fortinet REST vs SSH VDOM-enumeration-failure asymmetry only inside a
  "bugs investigated and found NOT to be bugs" aside, easy to miss — this file surfaces it as a
  first-class quirk under Fortinet quirk #2 since it's exactly the kind of behavior a future change
  could accidentally "fix" into a regression.

**Fortinet system_info in the parsed config** (added 2026-08-25, v2.59.0). Until
now `parseFullConfiguration()` took only the config text, so EVERY Fortinet
snapshot stored no `system_info` at all — 149/149 on TUS, 96/96 on TSR-TL, 95/95
on Vietnam-YCC, 94/94 on TSR_EKM, 74/74 on TSR_EKC — even though `getVersion()`
was already fetching model/serial/version/hostname from `get system status` on the
same pull. `getConfig()` now passes that (cached per adapter instance, so no extra
command) and the parser merges it under `system_info`.

⛔ The key is OMITTED when the status read fails, never written as `{}` — an empty
object is exactly what produced Palo Alto's false "12 removed / 12 added" change
alerts (see gotchas.md). Expect ONE genuine `added` diff per Fortinet device on the
first pull after upgrade: the data really did appear, so it is a real change, not noise.

## ⛔ RULE NEGATION — where it lives, and why a consolidation engine must ask (verified 2026-09-25)

`firewall_rules` has **NO negation column**, and no adapter parses one (`grep -rn negate lib/adapters/`
returns nothing). Negation INVERTS a field's extent, so any engine concluding "these two rules are
disjoint" gets exactly the wrong answer on a negated field. `ruleConsolidation.js` therefore scans
`raw_rule` for a truthy `/negate/i` key and falls to `unknown` — which lands on `needs_review`.

Verified on the live fleet that `raw_rule` actually carries it:

| vendor | rules | `raw_rule` populated | mentions `negate` | negate ENABLED |
|---|---|---|---|---|
| `paloalto` | 1,601 | 1,601 | **133** | **0** |
| `fortinet` | 181 | 181 | 0 | 0 |

⛔ **Palo Alto is PROVEN**: PAN-OS emits `negate-source`/`negate-destination` and they survive into
`raw_rule` (133 rules carry them, none enabled). ⛔ **Fortinet's zero is an ABSENCE, not a proof** —
but the passthrough is verifiable: `withVdomRaw()` in `fortinet/parser.js` spreads the whole policy
object, and the live SSH captures carry **24 distinct keys** including optional ones
(`av-profile`, `dnsfilter-profile`, `ips-sensor`, `port-preserve`). A whitelist of the fields the
normaliser needs would hold about eight. So a set `srcaddr-negate`/`dstaddr-negate` would appear,
and the guard would see it.

⛔ **IF AN ADAPTER IS EVER CHANGED TO NORMALISE `raw_rule` INTO A FIXED SHAPE, THIS GUARD GOES
BLIND** and the engine can return `safe_to_merge` on a pair that is not. `raw_rule` being a verbatim
vendor dump is a load-bearing property, not an implementation detail.

## Cisco ASA syslog parsing (added 2026-10-03) — the first parser NOT from our own captures

`lib/syslog/vendorParsers.js` gains `parseCiscoAsa()` + `classifyCiscoAsa()`, and `detectVendor()`
now returns `cisco_asa`. It is the third vendor SecVault can parse syslog from, and the first whose
evidence did not come off this fleet.

⛔ **PROVENANCE IS THE POINT, SO IT IS RECORDED PER FIXTURE.**
`tests/fixtures/ciscoAsaSyslog.js` carries the captured lines, their source, licence and retrieval
date. Source: **logstash-plugins/logstash-patterns-core**, `spec/patterns/firewalls_spec.rb`,
**Apache 2.0** (verified against that repo's LICENSE, 2026-10-03).

⛔ **ELASTIC'S FIXTURES WERE DELIBERATELY NOT COPIED.** `elastic/integrations` ships `cisco_asa`
`.log` files too, but that repo is **Elastic License 2.0**, not Apache, so nothing from it is
vendored. It was used only to CORROBORATE — two different projects, two different licences, both
showing `%ASA-6-302013: Built outbound TCP connection 11757 for outside:...` with identical
structure. **Independent agreement is the substitute for a live device**, and it is why this is a
legitimate parser rather than the "documentation lies" trap. A single source would not have been.

⛔ **WHAT THE EVIDENCE DOES NOT ESTABLISH**, and no UI may imply otherwise: that a customer's ASA
emits these message IDs (that depends on configured logging level and enabled features), or that
the format is identical on their firmware. **The first real ASA is still a verification step**, the
same as a new device adapter.

⛔ **ONLY EIGHT MESSAGE IDS ARE PARSED** — `106001`, `106006`, `106023`, `106100`, `302013/14/15/16`
— gated by `ASA_PARSED_IDS`. The same call `parsePaloAlto` makes about TRAFFIC/THREAT. The ASA
emits hundreds of ids; one whose layout has never been observed yields the ENVELOPE ONLY (vendor,
severity, msgId) with every data field null, which reads honestly as "received, not understood".
⛔ The test for that gate initially COULD NOT FIRE: its fixture body matched no regex, so it parsed
to nulls whether or not the gate existed. It now uses `302035` — a real id NOT in the set — with a
body shaped exactly like the `302013` we do parse, plus a control asserting the same body under a
verified id DOES populate.

⛔ **THE RULE LINKAGE IS THE ACCESS-LIST NAME**, ASA's analogue of FortiOS `policyid`: `106023`
carries `by access-group "<name>"` and `106100` carries `access-list <name> ... hit-cnt <n>`.
⛔ `106001`/`106006` name no ACL, so `ruleName` stays **NULL** — a deny we cannot attribute is still
a real deny, and attributing it to a guessed rule would be worse than leaving it unattributed.

⛔ **`Teardown` IS A CLOSE, NEVER A DENY.** A session ending is not a block; reading it as one would
invert the row's meaning and manufacture denials out of normal traffic — the trap FortiOS `close`
and PAN-OS `reset-both` sit either side of. Actions come from the SHARED `lib/syslog/actions.js`
sets, never a private copy.

⛔ **NO TIMESTAMP IS INVENTED.** An ASA syslog line carries no year and no timezone, so `eventAt`
stays null and `received_at` anchors the row — the same call `parseFortinet` makes when `tz` is
absent.

**The generator REPLAYS, it does not template.** `scripts/mockSyslog.js` imports the SAME fixtures
the parser is tested against and substitutes only variable values (addresses, ports, ACL names),
so every structural quirk survives verbatim and the generator cannot drift in step with the parser
— which is what `mockSyslog`'s own header warns about. ⛔ ACL names carry their SEEDED INTENT: the
first version picked one at random and produced `deny, permit` on all three including the deny
rule. Verified live on the mock fleet: **867 ASA events, 0 unattributed**, correlation populated on
all three access-lists, each showing only its own intent.

### The other three vendors remain BLOCKED ON EVIDENCE

Researched 2026-10-03. **Check Point** and **Forcepoint** are both tractable — Elastic ships
Check Point captures (RFC 5424 + bracketed `key:"value";`, with real quirks like a double-colon
`sys_message::`), and Forcepoint NGFW exports **CEF**, a self-describing open standard rather than
a proprietary layout. **Sangfor is not**: the only public sample is a FortiSIEM forum thread with
two free-text lines whose own field labels disagree (`"Log type"` vs `"Log Type"`), and Fortinet
staff state it is "not compatible with SIEM". ⛔ Do not write a Sangfor parser from that.

## CEF: Forcepoint NGFW + Check Point Log Exporter (added 2026-10-04)

`lib/syslog/cef.js` is the ArcSight CEF **grammar**, shared; `vendorParsers.parseCefEvent()` maps a
CEF record to the event shape. Five of six vendors can now be parsed. Only **Sangfor** remains.

⛔ **CEF IS THE ONE PLACE "DOCUMENTATION" IS NOT THE TRAP THIS REPO WARNS ABOUT.** Every other
parser reverse-engineers a proprietary layout, because vendor docs lie about field names. CEF is a
PUBLISHED, SELF-DESCRIBING format: the header names the vendor and product, the extension carries
its own labels. There is no layout to guess. What the grammar cannot tell us is which SLOT a vendor
puts a fact in — and that part was still read off samples.

⛔ **THE FIXTURES ARE RECONSTRUCTIONS, NOT CAPTURES, AND THAT IS A WEAKER CLASS OF EVIDENCE.** No
Apache-licensed Forcepoint or Check Point captures exist (logstash-patterns-core carries only Cisco
and SuSE); the sources that publish samples are Elastic License 2.0 or ordinary documentation. So
`tests/fixtures/cefSyslog.js` holds OUR reconstruction of a structure corroborated across
independent sources, and says so. **A disagreement with a real device is resolved in the device's
favour, without argument.** Contrast `tests/fixtures/ciscoAsaSyslog.js`, which is verbatim Apache-2.0
captures.

⛔ **`cs<N>` SLOTS ARE VENDOR-ASSIGNED, AND THAT IS WHY THE LABELS EXIST.** Forcepoint puts its rule
id in **cs1** (`cs1Label=RuleID`); Check Point puts its rule **NAME** in **cs2**
(`cs2Label=Rule Name`). Reading `cs1` unconditionally takes Check Point's **NAT rule id** for a rule
name — a wrong value that looks entirely plausible. `bySlotLabel()` resolves every slot through its
`Label` companion, which is what lets ONE parser serve both vendors. A mutation reading `cs1`
directly nulls Check Point's rule name on every fixture.

⛔ **THREE THINGS A NAIVE CEF PARSER GETS WRONG, all observed in real samples:**
1. **Extension values contain SPACES** — `deviceExternalId=NGFW2 node 1 dvchost=...`. Splitting on
   whitespace yields `NGFW2` plus two tokens of garbage that look like data.
2. **`=` is escaped inside values** — `originsicname=CN\=gate2,O\=...`. Splitting on a bare `=` cuts
   the value in half and invents a key called `O\`.
3. **`|` is escaped inside header fields.** The header is POSITIONAL, so an unescaped split shifts
   every later field left by one and the severity reads as a signature name.

⛔ **CHECK POINT HAS THREE EXPORT FORMATS, NOT TWO** — CEF, a semicolon-delimited `key:"value";`
native form, and a pipe-delimited `key=value|` form. Only CEF is handled. **Detection must never
assume a Check Point device speaks CEF**; the other two remain unparsed and their events are stored
unattributed, which is correct.

⛔ **`proto` DISAGREES ACROSS VENDORS**: Forcepoint sends the IP protocol NUMBER (`6`, `17`), Check
Point a name (`tcp`). Both normalise to a lowercase name; an unrecognised value passes through
verbatim, because an unknown protocol is a fact, not a gap. ⛔ **`rt` is used ONLY when it is
plainly a 13-digit millisecond epoch** — a wrong scale backdates the row to 1970, present in the
table and outside every time window, the same lesson FortiOS `eventtime` digit-length encodes.

### ⛔ Two product defects this exposed, neither visible on a two-vendor fleet

**1. `Discard` was in NEITHER action set.** Forcepoint says `Discard` where others say `deny`/`drop`,
and `lib/syslog/actions.js` knew neither. The failure is ASYMMETRIC: `log_hit` fails SAFE (an
unrecognised verb never counts as "reached"), but retention fails UNSAFE —
`shouldKeepRawMessage` keeps the raw line for DENIED traffic, so **every Forcepoint block would have
silently lost its raw text** at `SYSLOG_RAW_MESSAGE=security`, precisely the events an investigation
opens. `tests/vendorActions.test.js` now fails the build if any parser can emit an action in neither
set.

**2. A Forcepoint device could never be attributed at all.** The collector's map read `mgmt_ip` and
`snmp_host`; a Forcepoint device has **neither** — it is reached through the SMC. Measured: 637
Forcepoint events, every one `device_id NULL`. ⛔ **But the naive fix is wrong: ONE SMC MANAGES MANY
ENGINES**, so `smc_host` is routinely shared, and a last-writer-wins map files every one of those
devices' events under whichever row returned last — a fabricated attribution, indistinguishable
from a real one once stored. `lib/syslog/deviceMap.js` (extracted so it is testable, as
`eventShape.js` was) therefore **withholds any address claimed by more than one device**, reports
it, and lets an explicit `device_syslog_sources` row resolve it. The same hazard already existed for
a shared `snmp_host` and had simply never been exercised.

**Verified live on the mock fleet:** 6,000 events, **all five parseable vendors attributed, zero
unattributed**, rule-hit correlation populated for every one, each rule showing only its own intent.

---

## 13. Sophos SFOS — syslog (v2.231.0). Verified on a live appliance, 2026-11-19

⛔ **FULLY WIRED as of v2.233.0.** This line said "PARSER ONLY. There is no Sophos ADAPTER yet"
through v2.231.x and "the registry wiring is what remains" through v2.232.0 — both are now done:
`lib/adapters/sophos/`, `ADAPTERS`/`DEFAULT_METHOD`, `VENDOR_META`, `VENDOR_PARSERS`, `VENDOR_CPES`,
`auditChecksSeed`, `osBranch`. **What genuinely remains is the hub side**: the nocvault-eol
`cve_ingest_state` has no Sophos ingest targets, so on a site that cannot reach NVD directly (which
CLAUDE.md records as the reference deployment's actual state) `VENDOR_CPES` alone yields nothing.

Verified against SFOS **22.0.3 MR-3-Build576** in a lab (`secvault-lab/`), 6,621 captured lines.
⛔ **BOTH FORMATS WERE CAPTURED SIMULTANEOUSLY FROM THE SAME EVENTS** via two syslog servers on one
host, so every mapping is a same-event comparison. Full analysis:
`secvault-lab/findings/FIELD-MAPPING.md`. Fixtures: `tests/fixtures/sophosSyslog.js`.

### ⛔ TWO FORMATS, AND NEITHER DOMINATES

SFOS 22 labels the key=value format that every published Sophos field reference documents as
**`Device standard format (legacy)`** and warns in its own UI that it "won't support the new
firewall features in future versions". Measured over 3,092 paired events:

| | legacy | standard |
|---|---|---|
| zone on Anti-Virus / Content Filtering rows | **absent** | present (857 rows) |
| src/dst country on those rows | **absent** | present (856 rows) |
| a MEASURED zero byte counter | stated (`recv_bytes=0`) | **field omitted** (91 rows) |
| orphan tokens with no key | 2,161 | **0** |
| bytes for one identical event | 1407 B | 614 B |

Standard is the better default — a lost zone breaks segmentation attribution outright, while a lost
zero is a weaker claim about bytes that already sum correctly. But it IS a trade with a named cost,
not a clean win, and anything needing "received exactly zero" must read the legacy format.

### ⛔ `device_name` NAMES DIFFERENT FACTS IN THE TWO FORMATS

    legacy    device="V01001C6CT6BFD5"       device_name="SF01V"   <- the MODEL
    standard  device_name="V01001C6CT6BFD5"  device_model="SF01V"

A parser keyed on `device_name` returns the model on one and the appliance on the other. Both are
plausible strings and neither errors. The FORMAT decides this, never the key name.
⛔ The fields actually NAMED for a serial — `device_id` / `device_serial_id` — carry the literal
string `NULL` on 100% of all 6,621 lines. `meaningful()` gained `null` for this.
⛔ **RESOLVED BY EXPERIMENT (2026-11-19): IT IS THE HOSTNAME.** SFOS defaults the hostname to the
serial, so the appliance reported one string for both and reading the capture could not separate
them. It was RENAMED to `V01001C6CT6BFD5-test` and re-captured: the value followed the hostname in
BOTH formats. **So SFOS syslog carries no serial at all** — `deviceSerial` is NULL by measurement,
not by caution, and a Sophos serial must come from SSH (`system diagnostics show version-info`).
Fixtures: `RENAMED` in `tests/fixtures/sophosSyslog.js`.

⛔ **AND THE MODEL STRING IS NOT STABLE.** The same appliance reported `device_name="SF01V"`
(legacy) / `device_model="SF01V"` from 06:39 to 07:55 and **`SFVH`** from 08:09 onward — across a
reboot, with no model change made. The SSH banner and the Control center said `SFVH` throughout.
Nothing may key on it; it stays in `fields` and is deliberately never promoted to a normalized
column. A test asserts no normalized field carries either value.

### ⛔ THE GRAMMAR IS NOT FortiOS's — `parseKeyValueSpanning`, not `parseKeyValue`

Legacy emits **unquoted values containing a space**: `ether_type=IPv4 (0x0800)`, on 2,118 lines.
`parseKeyValue`'s bare-value branch is `[^\s]*` and drops `(0x0800)` on the floor.
⛔ **But spanning naively is WORSE**: legacy also emits bare orphan tokens with NO KEY
(`src_ip=172.16.16.2 N/A message="..."`, 43 lines), and absorbing them produced
`srcIp = "172.16.16.2 N/A"` — a fabricated address. A bare value therefore continues ONLY into a
**parenthesised** token, which is the only multi-word unquoted shape this device emits; everything
else is recorded under `$unparsed` — counted, never merged and never dropped.
⛔ Fortinet was deliberately NOT repointed at the looser grammar: that would change a live-verified
parser on a 16-firewall fleet to fix a problem Fortinet's evidence does not show.

### ⛔ THE TRAFFIC VERDICT IS IN `log_subtype`, NEVER `status`

Legacy `status` carries Allow=2063/Deny=39. **Standard's `status` carries only Successful and
Renew** — the verdict is not in that field at all. Keying on `status` leaves every standard-format
row with a null action, and `log_hit` (decision rule **2** of the CVE priority tree, ABOVE CVSS 9.0)
could never fire for this vendor. `actions.js` gained `allowed`; `denied` was already there, and
that asymmetry is why it mattered — blocks would have classified while allows answered `unknown`.

### ⛔ A SESSION EMITS TWO ROWS AND THE FIRST ONE'S COUNTERS ARE NOT A MEASUREMENT

Same `con_id`, `connevent` Start then Stop. Of 1,031 legacy Start rows **ALL** carry
`sent_bytes=0`; of 1,033 standard Start rows **NOT ONE** carries a bytes field. Legacy's zeros are
the `hit_count DEFAULT 0` bug arriving over syslog. A third state exists — `Interim`, a running
mid-session counter — so **only `Stop` is summable**. Sophos is therefore a THIRD sizing category
beside paloalto (summable) and fortinet (cumulative, never summable).

### ⛔ THE LEGACY FORMAT IS INCONSISTENT WITH ITSELF

Its Firewall rows spell the session id `connid`; its **Content Filtering rows spell it `con_id`**,
the standard format's spelling. Reading only `connid` dropped the id from 856 of 3,092 paired
events. Likewise `category` is `http_category` in standard — a rename in the OPPOSITE direction to
the zones. **Both bugs were found by the cross-format agreement test, not by reading either format
alone**, which is the argument for keeping that test.

### Other verified facts

- **`log_id` is a BIJECTIVE dispatch key**: 25 distinct ids, none mapping to more than one
  `(log_type / log_component / log_subtype)` triple.
- **PRI encodes severity usably**: `<26>` critical, `<29>` notice, `<30>` info (facility 3 daemon).
- **Neither format carries a syslog header** — `<PRI>` is followed immediately by `device…`. No
  RFC 3164 timestamp/host/tag, and "Standard syslog protocol" is **not** RFC 5424 (no version digit).
- **`timezone=` is a zone NAME, not an offset** (`"GMT"`), and legacy splits the time across
  date/time/timezone. Only GMT/UTC/Z and explicit ±HHMM are resolved; an ambiguous abbreviation
  (IST is Irish, Indian AND Israeli) leaves `eventAt` NULL rather than anchoring it somewhere
  invented. Standard's `timestamp="…+0000"` is self-describing.
- **`R1` is not an ISO country code** — it is Sophos's code for reserved/private space. Kept
  verbatim, following the precedent `meaningful()` sets for FortiOS's "Reserved", so this column is
  NOT ISO-only.
- **App-ID works on UNDECRYPTED TLS**: `app_name="GitHub"` on an https request with
  `DecryptHTTPS` disabled — SNI-derived.
- **12 log classes verified.** IDP (IPS), ATP, VPN, authentication and SSL/TLS inspection produced
  **zero** rows: the lab appliance has no IPS signature database (`IPS_CAT_VER="0"`), and eleven
  attack patterns plus a 17-port version sweep produced nothing. ⛔ Those classes are **UNVERIFIED,
  not absent**, and `classifySophos` returns null for them rather than mapping from documentation.

### 13b. Sophos SFOS — the ADAPTER (v2.232.0)

`lib/adapters/sophos/{api,parser,console,index}.js`. ⛔ Section 13 above said
"PARSER ONLY. There is no Sophos ADAPTER yet" — that is no longer true; the
registry wiring (`ADAPTERS`, `VENDOR_META`, `VENDOR_PARSERS`, `VENDOR_CPES`,
`auditChecksSeed`, `osBranch`, the hub's ingest targets) is what remains.

⛔ **TWO TRANSPORTS IN ONE ADAPTER, forced by the device.** The XML API has no
version, licence or HA surface — nine candidate entity names all return 529 and
`APIVersion="2200.1"` does not track the patch level — while the SSH console has
no command that dumps a rulebase. Neither can do the other's job.

| capability | transport | notes |
|---|---|---|
| `getRules` / `getConfig` / `getObjects` / `getInterfaces` / `getRoutingTable` | XML API | |
| `getVersion` (+`contentVersions`) / `getHaStatus` / `getDiskUsage` / `getPerformanceMetrics` | SSH console | |
| `getLicenses` | — | **method ABSENT, not stubbed** |

⛔ **A DEVICE WITH NO SSH CREDENTIAL STILL COLLECTS.** `getVersion()` throws;
`collectAndStore` isolates that into `result.errors` and carries on. The cost is
stated: no version means no CVE assessment, and v2.230.0's guard reports such a
firewall as NOT ASSESSED rather than silently not-affected. The SSH connection
falls back to the API credential when no separate `ssh` one is stored — it is the
same admin account on the same appliance, and demanding it twice loses
`getVersion()` whenever an operator does not.

⛔ **`getLicenses` IS ABSENT BY MEASUREMENT.** Nine XML names return 529;
`system license show` and `system diagnostics show subscription-info` both return
`Unknown Parameter`; the full `system diagnostics show` list contains nothing
licence-shaped. The optional-capability contract says an absent method is how an
adapter declares what it cannot do, so `/lifecycle` shows Sophos as not
collectable rather than as "no renewals due" — which would make the one vendor we
cannot read look like the healthiest on the fleet.

⛔ **THREE RESPONSE SHAPES AND ONLY ONE IS AN ERROR**, discriminated by the
PRESENCE OF A `code` ATTRIBUTE: `<Status code="529">` is a failure,
`<Status>No. of records Zero.</Status>` is a measured empty collection, anything
else is data. All three arrive as **HTTP 200**. `interpretResponse()` is extracted
as a PURE function precisely so this can be exercised — mutating it to treat an
error as empty goes red.

⛔ **RULE ORDER IS A LINKED LIST** (`Position: Top` / `After` + `<After><Name>`),
with no sequence number anywhere. `orderRules()` walks the chain and THROWS on an
unhandled Position value, a cycle, zero or multiple Tops, a duplicate name, or an
unreachable rule — naming what it saw. A guessed order is a confident wrong answer
about reachability.

⛔ **AN OMITTED ELEMENT MEANS ANY.** The `Lab` rule permits any source,
destination and service and carries none of those three elements; the auto-added
MTA rule carries no zones at all. Mapped to `['any']`, never `[]`.

⛔ **`hit_count` IS ALWAYS NULL** — the XML API reports no hit counts across any
of the 24 readable entities. `unused` findings must never be derived from it;
rule usage comes from syslog correlation, which works because the log rows carry
the rule NAME. ⛔ Consequently **`rule_id_vendor` IS THE RULE NAME** — the API
offers no numeric id and no UUID — so RENAMING A RULE BREAKS ITS HISTORY.

⛔ **CONFIG REDACTION IS AN EXACT TAG LIST, NOT A KEYWORD PATTERN.** SFOS's
AdminSettings carries `PasswordComplexityCheck`, `MinimumPasswordLength` and
`MinimumPasswordLengthValue` — the fields an audit check grades. A `/pass/i`
matcher would blank all three while claiming to protect something. The matcher is
`paloalto/parser.js`'s `TAG_OPEN_ATTRS` form, which requires whitespace or `>`
after the tag name. ⛔ The list is NECESSARILY INCOMPLETE: the verifying appliance
had no directory server, no VPN and no users, so the secret-bearing schema could
not be enumerated. Re-enumerate against a configured appliance; a missing name is
a plaintext secret in a readonly-readable table.

⛔ **THE CONFIG SNAPSHOT IS A BOUNDED ENTITY LIST.** `ApplicationFilterPolicy`
measured **305 KB** and `WebFilterPolicy` 40 KB on an appliance with NOTHING
configured, and `device_configs` stores a row per pull — a table CLAUDE.md records
reaching 449 MB of a 529 MB database. A vendor signature catalogue is not
configuration.

⛔ **`cpuPercent` IS ALWAYS NULL from the SSH transport.** `system diagnostics
show cpu` returns /proc/cpuinfo — a processor model name and core count, no load
figure. CPU utilisation for this vendor arrives in the syslog System Health class.
⛔ `memoryPercent` uses `(MemTotal - MemAvailable) / MemTotal` and the formula is
carried in `raw`, because three different "used %" are derivable from that output
and the SFOS console prints a third one — the gap has to be explainable rather
than read as SecVault being wrong.

⛔ **THE REBOOT HAZARD IS STRUCTURAL, NOT CAREFUL.** The login menu's option 7 is
*Shutdown/Reboot Device* and takes a bare digit; the console opens with `system
restart` and `system shutdown`. Every command is a module constant, `'4'` is the
only keystroke ever sent to the menu, and `sshClient.runCommands` writes nothing
until it has observed `promptRegex`. A test asserts no command in this module's
vocabulary matches `restart|shutdown|reboot|halt|reset|factory`.

Tests: `tests/sophosAdapter.test.js` (52 cases) against
`tests/fixtures/sophosApi.js`. Four guards mutation-verified red: error-as-empty,
guessed rule order, any-as-empty, and an over-broad redaction matcher.

---

## 14. Juniper Junos / SRX — syslog ONLY (v2.234.0). NO ADAPTER.

`lib/syslog/junos.js` (the grammar) + `parseJuniper`/`classifyJunos`/`junosAction` in
`lib/syslog/vendorParsers.js` (the mapping). 53 tests in `tests/juniperSyslog.test.js`,
105-line fixture in `tests/fixtures/juniperSyslog.js`. Full field analysis:
`secvault-lab/findings/JUNIPER-SYSLOG.md`.

⛔ **THERE IS NO JUNIPER ADAPTER, AND `juniper` IS DELIBERATELY ABSENT FROM `VENDOR_META`,
`ADAPTERS`, `VENDOR_CPES`, `VENDOR_PARSERS`, `auditChecksSeed` AND `osBranch`.** This is a
parser-only landing, the same state the Sophos parser shipped in at v2.231.0, two releases ahead of
its adapter. `tests/vendorRegistryParity.test.js` iterates `VENDOR_META`, so it CANNOT see a
syslog-only slug and does not fail — that asymmetry is recorded by a test of its own in
`juniperSyslog.test.js` section 11 rather than left to be rediscovered.

⛔ **AND THERE IS NO LONGER A vSRX DOWNLOAD TRIAL TO VERIFY IT AGAINST — MEASURED 2026-11-19.**
Both `juniper.net/{us,gb}/en/dm/download-next-gen-vsrx-firewall-trial.html` now answer `301` to the
**HPE home page** (not an HPE trial page — the corporate homepage), the self-serve funnel having
gone with the acquisition; it was restricted to existing Juniper customers before that anyway.
⛔ **`vJunos-labs` IS FREE AND DOES NOT HELP**: it ships vJunos-router/switch/Evolved and **no
vSRX**, so it has no security policies and emits no `RT_FLOW`, `RT_IDP` or `RT_UTM` — every family
this mapping is about. ⛔ **AND NEITHER DOES vLabs — IT WAS RETIRED ON 2026-10-31**, which an automated read of its page
reported as "likely still operating" while a red retirement banner sat at the top of it; the banner
then advertised three replacement trials whose own links are among the dead URLs above. `juniper.net/try`
redirects to **hpe.com/contact-hpe**, and `hpedemos.com` carries Aruba Central and Mist AI only, no
SRX. **There is no free self-serve vSRX left.** What remains is the AWS/Azure Marketplace listing —
software free for 30 days, EC2 billed separately (~$0.09/hr on the recommended `c5.large`), and
⛔ **it converts to a paid subscription at $0.65/hr unless cancelled**. ⛔ A page that cannot confirm
its own status is UNCONFIRMED, not live; where the decision turns on whether a service still exists,
look at the rendered page rather than a summary of its text.
⛔ Whichever device is eventually used, the capture needs no egress: **`structured-data` is valid at
`[edit system syslog file <name>]`**, not
only under `host` (Junos 8.3+, RFC 5424), so the device writes the exact bytes to a local file and
`show log` prints them. `secvault-lab/verify-junos-capture.js` turns such a capture into a
CONFIRMED / CONTRADICTED / **NOT EXERCISED** verdict per frozen claim — the third state existing
because a capture with no RT_UTM line cannot confirm the `url` trap and must not look as though it
did. Runbook: `secvault-lab/RUNBOOK-JUNIPER.md`.

⛔ **THE EVIDENCE IS A THIRD-PARTY ANONYMISED CORPUS, NOT A LIVE APPLIANCE** — Elastic's own SRX
integration fixtures, 105 lines, 43 MSGIDs, 145 distinct structured-data keys. That is a long way
above documentation and it is NOT what every other parser in this file was built from. The
anonymisation destroyed the `junos@` enterprise id in four incompatible spellings, two containing
letters, which is why **detection never anchors on the SD-ID** — it anchors on the APP-NAME/MSGID
vocabulary, and 5 real flow lines omit the SD-ID entirely anyway.

### The traps, each measured

| trap | what it costs if missed |
|---|---|
| **RT_FLOW has NO `action` field** (0 of 24 lines) | the busiest family gets a null action; `log_hit` — decision rule 2, above CVSS 9.0 — can never fire for this vendor. The MSGID is the only source. |
| `url` is a hostname on WEBFILTER and a **MALWARE NAME** on `AV_VIRUS_DETECTED_MT` | a malware name in `url_hostname`, indexed as a site somebody visited |
| `category` means three things; a URL category **only on WEBFILTER** | threat-feed names (`secintel`) filed into the web-filtering dimension |
| two zone spellings (`source-zone-name` / `source-zone` on RT_UTM) | the zone drops from whichever family uses the other — 6 lines or 61 |
| two session-id spellings (`session-id-32` / `session-id`) | the id drops on whichever half of the fleet runs the other release — the Sophos `connid`/`con_id` split again |
| three protocol keys over two value domains (`protocol-id` numeric, `protocol-name`/`protocol` words) | null protocol on two families |
| **byte counters are CUMULATIVE** | summing over-counts by **2.55×**. `bytesSummable` is hard `false`. |
| `threat-severity` is a WORD on RT_IDP and a NUMBER on RT_SECINTEL | two scales conflated into one ramp |
| `rule-name` is an **IDP rule** on RT_IDP and not RT_FLOW's concept | an IDP rule number stored as a firewall policy id |
| escaped `\]` inside an SD value | a first-`]` scan truncates a VPN event and drops every key after it |
| `0 0` ports on `FW:` packet-filter lines mean N/A | phantom port-0 traffic in every per-port rollup |
| `unknown-user` | a fake account name in user-attribution views (stripped **locally**, not by widening the shared `NOT_AVAILABLE` set) |

### What Junos simply does not carry

**No serial, chassis-id, model or platform on ANY of the 145 keys** — `deviceSerial` is null by
measurement, and a serial must come from an adapter. **No country, geo, region or city** — any
country for a Juniper event is OURS, derived by GeoIP downstream. **No rule UUID.**

### Time

A **zoned header wins**, then `epoch-time`, then a zoneless header. The findings document says to
prefer `epoch-time` on RT_IDP; that is right about the REASON (zoneless stamps cluster there) and
applying it unconditionally **discards sub-second precision** — `…03.193Z` came back `…03.000Z`.
12 of 105 stamps are zoneless, 4 carry an epoch, and the remaining **8 reach the local-zone
assumption, which is RECORDED on the row as `fields.$eventAtZoneless`** rather than being
indistinguishable from a stamp the device zoned.

### Brief format — a NAMED GAP, never silence

`structured-data` is **not** the Junos default. An SRX without it emits RFC 3164, which has five
whitespace fields after the PRI just as RFC 5424 does — so the header regex **"succeeds" on it**
and would report `timestamp=Nov`, `hostname=19`, `appName=09:37:51`. Confident garbage, nothing
errors. `parseJuniper` guards on `looksJunosBrief` FIRST and returns a field-free row carrying
`$formatGap: 'junos_brief'` and the exact command to fix it. Only the RFC 3164 hostname is taken,
because its position is the RFC's and not a Junos field mapping.

### ⛔ The seam this opened — see gotchas.md

A syslog-only vendor made `DeviceForm`'s `VENDOR_META[vendor] || VENDOR_META.forcepoint` fallback
REACHABLE for the first time. `components/devices/DiscoveredDeviceActions.js` now drops an
unmanageable vendor from the Add Device prefill and says so on screen.

---

## 15. SonicWall SonicOS "Enhanced Syslog" — syslog ONLY (v2.235.0). NO ADAPTER.

`lib/syslog/sonicos.js` (grammar) + `lib/syslog/sonicosCatalogue.js` (the `m=` dispatch, 349 vendor
ids + 21 derived) + `parseSonicwall` in `vendorParsers.js`. 60 tests in
`tests/sonicwallSyslog.test.js`, 220-line fixture. Analysis:
`secvault-lab/findings/SONICWALL-SYSLOG.md` (1,083 lines).

⛔ **NO ADAPTER, and `sonicwall` is deliberately absent from `VENDOR_META`, `ADAPTERS`,
`VENDOR_CPES`, `VENDOR_PARSERS`, `auditChecksSeed` and `osBranch`** — the same parser-only landing
Juniper took at v2.234.0 and Sophos at v2.231.0. See gotchas.md on the `DeviceForm` seam that a
syslog-only vendor opens; `DiscoveredDeviceActions` already refuses to prefill an unmanageable
vendor, so this slug inherits that guard.

⛔ **THIRD-PARTY ANONYMISED CORPUS** — Elastic's integration fixtures, 220 lines, 55 keys, 44
message ids. The SYNTAX is settled unusually well: **our address splitter and Elastic's independent
implementation agree on all 1,724 address facets across 220 events with zero mismatches.** What a
key MEANS on an unseen firmware is not settled by that.

### ⛔ THE BYTE COUNTERS — the sharpest trap, and worse than Sophos's

`sent=`/`rcvd=` appear on connection-OPEN (`m=98`), on TCP abort (`m=713`), on web-management
(`m=526`) and on web hits (`m=97`) — carrying **real, small, plausible numbers**: 52/60/64 (TCP SYN
sizes) and 46 (an RST). **Not one counter anywhere in the corpus is literally `0`**, so unlike
Sophos's session-start zeros there is no sentinel to notice. It is a partial count wearing a
total's clothes.

⛔ **IT IS A THREE-WAY COUNT**: one socket reports `m=98 sent=52`, then `m=1235 sent=52`, then
`m=537 sent=334` — the SYN twice before the total. Measured over one corpus file, naive `SUM(sent)`
gives **91,066 against 86,898 real: +4.8%, and NOT a constant** — it scales with short connections
and with how many RSTs the device emits.

**So bytes are read on `m=537` ONLY** (`bytesSummable := m === '537'`). ⛔ And `m=537` only fires
when a connection CLOSES, so a SonicWall byte rollup is complete only for connections that ended in
the window — a permanent vendor limitation that must be stated beside any figure.

### ⛔ `fw_action` IS `NA` ON THE TWO EVENTS THAT MATTER MOST

Measured: `m=537` is `NA` on 37 of 45 and `m=98` on 31 of 42. Reading the field and stopping leaves
every SonicWall connection with a null action and **`log_hit` — decision rule 2, ABOVE CVSS 9.0 —
could never fire for this vendor.** `NA` means the field does not apply, not that nothing was
decided. SonicOS opens and closes only connections it PERMITTED, so those two ids supply the
verdict, exactly the call CLAUDE.md already records for Fortinet's `close`. ⛔ **Only those two**:
`m=97` and `m=1382` also carry `NA` and neither is a traffic decision. ⛔ `mgmt` names a PLANE, not
a verdict, and is nulled. ⛔ `forward` was added to `ALLOWED_ACTIONS`.

### The other traps

| trap | cost if missed |
|---|---|
| `src=`/`dst=` are COMPOUND, 8 shapes, with an empty IP slot AND an empty port slot | a naive split stores `fe80` as an IP; an empty port stored as `0` lands in every per-port rollup |
| a compressed IPv6 `::1` splits to `['','','1']` | part[2] reads as an interface named "1" — **only the `^[A-Za-z]` interface pattern refuses it** |
| IPv6 arrives in parallel `srcV6=`/`dstV6=` keys, never in `src=` | the address is simply lost |
| **`m=713`: the SOURCE is the firewall itself** (53 lines, 24%) | a top-talkers rollup credits a quarter of the device's events to the firewall. Stored as reported, flagged `$replyDirection` — **never swapped**, or the row disagrees with the raw line |
| `code=` is a URL-category id on `m=14`/`m=97` and an **ICMP code** on `m=38` | both are small integers and indistinguishable without `m=`; it is never promoted |
| `dstname=` is a hostname on web events and an **email attachment name** on anti-virus events | gated on `arg=` being present, which is Elastic's own behaviour |
| `app=` is a NUMERIC id, `appid=` a different number, `appName=` the only name | falling back to `app=` put a bare integer in `application` on 161 of 220 events |
| `appName='General UDP'` is a NON-identification | every unidentified flow looks identified |
| `proto=`'s tail is a service name OR a port, and does not track `dstPort` | a port stored as a service name |
| `time=` is zoneless on 204/220 and **one appliance emitted both forms 7h03m apart** | a per-device zone decision gets one batch wrong by the local offset — the suffix is honoured PER LINE |
| `usr="Unknown (SSO failed)"`, `ipscat="N/A"` | a fake username and a fake threat name |
| `n=` is a LOG MESSAGE COUNTER, `sess=` an admin session TYPE | mapping either to `sessionId` makes every event its own session |

### ⛔ What SonicOS does not carry

**No device name** — `id=` is the constant `firewall`, `fw=` is the IP of the interface the EVENT
CONCERNS and **varies within one serial** (keying on it splits one firewall in two), and the RFC
3164 header is a third address matching neither. Elastic has none either. **No country. No session
id. No vdom.** `deviceSerial` ← `sn=`, and ⛔ **its shape is never validated** — the corpus's values
are anonymiser output (`000SERIAL`, `XXXX`, `123456789`), so a rule built from them would reject
real appliances.

### ⛔ SEGMENTATION IS NOT SUPPORTED FOR THIS VENDOR, AND THE BLOCKER IS VOCABULARY

Zones exist (`srcZone=`/`dstZone=` on 120/220) but there are **THREE disagreeing vocabularies**: the
zone keys carry a SECURITY TYPE for built-in zones (`Trusted`/`Untrusted`) and a NAME for custom
ones (`TEST`), while `rule=` embeds a third pair — a rule filed `LAN->WAN` sits beside
`srcZone=Trusted`, and `157 (SSLVPN->SERVER)` beside `TEST`/`Trusted`. **Three names for two
zones.** Which string matches the appliance's own `show zone` cannot be settled from this corpus.
`$ruleZonePair` is preserved in `fields` and nothing is promoted. ⛔ **Do not claim SonicWall
segmentation support** — the failure mode is safe (`unknown`, not `ok_blocked`) but the feature
would be silently inert. ⛔ `m=98` NEVER carries a zone, and `m=537` only 69% of the time.
