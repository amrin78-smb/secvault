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
4. **Hit counts: REAL on REST, always ZERO on SSH.** REST fetches real per-policy hit counts via
   `GET /api/v2/monitor/firewall/policy`, fetched per-VDOM (policy IDs are only unique within a
   VDOM). SSH passes `[]` as stats — `diagnose firewall iprope show ...` (the CLI equivalent) is
   "an undocumented, firmware-specific debug format," deliberately not attempted. Every
   SSH-collected rule has `hit_count: 0`, which Phase 5 reads as `unused` — an SSH-collected
   FortiGate will flag every rule unused. Use REST if unused-rule findings matter.
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
   honest `[]`, not a failure).
5. **XML API's default xpath is single-vsys only** (`vsys1`, hardcoded as `DEFAULT_VSYS`). Zero
   rules from that xpath is ambiguous — could be genuinely empty OR a multi-vsys device whose rules
   live under vsys2/vsys3. `index.js:getRules()` only tries the predicate-free any-vsys fallback
   (`api.getSecurityRulesAnyVsys()` → `parser.parseRulesDeep()`) when the primary path returns
   zero — never regresses the working single-vsys case.
6. **Hit-count enrichment (both transports) is ADDITIVE and can never affect the returned ruleset**
   — wrapped separately, never throws past its own boundary, defaults every rule to `hit_count: 0`
   on any failure. SSH specifically gates on `containersFound === 1` before even attempting vsys-name
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
implemented. `getSnmpMetrics` and `getVpnSessionSummary` **not implemented** (Check Point is
explicitly deferred to "SNMP Phase 2," not started).

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
`getSnmpMetrics` all implemented. `getVpnSessionSummary` **not implemented** (only a minimal
presence-only `webvpn.enabled` config field exists — see below).

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
`getVpnSessionSummary` not implemented at all.

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
5. **`hit_count` is a static literal `0` for every rule, unconditionally** — no attempt at
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
| forcepoint | SMC REST | `smc_api` (raw string) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (SMC-bypass exception) | ✗ | never — throws |
| fortinet | REST + SSH | `rest_api` / `ssh` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | never — throws |
| paloalto | XML API + SSH | `rest_api` / `ssh` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ | never — throws (SSH has a Panorama fallback before throwing) |
| checkpoint | Mgmt API | `rest_api` | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ (Phase 2) | ✗ | never — throws |
| cisco_asa | SSH | `ssh` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ (presence-only `webvpn.enabled` in config only) | never — throws |
| sangfor | SSH | `ssh` | ✓ | ✓ | ✓ | ✓ | stub (always empty) | ✓ (MIB-II/HR-MIB only) | ✗ | never — throws |

All 6 vendors additionally use a SEPARATE `credential_type='snmp'` for `getSnmpMetrics()`, never
mixed with the management-plane credential.

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
