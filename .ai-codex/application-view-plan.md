# Application-Centric View — proposal (drafted 2026-09-15, NOT BUILT)

Status: **proposal only.** Nothing in this file exists in code yet. It is the plan for the one
capability where the competitive table has SecVault at "None" and both leaders shipping: Tufin's
SecureApp and AlgoSec's AppViz/BusinessFlow.

---

## 1. What the competitors actually sell

Strip the marketing and an application-centric view is one idea:

> A business application is a named set of **flows** — (source, destination, service). Stop asking
> "what does rule 47 do" and start asking "what does SAP need, which rules deliver it, and what
> breaks if I touch them."

From that one idea they derive everything they demo:

| capability | what it means |
|---|---|
| Connectivity map | Application → its flows → the rules across N firewalls that permit each one |
| Broken-flow detection | A declared flow that nothing permits — the app is (or will be) down |
| Impact analysis | "If I remove rule 47, which applications lose a flow?" |
| Ownership | Every rule traced to an application and therefore to a business owner |
| Orphan rules | Rules serving no declared application — the decommission list |
| Decommissioning | Retire an application → the exact rules that can now go |
| Change requests | Framed as "SAP needs this flow", not "add a rule" |

⛔ **The half they do not do.** In both products the application model is **DECLARED** — a human
types the flows, or imports them from a CMDB — and then nobody re-verifies it. The map is accurate
on the day it is entered and decays silently from then on. Neither product tells you which parts of
its own map it could not check. That is the gap, and it is the same gap this product has exploited
everywhere else.

## 2. The thesis for SecVault's version

> **Everyone else's application map is a declaration. Ours is a declaration that gets re-checked
> against the collected rulebase on every pull, and that states which flows it could not verify.**

This is the same shape as `/segmentation` — declared intent, evaluated two ways, honest about
coverage — moved from ZONE granularity to FLOW granularity. That is deliberate: segmentation is the
proof that the pattern works here, and it means most of this is assembly, not invention.

## 3. What already exists (why this is cheaper than it looks)

| need | already built | file |
|---|---|---|
| Resolve a flow against one device's rules | `queryAccessPath(rules, objects, {srcIp,dstIp,protocol,port})` — tri-state `match`/`no-match`/`unresolved`, returns the deciding rule and a `hasCaveat` flag | `lib/engines/objectResolver.js` |
| Expand address/service groups to real ranges | `buildObjectMap`, `resolveAddressField`, `resolveServiceField` | same |
| Cross firewalls, apply NAT, longest-prefix routing | `simulateMultiHopPath()` | `lib/engines/topology.js` |
| Declared-intent CRUD + evaluation pattern | `segmentation_intents`, `listIntents`, `evaluateSegmentation` | `lib/engines/segmentation*.js` |
| Is a rule actually used? | `enrichRulesWithLogEvidence` — separates `measured` / `measured-zero` / `no-coverage` | `lib/engines/ruleHitCorrelation.js` |
| Surfacing findings as work | `workQueue.js` / `workQueueData.js` | — |
| Propose removals and VERIFY they happened | `ruleChangeRequests.js` | — |
| A branded PDF of any of it | the report chassis + catalogue | `lib/reports/` |

`queryAccessPath` is the load-bearing one. It already takes exactly the tuple a flow is, and it is
already reused unchanged by two other engines (`topology.js`, `exposure.js`) — so a third reuse is
the established pattern, not a new dependency.

## 4. ⛔ What SecVault genuinely CANNOT answer today

This section is the point of the document. Measured on the live fleet, 2026-09-15.

### 4.1 Flow-level traffic evidence does not exist, and no query can produce it

**Every syslog rollup is either source-keyed or destination-keyed. None carries both ends.**

| rollup | src | dst | port |
|---|:--:|:--:|:--:|
| `syslog_talker_hourly` | ✓ | — | — |
| `syslog_rollup_hourly` | ✓ | — | — |
| `syslog_blocked_dst_hourly` | — | ✓ | ✓ |
| `syslog_device_inbound_hourly` | — | ✓ | ✓ |
| `syslog_app_hourly` | — | — | — |
| `syslog_rule_hits_hourly` | see 4.2 | — | — |

So **"did this flow carry traffic?" is not answerable at flow grain.** Only "did the RULE that
permits this flow see traffic" is. That is a weaker claim and Phase 1 must make it in weaker words.

⛔ `syslog_events` is **refused** as the fallback — the same refusal CLAUDE.md already records for
VPN traffic attribution, and a test enforces it there. ~28M rows/day, no suitable index, and adding
one puts the write cost on the collector at ~1,000 inserts/sec.

### 4.2 `syslog_rule_hits_hourly.source_ip` is the FIREWALL, not the session source

Found while sizing this proposal. `rollup_src` carries two different columns —

```
source_ip   the syslog frame's sender  (the firewall's own logging address)
src_ip      the parsed traffic source  (the actual host)
```

— and `RULE_INSERT` groups by `source_ip` while `TALKER_INSERT` groups by `src_ip`
(`lib/syslog/rollups.js`). The evidence, over 7 days:

```
syslog_talker_hourly      77,416 distinct src_ip
syslog_rule_hits_hourly       20 distinct source_ip   ← ~one per device, all .1/.254/.26
```

⛔ **Nothing consuming it today is wrong** — `ruleHitCorrelation` groups by rule identity, so hit
totals are correct. But the column NAME actively invites the assumption that it is the session
source, which is exactly the mistake an application view would make first. Treat it as redundant
with `device_id`. Worth a schema comment regardless of whether this feature is built.

### 4.3 Topology collection covers 2 of 6 vendors

`getInterfaces`/`getRoutingTable`/`getNatRules` exist for `paloalto` (both transports) and
`fortinet` (SSH only). A multi-hop flow crossing any other vendor ends with "path continues beyond
SecVault's managed fleet". ⛔ A flow whose path leaves coverage is **unverified, never broken** — an
application view that reported flows as broken because we stopped being able to see them would be
worse than useless on a migration weekend.

### 4.4 Hit counts are absent on the most common transport

Fortinet over SSH reports no hit counts at all (0 of 180 live rules). So `unknown` is the normal
answer for rule-level usage on a large slice of the fleet, not an edge case — same finding that
makes `/segmentation`'s DID column mostly `null`.

### 4.5 A naming collision to avoid

`syslog_app_hourly.application` is the **vendor L7 app-ID** — live top values are `ssl`,
`dns-base`, `ping`, `quic-base`, `web-browsing`. That is not a business application and must never
be presented as one, nor share a table name, column name or UI label with one.

## 5. Data model

Two tables, mirroring `segmentation_intents`' shape and constraints.

```sql
CREATE TABLE IF NOT EXISTS applications (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name         TEXT NOT NULL,
  owner        TEXT,                 -- business owner, free text; not a SecVault user
  criticality  TEXT NOT NULL DEFAULT 'normal',   -- 'critical' | 'normal'
  status       TEXT NOT NULL DEFAULT 'active',   -- 'active' | 'retiring' | 'retired'
  note         TEXT,
  created_by   TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (name)
);

CREATE TABLE IF NOT EXISTS application_flows (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  src            TEXT NOT NULL,      -- CIDR, IP, or range. NOT an object name (see below)
  dst            TEXT NOT NULL,
  protocol       TEXT NOT NULL DEFAULT 'tcp',
  port_start     INTEGER,
  port_end       INTEGER,
  expectation    TEXT NOT NULL DEFAULT 'allow',  -- 'allow' | 'deny'
  note           TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

⛔ **`src`/`dst` are LITERAL addresses, not vendor object names.** An object name is per-device
(`network_objects` is keyed by device) and means different things on different firewalls, so a flow
declared against one would silently evaluate against nothing on the others — the same failure
`zone_classifications` had when it was briefly global. The resolver already turns rules' object
names into ranges; the flow declares the range directly and meets them there.

⛔ **`expectation` is both-ways, exactly as in segmentation.** A declared `allow` flow that nothing
permits is a broken application. A declared `deny` flow that a rule permits is a violation. Both are
findings; neither is the absence of the other.

⛔ **No stored verdict column, no cached rule list.** Same rule as segmentation: a verdict is a
function of the current rulebase and traffic window. Storing one lets it go stale and be read as
fact — which is precisely the defect this feature exists to beat the competition on.

## 6. Evaluation semantics

Per flow, two independent axes. Never collapse them into one status.

**PERMITTED** — what the rulebase says (`objectResolver` / `topology`):

| verdict | meaning |
|---|---|
| `permitted` | at least one enabled allow rule matches, on a resolvable path |
| `blocked` | a deny rule decides it first |
| `unspecified` | no rule decides — ⛔ NEVER rendered as "denied". No implicit-policy data exists in this codebase for any vendor |
| `unverified` | the path left vendor coverage (§4.3), or the decision involved an unresolved object (`hasCaveat`) |

**USED** — what the traffic says, and **at rule grain only**:

| verdict | meaning |
|---|---|
| `rule-active` | a permitting rule has measured hits. ⛔ Says the RULE is used, NOT that this flow is |
| `rule-idle` | every permitting rule has a MEASURED zero |
| `unknown` | ⛔ any permitting rule cannot report usage → the whole flow is unknown. One silent rule may be the one carrying it. Common, not rare (§4.4) |

⛔ **The UI must never print "this flow is in use."** It prints "a rule permitting this flow is in
use." The difference is the whole of §4.1, and overclaiming it would hand back the honesty
advantage the feature is built on.

**Application rollup:** an application is as unverified as its least-verified flow. ⛔ An all-clear
is forbidden while any flow is `unverified` or `unknown` — the rule already enforced by
`lib/evidence.js` and pinned by `tests/evidence.test.js`.

## 7. Phasing

### Phase 1 — Declared applications, verified against the rulebase *(the whole differentiator)*
- `applications` / `application_flows` + CRUD, gated on `OPERATE` (declaring intent changes no
  device — same reasoning as segmentation).
- `lib/engines/applicationView.js` — **pure**: flow → verdict, given rules/objects. No pool.
- `lib/engines/applicationViewData.js` — the plumbing, reusing `queryAccessPath` UNCHANGED.
- `/applications`: list → application → flow table with PERMITTED and USED as separate columns,
  the deciding rules named, and a counted "could not verify" section.
- **Orphan rules**: enabled allow rules matched by no declared flow. ⛔ Rendered as "not claimed by
  any declared application", never "unused" — `unused` is `ruleAnalysis.js`'s word and requires a
  measured zero. Conflating them would manufacture deletion candidates out of an incomplete
  declaration, which is this codebase's signature bug wearing a new hat.
- Work-queue source: broken `allow` flows (evidence `reported`), permitted `deny` flows.

### Phase 2 — Impact and decommissioning
- Reverse index: rule → applications whose flows it serves. Shown on the rule row in
  `/devices/[id]/analysis`, so the existing cleanup flow gains "3 applications depend on this."
- ⛔ **Impact analysis is advisory and must say so**: it answers "which DECLARED flows lose their
  only permitting rule", which is only as complete as the declaration. A rule serving no declared
  application is not proven safe to remove.
- Retire an application → the rules only it claimed → an existing `ruleChangeRequests` request,
  which already verifies against the re-collected ruleset.
- An "Application Connectivity" report in the existing catalogue.

### Phase 3 — Real flow-level usage *(needs a schema change, not a query change)*
The only honest way to close §4.1 is a new narrow rollup carrying both endpoints:

```sql
syslog_flow_hourly (bucket_hour, device_id, src_ip, dst_ip, dst_port, protocol,
                    action, event_count, ...)
```

⛔ **Cost it before agreeing to it.** This is a high-cardinality rollup — the pair space is far
larger than any existing one (talker alone is 77k distinct sources over 7 days). It needs a measured
cardinality estimate over a real 24h window, its own `SYSLOG_DETAIL_RETENTION_DAYS`-style budget,
and a decision on whether to keep only flows matching a declared application (cheap, but then the
data cannot answer discovery in Phase 4). **Do not start here.** Phase 1 is shippable and honest
without it.

### Phase 4 — Discovery *(optional, and the most likely to overpromise)*
Suggest candidate applications by clustering observed traffic. ⛔ A suggestion is a HYPOTHESIS and
must be labelled one — an auto-discovered "application" presented as fact is a declaration with no
human behind it, which is worse than the competitors' stale-but-owned map. Gate behind Phase 3.

## 8. Recommendation

**Build Phase 1 only, then stop and look at it on the live fleet.**

It is the entire competitive claim ("verified, not just declared"), it needs no schema work beyond
two small tables, it reuses three proven engines unchanged, and it is testable without a device.
Phase 2 is a natural follow-on once there is a real declaration to reason about. Phase 3 is a
storage decision dressed as a feature and should be argued on its own measured numbers.

The risk to manage is **the empty state**: with no applications declared, this page says nothing,
and a fleet with 1,757 rules and zero declared flows will report 1,095 "unclaimed" allow rules —
which is accurate and useless. Phase 1 must therefore ship with the orphan count expressed as a
COVERAGE figure ("0 of 1,095 allow rules are claimed by a declared application") rather than as a
finding, or the first screenshot of the feature is an alarming number that means nothing.

## 9. Open questions

1. **Who declares the flows?** A CMDB import is how AlgoSec gets volume. Is there a source of
   application/flow data in the environment, or is this hand-entry only at first?
2. **Is Phase 2's impact analysis the actual draw**, or is Phase 1's broken-flow detection enough to
   demo? That changes whether the reverse index is built now or later.
3. **Does §4.2 get fixed independently?** A schema comment costs nothing; renaming the column or
   dropping it from the unique key is a rollup rebuild.
