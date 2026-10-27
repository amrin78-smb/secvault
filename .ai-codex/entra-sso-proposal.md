# Microsoft Entra ID SSO — proposal

⛔ **STATUS: PROPOSAL ONLY (not built), as of v2.204.0.**
This file is the design record. When any phase ships, **correct this line in the same
commit** and amend the entry in CLAUDE.md's index list. That list has carried a stale
"PROPOSAL ONLY" over shipped work **three separate times** (central CVE feed, analytics,
application view), so treat the header as part of the deliverable, not documentation about it.

---

## Why this is smaller than it looks

The hard part is already built. `lib/ldapRoles.js` answers *"a directory says this person
is in these groups — what role is that?"*, and nothing in that answer is LDAP-specific:

| already exists | reused as-is |
|---|---|
| `resolveRole({ groups, mappings })`, most-privileged-match-wins | yes |
| `isPermitted()` / the `OUTCOME` vocabulary | yes |
| `ldap_role_mappings` + its Settings UI | **schema change needed** — see §3 |
| `jwt()` re-resolving directory roles on **every token use** | yes |
| legacy-mode vs configured distinction | **must NOT be copied** — see §4 |

And `next-auth@4.24.15` **already ships the provider** (`next-auth/providers/azure-ad`,
verified present in `node_modules`). No new dependency — which matters, because
`Update-SecVault.ps1` runs `npm ci` on a firewall-management box and this repo
deliberately carries no devDependencies.

---

## 1. ⛔ THE BLOCKING DEFECT: an Entra account is handed the whole fleet

**This must be fixed before the provider is wired, not after.** It is not a new bug; it
is an existing one that only becomes reachable the moment a third identity provider
exists.

`lib/deviceScope.js:185` decides whether an account can be scoped by the **shape of
`session.user.id`**:

```js
const looksLocal = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
// A non-empty, non-UUID id is an LDAP username: a real identity with no
// `users` row to hang a scope on, so genuinely unscoped.
if (!looksLocal) return { state: SCOPE_STATES.UNSCOPED, deviceIds: null };
```

**An Entra `oid` is a GUID.** It matches that regex exactly. So the chain is:

1. `looksLocal` → **true** (wrongly: it is not a local account)
2. `SELECT device_id FROM user_device_scopes WHERE user_id = <entra oid>` → **0 rows**
   (there is no `users` row, so there can be no scope rows)
3. `scopeFromRows([])` → `UNSCOPED` — documented and correct for a local account:
   *"ZERO ROWS IS UNSCOPED, NOT 'NO DEVICES'"*
4. **Result: the whole fleet, silently.** Nothing errors and nothing on screen differs.

It is worse than silent. `user_device_scopes.user_id` is
`UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE` (`schema.sql:2846`), so an Entra
account **cannot be scoped even deliberately** — the insert violates the foreign key. An
administrator would be unable to restrict an Entra contractor to two firewalls at all.

⛔ The comment above that regex says *"three cases, not two"*, and records that an
earlier version fell open on the third. **Entra is a fourth case the shape-check cannot
see**, because it is distinguished from a local account by provenance, not by shape.

### The fix (prerequisite, ships before the provider)

**Decide on `session.user.provider`, never on the shape of the id.** The field already
exists and is already carried on the token. `loadScopeForSession` becomes:

- `provider === 'local'` → look up `user_device_scopes` (today's behaviour)
- `provider === 'ldap'` → `UNSCOPED` (today's behaviour, now stated rather than inferred)
- `provider === 'entra'` → see §5 — **`UNKNOWN`, which denies**, until scoping supports it
- missing / unrecognised provider → `UNKNOWN` (denies)

⛔ Shape-matching stays as a **secondary assertion**, not the decision: a `local` provider
whose id is not a UUID is a contradiction and must resolve `UNKNOWN`, not be trusted.

⛔ A test must assert that **a GUID-shaped id from a non-local provider does not reach the
`user_device_scopes` query at all**. Pin it with a real Entra-shaped `oid`.

---

## 2. Scope of the change

| file | change |
|---|---|
| `app/api/auth/[...nextauth]/route.js` | add `AzureADProvider`; `jwt()` re-resolves Entra roles like LDAP |
| `lib/entraRoles.js` *(new)* | thin wrapper over `ldapRoles.resolveRole`; owns group-claim handling |
| `lib/deviceScope.js` | **§1 prerequisite** — decide on provider, not id shape |
| `lib/schema.sql` | `directory_role_mappings` (see §3) |
| `components/settings/LdapRolesPanel.js` | becomes provider-aware, or gains a sibling |
| `.env.local.example` | `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET` |

---

## 3. ⛔ Entra groups are GUIDs, and the existing table cannot hold them

`ldap_role_mappings` stores `group_dn` plus `group_dn_normalised UNIQUE`, where
normalisation collapses case and spacing **around commas** — meaningful for
`CN=Firewall Admins,OU=…`, meaningless for `8f4a1c2e-…`.

Two further problems a GUID brings:

- ⛔ **A GUID is unreadable, so the panel is unadministrable without a display name.**
  "Which of these four GUIDs is Firewall Admins?" is not a question an operator can
  answer. The group's display name must be stored **as a label only** and never used for
  matching — a display name is mutable in Entra and two groups may share one.
- ⛔ **A GUID and a DN must not collide in one unique index.** Scope the uniqueness to
  `(provider, group_key_normalised)`.

**Proposal:** rename to `directory_role_mappings` with a `provider` column
(`'ldap' | 'entra'`), `group_key` (DN or GUID), `group_key_normalised`, `display_name`,
`role`, `description`. Keep `ldap_role_mappings` as a **view** for one release so nothing
reading it breaks, per this codebase's habit of not silently changing a shape others read.

⛔ Migration is a **data move, so it goes through `lib/backfillLedger.js`** with a revision —
not an unguarded statement in `schema.sql` that re-runs every deploy.

---

## 4. ⛔ Entra must NOT inherit LDAP's legacy mode

`ldapRoles.js` treats **zero mappings as "grant `admin`"**, because LDAP shipped before
mappings existed and making an empty table mean *deny* would have locked every existing
installation out of its own platform on the upgrade that delivered it. That reasoning is
sound **and it does not transfer**: SecVault has never shipped Entra SSO, so there is no
installed base to protect.

⛔ **Zero Entra mappings = no Entra user may sign in.** The same call
`productLicense.js` makes about `modules` failing closed where the siblings fail open:
*there are no legacy keys to protect, so failing open would only create a hole.*

The Settings panel must state this plainly before the first mapping is created, or the
first customer to enable Entra will conclude the integration is broken.

---

## 5. ⛔ The group claim is capped, and the overage is the dangerous case

Entra omits the `groups` claim once a user exceeds roughly **200 memberships** and sends
a `_claim_names` / `_claim_sources` overage pointer instead, which must be followed with a
Microsoft Graph call (`GET /me/memberOf`).

Unhandled, the token simply has no `groups` array — which reads as *"this user is in no
groups"* and resolves to **no role**. That is this codebase's signature bug: **a failed
read recorded as an affirmative value.** A user in 201 groups is not a user in zero.

⛔ **Absent-because-overage and genuinely-no-groups must be distinguished, and the first
must FAIL CLOSED with its own outcome**, exactly as `ldapRoles` already does for
`groups === null` (*"UNREADABLE GROUPS IS NOT 'NO GROUPS'"*).

Two options, and the recommendation is the first:

1. **Configure Entra to emit only groups assigned to the application.** Keeps the claim
   small, avoids Graph entirely, and keeps the air-gap surface at one host. Documented as
   a setup step.
2. Follow the overage link via Graph. Needs `GroupMember.Read.All`, a second outbound
   dependency **on the login path**, and a failure mode that must deny rather than degrade.

⛔ Until the overage path is implemented, an overage token must **refuse the login with a
named reason**, never resolve to "no role" and never to a default role.

---

## 6. ⛔ It breaks the air-gap assumption, so it is strictly optional

This product installs on segmented and air-gapped networks — **the target customer, not
an edge case**. It is why fonts are vendored rather than fetched from a CDN, why
`qrcode` renders server-side, and why the central CVE feed exists at all.

Entra needs outbound HTTPS to `login.microsoftonline.com` **at every sign-in**.

- ⛔ **Unconfigured means absent, not broken.** No `ENTRA_TENANT_ID` → the provider is not
  registered, the button does not render, and nothing is logged as an error. Same contract
  as `CVE_HUB_LICENSE_KEY` returning `notRun`.
- ⛔ **Local admin sign-in must never depend on Entra being reachable.** If Microsoft is
  unreachable, the credentials provider must still work — otherwise an internet outage
  locks an operator out of the console that manages their firewalls.
- ⛔ The Settings panel must **state the egress requirement** before the customer enables it.

---

## 7. Identity, MFA and the other per-user features

| feature | today | with Entra |
|---|---|---|
| device scoping | local only | **blocked until §1 + a design** — see below |
| saved views | local only (UUID id) | same question as scoping |
| SecVault TOTP | local only (needs a `users` row) | **not offered** — MFA belongs in Entra |
| `activity_log` actor | `session.user.name` | unchanged (UPN) |

⛔ **MFA is deliberately not offered for Entra accounts**, the same call already made for
LDAP: those accounts have no `users` row to attach a secret to, and their second factor
belongs in the directory that owns the identity. Entra Conditional Access is strictly
better than this product's hand-rolled TOTP for those users.

⛔ **Per-user device scoping for Entra needs a `users`-row-shaped anchor** — a local
shadow row keyed on the Entra `oid`, created on first sign-in. That is a real design
decision with its own failure modes (what happens when the account is deleted in Entra?),
so **Phase 1 ships with Entra accounts refused by scoped surfaces**, not silently unscoped.
A smaller product, honestly described, is the behaviour the register already defines.

---

## 8. Phases

**Phase 0 — the prerequisite (ships alone, before any Entra code).**
Fix `loadScopeForSession` to decide on `provider`, not id shape (§1). Add the test pinning
a GUID-shaped non-local id. This is worth doing **whether or not Entra is ever built**,
because the fail-open is already in the code and only needs a third provider to become
reachable.

**Phase 1 — sign-in.** Provider registered, `directory_role_mappings` with `provider`,
Settings panel, fail-closed on zero mappings, overage refused with a reason. Entra users
are refused by `blocked`/scoped surfaces.

**Phase 2 — administration.** Group picker showing display names beside GUIDs; an
"unmapped sign-in attempt" log so an admin can see who was refused and why.

**Phase 3 — scoping parity (only if customers ask).** Shadow `users` rows, Graph overage,
scoping for Entra accounts.

---

## 9. Test plan

Everything here is pure or pool-taking, so it belongs in `npm test` rather than a live gate:

- `resolveRole` with Entra GUIDs — unchanged behaviour, most-privileged wins
- **zero mappings → refuse** (the inverse of the LDAP legacy-mode test)
- overage claim → refuse with a named reason, **never** "no role"
- `groups` absent vs `groups: []` resolve **differently**
- ⛔ **a GUID-shaped id with `provider: 'entra'` never reaches the scope query**, and
  resolves `UNKNOWN` not `UNSCOPED` — mutation-verified, because this is the §1 defect
- an unreachable Entra endpoint does not prevent local credentials sign-in

⛔ Each test must include the **"we could not read this"** case, not only pass and fail —
that is the one that regresses silently here, because the wrong answer is a plausible role
rather than a crash.

---

## 10. Estimate

| phase | effort |
|---|---|
| Phase 0 (prerequisite) | ~half a day, mostly tests |
| Phase 1 | 1–2 days |
| Phase 2 | ~1 day |
| Phase 3 | 2–3 days, and only on demand |

The provider wiring itself is a few hours. **Everything else is the honesty work** — the
fail-closed decisions, the overage, and making sure an Entra account cannot quietly become
the most privileged, least restricted identity in the product.
