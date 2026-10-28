# Microsoft Entra ID SSO — proposal

⛔ **STATUS: PHASES 0, 1 AND 2 ARE BUILT. ONLY PHASE 3 IS PROPOSAL ONLY (not built).**

| phase | state | where |
|---|---|---|
| 0 — scope decides on `provider`, not id shape | **SHIPPED v2.205.0** | `lib/deviceScope.js` |
| 1 — sign-in: provider, `provider` column, mapping panel, fail-closed on zero mappings, overage refused | **SHIPPED v2.206.0–v2.208.0** | `lib/entraRoles.js`, `app/api/auth/[...nextauth]/route.js`, `components/settings/EntraRolesPanel.js` |
| 1b — tenant configurable from the console | **SHIPPED v2.209.0** (not in the original plan) | `app/api/system/entra/route.js`, `components/settings/EntraSsoPanel.js` |
| 2 — the refused-sign-in log | **SHIPPED v2.211.0** | `jwt()` → `activity_log` `entra_signin_refused`, surfaced by `GET /api/system/entra` |
| 3 — scoping parity: shadow `users` rows, Graph overage | **NOT BUILT** | — |

This file is the design record. When Phase 3 ships, **correct this line in the same commit**
and amend the entry in CLAUDE.md's index list.

⛔ **THIS HEADER READ "PHASES 1-3 ARE PROPOSAL ONLY" FOR SEVEN VERSIONS AFTER PHASE 1 SHIPPED,
AND IT SAID IN ITS OWN NEXT SENTENCE WHY THAT MATTERS.** The warning below was written and
then not acted on by the commits it was written for — §8 carried a "PHASE 1 SHIPPED" note
while this line three hundred lines above it said the opposite, so the file contradicted
itself and the stale claim was the one a reader met first. CLAUDE.md's index list has now
carried a stale "PROPOSAL ONLY" over shipped work **four separate times** (central CVE feed,
analytics, application view, and this). Treat the header as part of the deliverable, not as
documentation about it.

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

## 1. ⛔ THE BLOCKING DEFECT: an Entra account is handed the whole fleet — FIXED v2.205.0

**Shipped.** Kept here in full because it is the reason Phase 0 exists and because the
failure mode is worth not re-introducing. `loadScopeForSession` now decides on
`session.user.provider`; what follows is what it used to do.

⛔ **The test for it nearly did not work, and that is the part to remember.** The first
version asserted only that an Entra-shaped id resolved `UNKNOWN`, using a pool that threw
if queried. But the OLD code reached `UNKNOWN` too — via `catch` -> `scopeFromRows(null)`
— so the test passed under the bug. Mutation-verified and corrected to assert **that the
query never ran**. Asserting the state was testing the mechanism; asserting the query was
testing the outcome.

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

## 1b. What to configure IN ENTRA (the other half of the exchange)

The three values SecVault needs (`ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`,
`ENTRA_CLIENT_SECRET`) all come FROM the app registration. But the registration also
needs one value FROM us, and it must match byte for byte or Entra refuses the sign-in
on its own side, before SecVault is ever reached.

| Entra asks for | value |
|---|---|
| **Redirect URI** (a.k.a. Reply URL) — platform **Web** | `<NEXTAUTH_URL>/api/auth/callback/entra` |
| Supported account types | Single tenant, unless the customer federates guests |
| Implicit grant / hybrid | **not needed** — leave off |
| API permissions | `openid`, `profile`, `email` (delegated). ⛔ `GroupMember.Read.All` is NOT needed and should not be granted — see §5 |
| Token configuration → groups claim | emit **"Groups assigned to the application"**, NOT "All groups" — see §5 |

⛔ **THE REDIRECT URI IS DERIVED FROM THE PROVIDER ID**, which is `entra`. NextAuth builds
`<NEXTAUTH_URL>/api/auth/callback/<id>`, so renaming the id silently invalidates every
customer's app registration, with the error surfacing on Microsoft's side rather than
ours. Pinned by `tests/entraRoles.test.js`.

⛔ **IT MUST MATCH `NEXTAUTH_URL` EXACTLY** — scheme, host and port. This is the same
value Settings → Certificate → Console address writes, and the console-address guard
already refuses a scheme that disagrees with the transport. A console reached on
`https://secvault.example.com:3010` needs that exact origin in the Redirect URI;
`http://`, a bare IP, or a trailing slash will all be rejected by Entra.

⛔ **"ENTITY ID" IS A SAML QUESTION, AND THIS IS NOT SAML.** If an identity team asks for
an Entity ID and an ACS/Consumer URL, they are provisioning a SAML application — those
fields have no equivalent here. This integration is **OIDC / OAuth2**, where the
equivalents are the Client ID (which Entra issues, not us) and the Redirect URI above.
Answering a SAML questionnaire with OIDC values produces a registration that cannot
work, so the right response is to ask for an **App registration**, not an
**Enterprise application SAML setup**.

## 2. Scope of the change

| file | change |
|---|---|
| `app/api/auth/[...nextauth]/route.js` | add `AzureADProvider`; `jwt()` re-resolves Entra roles like LDAP |
| `lib/entraRoles.js` *(new)* | thin wrapper over `ldapRoles.resolveRole`; owns group-claim handling |
| `lib/deviceScope.js` | **§1 prerequisite** — decide on provider, not id shape |
| `lib/schema.sql` | `directory_role_mappings` (see §3) — ⛔ **SHIPPED DIFFERENTLY**: `ldap_role_mappings` + `provider`, no rename |
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

**Proposal was:** rename to `directory_role_mappings` with a `provider` column
(`'ldap' | 'entra'`), `group_key` (DN or GUID), `group_key_normalised`, `display_name`,
`role`, `description`, keeping `ldap_role_mappings` as a **view** for one release.

⛔ **WHAT SHIPPED (v2.206.0) IS NARROWER, AND THE RENAME WAS REJECTED DURING
IMPLEMENTATION.** `ldap_role_mappings` keeps its name and gains `provider`
(`NOT NULL DEFAULT 'ldap'` — every existing row WAS an LDAP mapping, so the default states a
fact) and `display_name`; the column-level `UNIQUE` on `group_dn_normalised` is dropped and
replaced by `uq_directory_mapping (provider, group_dn_normalised)`. `group_dn` keeps its name
and simply holds a GUID for Entra rows.

The rename lost on a migration-safety argument, not a naming one: `ALTER TABLE ... RENAME` is
not idempotent, so it needs a DO block against `pg_class`, plus the view and duplicate grants
— and `lib/migrate.js` sends `schema.sql` as ONE multi-statement batch where any error aborts
the entire migration. **A misleading table name is cosmetic; a migration that aborts half-way
on a live firewall platform is not.** `ADD COLUMN IF NOT EXISTS` and
`CREATE UNIQUE INDEX IF NOT EXISTS` are additive and re-runnable, so that is what it does, and
the reasoning is written out in `schema.sql` beside the columns.

⛔ **No `backfillLedger.js` revision was needed either**, because nothing moved: the default
on `provider` classifies every existing row correctly without touching data.

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
| device scoping | local only | **not available** — `entra` is UNSCOPABLE (v2.212.0); Phase 3 — see below |
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
so **Phase 1 shipped with Entra accounts refused by scoped surfaces** — ⛔ and that was
REVERSED in v2.212.0. An Entra account is now UNSCOPED (it sees the whole fleet, exactly as an
LDAP account always has) rather than refused, because the refusal misdescribed its own cause:
see the ⛔ note at the end of §8.

---

## 8. Phases

**Phase 0 — the prerequisite. ⛔ SHIPPED v2.205.0.**
`loadScopeForSession` decides on `provider`, not id shape (§1). `SCOPABLE_PROVIDERS` =
`{local}`, `UNSCOPABLE_PROVIDERS` = `{ldap}` — **`{ldap, entra}` since v2.212.0**, see the
⛔ note at the end of this section — anything else, including absent, is
`UNKNOWN`, which denies, and is logged. Shape matching survives only as a contradiction
check on a provider claiming to be local. Six tests across `deviceScope.test.js` and
`deviceScopeEnforcement.test.js`, mutation-verified against the restored shape check.

**Phase 1 — sign-in. ⛔ SHIPPED v2.206.0–v2.208.0.** `AzureADProvider` appended to the
provider array ONLY when all three `ENTRA_*` vars are set; `lib/entraRoles.js` owning the
group claim and the zero-mappings call; `EntraRolesPanel`; fail-closed on zero mappings;
overage refused with a named reason. ⛔ **Two things here landed differently from this plan**:
the table was NOT renamed to `directory_role_mappings` — `ldap_role_mappings` gained a
`provider` column instead, because a rename needs a non-idempotent `ALTER TABLE` inside the
one multi-statement batch `migrate.js` sends, where any error aborts the whole migration
(the reasoning is written out in `lib/schema.sql` beside the column). And Entra accounts are
no longer refused by scoped surfaces — see the ⛔ note at the end of this section.

**Phase 1b — configurable from the console. ⛔ SHIPPED v2.209.0, and it was not in this plan
at all.** `GET/PUT /api/system/entra` + `EntraSsoPanel` write the three `ENTRA_*` values to
`.env.local` through `lib/envFile.js`. It was added because "edit `.env.local` on the server"
is not a setup step a customer can be given — the same conclusion Settings → Certificate →
Console address and Settings → Security had already reached. ⛔ Gated on `manage_users`, not
`manage_settings`: whoever sets the tenant decides WHICH DIRECTORY IS TRUSTED to issue
identities, which cannot be a lesser privilege than configuring the group mappings.

**Phase 2 — administration. ⛔ SHIPPED v2.211.0.** The refused-sign-in log: the `signIn`
callback writes an `entra_signin_refused` row to `activity_log`, and `GET /api/system/entra`
returns the recent ones so `EntraSsoPanel` shows them beside the settings that cause them.
⛔ **The refusal is split in two, deliberately**: the user is redirected to
`/login?sso=refused` and told only that the account is not mapped to a role, while the NAMED
cause (`no_matching_group` / `groups_unreadable` / `groups_overage` — three different
administrator fixes) goes to the log and the Settings panel. Naming it on a pre-authentication
page would tell an unauthenticated visitor how the customer's directory is wired, the same
rule the login form already follows for MFA. ⛔ **The GROUP PICKER was not built and is not
needed**: `ldap_role_mappings.display_name` carries the operator's own label beside the GUID,
which is what made the panel administrable. A picker would mean a Microsoft Graph call, i.e.
the `GroupMember.Read.All` consent this design deliberately asks the customer's Entra
administrator NOT to grant.

**Phase 3 — scoping parity (only if customers ask). ⛔ NOT BUILT — the only unbuilt phase.**
Shadow `users` rows keyed on the Entra `oid`, Graph overage resolution, scoping for Entra
accounts. Shipping it moves `entra` from `UNSCOPABLE_PROVIDERS` to `SCOPABLE_PROVIDERS`.

⛔ **PHASE 1 SHIPPED REFUSING ENTRA ON SCOPED SURFACES AND THAT WAS CHANGED IN v2.212.0.**
The refusal was correct about the limitation and wrong about how it presented it: an
Entra Super Admin saw an empty product under a banner reading "Your account is restricted
to specific firewalls", which was false — nobody had restricted them, SecVault simply
could not represent their identity. A refusal that misdescribes its own cause is worse
than the limitation it guards. `entra` now sits in `UNSCOPABLE_PROVIDERS` beside `ldap`,
so an Entra user sees the whole fleet exactly as an LDAP user always has, and what they
can DO is governed by the group-to-role mapping. Phase 3 reverses this by moving `entra`
to `SCOPABLE_PROVIDERS` once a shadow row exists.

---

## 9. Test plan

Everything here is pure or pool-taking, so it belongs in `npm test` rather than a live gate:

- `resolveRole` with Entra GUIDs — unchanged behaviour, most-privileged wins
- **zero mappings → refuse** (the inverse of the LDAP legacy-mode test)
- overage claim → refuse with a named reason, **never** "no role"
- `groups` absent vs `groups: []` resolve **differently**
- ⛔ **a GUID-shaped id with `provider: 'entra'` never reaches the scope query** —
  mutation-verified, because this is the §1 defect. It resolved `UNKNOWN` as Phase 1
  shipped; since v2.212.0 it resolves `UNSCOPED`. **What the test pins either way is that
  the shape of the id decides nothing** — the answer comes from the provider list
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
