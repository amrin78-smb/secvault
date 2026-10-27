# Entra ID single sign-on — setup guide

Operator-facing. The design record and the reasoning behind each decision live in
`.ai-codex/entra-sso-proposal.md`; this file is what to actually do.

> **Nothing here is required.** SecVault runs without it. Local accounts work exactly as
> before, with or without Entra, and continue to work if Microsoft is unreachable.

---

## Part 0 — ⛔ YOU NEED A DNS HOSTNAME FIRST, NOT AN IP ADDRESS

**Check this before raising the request.** Entra will not accept a Redirect URI that
points at a bare IP address — only `localhost` is exempt. A console reached on
`https://192.168.7.69:3010` therefore **cannot be used for SSO as-is**, and an app
registration created against such a URI can never complete a sign-in.

The reference deployment is in exactly that state today (`NEXTAUTH_URL=https://192.168.7.69:3010`),
so this is the first thing to resolve.

What has to be true before SSO can work:

1. **A DNS name that resolves to the SecVault server**, e.g. `secvault.example.com`.
   Internal DNS is fine — Entra never resolves it; the user's browser does.
2. **A TLS certificate covering that name.** Settings → Certificate installs it. ⛔ SANs
   are mandatory — browsers ignore the CN entirely.
3. **`NEXTAUTH_URL` updated to the same origin.** Settings → Certificate → Console
   address writes it, and refuses values that would lock you out. A restart is required
   and the panel says so.
4. **Then** the Redirect URI below is `https://<that name>:3010/api/auth/callback/entra`.

⛔ Do all of this BEFORE the app registration is created, or the Redirect URI will have
to be amended afterwards — a second round-trip through whoever owns the tenant.

⛔ **Nothing above affects local sign-in.** The console keeps working on its current
address throughout; this only governs whether Entra will talk to it.

---

## Part 1 — What to send the Entra administrator

Copy this into the request. **Ask for an App registration, not an Enterprise application
SAML setup** — the two are different and a SAML registration cannot be used here.

> Please create an **App registration** in Entra ID (Azure AD) for an internal
> application. It uses **OpenID Connect / OAuth 2.0**, not SAML.
>
> **Name:** SecVault
>
> **Supported account types:** Accounts in this organizational directory only
> (single tenant)
>
> **Redirect URI** — platform **Web**:
>
>     https://<secvault-host>:3010/api/auth/callback/entra
>
> **API permissions** (delegated, Microsoft Graph):
> `openid`, `profile`, `email`
> *No admin-consent permissions are required.* In particular **`GroupMember.Read.All`
> is NOT needed** — please do not grant it.
>
> **Token configuration → add a groups claim:**
> Select **"Groups assigned to the application"** — **not** "All groups", and not
> "Security groups".
>
> **Implicit grant / hybrid flows:** not required, please leave disabled.
>
> **Client secret:** please create one and send it with the IDs below. Note its expiry
> date — sign-in stops working when it lapses.
>
> **Please send back:**
> 1. Directory (tenant) ID
> 2. Application (client) ID
> 3. Client secret **value** (not the secret ID)
> 4. The expiry date of that secret

### ⛔ Three things that are commonly got wrong

1. **The Redirect URI must match exactly** — scheme, host, port, path, no trailing
   slash. It must be identical to `NEXTAUTH_URL` in `.env.local` (the same value
   Settings → Certificate → Console address writes). `http://` where the console serves
   `https://`, or a bare IP where the console uses a hostname, is rejected by Entra
   before SecVault is ever reached.
2. **"Entity ID" and "ACS URL" are SAML fields.** If they are asked for, the request has
   been read as a SAML setup. There is no equivalent here — the OIDC counterparts are
   the Client ID (which Entra issues) and the Redirect URI above.
3. **The client secret VALUE is only shown once**, at creation. If it is missed, a new
   secret must be generated — the secret ID is not usable.

---

## Part 2 — Groups

**SecVault does not expect any particular group names — you choose them.** Only the
group's **Object ID** is used; the name is a label shown in SecVault's own list.

SecVault has three roles, so a clean starting point is:

| Entra group (suggested name) | SecVault role | can do |
|---|---|---|
| `SecVault-SuperAdmins` | Super Admin | everything, including managing users and the licence |
| `SecVault-Admins` | Admin | devices, settings, updates — not user management |
| `SecVault-Operators` | Operator | act on findings; no administration |

Use **security groups**. You do not need all three — one is enough to start.

### ⛔ Creating the group is not enough — it must also be ASSIGNED to the application

Because the groups claim is set to *"Groups assigned to the application"*, a group only
appears in the sign-in token if it is **also assigned to the enterprise application**:

> Entra → Enterprise applications → SecVault → Users and groups → **Add user/group**

Miss this step and the sign-in is refused with *"not in any mapped group"*, while the
mapping looks perfectly correct in SecVault. That is the single most likely setup
failure.

⛔ **Why that claim setting rather than "All groups":** Entra drops the groups claim
entirely once a user is in roughly 200+ groups, and sends a pointer that requires a
Graph call SecVault deliberately does not make. "Assigned to the application" keeps the
claim small, so it never happens. With "All groups", your most group-heavy accounts —
usually the administrators — would be the ones refused.

---

## Part 3 — Enabling it in SecVault

### 1. Add the three values to `.env.local`

On the server, `C:\Apps\SecVault\.env.local`:

```
ENTRA_TENANT_ID=<directory (tenant) ID>
ENTRA_CLIENT_ID=<application (client) ID>
ENTRA_CLIENT_SECRET=<the secret VALUE>
```

⛔ **All three are required together.** With any one blank, Entra is treated as not
configured: no sign-in button appears and nothing is logged as a fault. That is the
normal state for an installation that does not use it.

⛔ **Check `NEXTAUTH_URL` in the same file matches the Redirect URI exactly.** This is
the most common cause of a sign-in that fails on Microsoft's side.

### 2. Restart the app

```powershell
sc.exe stop SecVault-App
sc.exe start SecVault-App
```

The environment is read once at startup.

### 3. Map at least one group

Settings → Users → **Entra group access**.

For each group: paste its **Object ID** (Entra → Groups → the group → Overview), give it
a name for the list, and choose a role.

⛔ **Until at least one group is mapped, no Entra user can sign in** — every attempt is
refused. This is deliberate and is the opposite of LDAP, where an empty mapping list
grants every directory user Administrator. SecVault has never shipped Entra sign-in, so
there is no existing access to preserve and the safe default is to grant nothing. The
panel says so on screen while the list is empty.

### 4. Sign in

Sign out, and the login page now shows **"Sign in with Microsoft"** beneath the normal
form.

---

## What to expect

- **A user in several mapped groups gets the most privileged of them.** Adding someone to
  a second group can only ever increase access, never reduce it.
- **A mapping change applies immediately.** A change to someone's group membership in
  Entra applies at their **next sign-in** — SecVault reads group membership once, when
  they authenticate, rather than calling Microsoft on every request.
- **Entra accounts cannot use SecVault's own MFA**, by design. Their second factor
  belongs in Entra (Conditional Access), which is better placed to enforce it.
- **Entra accounts cannot be restricted to specific firewalls yet.** Per-user device
  scoping needs a local account record, which a directory account does not have. A
  scoped-surface request from an Entra account is refused rather than silently granted
  the whole fleet. That is Phase 3 of the proposal and is not built.

## If sign-in fails

| symptom | likely cause |
|---|---|
| Error on Microsoft's page before returning to SecVault | Redirect URI does not match `NEXTAUTH_URL` exactly |
| "Sign in with Microsoft" button does not appear | one of the three env vars is blank, or the app was not restarted |
| Returns to SecVault but refused | no group mapped yet, or the group is not **assigned to the enterprise application** |
| Worked, then stopped weeks later | the client secret expired |

Local sign-in is unaffected in every one of these cases.
