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
   slash. Settings → Single sign-on prints the exact string; it follows the Console address
   (`NEXTAUTH_URL`), set on Settings → Certificate. `http://` where the console serves
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

### 1. Enter the three values in the console

**Settings → Single sign-on.** Paste the Directory (tenant) ID, the Application (client) ID
and the client secret **value**, and save. Super Admin only.

The panel also **shows you the exact Redirect URI to register in Entra**, derived from the
console address rather than typed. It has to match byte for byte, and a mismatch fails on
Microsoft's side with an error that never reaches SecVault's logs — so copy it from here
rather than composing it by hand.

⛔ **All three are required together.** With any one blank, Entra is treated as not
configured: no sign-in button appears and nothing is logged as a fault. That is the
normal state for an installation that does not use it.

⛔ **The client secret is write-only.** It is never sent back to the browser, so the field
cannot be pre-filled and a blank box looks identical to a cleared one. **Leaving it blank
keeps the stored secret**; it is replaced only when you type a new one.

⛔ **To turn SSO off, clear all three fields and save.** Clearing only some of them is a
half-configuration, not a disable.

⛔ **Check that the Console address matches the Redirect URI.** It is on Settings →
Certificate, and a disagreement between the two is the most common cause of a sign-in that
fails on Microsoft's side. The Single sign-on panel prints the console address it is using.

### 1b. Or, as a fallback, edit `.env.local` by hand

The console panel is the supported route — this is here for an install being provisioned
before anyone can sign in, or for a scripted deployment. On the server,
`C:\Apps\SecVault\.env.local`:

```
ENTRA_TENANT_ID=<directory (tenant) ID>
ENTRA_CLIENT_ID=<application (client) ID>
ENTRA_CLIENT_SECRET=<the secret VALUE>
```

`NEXTAUTH_URL` in the same file must match the Redirect URI exactly.

### 2. Restart the app

```powershell
sc.exe stop SecVault-App
sc.exe start SecVault-App
```

The environment is read **once at startup**, by either route — saving in the console does
not apply the change on its own, and the panel says so, showing the saved value beside the
running one until the service is restarted.

### 3. Map at least one group

Settings → Single sign-on → **Entra group access**, on the same tab.

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
- ⛔ **An Entra account sees the WHOLE FLEET, and cannot be restricted to specific
  firewalls.** Per-user device scoping needs a local account record, which a directory
  account does not have — so an Entra user is treated as unscoped, exactly as an LDAP user
  always has been. What they can *do* with the fleet is still governed by the group-to-role
  mapping; **which firewalls they can see is not restrictable at all.** If you need a
  contractor limited to two firewalls, give them a local SecVault account instead.
  Per-firewall scoping for directory accounts is Phase 3 of the proposal and is not built.
  (Earlier drafts of this guide said such a request was *refused* rather than granted. That
  was Phase 1's behaviour and it was reversed in v2.212.0: the refusal showed an Entra Super
  Admin an empty product under a banner saying their account was restricted to specific
  firewalls, which was untrue — nobody had restricted them.)

## If sign-in fails

⛔ **The named reason always exists — look in Settings → Single sign-on.** Every refused
Entra sign-in is recorded there under **Recent refused sign-ins**, with who it was and which
of the three causes it was: the token carried no readable group claim, the user is in no
mapped group, or the user is in too many groups for Entra to list them (overage). The three
need three different fixes, so start here rather than guessing.

| symptom | likely cause |
|---|---|
| Error on Microsoft's page before returning to SecVault | Redirect URI does not match the console address exactly — scheme, host, port, path, no trailing slash. The panel prints the string to register. |
| "Sign in with Microsoft" button does not appear | one of the three values is blank, or the service was not restarted after saving. The panel shows the saved value beside the running one when they differ. |
| Returned to the login page saying the account is not mapped to a role | the sign-in was refused. No group mapped yet, or the group is not **assigned to the enterprise application** — check Recent refused sign-ins for which of the two. |
| Refused with "too many groups" | the app registration is emitting *All groups* instead of *Groups assigned to the application*. SecVault will not follow Entra's overage pointer (that needs a Graph permission this setup deliberately does not ask for). |
| Worked, then stopped weeks later | the client secret expired. Create a new one in Entra and paste the value into Settings → Single sign-on. |

⛔ **The user is told THAT they were refused, never WHICH of the three causes it was**, and
the split is deliberate. They are returned to the login page with one message — Microsoft
signed them in, the account is not mapped to a SecVault role, ask an administrator to map one
of their directory groups — so they go to the right person instead of resetting a password
that works perfectly. The specific cause names how your directory is wired and would be
readable by an unauthenticated visitor, so it goes only to the administrator, in Settings.
No session is created on a refusal.

Local sign-in is unaffected in every one of these cases.
