# Local development credentials

Credentials Claude Code (or you) need to query a SecVault database during
development live in **one file, outside this repository**:

```
~/.secvault-local-secrets.json      mode 0600
```

Same pattern as `~/.certvault-e2e.json`. Two helpers read it, and neither ever
puts a password in `argv`:

```bash
# PostgreSQL
scripts/devdb.sh production -c "SELECT count(*) FROM devices"
scripts/devdb.sh production                  # interactive psql
scripts/devdb.sh dev -f /tmp/query.sql

# WinRM (remote PowerShell on the Windows servers)
scripts/devwinrm.py production --probe        # authenticate only, run nothing
scripts/devwinrm.py production --cmd 'sc.exe query SecVault-App'
scripts/devwinrm.py production -- 'Get-Volume | Format-Table -AutoSize'
```

## ⛔ Why it is not in the repo, even gitignored

A gitignored file inside a working tree is one `git add -f`, one rebase onto a
branch whose `.gitignore` differs, or one `git clean -x` away from being
committed or destroyed. `$HOME` cannot be committed by accident at all — ask
git about the real file and it answers *"outside repository"*, which is a
stronger guarantee than any rule in `.gitignore`.

The `*local-secrets*` patterns in `.gitignore` are therefore **not** what
protects this file. They catch a copy somebody drops in the tree "just for a
minute". `devdb.sh` refuses such a copy outright; the ignore rule is the second
expression of the same refusal.

## Targets

| target | what | notes |
|---|---|---|
| `production` | `192.168.7.69` — the reference fleet | needs the **VPN up** (`tun0`); role is SELECT-only |
| `staging` | `192.168.31.10` (`LAPTOP-6PETB251`) | hosts CertVault today; SecVault is **not** installed there |
| `dev` | local socket, `secvault_mock` | peer auth, no password |

## ⛔ What the file may and may not hold

**May**: readonly database passwords for development diagnostics.

**May NOT**: the `sudo` password (ask each time, never store it — CLAUDE.md),
`CREDENTIAL_KEY`, `NEXTAUTH_SECRET`, `PG_ADMIN_PASSWORD`, any private key, or
any production *write* credential. Those are per-install secrets that belong on
the server in an admin-ACL'd file, and their **location** is what gets reported,
never their contents.

## The guards, and that they fire

`devdb.sh` refuses, each with its own exit code and message — all five verified
by running them, not by reading the source:

1. the file is missing
2. the file is mode other than `600`/`400`
3. the file is **inside the repository**
4. the target is unknown (it lists the ones it knows)
5. the target's password is empty

⛔ (5) is deliberately not an authentication failure. *"Not configured"* and
*"the server rejected you"* send you to different places, so they must never
produce the same message — the same distinction `ldapRoles.js` draws between
no mappings configured and no mapping matched.

A target marked `"readonly": true` also gets
`default_transaction_read_only=on` on the session, so a write fails even if the
role turned out to have rights the name implies it does not. The role and the
session both enforce it, the way `dbcheck` enforces read-only three ways.

## Rotation

`claude_readonly` / `nocvault_readonly` are **cluster-wide** and shared with the
sibling suite apps on the same PostgreSQL. Rotating one affects every app on
that cluster:

```sql
ALTER ROLE claude_readonly LOGIN PASSWORD '...';
ALTER ROLE nocvault_readonly LOGIN PASSWORD '...';
```

Then update this file. Since v2.196.0 a **fresh** install generates its own
password (`Install-SecVault.ps1` → `schema-grants.sql`); servers already in the
field keep the old one until the `ALTER ROLE` above is run.


---

# WinRM

`.winrm.hosts.<target>` in the same file. `production` is `192.168.7.69:5985`
(**VPN required**); `staging` is a fallback behind the SSH key.

## ⛔ NTLM only — `basic` is refused, not discouraged

5985 is plain HTTP and **5986 does not answer on these hosts**, so the transport
is unencrypted. NTLM never puts the password on the wire and encrypts the
message payload; `basic` would send it in cleartext across the VPN.
`devwinrm.py` refuses any transport but `ntlm` before it opens a socket.

## ⛔ The domain logon form is discovered, never guessed

The AD domain and the UPN suffix **disagree on this directory**, which CLAUDE.md
records from a live probe:

| | value |
|---|---|
| AD domain | `thaiunion.co.th` (`DC=thaiunion,DC=co,DC=th`) |
| UPN suffix | `@thaiunion.com` — **not** derivable from the DNS domain |

That mismatch already broke the LDAP bind once. So `username` holds the **bare**
login and `logon_forms` is tried in order:

```
thaiunion.co.th\{user}      {user}@thaiunion.com
{user}@thaiunion.co.th      THAIUNION\{user}
```

A template whose placeholder is blank is **skipped**, never sent as a broken
name like `\user`.

## ⛔ Trying forms spends lockout strikes

Each form is a separate failed logon for the same account, so a wrong *password*
across four forms is four strikes against domain policy. Attempts are capped at
`max_attempts`, the cap is printed before the first one, and on success the
helper tells you the exact template to pin:

```json
".winrm.hosts.production.logon_form": "{user}@thaiunion.com"
```

Pin it and later runs cost one attempt. ⛔ If every form fails, the **password**
is the likelier cause than the form — check it rather than editing templates and
retrying.

## ⛔ MD4, and why there is a shim

NTLM's NT hash is `MD4(password as UTF-16LE)` — that is the protocol, not a
choice — and `ntlm_auth` reaches it via `hashlib.new('md4')`. **OpenSSL 3 on
Ubuntu 24.04 does not provide MD4**, so without help every connection dies with
`unsupported hash type md4`.

Enabling OpenSSL's legacy provider was refused: it would re-enable MD4, MD2, RC4
and DES **process-wide for every program on the machine** to fix one client.
`scripts/_md4compat.py` is a 40-line pure-Python MD4 instead, installed only
into this process.

⛔ **It self-verifies against the RFC 1320 vectors before it installs, and that
is load-bearing.** A subtly wrong MD4 does not crash — it returns 16 plausible
bytes, the server rejects them, and the helper reports *"credentials rejected"*.
That is a correct password presented as a wrong one, and every retry spends a
real lockout strike chasing a bug in our own file. MD4 is used here **only**
because NTLM specifies it; never reuse it for anything else.

## Exit codes

| code | meaning |
|---|---|
| 2 | bad arguments |
| 3 | config refused (missing/loose-perms/in-repo file, basic transport, empty field) |
| 4 | unknown target |
| 5 | transport error — **not** an auth failure, costs no strike |
| 6 | every logon form rejected |

## ⛔ Rules that still apply on the remote host

It is a production server. `sc.exe` **always**, never `Start-Service` /
`Stop-Service` / `Get-Service` (they silently disconnect the session and hang).
`npm ci`, never `npm install`. Never restart, reconfigure or stop `sshd`
remotely. Prefer read-only commands; anything that changes the box should be a
deliberate, announced step, not a side effect of a diagnostic.
