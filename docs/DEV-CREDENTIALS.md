# Local development credentials

Credentials Claude Code (or you) need to query a SecVault database during
development live in **one file, outside this repository**:

```
~/.secvault-local-secrets.json      mode 0600
```

Same pattern as `~/.certvault-e2e.json`. Use `scripts/devdb.sh` to reach a
database; it reads that file and never puts the password in `argv`.

```bash
scripts/devdb.sh production -c "SELECT count(*) FROM devices"
scripts/devdb.sh production                  # interactive psql
scripts/devdb.sh dev -f /tmp/query.sql
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
