#!/usr/bin/env bash
#
# dbcheckUrl.sh -- print a DBCHECK_URL for scripts/dbCheck.js, built from the
# credential kept OUTSIDE this repository in ~/.secvault-local-secrets.json.
#
#   DBCHECK_URL="$(scripts/dbcheckUrl.sh production)" npm run dbcheck
#
# ⛔ THIS EXISTS BECAUSE dbCheck.js USED TO CARRY THE CREDENTIAL IN SOURCE.
# Its READONLY_URL fell back to a literal connection string containing the
# reference deployment's claude_readonly password, committed to git -- the same
# defect CLAUDE.md records as fixed in lib/schema-grants.sql on 2026-10-16,
# surviving in a file that fix never looked at. The default is gone; this is
# the replacement, and it reuses scripts/devdb.sh's guards rather than
# inventing a second credential discipline.
#
# ⛔ IT PRINTS TO STDOUT, TO BE CAPTURED INTO AN ENVIRONMENT VARIABLE, AND IS
# NEVER PASSED IN argv. /proc/<pid>/cmdline is readable by any process on the
# box, so `npm run dbcheck -- --url postgresql://user:pw@...` would publish the
# password to every local user for the life of the run. An environment variable
# is /proc/<pid>/environ, readable only by this uid and root -- the same
# exposure DATABASE_URL already has, and the reason devdb.sh uses a PGPASSFILE
# for psql specifically (psql's `\!` meta-command runs a local shell that
# inherits this process's environment; node has no such meta-command).
#
# ⛔ AND IT IS NEVER ECHOED ANYWHERE ELSE. No `set -x`, and every error names
# the TARGET and the FILE, never the secret.
set -euo pipefail

SECRETS="${SECVAULT_SECRETS_FILE:-$HOME/.secvault-local-secrets.json}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

[ $# -eq 1 ] || { echo "usage: scripts/dbcheckUrl.sh <target>" >&2; exit 2; }
TARGET="$1"

if [ ! -f "$SECRETS" ]; then
  echo "[dbcheckUrl] no credential file at $SECRETS" >&2
  echo "             create it (mode 0600, OUTSIDE this repo) -- see docs/DEV-CREDENTIALS.md" >&2
  exit 3
fi

# ⛔ A credential file the whole machine can read is not a credential file.
# Checked BEFORE the file is parsed -- reading it first would already have
# exposed it this run. Same guard, same order, as devdb.sh.
MODE="$(stat -c '%a' "$SECRETS")"
case "$MODE" in
  600|400) ;;
  *)
    echo "[dbcheckUrl] REFUSING: $SECRETS is mode $MODE, expected 600." >&2
    echo "             fix with: chmod 600 $SECRETS" >&2
    exit 3
    ;;
esac

# ⛔ A copy inside the working tree is one `git add -f` from being published.
case "$(readlink -f "$SECRETS")" in
  "$REPO_ROOT"/*)
    echo "[dbcheckUrl] REFUSING: the credential file is INSIDE the repository." >&2
    echo "             Keep it in \$HOME; git cannot address it there." >&2
    exit 3
    ;;
esac

# ⛔ -I (isolated): the file is DATA, and an interpreter started in a directory
# someone else can write to will load a planted module on import.
#
# ⛔ IT REFUSES A TARGET NOT MARKED readonly. dbCheck.js asserts the role's
# privileges itself once connected, but that guard fires AFTER a connection has
# been opened as a write role against a production security database. Refusing
# here means the write credential is never even assembled -- the same
# "expressed twice" doubling devdb.sh applies to its read-only session.
python3 -I -c '
import json,sys,urllib.parse as u
path,target=sys.argv[1],sys.argv[2]
try:
    d=json.load(open(path))
except Exception as e:
    sys.stderr.write("[dbcheckUrl] %s is not valid JSON: %s\n"%(path,e)); sys.exit(3)
dbs=d.get("databases") or {}
t=dbs.get(target)
if t is None:
    sys.stderr.write("[dbcheckUrl] no target %r. known: %s\n"%(target,", ".join(sorted(dbs)))); sys.exit(4)
if str(t.get("readonly")).lower() != "true":
    sys.stderr.write("[dbcheckUrl] REFUSING: target %r is not marked readonly in %s.\n"%(target,path))
    sys.stderr.write("             dbcheck runs 100+ reads against a live security database; the\n")
    sys.stderr.write("             role must be able to write NOTHING.\n")
    sys.exit(3)
pw=t.get("password")
if not pw:
    sys.stderr.write("[dbcheckUrl] target %r has no password set in %s (the field is empty, so the\n"%(target,path))
    sys.stderr.write("             credential was never supplied -- that is NOT an auth failure).\n")
    sys.exit(3)
q=lambda v: u.quote(str(v), safe="")
sys.stdout.write("postgresql://%s:%s@%s:%s/%s" % (
    q(t.get("user")), q(pw), t.get("host"), t.get("port"), t.get("database")))
' "$SECRETS" "$TARGET"
