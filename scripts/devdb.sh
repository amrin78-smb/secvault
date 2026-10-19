#!/usr/bin/env bash
#
# devdb.sh -- open psql against a SecVault database using the credential kept
# OUTSIDE this repository, in ~/.secvault-local-secrets.json (mode 0600).
#
#   scripts/devdb.sh production -c "SELECT count(*) FROM devices"
#   scripts/devdb.sh production                 # interactive
#   scripts/devdb.sh dev -f /tmp/some.sql
#
# ⛔ THE CREDENTIAL IS NEVER PASSED IN argv. /proc/<pid>/cmdline is readable by
#    any process on the box, so `psql "postgresql://user:pw@host/db"` publishes
#    the password to every local user for the life of the query. It goes in
#    a temporary PGPASSFILE (mode 0600, removed on every exit path) instead.
#    ⛔ IT USED TO USE PGPASSWORD, and that was wrong for a reason this comment
#    did not consider: psql's `\!` meta-command runs a LOCAL SHELL that inherits
#    this process's environment, and `-X` does not disable it. So
#    `devdb.sh production -c '\! printenv PGPASSWORD'` printed the credential.
#    A pass file is never in the environment.
#
# ⛔ AND IT IS NEVER ECHOED. No `set -x`, no printing of the parsed value, and
#    errors name the TARGET and the FILE, never the secret.
#
set -euo pipefail

SECRETS="${SECVAULT_SECRETS_FILE:-$HOME/.secvault-local-secrets.json}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  echo "usage: scripts/devdb.sh <target> [psql args...]" >&2
  echo "       targets are the keys under .databases in $SECRETS" >&2
}

[ $# -ge 1 ] || { usage; exit 2; }
TARGET="$1"; shift

if [ ! -f "$SECRETS" ]; then
  cat >&2 <<EOF
[devdb] no credential file at $SECRETS

Create it (mode 0600, OUTSIDE this repo) and fill in the password for the
target you want. See docs/DEV-CREDENTIALS.md.
EOF
  exit 3
fi

# ⛔ A credential file the whole machine can read is not a credential file.
# libpq enforces this for ~/.pgpass and refuses to use a loose one; nothing
# enforces it for a JSON file, so it is enforced here. Checked BEFORE the file
# is parsed -- reading it first would already have exposed it this run.
MODE="$(stat -c '%a' "$SECRETS")"
case "$MODE" in
  600|400) ;;
  *)
    echo "[devdb] REFUSING: $SECRETS is mode $MODE, expected 600." >&2
    echo "        fix with: chmod 600 $SECRETS" >&2
    exit 3
    ;;
esac

# ⛔ A copy inside the working tree is one `git add -f` from being published,
# and this script would happily use it. Refuse rather than warn.
case "$(readlink -f "$SECRETS")" in
  "$REPO_ROOT"/*)
    echo "[devdb] REFUSING: the credential file is INSIDE the repository" >&2
    echo "        ($SECRETS). Keep it in \$HOME; git cannot address it there." >&2
    exit 3
    ;;
esac

# Parse with -I (isolated): the file is data, and an interpreter started in a
# directory someone else can write to will load a planted module on import.
read_field() {
  python3 -I -c '
import json,sys
try:
    d=json.load(open(sys.argv[1]))
except Exception as e:
    sys.stderr.write("[devdb] %s is not valid JSON: %s\n"%(sys.argv[1],e)); sys.exit(3)
dbs=d.get("databases") or {}
t=dbs.get(sys.argv[2])
if t is None:
    sys.stderr.write("[devdb] no target %r. known: %s\n"%(sys.argv[2], ", ".join(sorted(dbs))))
    sys.exit(4)
v=t.get(sys.argv[3])
sys.stdout.write("" if v is None else str(v))
' "$SECRETS" "$TARGET" "$1"
}

HOST="$(read_field host)"
PORT="$(read_field port)"
DBNAME="$(read_field database)"
DBUSER="$(read_field user)"
RO="$(read_field readonly)"
DBPASS="$(read_field password)"

# ⛔ A PGPASSFILE, NOT PGPASSWORD -- BECAUSE psql's `\!` IS A LOCAL SHELL AND
# INHERITS THIS PROCESS'S ENVIRONMENT. `-X` suppresses .psqlrc; it does NOT
# disable backslash meta-commands, and "$@" is forwarded verbatim, so
#   scripts/devdb.sh production -c '\! printenv PGPASSWORD'
# printed the production password to stdout. The header above claimed the value
# was readable "only by this uid and root", which was true of /proc/<pid>/environ
# and beside the point: the leak was a command this script hands to psql itself.
# A pass FILE is never in the environment, so the same `\!` now prints nothing.
#
# ⛔ `\!` still runs a local shell, and that is NOT what is being defended
# against here: whoever runs this script already has a shell as this user. What
# must not happen is a credential they do not otherwise hold being handed to
# them -- and with PGPASSFILE it is not.
PGPASS_TMP=""
if [ -n "$DBPASS" ]; then
  PGPASS_TMP="$(mktemp "${TMPDIR:-/tmp}/.devdb-pgpass.XXXXXX")"
  chmod 600 "$PGPASS_TMP"
  # host:port:database:user:password -- ':' and '\' must be backslash-escaped.
  esc() { printf '%s' "$1" | sed -e 's/[\\:]/\\&/g'; }
  printf '%s:%s:%s:%s:%s\n' \
    "$(esc "$HOST")" "$(esc "$PORT")" "$(esc "$DBNAME")" "$(esc "$DBUSER")" "$(esc "$DBPASS")" \
    > "$PGPASS_TMP"
  export PGPASSFILE="$PGPASS_TMP"
fi
# Removed on every exit path, including a signal -- a stray pass file is the
# same class of leftover as the .env.local backups this repo just cleaned up.
cleanup_pgpass() { [ -n "$PGPASS_TMP" ] && rm -f "$PGPASS_TMP"; }
trap cleanup_pgpass EXIT HUP INT TERM

# ⛔ EMPTY IS "NOT CONFIGURED", NOT "NO PASSWORD". Those send you to different
# places -- one means fill in the file, the other means the server rejected
# you -- so they must never produce the same message. Peer/socket auth is the
# one case where empty is legitimately correct.
case "$HOST" in
  /*) SOCKET=1 ;;
  *)  SOCKET=0 ;;
esac
if [ -z "$DBPASS" ] && [ "$SOCKET" -eq 0 ]; then
  cat >&2 <<EOF
[devdb] target '$TARGET' has no password set in $SECRETS

That is NOT an authentication failure -- the field is empty, so the credential
was never supplied. Fill in .databases.$TARGET.password and retry.
EOF
  exit 3
fi

# ⛔ Expressed twice, like dbcheck's read-only enforcement: the role is
# SELECT-only AND the session refuses writes. Either alone is enough until the
# day someone hands this script a role that is not what they thought.
if [ "$RO" = "True" ] || [ "$RO" = "true" ]; then
  export PGOPTIONS="${PGOPTIONS:-} -c default_transaction_read_only=on"
fi

# Say which database answered. A diagnostic number with no provenance is how
# a staging figure gets reported as production.
echo "[devdb] $TARGET -> $DBUSER@$HOST:$PORT/$DBNAME$([ "$RO" = "True" ] || [ "$RO" = "true" ] && echo ' (read-only session)')" >&2

# ⛔ NOT `exec` ANY MORE: exec replaces this shell and the EXIT trap never runs,
# which would leave the temporary pass file behind on every invocation.
psql -X -v ON_ERROR_STOP=1 \
  -h "$HOST" -p "$PORT" -U "$DBUSER" -d "$DBNAME" "$@"
status=$?
cleanup_pgpass
trap - EXIT HUP INT TERM
exit "$status"
