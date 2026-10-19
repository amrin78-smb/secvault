#!/usr/bin/env python3
"""
devwinrm.py -- run a command on a SecVault Windows server over WinRM, using the
credential kept OUTSIDE this repository in ~/.secvault-local-secrets.json.

    scripts/devwinrm.py production -- 'Get-Volume | Format-Table -AutoSize'
    scripts/devwinrm.py production --cmd 'sc.exe query SecVault-App'
    scripts/devwinrm.py production --probe        # auth only, runs nothing

⛔ NTLM ONLY, AND BASIC IS REFUSED. Port 5985 is plain HTTP and 5986 does not
   answer on these hosts, so the transport is unencrypted. NTLM never puts the
   password on the wire and encrypts the message payload; `basic` would send it
   in cleartext across the VPN. The refusal is here rather than in a comment
   because the config file is the easiest place to get this wrong.

⛔ THE DOMAIN LOGON FORM IS DISCOVERED, NOT GUESSED. CLAUDE.md records from a
   live probe that this directory's AD domain (thaiunion.co.th) and its UPN
   suffix (@thaiunion.com) DISAGREE, and that assuming one from the other
   already broke the LDAP bind. So the bare username is stored and the forms
   are tried in order, with the winning one reported.

⛔ AND TRYING FORMS COSTS LOCKOUT STRIKES. Every form is a separate failed
   logon for the same account, so a wrong PASSWORD across four forms is four
   strikes against the domain policy. Attempts are capped, the cap is stated
   before the first one, and the moment a form works you are told to pin it.
"""
import json
import os
import sys
import sysconfig

SECRETS = os.environ.get("SECVAULT_SECRETS_FILE",
                         os.path.expanduser("~/.secvault-local-secrets.json"))
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def die(msg, code=3):
    sys.stderr.write(f"[devwinrm] {msg}\n")
    sys.exit(code)


def load_target(name):
    if not os.path.exists(SECRETS):
        die(f"no credential file at {SECRETS}\n"
            f"            See docs/DEV-CREDENTIALS.md.")

    # ⛔ Checked BEFORE the file is opened -- reading it first would already
    # have exposed it this run. Same rule scripts/devdb.sh applies.
    mode = oct(os.stat(SECRETS).st_mode & 0o777)[2:]
    if mode not in ("600", "400"):
        die(f"REFUSING: {SECRETS} is mode {mode}, expected 600.\n"
            f"            fix with: chmod 600 {SECRETS}")

    if os.path.realpath(SECRETS).startswith(REPO_ROOT + os.sep):
        die(f"REFUSING: the credential file is INSIDE the repository\n"
            f"            ({SECRETS}). Keep it in $HOME; git cannot address it there.")

    with open(SECRETS, encoding="utf-8") as fh:
        data = json.load(fh)

    hosts = (data.get("winrm") or {}).get("hosts") or {}
    if name not in hosts:
        die(f"no winrm target {name!r}. known: {', '.join(sorted(hosts))}", 4)
    return hosts[name]


def logon_names(t):
    """Candidate logon strings, most likely first, de-duplicated in order."""
    user = (t.get("username") or "").strip()
    subs = {
        "user": user,
        "domain_fqdn": t.get("domain_fqdn") or "",
        "upn_suffix": t.get("upn_suffix") or "",
        "netbios": t.get("netbios") or "",
    }
    pinned = (t.get("logon_form") or "").strip()
    templates = [pinned] if pinned else list(t.get("logon_forms") or ["{user}"])
    out = []
    for tpl in templates:
        try:
            v = tpl.format(**subs)
        except KeyError:
            continue
        # A template whose placeholder resolved to nothing produces a broken
        # name like "\\user" or "user@" -- skip it rather than burning a strike.
        if not v or v.startswith("\\") or v.endswith("@") or v.endswith("\\"):
            continue
        if v not in [o[1] for o in out]:
            out.append((tpl, v))
    return out, bool(pinned)


def _clean_stderr(text):
    """
    Strip the CLIXML envelope PowerShell remoting wraps stderr in.

    ⛔ STRIPS THE ENVELOPE, NEVER THE MESSAGE. An <S S="Error"> record carries
    a real failure and is unwrapped and kept; only the progress/objects
    scaffolding is dropped. Silently discarding an unrecognised shape here
    would turn a remote error into a clean exit, which is the one outcome this
    whole file is written to avoid.
    """
    import re
    if "#< CLIXML" not in text:
        return text.strip()
    kept = []
    for m in re.finditer(r'<S S="(?:Error|Warning)"[^>]*>(.*?)</S>', text, re.S):
        frag = m.group(1)
        frag = frag.replace("_x000D__x000A_", "\n").replace("_x000A_", "\n")
        frag = (frag.replace("&lt;", "<").replace("&gt;", ">")
                    .replace("&quot;", '"').replace("&apos;", "'").replace("&amp;", "&"))
        kept.append(frag)
    out = "".join(kept).strip()
    if out:
        return out
    # Nothing recognised and the body was not just progress scaffolding: hand
    # it back rather than swallowing it.
    residue = re.sub(r"#< CLIXML\s*", "", text)
    residue = re.sub(r"<Objs .*?</Objs>", "", residue, flags=re.S).strip()
    return residue


def main():
    argv = sys.argv[1:]
    if not argv:
        die("usage: scripts/devwinrm.py <target> [--probe] [--cmd '<powershell>' | -- <powershell>]", 2)

    target_name, argv = argv[0], argv[1:]
    probe, command = False, None
    while argv:
        a = argv.pop(0)
        if a == "--probe":
            probe = True
        elif a == "--cmd":
            command = argv.pop(0) if argv else die("--cmd needs a command", 2)
        elif a == "--":
            command = " ".join(argv)
            argv = []
        else:
            die(f"unknown argument {a!r}", 2)
    if not probe and not command:
        die("nothing to run: pass --probe, --cmd '<ps>' or -- <ps>", 2)

    t = load_target(target_name)

    transport = (t.get("transport") or "").lower()
    port = int(t.get("port") or 5985)
    # ⛔ The whole reason this check exists. Never relax it for 5985.
    if transport != "ntlm":
        die(f"REFUSING transport {transport!r} on port {port}.\n"
            f"            Only 'ntlm' is permitted: 5985 is plain HTTP, and basic\n"
            f"            auth would put the password on the wire in cleartext.")

    if not (t.get("username") or "").strip():
        die(f"target '{target_name}' has no username set in {SECRETS}\n"
            f"            That is NOT an authentication failure -- the field is empty,\n"
            f"            so no credential was ever supplied.")
    if not (t.get("password") or ""):
        die(f"target '{target_name}' has no password set in {SECRETS}\n"
            f"            That is NOT an authentication failure -- the field is empty.")

    # ⛔ BEFORE importing winrm: ntlm_auth computes the NT hash with
    # hashlib.new('md4'), and OpenSSL 3 on this distro does not provide MD4, so
    # the import path works and the first connection dies with "unsupported
    # hash type md4". The shim self-verifies against RFC 1320 before it
    # installs -- a wrong MD4 would surface as "credentials rejected" and spend
    # real lockout strikes on a correct password.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        import _md4compat
        md4_mode = _md4compat.install()
    except Exception as e:
        die(f"MD4 is unavailable and the fallback could not be installed: {e}\n"
            f"            NTLM cannot compute an NT hash without it.")
    if md4_mode == 'shim':
        sys.stderr.write("[devwinrm] using the local MD4 fallback "
                         "(OpenSSL 3 disables md4); RFC 1320 vectors verified\n")

    try:
        import winrm
        from winrm.exceptions import InvalidCredentialsError
    except ImportError:
        die("pywinrm is not installed (python3-winrm / pip install pywinrm)")

    names, pinned = logon_names(t)
    if not names:
        die("no usable logon form: check username/domain_fqdn/upn_suffix in the file")

    cap = int(t.get("max_attempts") or len(names))
    names = names[:max(1, cap)]

    host = t["host"]
    endpoint = f"http://{host}:{port}/wsman"

    if pinned:
        sys.stderr.write(f"[devwinrm] {target_name} -> {endpoint} (pinned logon form)\n")
    else:
        sys.stderr.write(
            f"[devwinrm] {target_name} -> {endpoint}\n"
            f"[devwinrm] logon form not pinned; trying {len(names)} form(s). ⛔ EACH FAILURE IS A\n"
            f"[devwinrm] LOCKOUT STRIKE against this account -- stop and check the password if\n"
            f"[devwinrm] they all fail rather than editing forms and retrying.\n")

    # ⛔ A PowerShell remoting stream carries progress records as CLIXML on
    # STDERR, so an ordinary successful command arrives with ~1 KB of
    # <Objs Version="1.1.0.1"> noise wrapped around its real output -- and a
    # GENUINE error arrives the same way, which means the noise trains you to
    # ignore the channel that carries the failures. Silence the progress stream
    # at the source rather than filtering it at every call site.
    prelude = "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Continue'; "
    ps = prelude + (command if command else "$env:COMPUTERNAME; [Environment]::UserName")
    last = None
    for i, (tpl, name) in enumerate(names, 1):
        shown = name
        sys.stderr.write(f"[devwinrm]   attempt {i}/{len(names)}: {shown}\n")
        try:
            s = winrm.Session(
                endpoint,
                auth=(name, t["password"]),
                transport="ntlm",
                # message encryption over plain HTTP; pywinrm negotiates it for NTLM
                message_encryption="auto",
                read_timeout_sec=70,
                operation_timeout_sec=60,
            )
            r = s.run_ps(ps)
        except InvalidCredentialsError as e:
            last = f"credentials rejected ({e.__class__.__name__})"
            continue
        except Exception as e:  # transport/connection problems are NOT a strike
            msg = str(e)
            if "401" in msg or "Unauthorized" in msg or "authentication" in msg.lower():
                last = "credentials rejected (401)"
                continue
            die(f"transport error, not an auth failure: {e}", 5)

        sys.stderr.write(f"[devwinrm] AUTHENTICATED as {shown}\n")
        if not pinned:
            sys.stderr.write(
                f'[devwinrm] ⛔ PIN IT so later runs cost no lockout strikes. Set\n'
                f'[devwinrm]    .winrm.hosts.{target_name}.logon_form = {json.dumps(tpl)}\n')
        sys.stdout.write(r.std_out.decode("utf-8", "replace"))
        err = _clean_stderr(r.std_err.decode("utf-8", "replace"))
        if err:
            sys.stderr.write(err + "\n")
        sys.exit(r.status_code)

    die(f"all {len(names)} logon form(s) were rejected -- last: {last}\n"
        f"            The PASSWORD is the more likely cause than the form. Check it\n"
        f"            before retrying: further attempts cost more lockout strikes.", 6)


if __name__ == "__main__":
    main()
