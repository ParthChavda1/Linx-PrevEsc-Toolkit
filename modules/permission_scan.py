import os
import stat
import subprocess

# ---------------- CONFIG ---------------- #

SAFE_WORLD_WRITABLE_DIRS = (
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/run",
    "/run/lock"
)

SYSTEMD_DIRS = (
    "/etc/systemd/system",
    "/lib/systemd/system",
    "/usr/lib/systemd/system"
)

CRON_FILES = (
    "/etc/crontab",
)

CRON_DIRS = (
    "/etc/cron.d",
    "/var/spool/cron"
)

SENSITIVE_FILES = {
    "/etc/passwd": "Writable passwd allows account takeover",
    "/etc/shadow": "Readable/writable shadow allows password hash theft",
    "/etc/sudoers": "Writable sudoers allows instant root"
}

# ---------------- HELPERS ---------------- #

def is_world_writable(mode):
    return bool(mode & stat.S_IWOTH)

def has_sticky_bit(mode):
    return bool(mode & stat.S_ISVTX)

def is_group_writable(mode):
    return bool(mode & stat.S_IWGRP)

def is_writable_by_non_root(st):
    # world-writable
    if st.st_mode & stat.S_IWOTH:
        return True

    # group-writable and group != root
    if st.st_mode & stat.S_IWGRP and st.st_gid != 0:
        return True

    return False

def scan_permissions():
    findings = []

    # ---------- 1. Sensitive Files ----------
    for path, reason in SENSITIVE_FILES.items():
        if not os.path.exists(path):
            continue

        st = os.stat(path)
        if is_world_writable(st.st_mode) or is_writable_by_non_root(st):
            findings.append({
                "type": "Sensitive File Permission",
                "path": path,
                "severity": "CRITICAL",
                "issue": reason,
                "why_exploitable": "File can be modified by non-root user"
            })

    # ---------- 2. Writable Systemd Services ----------
    for base in SYSTEMD_DIRS:
        if not os.path.isdir(base):
            continue

        for root, _, files in os.walk(base):
            for f in files:
                if not f.endswith(".service"):
                    continue

                path = os.path.join(root, f)

                try:
                    # lstat → DO NOT follow symlinks
                    st = os.lstat(path)
                except OSError:
                    continue

                # Ignore symlinks (masked services etc.)
                if stat.S_ISLNK(st.st_mode):
                    try:
                        target = os.path.realpath(path)
                        if target == "/dev/null":
                            continue  # masked service → safe
                    except OSError:
                        continue
                    else:
                        continue  # any symlink → ignore

                # Must be a regular file
                if not stat.S_ISREG(st.st_mode):
                    continue

                # Must be owned by root
                if st.st_uid != 0:
                    continue

                # Must be writable by non-root
                if not (is_world_writable(st.st_mode) or is_group_writable(st.st_mode)):
                    continue

                # Parse ExecStart safely
                exec_start = None
                try:
                    with open(path, "r", errors="ignore") as sf:
                        for line in sf:
                            line = line.strip()
                            if line.startswith("ExecStart="):
                                exec_start = line.split("=", 1)[1].split()[0]
                                break
                except OSError:
                    continue

                if not exec_start:
                    continue

                # ExecStart must point to real executable
                if not os.path.isfile(exec_start):
                    continue

                try:
                    est = os.stat(exec_start)
                except OSError:
                    continue

                if est.st_uid != 0:
                    continue

                findings.append({
                    "type": "Writable systemd Service",
                    "path": path,
                    "execstart": exec_start,
                    "severity": "HIGH",
                    "issue": "Writable systemd service file executed by root",
                    "why_exploitable": "Attacker can modify ExecStart or service directives"
                })
    # ---------- 3. Writable Cron Scripts ----------
    cron_targets = []

    for f in CRON_FILES:
        if os.path.exists(f):
            cron_targets.append(f)

    for d in CRON_DIRS:
        if os.path.isdir(d):
            for f in os.listdir(d):
                cron_targets.append(os.path.join(d, f))

    for cron in cron_targets:
        try:
            with open(cron, "r", errors="ignore") as c:
                lines = c.readlines()
        except:
            continue

        for line in lines:
            if line.startswith("#") or len(line.split()) < 6:
                continue

            script = line.split()[-1]
            if not os.path.exists(script):
                continue

            try:
                st = os.stat(script)
            except:
                continue

            if is_world_writable(st.st_mode) or is_writable_by_non_root(st):
                findings.append({
                    "type": "Writable Cron Script",
                    "path": script,
                    "severity": "HIGH",
                    "issue": "Cron executes writable script as root",
                    "why_exploitable": "Cron runs as root automatically"
                })

    # ---------- 4. World-Writable Directories (STRICT) ----------
    dir_cmd = "find / -xdev -type d -perm -0002 2>/dev/null"
    dirs = subprocess.getoutput(dir_cmd).splitlines()

    for d in dirs:
        try:
            st = os.stat(d)
        except:
            continue

        if d.startswith(SAFE_WORLD_WRITABLE_DIRS):
            if has_sticky_bit(st.st_mode):
                continue

        findings.append({
            "type": "Exploitable World-Writable Directory",
            "path": d,
            "severity": "MEDIUM",
            "issue": "World-writable directory without sticky-bit",
            "why_exploitable": "Files can be replaced or hijacked by attacker"
        })

    return findings
