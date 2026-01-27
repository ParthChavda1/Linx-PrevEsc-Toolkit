import os
import stat

CRON_FILES = [
    "/etc/crontab"
]

CRON_DIRS = [
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly"
]

DANGEROUS_PATHS = ["/tmp", "/var/tmp", "/dev/shm"]

def is_world_writable(mode):
    return bool(mode & stat.S_IWOTH)

def is_group_writable(mode):
    return bool(mode & stat.S_IWGRP)

def is_writable_by_non_root(st):
    return is_world_writable(st.st_mode) or is_group_writable(st.st_mode)

def is_symlink(path):
    return os.path.islink(path)

def record(findings, **kwargs):
    findings.append(kwargs)

def scan_crontab_file(path, findings):
    try:
        with open(path, "r") as f:
            lines = f.readlines()
    except:
        return

    for line in lines:
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) < 7:
            continue

        user = parts[5]
        command = " ".join(parts[6:])

        if user != "root":
            continue

        # Extract executable
        cmd = command.split()[0]

        if not cmd.startswith("/"):
            record(findings,
                type="Cron PATH Hijack",
                cron_source=path,
                runs_as="root",
                command=command,
                severity="HIGH",
                issue="Cron executes command without absolute path",
                why_exploitable="Attacker can hijack PATH to execute malicious binary"
            )
            continue

        if not os.path.exists(cmd):
            continue

        try:
            st = os.stat(cmd)
        except:
            continue

        if is_symlink(cmd):
            record(findings,
                type="Cron Symlink Execution",
                cron_source=path,
                runs_as="root",
                path=cmd,
                severity="HIGH",
                issue="Cron executes symlinked script",
                why_exploitable="Symlink replacement leads to root execution"
            )

        if is_writable_by_non_root(st):
            record(findings,
                type="Writable Cron Script",
                cron_source=path,
                runs_as="root",
                path=cmd,
                severity="HIGH",
                issue="Cron executes writable script as root",
                why_exploitable="Attacker can inject commands executed by root"
            )

        for bad in DANGEROUS_PATHS:
            if cmd.startswith(bad):
                record(findings,
                    type="Cron Timing Attack",
                    cron_source=path,
                    runs_as="root",
                    path=cmd,
                    severity="HIGH",
                    issue="Cron executes script from temporary directory",
                    why_exploitable="Script replacement race leads to root execution"
                )

def scan_cron_dirs(findings):
    for d in CRON_DIRS:
        if not os.path.exists(d):
            continue

        try:
            st = os.stat(d)
        except:
            continue

        if is_writable_by_non_root(st):
            record(findings,
                type="Writable Cron Directory",
                cron_source=d,
                runs_as="root",
                severity="HIGH",
                issue="Cron directory writable by non-root user",
                why_exploitable="Attacker can drop malicious script executed by cron"
            )

        if os.path.isdir(d):
            for f in os.listdir(d):
                path = os.path.join(d, f)

                if not os.path.isfile(path):
                    continue

                try:
                    st = os.stat(path)
                except:
                    continue

                if is_writable_by_non_root(st):
                    record(findings,
                        type="Writable Cron Script",
                        cron_source=d,
                        runs_as="root",
                        path=path,
                        severity="HIGH",
                        issue="Writable script executed by cron as root",
                        why_exploitable="Attacker can modify script to gain root"
                    )

                if is_symlink(path):
                    record(findings,
                        type="Cron Symlink Execution",
                        cron_source=d,
                        runs_as="root",
                        path=path,
                        severity="HIGH",
                        issue="Cron executes symlinked script",
                        why_exploitable="Symlink replacement attack"
                    )

def scan_cron():
    findings = []

    for f in CRON_FILES:
        if os.path.exists(f):
            scan_crontab_file(f, findings)

    scan_cron_dirs(findings)
    return findings
