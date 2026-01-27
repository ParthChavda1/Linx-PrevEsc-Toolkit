import os
import stat
import pwd

SYSTEMD_DIRS = [
    "/etc/systemd/system",
    "/lib/systemd/system",
    "/usr/lib/systemd/system"
]

EXCLUDED_PATHS = ("/proc", "/sys", "/dev", "/run")

def is_world_writable(mode):
    return bool(mode & stat.S_IWOTH)

def is_writable_by_user(path):
    try:
        return os.access(path, os.W_OK)
    except:
        return False

def is_real_file(path):
    if os.path.islink(path):
        target = os.readlink(path)
        if target == "/dev/null":
            return False
    return os.path.isfile(path)

def parse_service_file(path):
    exec_cmds = []
    env_files = []
    user = "root"
    path_env = None

    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()

                if line.startswith("ExecStart"):
                    exec_cmds.append(line.split("=", 1)[1].split()[0])

                if line.startswith("EnvironmentFile"):
                    env_files.append(line.split("=", 1)[1])

                if line.startswith("Environment=PATH="):
                    path_env = line.split("=", 2)[2]

                if line.startswith("User="):
                    user = line.split("=", 1)[1]
    except:
        pass

    return user, exec_cmds, env_files, path_env

def scan_services():
    findings = []

    for base in SYSTEMD_DIRS:
        if not os.path.isdir(base):
            continue

        for root, _, files in os.walk(base):
            for f in files:
                if not f.endswith(".service"):
                    continue

                svc_path = os.path.join(root, f)

                if not is_real_file(svc_path):
                    continue

                try:
                    st = os.stat(svc_path)
                except:
                    continue

                user, exec_cmds, env_files, path_env = parse_service_file(svc_path)

                # Only root-run services
                if user not in ("root", ""):
                    continue

                # 1️⃣ Writable service file
                if is_world_writable(st.st_mode):
                    findings.append({
                        "type": "Writable systemd service file",
                        "service": svc_path,
                        "severity": "HIGH",
                        "issue": "Service file is world-writable",
                        "exploit": "Attacker can inject commands into ExecStart executed by root"
                    })

                # 2️⃣ ExecStart binary/script writable
                for cmd in exec_cmds:
                    if not cmd.startswith("/"):
                        continue

                    if any(cmd.startswith(p) for p in EXCLUDED_PATHS):
                        continue

                    if os.path.exists(cmd) and is_writable_by_user(cmd):
                        findings.append({
                            "type": "Writable ExecStart target",
                            "service": svc_path,
                            "binary": cmd,
                            "severity": "HIGH",
                            "issue": "Root executes a user-writable file",
                            "exploit": "Modify executable to gain root shell on service restart"
                        })

                # 3️⃣ PATH hijacking
                if path_env:
                    for p in path_env.split(":"):
                        if os.path.isdir(p) and is_writable_by_user(p):
                            findings.append({
                                "type": "Insecure PATH in service",
                                "service": svc_path,
                                "path": p,
                                "severity": "HIGH",
                                "issue": "Writable directory in PATH",
                                "exploit": "Place malicious binary to hijack command execution"
                            })

                # 4️⃣ Writable EnvironmentFile
                for env in env_files:
                    if os.path.exists(env) and is_writable_by_user(env):
                        findings.append({
                            "type": "Writable EnvironmentFile",
                            "service": svc_path,
                            "file": env,
                            "severity": "HIGH",
                            "issue": "Environment variables controlled by user",
                            "exploit": "Inject malicious variables executed by root"
                        })

    return findings


