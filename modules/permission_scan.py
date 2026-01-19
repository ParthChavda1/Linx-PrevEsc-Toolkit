import subprocess


EXCLUDED_PATHS = ("/tmp","/var/tmp","/proc","/sys","/dev")

def is_excluded(path:str):
    return path.startswith(EXCLUDED_PATHS)

def detect_content(path:str):
    if path.startswith("/etc/cron"):
        return "CRON"
    if path.startswith("/etc/systemd/system") and path.endswith(".service"):
        return "SYSTEMD"
    if path.startswith("/etc/init."):
        return "INIT"
    if path.startswith("/usr/local/bin") or path.startswith("/usr/bin") or path.startswith("/bin"):
        return "EXECUTABLE"
    if path.startswith("/etc") and path.endswith(".conf"):
        return "CONFIG"
    return "UNKNOWN"

def classify_severity(context):
    if context in ("CRON","SYSTEMD"):
        return "HIGH"
    if context in ("EXECUTABLE","CONFIG","INIT"):
        return "MEDIUM"
    return "LOW"

def impact_for_context(context):
    impacts = {
        "CRON": "Attacker can inject commands that execute as root via cron",
        "SYSTEMD": "Attacker can modify a root-executed systemd service",
        "INIT": "Attacker can alter init scripts executed by root",
        "EXECUTABLE": "Attacker can modify a binary executed by root",
        "CONFIG": "Attacker can change configuration affecting root processes",
        "UNKNOWN": "Potential misconfiguration with unclear impact"
    }
    return impacts.get(context, "Unknown impact")


def scan_permissions():
    findings = []

    file_cmd = "find / -xdev -type f -user root -perm -0002 2>/dev/null"
    dir_cmd = "find / -xdev -type d -user root -perm -0002 2>/dev/null"

    files = subprocess.getoutput(file_cmd).splitlines()
    dirs = subprocess.getoutput(dir_cmd).splitlines()

    for path in files + dirs:
        if not path or is_excluded(path):
            continue
        context = detect_content(path)
        severity = classify_severity(context)
        impact = impact_for_context(context)
        findings.append({
            "path":path,
            "severity":severity,
            "context":context,
            "impact":impact
        })

    
    return findings

