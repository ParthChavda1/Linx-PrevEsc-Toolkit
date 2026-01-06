import os

CRON_FILE = "/etc/crontab"

def scan_cron_jobs():
    findings = []

    if not os.path.exists(CRON_FILE):
        return findings
    with open(CRON_FILE,"r") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) <7:
                continue

            user = parts[5]
            command = parts[6]
            if user == "root":
                findings.append({
                    "type":"cron",
                    "user":user,
                    "command":command
                })
    
    return findings

