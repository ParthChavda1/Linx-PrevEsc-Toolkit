import os
import stat

CRON_FILE = "/etc/crontab"

def is_writable(path):
    try:
      st = os.stat(path)
      return bool(st.st_mode and stat.S_IWOTH)
    except :
        return False


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
            if user != "root":
                continue
            
            finding = {
                "type":"cron",
                "user":user,
                "command":command,
                "dir_writable": False,
                "file_writable":False
            }
            if os.path.exists(command):
                finding["file_writable"] = is_writable(command)
                finding["dir_writable"] = is_writable(os.path.dirname(command))
            findings.append(finding)
    
    return findings

