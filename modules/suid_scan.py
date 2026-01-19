import json
import os
import subprocess

GTFO_DB = "data/gtfobins.json"

def load_gtfobins():
    if not os.path.exists(GTFO_DB):
        return []
    with open(GTFO_DB,"r") as f:
        return json.load(f)


def scan_suid_binaries():
    findings = []

    try: 
        result = subprocess.run(["find","/","-perm","-4000","-type", "f"],
                                capture_output=True,
                                text=True)
        
    except Exception:
        return findings
    
    gtfobins = load_gtfobins()
    print(gtfobins)
    for lines in result.stdout.splitlines():
        binary_path = lines.strip()
        binary_name = os.path.basename(binary_path)
        finding = {
            "type": "suid",
            "path": binary_path,
            "binary":binary_name,
            "potentially_exploited": False,
            "reason":""
        }
        if binary_name in gtfobins:
            finding["reason"] = gtfobins[binary_name]
            finding["potentially_exploited"] = True

        findings.append(finding)

    return findings