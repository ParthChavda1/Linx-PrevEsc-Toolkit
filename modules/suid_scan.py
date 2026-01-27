import json
import os
import subprocess

GTFO_DB = "data/gtfobins.json"


def load_gtfobins():
    if not os.path.exists(GTFO_DB):
        return {}
    with open(GTFO_DB, "r") as f:
        return json.load(f)


def scan_suid_sgid_binaries():
    findings = []

    find_cmd = "find / -xdev -type f -executable -user root -perm -4000 -o -perm -2000 2>/dev/null"
    # find_cmd1 = ["find", "/", "-xdev", "-type", "f", "-executable", "-user", "root", "-perm", "-4000", "-o", "-perm" ,"-2000"]

    try:
        result = subprocess.getoutput(find_cmd)
        # result1 = subprocess.run(find_cmd1,stderr=subprocess.DEVNULL,stdout=subprocess.PIPE)
    except Exception:
        return findings

    gtfobins = load_gtfobins()

    for line in result.splitlines():
        binary_path = line.strip()
        binary_name = os.path.basename(binary_path)

        finding = {
            "type": "SUID/SGID Binary",
            "path": binary_path,
            "binary": binary_name,
            "severity": "LOW",
            "potentially_exploited": False,
            "reason": "",
            "mitigation": "Review necessity of special permission bits"
        }

        # High-risk GTFOBins match
        if binary_name in gtfobins:
            finding["severity"] = "HIGH"
            finding["potentially_exploited"] = True
            finding["reason"] = gtfobins[binary_name]
            finding["mitigation"] = (
                "Remove SUID/SGID bit if not required or restrict access"
            )
        if finding["potentially_exploited"]:
            findings.append(finding)

    return findings
