import platform
import json
import os

CVE_DB = "data/kernel_cves.json"

def get_kernel_version():
    return platform.release()

def load_cve_database():
    if not os.path.exists(CVE_DB):
        return {}
    with open(CVE_DB,"r") as f:
        return json.load(f)

def scan_kernel():
    kernel_version = get_kernel_version()
    kernel_major = ".".join(kernel_version.split(".")[:2])
    
    kernel_cves = load_cve_database()

    finding = {
        "type":"Kernel",
        "version":kernel_version,
        "risk":"LOW",
        "cves":[],
        "reason": "No known privilege escalation CVEs in reference database",
        "mitigation": "Maintain regular kernel updates"
    }
    if kernel_major in kernel_cves:
        entry = kernel_cves["kernel_major"]
        finding["risk"] = entry["risk"]
        finding["cves"] = entry["cves"]
        finding["reason"] = "Update kernel to latest stable version"
        finding["mitigation"] = entry["note"]
    
    return finding



