import json
import os
import datetime
import platform

OUTPUT_TXT = "reports/report.txt"


def calculate_overall_risk(severity_count):
    if severity_count.get("CRITICAL", 0) > 0:
        return "CRITICAL"
    if severity_count.get("HIGH", 0) > 0:
        return "HIGH"
    if severity_count.get("MEDIUM", 0) > 0:
        return "MEDIUM"
    return "LOW"

def write_section(f,title):
    f.write("\n" + "="*60 + "\n")
    f.write(f"{title}")
    f.write("="*60 + "\n")



def generate_report(
    system_info,
    suid_findings,
    permission_findings,
    service_findings,
    cron_findings,
    kernel_finding
):
    findings = []
    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    fid = 1

    def add_finding(category, severity, title, component, exploit, mitigation):
        nonlocal fid
        findings.append({
            "id": f"FND-{fid:03}",
            "category": category,
            "severity": severity,
            "title": title,
            "affected_component": component,
            "exploitation_possibility": exploit,
            "suggested_mitigation": mitigation
        })
        severity_count[severity] += 1
        fid += 1

    # ---------------- SUID SCAN ----------------
    for f in suid_findings:
        add_finding(
            category="SUID Binary",
            severity="HIGH",
            title="Suspicious SUID binary detected",
            component=f["path"],
            exploit="SUID binary may allow execution of commands with root privileges if abused.",
            mitigation="Review necessity of SUID bit, restrict permissions or remove the binary."
        )

    # ---------------- PERMISSION SCAN ----------------
    for f in permission_findings:
        add_finding(
            category="Weak File Permissions",
            severity=f["severity"],
            title=f["issue"],
            component=f["path"],
            exploit=f["why_exploitable"],
            mitigation="Restrict permissions and ensure root-only ownership."
        )

    # ---------------- SERVICE SCAN ----------------
    for f in service_findings:
        add_finding(
            category="Service Misconfiguration",
            severity=f["severity"],
            title=f["issue"],
            component=f["service"],
            exploit=f["exploit"],
            mitigation="Ensure service files and referenced binaries are root-owned and non-writable."
        )

    # ---------------- CRON SCAN ----------------
    for f in cron_findings:
        add_finding(
            category="Cron Job Vulnerability",
            severity=f["severity"],
            title=f["issue"],
            component=f["path"],
            exploit=f["why_exploitable"],
            mitigation="Ensure cron jobs execute only root-owned, non-writable scripts."
        )

    # ---------------- KERNEL SCAN ----------------
        add_finding(
            category="Kernel Analysis",
            severity=kernel_finding["risk"],
            title="Kernel privilege escalation assessment",
            component=kernel_finding["version"],
            exploit=kernel_finding["reason"],
            mitigation=kernel_finding["mitigation"]
        )

    report = {
        "scan_metadata": {
            "scan_time": datetime.datetime.utcnow().isoformat() + "Z",
            "tool_name": "Linux PrivEsc Audit Tool",
            "tool_version": "1.0",
            "scan_type": "Local Privilege Escalation Assessment"
        },

        "system_information": {
            "user": system_info["user"],
            "uid": system_info["uid"],
            "is_root": system_info["is_root"],
            "os": system_info["os"],
            "kernel": system_info["kernel"],
            "architecture": platform.machine()
        },

        "summary": {
            "total_findings": len(findings),
            "severity_breakdown": severity_count,
            "overall_risk": calculate_overall_risk(severity_count)
        },

        "findings": findings
    }

    os.makedirs("reports", exist_ok=True)
    output_file = "reports/report.json"

    with open(output_file, "w") as f:
        json.dump(report, f, indent=4)

    return output_file


def generate_txt_report(json_file):
    lines = []
    with open(json_file,"r") as f:
        data = json.load(f)
    # =========================
    # HEADER
    # =========================
    meta = data.get("scan_metadata", {})
    sysinfo = data.get("system_information", {})
    summary = data.get("summary", {})

    lines.append("LINUX PRIVILEGE ESCALATION ASSESSMENT REPORT")
    lines.append("=" * 55)
    lines.append(f"Tool Name     : {meta.get('tool_name')}")
    lines.append(f"Tool Version  : {meta.get('tool_version')}")
    lines.append(f"Scan Type     : {meta.get('scan_type')}")
    lines.append(f"Scan Time     : {meta.get('scan_time')}")
    lines.append("")

    # =========================
    # SYSTEM INFORMATION
    # =========================
    lines.append("SYSTEM INFORMATION")
    lines.append("-" * 25)
    lines.append(f"User          : {sysinfo.get('user')}")
    lines.append(f"UID           : {sysinfo.get('uid')}")
    lines.append(f"Is Root       : {sysinfo.get('is_root')}")
    lines.append(f"Operating Sys : {sysinfo.get('os')}")
    lines.append(f"Kernel        : {sysinfo.get('kernel')}")
    lines.append(f"Architecture  : {sysinfo.get('architecture')}")
    lines.append("")

    # =========================
    # EXECUTIVE SUMMARY
    # =========================
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 25)
    lines.append(f"Total Findings : {summary.get('total_findings')}")
    lines.append("Severity Breakdown:")

    sev = summary.get("severity_breakdown", {})
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        lines.append(f"  {level:<9}: {sev.get(level, 0)}")

    lines.append(f"Overall Risk   : {summary.get('overall_risk')}")
    lines.append("")

    # =========================
    # DETAILED FINDINGS
    # =========================
    lines.append("DETAILED FINDINGS")
    lines.append("=" * 55)

    for finding in data.get("findings", []):
        lines.append(f"Finding ID    : {finding.get('id')}")
        lines.append(f"Category      : {finding.get('category')}")
        lines.append(f"Severity      : {finding.get('severity')}")
        lines.append(f"Title         : {finding.get('title')}")
        lines.append(f"Affected Item : {finding.get('affected_component')}")
        lines.append("")
        lines.append("Exploitation Possibility:")
        lines.append(f"  {finding.get('exploitation_possibility')}")
        lines.append("")
        lines.append("Suggested Mitigation:")
        lines.append(f"  {finding.get('suggested_mitigation')}")
        lines.append("-" * 55)


    with open(OUTPUT_TXT, "w") as f:
        f.write("\n".join(lines))

    return OUTPUT_TXT
