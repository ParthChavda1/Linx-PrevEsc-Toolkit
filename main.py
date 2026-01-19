from core.system_info import get_sytem_info
from core.analyzer import cron_analyzer

from modules.cron_scan import scan_cron_jobs
from modules.kernel_scan import scan_kernel
from modules.suid_scan import scan_suid_binaries

def main():
    print("[*] Starting Linux PrivExc Audit Tool \n")

    system_info = get_sytem_info()
    print("[+] System Information:")
    for k ,v in system_info.items():
        print(f"    {k}: {v}")

    suid_findings = scan_suid_binaries()
    print("[+]  SUID Binary Scan")
    for item in suid_findings:
        if item["potentially_exploited"]:
            print(f"[High] {item['path']} -> {item['reason']}")
        else:
            print(f"[INFO] {item["path"]}")
    

    # cron_findings = scan_cron_jobs()
    # print("\n[+] Cron Jobs Running as Root:")
    # for job in cron_findings:
    #     print(f"    {job['command']}")
    
    # analysis_result = cron_analyzer(cron_findings)
    # print("\n[+] Cron Analysis result")
    # for item in analysis_result:
    #     print(f"    [{item['severity']}] {item['command']} → {item['reason']}")


    # kernel_finding = scan_kernel()
    # print("\n[+] Kernel Analysis")
    # print(kernel_finding)




if __name__ == "__main__":
    main()