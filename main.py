from core.system_info import get_sytem_info
from modules.cron_scan import scan_cron_jobs

def main():
    print("[*] Starting Linux PrivExc Audit Tool \n")

    system_info = get_sytem_info()
    print("[+] System Information:")
    for k ,v in system_info.items():
        print(f"    {k}: {v}")

    cron_findings = scan_cron_jobs()
    print("\n[+] Cron Jobs Running as Root:")
    for job in cron_findings:
        print(f"    {job['command']}")

if __name__ == "__main__":
    main()