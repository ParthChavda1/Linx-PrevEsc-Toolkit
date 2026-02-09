from modules.system_info import get_sytem_info
from modules.cron_scan import scan_cron
from modules.kernel_scan import scan_kernel
from modules.suid_scan import scan_suid_sgid_binaries
from modules.permission_scan import scan_permissions
from modules.service_scan import scan_services
from report_generation.reprot_generator import generate_report,generate_txt_report

def main():
    print("[*] Starting Linux PrivExc Audit Tool")
    print("="*60+"\n")

    print("[+] Getting System Information")
    system_info = get_sytem_info()

    print("[+]  SUID Binary Scan")
    suid_findings = scan_suid_sgid_binaries()
    print("SUID Binary Scan Complete")
  
    print("[+] Permission Scan")
    permission_findings = scan_permissions()
    print("Permission Scan Complete")
    
    print("[+] Service Scan")
    service_findings = scan_services()
    print("Service Scan Complete")

    print("[+] Cron Scan")
    cron_findings = scan_cron()
    print("Cron Scan Complete")

    print("[+] Kernel Analysis")
    kernel_finding = scan_kernel()
    print("Kernel Analysis Complete\n")

    print("Generating Report....")
    json_file = generate_report(system_info,suid_findings,permission_findings,service_findings,cron_findings,kernel_finding)
    report_file = generate_txt_report(json_file)
    print("Report Generation Complete")
    print(f"\n\nReport.json:{json_file}\n Report.txt: {report_file}")

if __name__ == "__main__":
    main()

