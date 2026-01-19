

def cron_analyzer(findings):
    severity = "LOW"
    reason = "cron jobs runs as root but scripts are not writable"
    analysis_result = []
    for item in findings:
        if item['file_writable'] or item['dir_writable']:
            severity = "HIGH"
            reason = "writable cron scripts or directory executed by root"
        
        result ={
            "type":"cron",
            "command" : item['command'],
            "user": item['user'],
            "severity":severity,
            "reason": reason
        }
        analysis_result.append(result)

    
    return analysis_result

