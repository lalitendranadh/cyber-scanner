import psutil

suspicious_paths = ["AppData", "Temp"]

def scan_processes():
    report = ""
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            name = proc.info['name'].lower()
            path = str(proc.info['exe'])

            # Suspicious location
            if any(loc in path for loc in suspicious_paths):
                report += f"[!] Suspicious Process Location: {name} (PID {proc.info['pid']})\n"

            # Hidden PowerShell attack
            if "powershell" in name and "-enc" in " ".join(proc.info['cmdline']).lower():
                report += f"[!!!] Encoded PowerShell Detected: PID {proc.info['pid']}\n"

        except:
            continue

    return report if report else "✔ No suspicious processes found.\n"
