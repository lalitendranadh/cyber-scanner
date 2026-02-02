import os

suspicious_ext = [".exe", ".bat", ".vbs", ".ps1"]

def scan_files():
    report = ""
    scan_dirs = ["C:\\Users\\Public\\Downloads", "C:\\Windows\\Temp"]

    for folder in scan_dirs:
        for root, dirs, files in os.walk(folder):
            for file in files:
                if any(file.endswith(ext) for ext in suspicious_ext):
                    report += f"[!] Suspicious File Found: {os.path.join(root, file)}\n"

    return report if report else "✔ No suspicious files detected.\n"
