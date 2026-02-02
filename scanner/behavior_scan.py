import psutil
import time
import os

def scan_behavior():
    report = ""
    
    # 🔥 High CPU usage detection
    for proc in psutil.process_iter(['name', 'cpu_percent']):
        try:
            if proc.info['cpu_percent'] > 85:
                report += f"[!] High CPU Usage: {proc.info['name']} ({proc.info['cpu_percent']}%)\n"
        except:
            continue

    # 🔥 Rapid file modification detection (ransomware indicator)
    temp_dir = "C:\\Users\\Public"
    file_changes = 0

    start_time = time.time()
    for root, dirs, files in os.walk(temp_dir):
        for file in files:
            full_path = os.path.join(root, file)
            try:
                if time.time() - os.path.getmtime(full_path) < 60:
                    file_changes += 1
            except:
                continue

    if file_changes > 50:
        report += "[!!!] Possible Ransomware Activity: Massive file changes detected!\n"

    return report if report else "✔ No abnormal behavior detected.\n"
