from datetime import datetime

LOG_FILE = "logs/scan_log.txt"

def log_result(text):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now()}]\n{text}\n")
