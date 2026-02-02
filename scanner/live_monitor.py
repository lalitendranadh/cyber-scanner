import time
from scanner.process_scan import scan_processes
from scanner.behavior_scan import scan_behavior

def start_live_monitoring(output_callback):
    while True:
        result1 = scan_processes()
        result2 = scan_behavior()

        if "[!]" in result1 or "[!!!]" in result2:
            output_callback("🚨 LIVE THREAT DETECTED!\n" + result1 + result2)

        time.sleep(15)  # scan every 15 seconds
