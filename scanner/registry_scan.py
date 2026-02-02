import winreg

def scan_registry():
    report = ""
    locations = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ]

    for hive, path in locations:
        try:
            key = winreg.OpenKey(hive, path)
            i = 0
            while True:
                name, value, _ = winreg.EnumValue(key, i)
                if "AppData" in value or "Temp" in value:
                    report += f"[!!!] Suspicious Startup Entry: {name} → {value}\n"
                i += 1
        except OSError:
            pass

    return report if report else "✔ No suspicious startup registry entries.\n"
