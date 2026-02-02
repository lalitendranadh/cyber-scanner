import psutil

# List to store suspicious IPs for map visualization
suspicious_ips = []

COMMON_PORTS = [80, 443, 53, 22]

def scan_network():
    global suspicious_ips
    report = ""
    suspicious_ips.clear()  # reset before each scan

    connections = psutil.net_connections(kind='inet')

    for conn in connections:
        if conn.raddr:
            ip = conn.raddr.ip
            port = conn.raddr.port

            if port not in COMMON_PORTS and not ip.startswith("127."):
                suspicious_ips.append(ip)
                report += f"[!] Unusual External Connection → {ip}:{port}\n"

    return report if report else "✔ No suspicious network activity.\n"
