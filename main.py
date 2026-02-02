import tkinter as tk
from tkinter import ttk, messagebox
import threading
import matplotlib.pyplot as plt
import psutil

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from scanner.process_scan import scan_processes
from scanner.file_scan import scan_files
from scanner.network_scan import scan_network, suspicious_ips
from scanner.behavior_scan import scan_behavior
from scanner.live_monitor import start_live_monitoring
from scanner.ip_map import generate_map

# ---------- Scan Logic ----------
def start_scan():
    risk_score = 0
    clear_tables()

    process_count = network_count = file_count = behavior_count = 0

    sections = [
        (process_table, scan_processes, "process"),
        (file_table, scan_files, "file"),
        (network_table, scan_network, "network"),
        (behavior_table, scan_behavior, "behavior"),
    ]

    for table, func, category in sections:
        result = func().split("\n")
        for line in result:
            if "[!]" in line or "[!!!]" in line:
                table.insert("", "end", values=(line,), tags=("threat",))
                risk_score += 1

                if category == "process": process_count += 1
                elif category == "network": network_count += 1
                elif category == "file": file_count += 1
                elif category == "behavior": behavior_count += 1
            elif line.strip():
                table.insert("", "end", values=(line,))

    update_risk_meter(risk_score)
    show_threat_pie(process_count, network_count, file_count, behavior_count)

def clear_tables():
    for table in [process_table, file_table, network_table, behavior_table]:
        for item in table.get_children():
            table.delete(item)

# ---------- Risk Meter ----------
def update_risk_meter(score):
    risk_bar["value"] = min(score * 10, 100)

    if score == 0:
        risk_label.config(text="SAFE", bg="green")
    elif score < 5:
        risk_label.config(text="MODERATE RISK", bg="orange")
    else:
        risk_label.config(text="HIGH RISK", bg="red")
        messagebox.showwarning("⚠ SECURITY ALERT", "High risk threats detected!")

# ---------- Threat Pie Chart ----------
def show_threat_pie(p, n, f, b):
    sizes = [p, n, f, b]
    if sum(sizes) == 0:
        return
    labels = ['Processes', 'Network', 'Files', 'Behavior']
    plt.figure(figsize=(4,4))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%')
    plt.title("Threat Distribution")
    plt.show()

# ---------- Live Monitoring ----------
def live_alert_output(message):
    behavior_table.insert("", "end", values=(message,), tags=("threat",))
    messagebox.showwarning("🚨 LIVE THREAT DETECTED", message[:200])

def start_live_protection():
    thread = threading.Thread(target=start_live_monitoring, args=(live_alert_output,), daemon=True)
    thread.start()

# ---------- Live System Graph ----------
def start_system_graph():
    graph_frame = tk.LabelFrame(content_frame, text="📈 Live System Performance",
                                fg="white", bg="#2b2b2b", font=("Arial", 11, "bold"))
    graph_frame.pack(padx=10, pady=10, fill="x")

    fig = Figure(figsize=(6, 2), dpi=100)
    ax = fig.add_subplot(111)
    canvas = FigureCanvasTkAgg(fig, master=graph_frame)
    canvas.get_tk_widget().pack()

    cpu_data, ram_data = [], []

    def update_graph():
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent

        cpu_data.append(cpu)
        ram_data.append(ram)

        cpu_data[:] = cpu_data[-20:]
        ram_data[:] = ram_data[-20:]

        ax.clear()
        ax.plot(cpu_data, label="CPU %")
        ax.plot(ram_data, label="RAM %")
        ax.legend()
        ax.set_title("Live CPU & RAM Usage")

        canvas.draw()
        root.after(2000, update_graph)

    update_graph()

# ---------- UI SETUP ----------
root = tk.Tk()
root.title("CyberScanner - Endpoint Security Dashboard")
root.geometry("1000x700")
root.configure(bg="#1e1e1e")

main_canvas = tk.Canvas(root, bg="#1e1e1e", highlightthickness=0)
main_canvas.pack(side="left", fill="both", expand=True)

scrollbar = ttk.Scrollbar(root, orient="vertical", command=main_canvas.yview)
scrollbar.pack(side="right", fill="y")

main_canvas.configure(yscrollcommand=scrollbar.set)

content_frame = tk.Frame(main_canvas, bg="#1e1e1e")
main_canvas.create_window((0, 0), window=content_frame, anchor="nw")

def on_configure(event):
    main_canvas.configure(scrollregion=main_canvas.bbox("all"))

content_frame.bind("<Configure>", on_configure)

def _on_mousewheel(event):
    main_canvas.yview_scroll(int(-1*(event.delta/120)), "units")

root.bind_all("<MouseWheel>", _on_mousewheel)

# ---------- HEADER ----------
title = tk.Label(content_frame, text="CyberScanner Security Dashboard",
                 font=("Arial", 18, "bold"), fg="white", bg="#1e1e1e")
title.pack(pady=10)

btn_frame = tk.Frame(content_frame, bg="#1e1e1e")
btn_frame.pack()

tk.Button(btn_frame, text="SCAN SYSTEM", bg="#ff4d4d", fg="white",
          command=start_scan).pack(side="left", padx=10)

tk.Button(btn_frame, text="START LIVE PROTECTION", bg="#007acc", fg="white",
          command=start_live_protection).pack(side="left", padx=10)

tk.Button(btn_frame, text="SHOW THREAT MAP", bg="#444", fg="white",
          command=lambda: generate_map(suspicious_ips)).pack(side="left", padx=10)

tk.Button(btn_frame, text="LIVE SYSTEM GRAPH", bg="#555", fg="white",
          command=start_system_graph).pack(side="left", padx=10)

# ---------- Risk Meter ----------
risk_label = tk.Label(content_frame, text="SYSTEM STATUS",
                      font=("Arial", 12, "bold"), width=20, bg="gray", fg="white")
risk_label.pack(pady=5)

risk_bar = ttk.Progressbar(content_frame, length=400, maximum=100)
risk_bar.pack(pady=5)

# ---------- Table Creator ----------
def create_table(title):
    frame = tk.LabelFrame(content_frame, text=title, fg="white", bg="#2b2b2b",
                          font=("Arial", 11, "bold"))

    tree = ttk.Treeview(frame, columns=("Details",), show="headings", height=8)
    tree.heading("Details", text="Details")
    tree.column("Details", width=850)

    scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)

    tree.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    tree.tag_configure("threat", background="#ffcccc")
    return frame, tree

frame1, process_table = create_table("🧠 Processes")
frame1.pack(padx=10, pady=5, fill="x")

frame2, network_table = create_table("🌐 Network")
frame2.pack(padx=10, pady=5, fill="x")

frame3, file_table = create_table("📁 Files")
frame3.pack(padx=10, pady=5, fill="x")

frame4, behavior_table = create_table("⚙ Behavior")
frame4.pack(padx=10, pady=5, fill="x")

root.mainloop()
