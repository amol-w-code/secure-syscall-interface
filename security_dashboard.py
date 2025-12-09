import tkinter as tk
from tkinter import ttk, scrolledtext
import subprocess
import threading
import os
import collections

# Matplotlib integration
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class SecurityDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows System Sentinel - [Authentication Check]")
        self.root.geometry("1000x750")
        self.root.configure(bg="#2c3e50")

        # --- Data Tracking ---
        self.severity_counts = collections.defaultdict(int)
        self.event_counts = collections.defaultdict(int)
        self.running = False

        # --- Styles ---
        style = ttk.Style()
        style.theme_use('vista')
        style.configure("TLabel", background="#2c3e50", foreground="white", font=("Segoe UI", 10))
        
        # --- Header Section ---
        header_frame = tk.Frame(root, bg="#2c3e50")
        header_frame.pack(pady=10, fill="x")
        
        title = tk.Label(header_frame, text="Secure System Call Interface", font=("Segoe UI", 18, "bold"), bg="#2c3e50", fg="white")
        title.pack()

        # --- NEW: Auth Status Badge ---
        self.auth_label = tk.Label(header_frame, text="Checking Privileges...", font=("Consolas", 12, "bold"), bg="#95a5a6", fg="white", padx=10, pady=5)
        self.auth_label.pack(pady=5)

        # --- Control Panel ---
        control_frame = tk.Frame(root, bg="#34495e", padx=10, pady=10)
        control_frame.pack(fill="x", padx=20)

        ttk.Label(control_frame, text="Target Application:").pack(side="left", padx=5)
        
        self.cmd_entry = ttk.Entry(control_frame, width=25)
        self.cmd_entry.insert(0, "notepad.exe") 
        self.cmd_entry.pack(side="left", padx=5)

        self.start_btn = tk.Button(control_frame, text="RUN & MONITOR", bg="#27ae60", fg="white", font=("Segoe UI", 9, "bold"), command=self.start_monitoring)
        self.start_btn.pack(side="left", padx=10)
        
        self.refresh_btn = tk.Button(control_frame, text="REFRESH CHARTS", bg="#2980b9", fg="white", font=("Segoe UI", 9, "bold"), command=self.refresh_charts)
        self.refresh_btn.pack(side="left", padx=10)

        # --- Tabs ---
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill="both", padx=20, pady=10)

        self.tab_logs = tk.Frame(self.notebook, bg="#2c3e50")
        self.notebook.add(self.tab_logs, text="Live Log Feed")

        self.tab_charts = tk.Frame(self.notebook, bg="white")
        self.notebook.add(self.tab_charts, text="Visual Analytics")

        # --- Log View ---
        self.log_area = scrolledtext.ScrolledText(self.tab_logs, width=100, height=25, bg="black", fg="#00ff00", font=("Consolas", 10))
        self.log_area.pack(expand=True, fill="both", padx=10, pady=10)
        
        self.log_area.tag_config("HIGH", foreground="#e74c3c")
        self.log_area.tag_config("MEDIUM", foreground="#f1c40f")
        self.log_area.tag_config("LOW", foreground="#2ecc71")
        self.log_area.tag_config("ADMIN", foreground="#3498db", font=("Consolas", 10, "bold"))

        # --- Chart Setup ---
        self.fig, (self.ax1, self.ax2) = plt.subplots(1, 2, figsize=(8, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.tab_charts)
        self.canvas.get_tk_widget().pack(expand=True, fill="both", padx=10, pady=10)
        self.refresh_charts()

    def start_monitoring(self):
        if self.running: return
        
        cmd = self.cmd_entry.get()
        self.log_area.delete(1.0, tk.END)
        self.log_area.insert(tk.END, f"[*] Initializing Sentinel on: {cmd}\n", "LOW")
        
        # Reset UI
        self.severity_counts.clear()
        self.event_counts.clear()
        self.auth_label.config(text="Waiting for Kernel...", bg="#95a5a6")
        self.running = True
        
        t = threading.Thread(target=self.run_cpp_engine, args=(cmd,))
        t.daemon = True
        t.start()

    def run_cpp_engine(self, target_cmd):
        exe_path = "monitor_core.exe"
        if not os.path.exists(exe_path):
             self.log_area.insert(tk.END, "[ERROR] monitor_core.exe not found.\n", "HIGH")
             self.running = False
             return

        full_cmd = [exe_path, target_cmd]
        
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        
        try:
            process = subprocess.Popen(
                full_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                startupinfo=startupinfo
            )

            for line in process.stdout:
                self.process_log_line(line.strip())
                
            process.wait()
            self.log_area.insert(tk.END, "\n[!] Monitoring Session Ended.\n", "LOW")
            self.running = False
            
        except Exception as e:
             self.log_area.insert(tk.END, f"[ERROR] Failed to start: {e}\n", "HIGH")
             self.running = False

    def process_log_line(self, log_line):
        try:
            parts = log_line.split("|")
            
            # --- NEW: Handle Auth Level ---
            if parts[0] == "AUTH_LEVEL":
                level = parts[1]
                msg = parts[2]
                
                if level == "ADMIN":
                    self.auth_label.config(text="🛡️ ADMIN MODE (High Integrity)", bg="#e74c3c")
                    self.log_area.insert(tk.END, f"[{level}] {msg}\n", "ADMIN")
                else:
                    self.auth_label.config(text="👤 USER MODE (Limited Rights)", bg="#2ecc71")
                    self.log_area.insert(tk.END, f"[{level}] {msg}\n", "LOW")
                return

            # Handle Standard Logs
            if len(parts) == 3:
                name, severity, pid = parts
                msg = f"[{severity}] Event: {name:<20} (PID: {pid})\n"
                self.log_area.insert(tk.END, msg, severity)
                self.log_area.see(tk.END)
                
                # Stats
                self.severity_counts[severity] += 1
                self.event_counts[name] += 1
                
        except:
            pass

    def refresh_charts(self):
        self.ax1.clear()
        self.ax2.clear()

        # Severity Pie Chart
        if self.severity_counts:
            labels = self.severity_counts.keys()
            sizes = self.severity_counts.values()
            colors = ['#e74c3c' if x == 'HIGH' else '#f1c40f' if x == 'MEDIUM' else '#2ecc71' for x in labels]
            self.ax1.pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors, startangle=140)
            self.ax1.set_title("Threat Severity")
        else:
            self.ax1.text(0.5, 0.5, "No Data", ha='center')

        # Event Bar Chart
        if self.event_counts:
            events = list(self.event_counts.keys())
            counts = list(self.event_counts.values())
            self.ax2.barh(events, counts, color='#3498db')
            self.ax2.set_title("System Call Volume")
        else:
            self.ax2.text(0.5, 0.5, "No Data", ha='center')

        self.fig.tight_layout()
        self.canvas.draw()

if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityDashboard(root)
    root.mainloop()