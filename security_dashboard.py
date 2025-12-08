import tkinter as tk
from tkinter import ttk, scrolledtext
import subprocess
import threading
import os

class SecurityDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows System Monitor")
        self.root.geometry("700x500")
        self.root.configure(bg="#2c3e50")

        # --- Styles ---
        style = ttk.Style()
        style.theme_use('vista') # Use Windows native theme
        style.configure("TLabel", background="#2c3e50", foreground="white", font=("Segoe UI", 12))

        # --- Header ---
        header = ttk.Label(root, text="Windows Process Sentinel", font=("Segoe UI", 18, "bold"))
        header.pack(pady=15)

        # --- Control Panel ---
        control_frame = tk.Frame(root, bg="#34495e", padx=10, pady=10)
        control_frame.pack(fill="x", padx=20)

        ttk.Label(control_frame, text="Target (e.g. notepad.exe):").pack(side="left", padx=5)
        
        self.cmd_entry = ttk.Entry(control_frame, width=30)
        self.cmd_entry.insert(0, "notepad.exe") 
        self.cmd_entry.pack(side="left", padx=5)

        self.start_btn = tk.Button(control_frame, text="RUN & MONITOR", bg="#27ae60", fg="white", command=self.start_monitoring)
        self.start_btn.pack(side="left", padx=10)

        # --- Log View ---
        self.log_area = scrolledtext.ScrolledText(root, width=80, height=20, bg="black", fg="#00ff00", font=("Consolas", 10))
        self.log_area.pack(pady=20, padx=20)
        
        self.log_area.tag_config("HIGH", foreground="#e74c3c")
        self.log_area.tag_config("MEDIUM", foreground="#f1c40f")
        self.log_area.tag_config("LOW", foreground="#2ecc71")

    def start_monitoring(self):
        cmd = self.cmd_entry.get()
        self.log_area.delete(1.0, tk.END)
        self.log_area.insert(tk.END, f"[*] Launching Monitor on: {cmd}\n", "LOW")
        
        t = threading.Thread(target=self.run_cpp_engine, args=(cmd,))
        t.daemon = True
        t.start()

    def run_cpp_engine(self, target_cmd):
        # Ensure we are calling the .exe
        exe_path = "monitor_core.exe"
        if not os.path.exists(exe_path):
             self.log_area.insert(tk.END, "[ERROR] monitor_core.exe not found.\n", "HIGH")
             return

        # Prepare the command structure
        full_cmd = [exe_path, target_cmd]
        
        # Hide the black console window for the C++ engine
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        
        try:
            process = subprocess.Popen(
                full_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                startupinfo=startupinfo # Hides the extra window
            )

            for line in process.stdout:
                self.update_log(line.strip())
                
            process.wait()
            self.log_area.insert(tk.END, "\n[!] Process Finished.\n", "LOW")
            
        except Exception as e:
             self.log_area.insert(tk.END, f"[ERROR] Failed to start: {e}\n", "HIGH")

    def update_log(self, log_line):
        try:
            parts = log_line.split("|")
            if len(parts) == 3:
                name, severity, pid = parts
                msg = f"[{severity}] Event: {name:<20} (PID: {pid})\n"
                self.log_area.insert(tk.END, msg, severity)
                self.log_area.see(tk.END)
        except:
            pass

if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityDashboard(root)
    root.mainloop()