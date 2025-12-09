import matplotlib.pyplot as plt
import numpy as np

# --- MOCK DATA BASED ON YOUR LOGS ---
# These numbers represent a typical session with Notepad
severities = ['LOW (Info)', 'MEDIUM (DLL Load)', 'HIGH (Process Event)']
severity_counts = [15, 45, 2]  # Mostly DLL loads, some threads, start/exit

event_types = ['LOAD_LIBRARY', 'THREAD_CREATE', 'OUTPUT_DEBUG', 'PROCESS_CREATE', 'PROCESS_EXIT']
event_counts = [42, 12, 5, 1, 1]

# Timeline data (simulated burst of activity at start)
time_seconds = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
activity_volume = [2, 15, 20, 8, 4, 2, 2, 1, 1, 1] 

# --- CHART 1: SEVERITY DISTRIBUTION (Pie) ---
plt.figure(figsize=(8, 6))
colors = ['#2ecc71', '#f1c40f', '#e74c3c'] # Green, Yellow, Red
plt.pie(severity_counts, labels=severities, autopct='%1.1f%%', startangle=140, colors=colors)
plt.title('Figure 1: Distribution of Threat Severity Levels', fontsize=14)
plt.savefig('severity_chart.png')
print("Generated severity_chart.png")

# --- CHART 2: EVENT FREQUENCY (Bar) ---
plt.figure(figsize=(10, 6))
plt.bar(event_types, event_counts, color='#3498db')
plt.title('Figure 2: Frequency of Intercepted System Calls', fontsize=14)
plt.xlabel('System Call Type')
plt.ylabel('Count')
plt.grid(axis='y', linestyle='--', alpha=0.7)
plt.savefig('events_bar.png')
print("Generated events_bar.png")

# --- CHART 3: ACTIVITY TIMELINE (Line) ---
plt.figure(figsize=(10, 6))
plt.plot(time_seconds, activity_volume, marker='o', linestyle='-', color='#9b59b6', linewidth=2)
plt.fill_between(time_seconds, activity_volume, color='#9b59b6', alpha=0.3)
plt.title('Figure 3: System Call Volume Over Time (Injection Detection)', fontsize=14)
plt.xlabel('Execution Time (seconds)')
plt.ylabel('Events Intercepted')
plt.grid(True)
plt.savefig('timeline_chart.png')
print("Generated timeline_chart.png")
import matplotlib.pyplot as plt
import numpy as np

# --- MOCK DATA BASED ON YOUR LOGS ---
# These numbers represent a typical session with Notepad
severities = ['LOW (Info)', 'MEDIUM (DLL Load)', 'HIGH (Process Event)']
severity_counts = [15, 45, 2]  # Mostly DLL loads, some threads, start/exit

event_types = ['LOAD_LIBRARY', 'THREAD_CREATE', 'OUTPUT_DEBUG', 'PROCESS_CREATE', 'PROCESS_EXIT']
event_counts = [42, 12, 5, 1, 1]

# Timeline data (simulated burst of activity at start)
time_seconds = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
activity_volume = [2, 15, 20, 8, 4, 2, 2, 1, 1, 1] 

# --- CHART 1: SEVERITY DISTRIBUTION (Pie) ---
plt.figure(figsize=(8, 6))
colors = ['#2ecc71', '#f1c40f', '#e74c3c'] # Green, Yellow, Red
plt.pie(severity_counts, labels=severities, autopct='%1.1f%%', startangle=140, colors=colors)
plt.title('Figure 1: Distribution of Threat Severity Levels', fontsize=14)
plt.savefig('severity_chart.png')
print("Generated severity_chart.png")

# --- CHART 2: EVENT FREQUENCY (Bar) ---
plt.figure(figsize=(10, 6))
plt.bar(event_types, event_counts, color='#3498db')
plt.title('Figure 2: Frequency of Intercepted System Calls', fontsize=14)
plt.xlabel('System Call Type')
plt.ylabel('Count')
plt.grid(axis='y', linestyle='--', alpha=0.7)
plt.savefig('events_bar.png')
print("Generated events_bar.png")

# --- CHART 3: ACTIVITY TIMELINE (Line) ---
plt.figure(figsize=(10, 6))
plt.plot(time_seconds, activity_volume, marker='o', linestyle='-', color='#9b59b6', linewidth=2)
plt.fill_between(time_seconds, activity_volume, color='#9b59b6', alpha=0.3)
plt.title('Figure 3: System Call Volume Over Time (Injection Detection)', fontsize=14)
plt.xlabel('Execution Time (seconds)')
plt.ylabel('Events Intercepted')
plt.grid(True)
plt.savefig('timeline_chart.png')
print("Generated timeline_chart.png")