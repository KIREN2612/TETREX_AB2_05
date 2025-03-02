import threading
import time
import logging
import psutil
import os
import subprocess
import asyncio
import csv
import hashlib
import math
import platform
from datetime import datetime
from pathlib import Path
import random
import string

import numpy as np
import pandas as pd

# Global variables and configuration
file_monitor_handler_global = None  
ensemble_models = None  
response_triggered_flag = threading.Event()  
connected_clients = []  
main_loop = None 
action_blocked = False

baseline_stats = {
    "cpu_usage": {"mean": 20, "std": 5},
    "memory_usage": {"mean": 30, "std": 10},
    "disk_usage": {"mean": 40, "std": 10},
    "modified": {"mean": 2, "std": 1},
    "renamed": {"mean": 1, "std": 0.5},
    "deleted": {"mean": 1, "std": 0.5},
    "entropy_alerts": {"mean": 3, "std": 1},
    "unauth_proc_count": {"mean": 0, "std": 0},
    "shadow_copy_flag": {"mean": 0, "std": 0},
    "registry_alerts_count": {"mean": 0, "std": 0},
    "susp_net_count": {"mean": 0, "std": 0},
    "susp_ext_count": {"mean": 0, "std": 0},
    "proc_injection": {"mean": 0, "std": 0},
    "sys_call_anomaly": {"mean": 0, "std": 0},
    "total_net_connections": {"mean": 50, "std": 20}
}

MODEL_PATH = None  
MONITOR_PATH = Path(r"C:\Users\Home\Documents")  
test_ransomware_dir = MONITOR_PATH / "TestRansomware"
os.makedirs(test_ransomware_dir, exist_ok=True)

# Utility functions

def robust_average(func, samples=5, delay=0.5, outlier_threshold=0.2):
    """
    Calls the provided function 'samples' times with a delay between samples.
    Filters out values deviating from the median by more than outlier_threshold.
    Returns the average of the filtered values (or the median if all are filtered).
    """
    vals = []
    for _ in range(samples):
        try:
            v = func()
            vals.append(v)
        except Exception:
            logging.exception(f"Error calling function")
        time.sleep(delay)
    if not vals:
        return None
    median_val = np.median(vals)
    if median_val == 0:
        return 0
    filtered = [v for v in vals if abs(v - median_val) / abs(median_val) <= outlier_threshold]
    return sum(filtered) / len(filtered) if filtered else median_val

def get_cpu_usage():
    return robust_average(lambda: psutil.cpu_percent(interval=0.5), samples=5)

def get_memory_usage():
    return robust_average(lambda: psutil.virtual_memory().percent, samples=5)

def get_disk_usage():
    return robust_average(lambda: psutil.disk_usage('/').percent, samples=5)

def get_registry_alerts_count():
    count = 0
    if platform.system() == "Windows":
        import winreg
        keys = [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"]
        for key in keys:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ) as reg:
                    for i in range(winreg.QueryInfoKey(reg)[0]):
                        name, _, _ = winreg.EnumValue(reg, i)
                        if "ransom" in name.lower() or "encrypt" in name.lower():
                            count += 1
            except Exception:
                logging.exception("Error reading registry key.")
    return count

def get_unauthorized_process_count():
    return robust_average(get_unauthorized_process_count_helper, samples=5)

def get_unauthorized_process_count_helper():
    count = 0
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info.get('name', '').lower() in ["cmd.exe", "wmic.exe"]:
                count += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return count

def get_shadow_copy_flag():
    try:
        output = subprocess.check_output('vssadmin list shadows', shell=True, stderr=subprocess.STDOUT)
        if b"Error" in output:
            return 1
    except subprocess.CalledProcessError:
        return 1
    return 0

def get_suspicious_network_count():
    return robust_average(get_suspicious_network_count_helper, samples=5)

def get_suspicious_network_count_helper():
    count = 0
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr and conn.raddr[0] == "192.168.1.100":
            count += 1
    return count

def get_total_network_connections():
    return robust_average(get_total_network_connections_helper, samples=5)

def get_total_network_connections_helper():
    try:
        return len(psutil.net_connections(kind='inet'))
    except Exception:
        logging.exception("Error obtaining total network connections.")
        return 0

def get_suspicious_file_extension_count(directory):
    try:
        return robust_average(lambda: get_suspicious_file_extension_count_helper(directory), samples=3)
    except Exception:
        return 0

def get_suspicious_file_extension_count_helper(directory):
    count = 0
    path = Path(directory)
    for file in path.rglob('*'):
        if file.suffix.lower() in {'.locked', '.encrypted'}:
            count += 1
    return count

def compute_file_hash(file_path):
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        logging.exception(f"Error computing hash for {file_path}")
        return None

def analyze_directory_entropy(directory):
    suspicious_count = 0
    try:
        path = Path(directory)
        for file in path.rglob('*'):
            if file.suffix.lower() in ['.docx', '.pdf', '.txt', '.exe']:
                try:
                    data = file.read_bytes()
                    if not data:
                        continue
                    probabilities = [data.count(byte) / len(data) for byte in set(data)]
                    entropy = -sum(p * math.log2(p) for p in probabilities if p > 0)
                    if entropy > 7.5:
                        suspicious_count += 1
                except Exception:
                    logging.exception("Error calculating entropy for file.")
    except Exception:
        logging.exception("Error during directory entropy analysis.")
    return suspicious_count

def monitor_crypto_operations():
    return 0

def monitor_process_injection():
    return 0

def monitor_sys_call_anomaly():
    return 0

# File monitoring using watchdog
from watchdog.events import FileSystemEventHandler

class FileMonitorHandler(FileSystemEventHandler):
    def __init__(self):
        self.modified_files = set()
        self.renamed_files = set()
        self.deleted_files = set()

    def on_modified(self, event):
        if not event.is_directory:
            self.modified_files.add(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.modified_files.add(event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.deleted_files.add(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.renamed_files.add(event.dest_path)

    def get_file_event_counts(self):
        counts = {
            "modified": len(self.modified_files),
            "renamed": len(self.renamed_files),
            "deleted": len(self.deleted_files)
        }
        self.modified_files.clear()
        self.renamed_files.clear()
        self.deleted_files.clear()
        return counts

def start_file_monitor(path, handler):
    from watchdog.observers import Observer
    if not path.exists():
        logging.error(f"Path {path} does not exist.")
        return
    observer = Observer()
    observer.schedule(handler, str(path), recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Additional utilities

def predict_ransomware_ensemble(ensemble_models, features, threshold=0.5):
    # Dummy implementation
    return 0

def update_baseline(baseline, new_data, alpha=0.1):
    updated = {}
    for key, stats in baseline.items():
        new_value = new_data.get(key, stats['mean'])
        updated_mean = (1 - alpha) * stats['mean'] + alpha * new_value
        updated_std = (1 - alpha) * stats['std'] + alpha * abs(new_value - updated_mean)
        updated[key] = {"mean": updated_mean, "std": updated_std}
    return updated

def check_and_trigger_early_alert(data):
    for key in ["memory_usage", "disk_usage", "modified", "entropy_alerts"]:
        base_mean = baseline_stats.get(key, {}).get("mean", 1)
        if base_mean > 0 and abs(data[key] - base_mean) / base_mean > 0.85:
            logging.info(f"Early alert: {key} deviated (current: {data[key]}, baseline: {base_mean}).")
            trigger_response(data)
            time.sleep(0.5)
            return
    if data["modified"] >= 30 or data["renamed"] >= 30 or data["deleted"] >= 30:
        logging.info(f"Early alert: File event threshold exceeded.")
        trigger_response(data)
        time.sleep(0.5)

def collect_system_data():
    file_events = (file_monitor_handler_global.get_file_event_counts()
                   if file_monitor_handler_global else {"modified": 0, "renamed": 0, "deleted": 0})
    data = {
        "timestamp": datetime.now().isoformat(),
        "cpu_usage": get_cpu_usage(),
        "memory_usage": get_memory_usage(),
        "disk_usage": get_disk_usage(),
        "modified": file_events.get("modified", 0),
        "renamed": file_events.get("renamed", 0),
        "deleted": file_events.get("deleted", 0),
        "entropy_alerts": analyze_directory_entropy(MONITOR_PATH),
        "unauth_proc_count": get_unauthorized_process_count(),
        "shadow_copy_flag": get_shadow_copy_flag(),
        "registry_alerts_count": get_registry_alerts_count(),
        "susp_net_count": get_suspicious_network_count(),
        "susp_ext_count": get_suspicious_file_extension_count(MONITOR_PATH),
        "proc_injection": monitor_process_injection(),
        "sys_call_anomaly": monitor_sys_call_anomaly(),
        "total_net_connections": get_total_network_connections(),
        "crypto_api_calls": monitor_crypto_operations()
    }
    return data

def collect_and_predict(ensemble_models):
    global baseline_stats
    data = collect_system_data()
    check_and_trigger_early_alert(data)
    
    features = [
        data["memory_usage"],
        data["disk_usage"],
        data["modified"],
        data["renamed"],
        data["deleted"],
        data["entropy_alerts"],
        data["unauth_proc_count"],
        data["shadow_copy_flag"],
        data["registry_alerts_count"],
        data["susp_net_count"],
        data["susp_ext_count"],
        data["proc_injection"],
        data["sys_call_anomaly"],
        data["total_net_connections"]
    ]
    
    sudden_anomaly = False
    for key in ["memory_usage", "disk_usage", "modified", "entropy_alerts"]:
        base_mean = baseline_stats.get(key, {}).get("mean", 1)
        if base_mean > 0 and abs(data[key] - base_mean) / base_mean > 0.85:
            sudden_anomaly = True
            logging.info(f"Sudden anomaly detected in {key}: current {data[key]}, baseline: {base_mean}")
            break
    if data["modified"] >= 30 or data["renamed"] >= 30 or data["deleted"] >= 30:
        sudden_anomaly = True
        logging.info("Sudden file event threshold exceeded.")
    
    detection = 1 if sudden_anomaly else 0
    data["ml_detection"] = detection
    data["state"] = "ransomware detected" if detection == 1 else "normal"
    data["ml_model_dedicated"] = True if detection == 1 else False

    if detection == 1:
        trigger_response(data)
        data["response_triggered"] = True
    else:
        data["response_triggered"] = False

    baseline_stats = update_baseline(baseline_stats, data, alpha=0.1)
    
    data["features"] = {
        "memory_usage": data["memory_usage"],
        "disk_usage": data["disk_usage"],
        "modified": data["modified"],
        "renamed": data["renamed"],
        "deleted": data["deleted"],
        "entropy_alerts": data["entropy_alerts"],
        "unauth_proc_count": data["unauth_proc_count"],
        "shadow_copy_flag": data["shadow_copy_flag"],
        "registry_alerts_count": data["registry_alerts_count"],
        "susp_net_count": data["susp_net_count"],
        "susp_ext_count": data["susp_ext_count"],
        "proc_injection": data["proc_injection"],
        "sys_call_anomaly": data["sys_call_anomaly"],
        "total_net_connections": data["total_net_connections"]
    }
    return data

def correlation_engine(data, csv_file="correlation_log.csv"):
    file_exists = os.path.isfile(csv_file)
    with open(csv_file, mode='a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow([
                "timestamp", "cpu_usage", "memory_usage", "disk_usage",
                "modified", "renamed", "deleted", "entropy_alerts",
                "unauth_proc_count", "shadow_copy_flag", "registry_alerts_count",
                "susp_net_count", "susp_ext_count", "proc_injection", "sys_call_anomaly",
                "total_net_connections", "ml_detection", "state", "response_triggered"
            ])
        writer.writerow([
            data.get("timestamp"),
            data.get("cpu_usage"),
            data.get("memory_usage"),
            data.get("disk_usage"),
            data.get("modified"),
            data.get("renamed"),
            data.get("deleted"),
            data.get("entropy_alerts"),
            data.get("unauth_proc_count"),
            data.get("shadow_copy_flag"),
            data.get("registry_alerts_count"),
            data.get("susp_net_count"),
            data.get("susp_ext_count"),
            data.get("proc_injection"),
            data.get("sys_call_anomaly"),
            data.get("total_net_connections"),
            data.get("ml_detection"),
            data.get("state"),
            data.get("response_triggered")
        ])

async def reset_response_flag(delay=60):
    await asyncio.sleep(delay)
    response_triggered_flag.clear()
    global action_blocked
    action_blocked = False

def notify_clients(alert_message):
    for client in connected_clients:
        try:
            asyncio.run_coroutine_threadsafe(client.send_json(alert_message), main_loop)
        except Exception:
            logging.exception("Error sending alert to client.")

def trigger_response(data):
    global action_blocked
    if not response_triggered_flag.is_set():
        response_triggered_flag.set()
        action_blocked = True
        alert_message = {
            "type": "alert",
            "alert": "Potential ransomware activity detected! Immediate action is recommended.",
            "data": data
        }
        notify_clients(alert_message)
        asyncio.run_coroutine_threadsafe(reset_response_flag(60), main_loop)

def notify_live_tracking(data):
    message = {"type": "live_tracking", "data": data["features"]}
    for client in connected_clients:
        try:
            asyncio.run_coroutine_threadsafe(client.send_json(message), main_loop)
        except Exception:
            logging.exception("Error sending live tracking data to client.")

def create_dummy_files(num_files=100):
    for i in range(num_files):
        file_path = test_ransomware_dir / f"file_{i}.txt"
        try:
            with open(file_path, "w") as f:
                f.write("This is a safe dummy file.\n" * 10)
        except Exception:
            logging.exception(f"Error creating {file_path}")

def simulate_ransomware():
    global action_blocked
    if action_blocked:
        logging.info("Ransomware simulation blocked due to prior alert.")
        return
    try:
        create_dummy_files(num_files=100)
        for i in range(100):
            original_path = test_ransomware_dir / f"file_{i}.txt"
            try:
                if original_path.exists():
                    with open(original_path, "w") as f:
                        random_content = ''.join(random.choices(string.ascii_letters + string.digits, k=100))
                        f.write(random_content)
                    new_path = test_ransomware_dir / f"file_{i}.encrypted"
                    os.rename(original_path, new_path)
                    logging.info(f"Simulated ransomware action on {new_path}")
                    time.sleep(0.1)
                    if new_path.exists():
                        os.remove(new_path)
                        logging.info(f"Deleted file: {new_path}")
            except Exception as e:
                logging.exception(f"Error processing file_{i}: {e}")
            time.sleep(0.1)
    except Exception as e:
        logging.exception(f"Error during ransomware simulation: {e}")

# Asynchronous tasks for periodic monitoring

async def periodic_display_with_baseline():
    global ensemble_models
    while True:
        data = collect_and_predict(ensemble_models)
        correlation_engine(data)
        notify_live_tracking(data)
        await asyncio.sleep(5)

async def monitor_system():
    while True:
        await asyncio.sleep(5)

async def main_async_tasks():
    task1 = asyncio.create_task(periodic_display_with_baseline())
    task2 = asyncio.create_task(monitor_system())
    await asyncio.gather(task1, task2)
