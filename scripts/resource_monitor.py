#!/usr/bin/env python3
"""
Federated Threat Monitor -- Resource Monitor
Monitors CPU and RAM usage of a specific process over time.
Outputs metrics to CSV file for performance evaluation.
"""

import argparse
import time
import csv
import psutil
import os
from datetime import datetime

def find_process_by_name(process_name):
    """
    Find a process by name and return its PID.
    
    Args:
        process_name: Name of the process to find (e.g., "agent.py")
    
    Returns:
        Process ID (PID) or None if not found
    """
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            # Check if process name matches or is in command line
            if process_name in proc.info['name'] or \
               (proc.info['cmdline'] and any(process_name in str(cmd) for cmd in proc.info['cmdline'])):
                return proc.info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None

def monitor_resources(process_name, output_file, interval=5, duration=300):
    """
    Monitor CPU and RAM usage of a process over time.
    
    Args:
        process_name: Name of the process to monitor
        output_file: Path to CSV file for output
        interval: Sampling interval in seconds (default: 5)
        duration: Total monitoring duration in seconds (default: 300)
    """
    # Find the process
    pid = find_process_by_name(process_name)
    if not pid:
        print(f"[monitor] Process '{process_name}' not found. Exiting.")
        return
    
    print(f"[monitor] Found process '{process_name}' with PID {pid}")
    print(f"[monitor] Monitoring every {interval}s for {duration}s")
    print(f"[monitor] Output: {output_file}")
    
    # Open CSV file for writing
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        # Write header
        writer.writerow(['timestamp', 'cpu_percent', 'ram_mb'])
        
        start_time = time.time()
        sample_count = 0
        
        # Monitor for specified duration
        while time.time() - start_time < duration:
            try:
                # Get process object
                proc = psutil.Process(pid)
                
                # Get CPU usage (interval parameter samples over time)
                cpu_percent = proc.cpu_percent(interval=1)
                
                # Get RAM usage in MB
                ram_bytes = proc.memory_info().rss
                ram_mb = ram_bytes / (1024 * 1024)
                
                # Get current timestamp
                timestamp = int(time.time())
                
                # Write to CSV
                writer.writerow([timestamp, cpu_percent, ram_mb])
                csvfile.flush()
                
                sample_count += 1
                print(f"[monitor] Sample {sample_count}: CPU={cpu_percent:.1f}%, RAM={ram_mb:.2f} MB")
                
            except psutil.NoSuchProcess:
                print(f"[monitor] Process {pid} terminated. Stopping monitoring.")
                break
            except psutil.AccessDenied:
                print(f"[monitor] Access denied to process {pid}. Retrying...")
            
            # Wait for next sample
            time.sleep(interval)
    
    print(f"[monitor] Monitoring complete. {sample_count} samples written to {output_file}")

def main():
    """Parse command line arguments and start resource monitoring."""
    parser = argparse.ArgumentParser(description="Monitor CPU and RAM usage of a process")
    parser.add_argument("--name", required=True, help="Process name to monitor (e.g., agent.py)")
    parser.add_argument("--out", required=True, help="Output CSV file path")
    parser.add_argument("--interval", type=int, default=5, help="Sampling interval in seconds (default: 5)")
    parser.add_argument("--duration", type=int, default=300, help="Monitoring duration in seconds (default: 300)")
    args = parser.parse_args()
    
    monitor_resources(args.name, args.out, args.interval, args.duration)

if __name__ == "__main__":
    main()
