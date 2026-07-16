#!/usr/bin/env python3
"""
Federated Threat Monitor -- Traffic Generator
Generates synthetic log entries to simulate network traffic with periodic DDoS spikes.
This is used for testing and demonstration purposes.
"""

import time
import random
import argparse
import csv
from datetime import datetime


def generate_traffic(log_file, duration, attack_interval, labels_file):
    """
    Generate synthetic log traffic with periodic DDoS volume spikes,
    and record ground-truth labels for every second of the run.

    Args:
        log_file: Path to the log file to write to
        duration: Total duration in seconds to run the generator
        attack_interval: Seconds between each DDoS spike
        labels_file: Path to the ground-truth CSV to write
                     (format: timestamp,is_attack -- one row per second)
    """
    # Open the log file in append mode (agent.py tails/reads this file)
    # and the labels file in write mode (fresh ground truth per run).
    with open(log_file, "a") as f, open(labels_file, "w", newline="") as label_f:
        label_writer = csv.writer(label_f)
        # Header row purely for human readability -- evaluate.py's csv.reader
        # loop only requires row[0]/row[1], so a header is harmless to include
        # as long as evaluate.py is tolerant of a non-numeric first row.
        # (See the accompanying evaluate.py rewrite, which skips a header row.)
        label_writer.writerow(["timestamp", "is_attack"])

        start_time = time.time()
        attack_start_ts = None

        print(f"[traffic] writing to {log_file} for {duration}s (spike every {attack_interval}s)")
        print(f"[traffic] writing ground-truth labels to {labels_file}")

        # Run for the specified duration
        while time.time() - start_time < duration:
            current_time = time.time()
            elapsed = current_time - start_time

            # Check if it's time for an attack spike
            if attack_start_ts is None and elapsed >= attack_interval:
                attack_start_ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                print(f"[traffic] INJECTING volume spike at second {int(elapsed)}")

            # Determine if we're in attack mode or normal mode
            in_attack_window = attack_start_ts and elapsed < attack_interval + 10

            if in_attack_window:
                # ATTACK MODE: Generate 40-50 log entries per second for 10 seconds
                # This simulates a DDoS volume spike
                entries = random.randint(40, 50)
                is_attack = 1
            else:
                # NORMAL MODE: Generate 2-3 log entries per second
                # This simulates normal network traffic
                entries = random.randint(2, 3)
                is_attack = 0
                # Reset attack timer after spike ends
                if attack_start_ts and elapsed >= attack_interval + 10:
                    end_ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                    print(f"[traffic] Spike ended at {end_ts}")
                    attack_start_ts = None
                    attack_interval += 60  # Schedule next attack 60 seconds later

            # Record the ground-truth label for THIS second, using the same
            # UTC timestamp format agent.py uses for its alert payloads
            # ("%Y-%m-%dT%H:%M:%SZ"). This alignment is what lets evaluate.py
            # compare alert timestamps against these labels later.
            current_ts_label = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            label_writer.writerow([current_ts_label, is_attack])
            label_f.flush()

            # Write log entries with syslog-style timestamps
            for _ in range(entries):
                timestamp = datetime.utcnow().strftime("%b %d %H:%M:%S")
                # Simulate various log message types
                messages = [
                    f"sshd[{random.randint(1000, 9999)}]: Accepted password for user{random.randint(1, 100)} from 192.168.10.{random.randint(1, 254)}",
                    f"kernel: [{random.randint(0, 9999)}] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=192.168.10.{random.randint(1, 254)}",
                    f"nginx[{random.randint(1000, 9999)}]: 192.168.10.{random.randint(1, 254)} - - [{timestamp}] \"GET / HTTP/1.1\" 200 1234",
                    f"systemd[1]: Started User Manager for UID {random.randint(1000, 9999)}",
                    f"cron[{random.randint(1000, 9999)}]: (root) CMD (run-parts /etc/cron.hourly)"
                ]
                f.write(f"{timestamp} {random.choice(messages)}\n")

            # Flush to ensure data is written immediately (agent.py polls the file)
            f.flush()

            # Sleep for 1 second before next batch -- this keeps the loop
            # aligned to one ground-truth label per second of wall-clock time
            time.sleep(1)

    print(f"[traffic] Done. Ground truth written to {labels_file}")


def main():
    """Parse command line arguments and start traffic generation."""
    parser = argparse.ArgumentParser(description="Generate synthetic log traffic with DDoS spikes")
    parser.add_argument("--log", required=True, help="Path to log file")
    parser.add_argument("--duration", type=int, default=300, help="Duration in seconds (default: 300)")
    parser.add_argument("--attack-every", type=int, default=60, help="Attack interval in seconds (default: 60)")
    # NEW: where to write the ground-truth labels this run produces.
    # Defaults to "ground_truth.csv" in the current directory, matching
    # the filename used in the README's evaluate.py example command.
    parser.add_argument("--labels", default="ground_truth.csv", help="Path to write ground-truth CSV (default: ground_truth.csv)")
    args = parser.parse_args()

    generate_traffic(args.log, args.duration, args.attack_every, args.labels)


if __name__ == "__main__":
    main()
