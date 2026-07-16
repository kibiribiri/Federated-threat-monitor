#!/usr/bin/env python3
"""
Federated Threat Monitor -- Evaluation Script
Evaluates detection performance by comparing alerts against ground truth labels.
Calculates True Positive Rate (TPR), False Positive Rate (FPR), and Precision.

"""

import argparse
import sqlite3
import csv
from datetime import datetime, timedelta


TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # matches agent.py's timestamp() and traffic_gen.py's labels


def parse_ts(ts_string):
    """Convert an agent/ground-truth timestamp string into a datetime object."""
    return datetime.strptime(ts_string, TIMESTAMP_FORMAT)


def load_ground_truth(labels_file):
    """
    Load ground truth labels from CSV file and group consecutive
    is_attack=1 seconds into discrete attack events.

    Args:
        labels_file: Path to CSV file with ground truth labels
                     Format: timestamp,is_attack (0 or 1), one header row

    Returns:
        Tuple of:
          - attack_events: list of (event_start, event_end) datetime pairs
          - normal_seconds: list of datetime objects labelled normal (0)
    """
    rows = []
    try:
        with open(labels_file, "r", newline="") as f:
            reader = csv.reader(f)
            for i, row in enumerate(reader):
                # Skip the header row ("timestamp,is_attack") written by
                # the updated traffic_gen.py.
                if i == 0 and row and row[0] == "timestamp":
                    continue
                if len(row) >= 2:
                    try:
                        ts = parse_ts(row[0])
                        is_attack = int(row[1])
                        rows.append((ts, is_attack))
                    except ValueError:
                        # Skip any malformed row rather than crashing the run
                        continue
    except FileNotFoundError:
        print(f"[evaluate] Ground truth file not found: {labels_file}")
        return [], []

    # Sort chronologically -- traffic_gen.py writes in order already,
    # but this guards against any file that was edited or merged.
    rows.sort(key=lambda r: r[0])

    # Group consecutive is_attack=1 rows into attack "events" so a single
    # 10-second spike counts as ONE thing to detect, not ten.
    attack_events = []
    normal_seconds = []
    current_event_start = None
    current_event_end = None

    for ts, is_attack in rows:
        if is_attack:
            if current_event_start is None:
                # Starting a new attack event
                current_event_start = ts
                current_event_end = ts
            else:
                # Extend the current event (still inside the spike)
                current_event_end = ts
        else:
            # Normal second -- close out any open attack event first
            if current_event_start is not None:
                attack_events.append((current_event_start, current_event_end))
                current_event_start = None
                current_event_end = None
            normal_seconds.append(ts)

    # Catch an attack event that was still open at end of file
    if current_event_start is not None:
        attack_events.append((current_event_start, current_event_end))

    return attack_events, normal_seconds


def load_alerts(db_path):
    """
    Load alerts from SQLite database.

    Args:
        db_path: Path to SQLite database file

    Returns:
        List of alert dicts with parsed datetime timestamps
    """
    alerts = []
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, z_score, event_count FROM alerts ORDER BY timestamp")
        for row in cursor.fetchall():
            try:
                alerts.append({
                    "timestamp": parse_ts(row[0]),
                    "z_score": row[1],
                    "event_count": row[2]
                })
            except ValueError:
                # Skip any alert with an unparseable timestamp
                continue
        conn.close()
    except sqlite3.Error as e:
        print(f"[evaluate] Database error: {e}")
    return alerts


def evaluate_performance(alerts, attack_events, normal_seconds, slack_seconds):
    """
    Evaluate detection performance against ground truth, using a
    time-tolerance window instead of exact timestamp matching.

    Args:
        alerts: list of alert dicts (from load_alerts)
        attack_events: list of (start, end) datetime pairs
        normal_seconds: list of datetime objects labelled normal
        slack_seconds: how many seconds of tolerance to allow when
                       matching an alert to a ground-truth attack event

    Returns:
        Dictionary with TP, FP, FN, TN counts and TPR/FPR/precision
    """
    slack = timedelta(seconds=slack_seconds)

    # Track which attack events were caught by at least one alert,
    # and which alerts were "used up" matching an attack event.
    event_detected = [False] * len(attack_events)
    alert_matched_attack = [False] * len(alerts)

    # ---- Recall pass: for each attack event, did any alert fall
    # ---- within [event_start - slack, event_end + slack]?
    for i, (event_start, event_end) in enumerate(attack_events):
        window_start = event_start - slack
        window_end = event_end + slack
        for j, alert in enumerate(alerts):
            if window_start <= alert["timestamp"] <= window_end:
                event_detected[i] = True
                alert_matched_attack[j] = True
                # Don't break -- multiple alerts can legitimately fire
                # during one spike; we only need to mark them all as
                # "explained" so they aren't double-counted as false positives.

    true_positives = sum(event_detected)          # attack events that were caught
    false_negatives = len(attack_events) - true_positives  # attack events that were missed

    # ---- Precision pass: any alert NOT matched to an attack event
    # ---- above is treated as a false positive (it fired without a
    # ---- corresponding labelled attack nearby).
    false_positives = sum(1 for matched in alert_matched_attack if not matched)

    # True negatives: normal-labelled seconds with no alert anywhere
    # near them. This is a coarse approximation -- useful for an FPR
    # figure, but treat it as indicative rather than exact, since
    # "no alert nearby" for a normal second doesn't guarantee the
    # agent was even evaluating that exact second.
    true_negatives = 0
    for normal_ts in normal_seconds:
        window_start = normal_ts - slack
        window_end = normal_ts + slack
        if not any(window_start <= a["timestamp"] <= window_end for a in alerts):
            true_negatives += 1

    total_attacks = true_positives + false_negatives
    total_normal = true_negatives + false_positives
    total_alerts_raised = len(alerts)

    # True Positive Rate (Recall): TP / (TP + FN)
    tpr = true_positives / total_attacks if total_attacks > 0 else 0.0

    # False Positive Rate: FP / (FP + TN)
    fpr = false_positives / total_normal if total_normal > 0 else 0.0

    # Precision: TP / total alerts raised (each true positive event may
    # have multiple matching alerts, so precision is computed against
    # raw alert volume, consistent with Chapter 5's reported precision
    # figures of ~5-8%).
    precision = true_positives / total_alerts_raised if total_alerts_raised > 0 else 0.0

    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "true_negatives": true_negatives,
        "total_alerts_raised": total_alerts_raised,
        "tpr": tpr,
        "fpr": fpr,
        "precision": precision
    }


def main():
    """Parse command line arguments and run evaluation."""
    parser = argparse.ArgumentParser(description="Evaluate detection performance")
    parser.add_argument("--labels", required=True, help="Path to ground truth CSV file")
    parser.add_argument("--db", default="central-manager/alerts.db", help="Path to SQLite database")
    # NEW: tolerance window in seconds. Chapter 5 of the thesis references
    # a "--slack 15" tolerance window -- this flag makes that real.
    parser.add_argument("--slack", type=int, default=15, help="Tolerance window in seconds for matching alerts to attack events (default: 15)")
    args = parser.parse_args()

    # Load data
    print(f"[evaluate] Loading ground truth from {args.labels}")
    attack_events, normal_seconds = load_ground_truth(args.labels)

    print(f"[evaluate] Loading alerts from {args.db}")
    alerts = load_alerts(args.db)

    print(f"[evaluate] {len(attack_events)} labelled attack events, "
          f"{len(normal_seconds)} labelled normal seconds, "
          f"{len(alerts)} alerts raised")
    print(f"[evaluate] Using tolerance window: +/- {args.slack}s")

    # Evaluate performance
    metrics = evaluate_performance(alerts, attack_events, normal_seconds, args.slack)

    # Print results
    print("\n" + "=" * 50)
    print("EVALUATION RESULTS")
    print("=" * 50)
    print(f"Labelled Attack Events:       {len(attack_events)}")
    print(f"Total Alerts Raised:          {metrics['total_alerts_raised']}")
    print("-" * 50)
    print(f"True Positives (TP):  {metrics['true_positives']}")
    print(f"False Positives (FP): {metrics['false_positives']}")
    print(f"False Negatives (FN): {metrics['false_negatives']}")
    print(f"True Negatives (TN):  {metrics['true_negatives']}")
    print("-" * 50)
    print(f"True Positive Rate (Recall): {metrics['tpr']:.4f} ({metrics['tpr']*100:.2f}%)")
    print(f"False Positive Rate:         {metrics['fpr']:.4f} ({metrics['fpr']*100:.2f}%)")
    print(f"Precision:                   {metrics['precision']:.4f} ({metrics['precision']*100:.2f}%)")
    print("=" * 50)


if __name__ == "__main__":
    main()

