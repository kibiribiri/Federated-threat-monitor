#!/usr/bin/env python3
"""
Federated Threat Monitor — Detection Evaluation

Compares the alerts stored in the manager's SQLite database against the
ground-truth attack windows produced by scripts/traffic_gen.py, and reports
detection performance (true/false positives, TPR/FPR).

    python3 scripts/evaluate.py --db central-manager/alerts.db \
        --labels ground_truth.csv --slack 15
"""

import argparse
import csv
import os
import sqlite3
from datetime import datetime


def parse(t: str) -> float:
    return datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ").timestamp()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=os.path.join(
        os.path.dirname(__file__), "../central-manager/alerts.db"))
    ap.add_argument("--labels", default="ground_truth.csv")
    ap.add_argument("--slack", type=int, default=15,
                    help="seconds of tolerance around each labelled window")
    args = ap.parse_args()

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    alerts = [parse(r["timestamp"])
              for r in conn.execute("SELECT timestamp FROM alerts")]

    windows = []
    with open(args.labels) as f:
        for row in csv.DictReader(f):
            windows.append((parse(row["start_utc"]), parse(row["end_utc"])))

    slack = args.slack
    matched_alerts = set()
    tp = 0
    for (w0, w1) in windows:
        hit = False
        for i, at in enumerate(alerts):
            if (w0 - slack) <= at <= (w1 + slack):
                hit = True
                matched_alerts.add(i)
        if hit:
            tp += 1

    fn = len(windows) - tp
    fp = len(alerts) - len(matched_alerts)
    tpr = tp / (tp + fn) if (tp + fn) else 0.0

    print("=== Detection performance ===")
    print(f"labelled attacks : {len(windows)}")
    print(f"alerts raised    : {len(alerts)}")
    print(f"true positives   : {tp}")
    print(f"false negatives  : {fn}")
    print(f"false positives  : {fp}")
    print(f"TPR (recall)     : {tpr:.3f}")
    if (tp + fp):
        print(f"precision        : {tp / (tp + fp):.3f}")


if __name__ == "__main__":
    main()
