#!/usr/bin/env python3
"""
Federated Threat Monitor — Synthetic Traffic & Attack Generator

Appends syslog-formatted lines to a monitored log file: a steady stream of
"normal" background events, punctuated by injected DDoS-style volume spikes.
The ground-truth injection windows are written to a CSV so scripts/evaluate.py
can score detection accuracy (TPR/FPR).

Point the edge agent at the same file:
    FTM_LOG_FILE=/tmp/ftm_synth.log python3 edge-agent/agent.py

Run the generator on the edge node:
    python3 scripts/traffic_gen.py --log /tmp/ftm_synth.log --duration 300 \
        --attack-every 60 --labels ground_truth.csv
"""

import argparse
import os
import random
import time
from datetime import datetime

NORMAL_RATE = 3       # avg normal lines per second
SPIKE_RATE = 150      # lines emitted during an attack second


def syslog_ts() -> str:
    # "Jul  1 09:00:00" — matches the agent's count_events regex (local time)
    return datetime.now().strftime("%b %d %H:%M:%S")


def write_line(f, host: str) -> None:
    f.write(f"{syslog_ts()} {host} sshd[{random.randint(1000, 9999)}]: "
            f"connection from 10.0.0.{random.randint(2, 254)}\n")


def emit(f, host: str, n: int) -> None:
    for _ in range(n):
        write_line(f, host)
    f.flush()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default=os.getenv("FTM_LOG_FILE", "/tmp/ftm_synth.log"))
    ap.add_argument("--host", default="edge-host")
    ap.add_argument("--duration", type=int, default=300, help="seconds to run")
    ap.add_argument("--attack-every", type=int, default=60,
                    help="inject a volume spike every N seconds")
    ap.add_argument("--attack-len", type=int, default=3,
                    help="attack duration in seconds")
    ap.add_argument("--labels", default="ground_truth.csv")
    args = ap.parse_args()

    labels = open(args.labels, "w")
    labels.write("start_utc,end_utc,kind\n")
    labels.flush()

    print(f"[traffic] writing to {args.log} for {args.duration}s "
          f"(spike every {args.attack_every}s)")
    with open(args.log, "a") as f:
        start = time.time()
        second = 0
        attack_remaining = 0
        attack_start_ts = None
        while time.time() - start < args.duration:
            begin_attack = (second > 0 and second % args.attack_every == 0
                            and attack_remaining == 0)
            if begin_attack:
                attack_remaining = args.attack_len
                attack_start_ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                print(f"[traffic] INJECTING volume spike at second {second}")

            if attack_remaining > 0:
                emit(f, args.host, SPIKE_RATE)
                attack_remaining -= 1
                if attack_remaining == 0:
                    end_ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                    labels.write(f"{attack_start_ts},{end_ts},conn_spike\n")
                    labels.flush()
            else:
                emit(f, args.host, max(0, int(random.gauss(NORMAL_RATE, 1))))

            time.sleep(1)
            second += 1

    labels.close()
    print("[traffic] done")


if __name__ == "__main__":
    main()
