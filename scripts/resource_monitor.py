#!/usr/bin/env python3
"""
Federated Threat Monitor — Resource Monitor

Samples a running process's CPU% and RAM (MB) to a CSV, to verify the edge
agent stays within the lightweight envelope (< 20 MB RAM target).

    python3 scripts/resource_monitor.py --name agent.py --out metrics.csv
"""

import argparse
import time

import psutil


def find_pid(name_substr: str):
    for p in psutil.process_iter(["pid", "cmdline"]):
        cmd = " ".join(p.info.get("cmdline") or [])
        if name_substr in cmd and "resource_monitor" not in cmd:
            return p.info["pid"]
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="agent.py",
                    help="substring of the target process cmdline")
    ap.add_argument("--out", default="metrics.csv")
    ap.add_argument("--interval", type=float, default=5.0)
    args = ap.parse_args()

    pid = find_pid(args.name)
    if pid is None:
        raise SystemExit(f"no process matching '{args.name}'")
    proc = psutil.Process(pid)
    print(f"monitoring pid {pid} ({args.name}) -> {args.out}")

    with open(args.out, "w") as f:
        f.write("ts,cpu_percent,rss_mb\n")
        proc.cpu_percent(None)  # prime the CPU% measurement
        while proc.is_running():
            time.sleep(args.interval)
            try:
                cpu = proc.cpu_percent(None)
                rss_mb = proc.memory_info().rss / (1024 * 1024)
            except psutil.NoSuchProcess:
                break
            line = f"{time.time():.0f},{cpu:.1f},{rss_mb:.2f}"
            print(line)
            f.write(line + "\n")
            f.flush()


if __name__ == "__main__":
    main()
