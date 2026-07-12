#!/usr/bin/env python3
"""
Federated Threat Monitor — Edge Agent
Monitors local logs, computes Z-score baseline profiling,
and publishes DDoS volumetric anomaly alerts via MQTT.

Configuration is read from environment variables so the same code runs on
every node without edits (set FTM_NODE_ID per node). By default it connects to
the broker on plain port 1883; set FTM_USE_TLS=true to use MQTT-over-TLS (8883).
"""

import time
import json
import math
import os
import re
import ssl
from datetime import datetime
import paho.mqtt.client as mqtt
import psutil

# ── Configuration (env-overridable) ──────────────────────────────
NODE_ID       = os.getenv("FTM_NODE_ID", "edge-node-01")
LOG_FILE      = os.getenv("FTM_LOG_FILE", "/var/log/syslog")
MQTT_BROKER   = os.getenv("FTM_BROKER", "192.168.10.10")
USE_TLS       = os.getenv("FTM_USE_TLS", "false").lower() == "true"
MQTT_PORT     = int(os.getenv("FTM_PORT", "8883" if USE_TLS else "1883"))
MQTT_TOPIC    = f"alerts/{NODE_ID}"
CA_CERT       = os.getenv("FTM_CA_CERT", "/etc/mosquitto/certs/ca.crt")
WINDOW_SIZE   = int(os.getenv("FTM_WINDOW_SIZE", "30"))    # observations for training baseline
Z_THRESHOLD   = float(os.getenv("FTM_Z_THRESHOLD", "3.0")) # alert if Z-score exceeds this
POLL_INTERVAL = int(os.getenv("FTM_POLL_INTERVAL", "5"))   # seconds between log reads
EVENT_WINDOW  = int(os.getenv("FTM_EVENT_WINDOW", "10"))   # seconds to count events within

# ── State ────────────────────────────────────────────────────────
observations = []
mu           = 0.0
sigma        = 0.0
trained      = False
alert_buffer = []      # stores alerts when disconnected (BUFFERING state)
connected    = False

# ── MQTT Callbacks (paho-mqtt v2 API) ────────────────────────────
def on_connect(client, userdata, flags, reason_code, properties):
    global connected
    if reason_code == 0:
        connected = True
        print(f"[{timestamp()}] Connected to MQTT broker at {MQTT_BROKER}:{MQTT_PORT}")
        flush_buffer(client)
    else:
        connected = False
        print(f"[{timestamp()}] Failed to connect, reason code: {reason_code}")

def on_disconnect(client, userdata, disconnect_flags, reason_code, properties):
    global connected
    connected = False
    print(f"[{timestamp()}] Disconnected from broker (reason_code={reason_code}). "
          f"Entering BUFFERING state.")

def on_publish(client, userdata, mid, reason_code, properties):
    print(f"[{timestamp()}] Alert published (mid={mid})")

# ── Helpers ──────────────────────────────────────────────────────
def timestamp():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def flush_buffer(client):
    """Publish any queued alerts after reconnection."""
    global alert_buffer
    if alert_buffer:
        print(f"[{timestamp()}] Flushing {len(alert_buffer)} buffered alerts...")
        for payload in alert_buffer:
            client.publish(MQTT_TOPIC, json.dumps(payload), qos=1)
        alert_buffer.clear()

def count_events(log_file, window_seconds):
    """Count log entries written in the last window_seconds."""
    now = time.time()
    count = 0
    try:
        with open(log_file, "r", errors="ignore") as f:
            for line in f:
                # syslog timestamps: "Jul  1 09:00:00"
                match = re.match(r"(\w+\s+\d+\s+\d+:\d+:\d+)", line)
                if match:
                    try:
                        log_time = datetime.strptime(
                            f"{datetime.now().year} {match.group(1)}",
                            "%Y %b %d %H:%M:%S"
                        )
                        if (now - log_time.timestamp()) <= window_seconds:
                            count += 1
                    except ValueError:
                        continue
    except FileNotFoundError:
        print(f"[{timestamp()}] Log file not found: {log_file}")
    return count

def compute_zscore(x, mu, sigma):
    """Z = (x - mu) / sigma"""
    if sigma == 0:
        return 0.0
    return (x - mu) / sigma

def update_baseline(observations):
    """Compute rolling mean and standard deviation."""
    n = len(observations)
    if n == 0:
        return 0.0, 0.0
    mu = sum(observations) / n
    variance = sum((x - mu) ** 2 for x in observations) / n
    sigma = math.sqrt(variance)
    return mu, sigma

def get_resource_usage():
    """Capture CPU and RAM for evaluation metrics."""
    return {
        "cpu_percent": psutil.cpu_percent(interval=1),
        "ram_mb": psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)
    }

# ── MQTT Client Setup ────────────────────────────────────────────
def setup_mqtt():
    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=NODE_ID,
        protocol=mqtt.MQTTv311
    )
    client.on_connect    = on_connect
    client.on_disconnect = on_disconnect
    client.on_publish    = on_publish
    client.reconnect_delay_set(min_delay=1, max_delay=30)
    if USE_TLS:
        client.tls_set(ca_certs=CA_CERT, tls_version=ssl.PROTOCOL_TLS)
    return client

# ── Main Loop ────────────────────────────────────────────────────
def main():
    global observations, mu, sigma, trained, alert_buffer

    print(f"[{timestamp()}] Edge Agent starting — Node ID: {NODE_ID}")
    print(f"[{timestamp()}] Broker {MQTT_BROKER}:{MQTT_PORT} "
          f"(TLS={'on' if USE_TLS else 'off'}), log={LOG_FILE}")
    print(f"[{timestamp()}] STATE: INITIALISING")

    client = setup_mqtt()

    # Connect (non-blocking so agent continues if broker unreachable)
    try:
        client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
        client.loop_start()
    except Exception as e:
        print(f"[{timestamp()}] Initial connection failed: {e}. Will retry.")

    print(f"[{timestamp()}] STATE: TRAINING — collecting {WINDOW_SIZE} observations")

    while True:
        try:
            # ── Read & count events ──────────────────────────────
            event_count = count_events(LOG_FILE, EVENT_WINDOW)
            print(f"[{timestamp()}] Event count (last {EVENT_WINDOW}s): {event_count}")

            # ── TRAINING phase ───────────────────────────────────
            if not trained:
                observations.append(event_count)
                if len(observations) >= WINDOW_SIZE:
                    mu, sigma = update_baseline(observations)
                    trained = True
                    print(f"[{timestamp()}] STATE: MONITORING — baseline μ={mu:.2f}, σ={sigma:.2f}")
                else:
                    print(f"[{timestamp()}] Training: {len(observations)}/{WINDOW_SIZE} observations collected")
                time.sleep(POLL_INTERVAL)
                continue

            # ── MONITORING phase — compute Z-score ───────────────
            z = compute_zscore(event_count, mu, sigma)
            print(f"[{timestamp()}] Z-score: {z:.4f} (μ={mu:.2f}, σ={sigma:.2f}, x={event_count})")

            # ── ALERTING: Z > threshold ──────────────────────────
            if z > Z_THRESHOLD:
                resources = get_resource_usage()
                payload = {
                    "node_id":     NODE_ID,
                    "timestamp":   timestamp(),
                    "event_type":  "DDoS_volume_spike",
                    "z_score":     round(z, 4),
                    "event_count": event_count,
                    "cpu_percent": resources["cpu_percent"],
                    "ram_mb":      round(resources["ram_mb"], 2)
                }
                print(f"[{timestamp()}] ALERT — Z={z:.4f} exceeds threshold {Z_THRESHOLD}")

                if connected:
                    client.publish(MQTT_TOPIC, json.dumps(payload), qos=1)
                else:
                    # BUFFERING state — queue locally
                    alert_buffer.append(payload)
                    print(f"[{timestamp()}] STATE: BUFFERING — alert queued ({len(alert_buffer)} in buffer)")

            else:
                # Z <= threshold — update rolling baseline (adaptive)
                observations.append(event_count)
                if len(observations) > WINDOW_SIZE * 2:
                    observations = observations[-WINDOW_SIZE:]
                mu, sigma = update_baseline(observations)
                print(f"[{timestamp()}] Baseline updated — μ={mu:.2f}, σ={sigma:.2f}")

            time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            print(f"[{timestamp()}] Shutdown signal received. Exiting.")
            client.loop_stop()
            client.disconnect()
            break
        except Exception as e:
            print(f"[{timestamp()}] Error: {e}")
            time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
