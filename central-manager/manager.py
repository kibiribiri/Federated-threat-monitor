#!/usr/bin/env python3
"""
Federated Threat Monitor — Central Manager
Subscribes to MQTT alert topics from all edge nodes,
persists alerts to SQLite, and prints real-time status.
"""

import json
import sqlite3
import ssl
import os
from datetime import datetime
import paho.mqtt.client as mqtt

# ── Configuration ────────────────────────────────────────────────
MQTT_BROKER   = "192.168.10.10"
MQTT_PORT     = 8883
MQTT_TOPIC    = "alerts/#"   # subscribes to all node alert topics
CA_CERT       = "/etc/mosquitto/ca.crt"
DB_PATH       = os.path.join(os.path.dirname(__file__), "alerts.db")

# ── Database Setup ───────────────────────────────────────────────
def init_db():
    """Create the SQLite database and tables if they don't exist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS nodes (
            node_id TEXT PRIMARY KEY,
            label   TEXT
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id     TEXT    NOT NULL,
            timestamp   TEXT    NOT NULL,
            event_type  TEXT    NOT NULL,
            z_score     REAL    NOT NULL,
            event_count INTEGER,
            cpu_percent REAL,
            ram_mb      REAL,
            FOREIGN KEY (node_id) REFERENCES nodes(node_id)
        );
    """)
    conn.commit()
    conn.close()
    print(f"[{timestamp()}] Database initialised at {DB_PATH}")

def insert_alert(payload):
    """Insert an alert record into SQLite."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Ensure node exists in nodes table
    cursor.execute(
        "INSERT OR IGNORE INTO nodes (node_id, label) VALUES (?, ?)",
        (payload["node_id"], payload["node_id"])
    )

    # Insert alert
    cursor.execute("""
        INSERT INTO alerts
            (node_id, timestamp, event_type, z_score, event_count, cpu_percent, ram_mb)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        payload.get("node_id"),
        payload.get("timestamp"),
        payload.get("event_type"),
        payload.get("z_score"),
        payload.get("event_count"),
        payload.get("cpu_percent"),
        payload.get("ram_mb")
    ))
    conn.commit()
    conn.close()

# ── Helpers ──────────────────────────────────────────────────────
def timestamp():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

# ── MQTT Callbacks ───────────────────────────────────────────────
def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        print(f"[{timestamp()}] Connected to broker at {MQTT_BROKER}:{MQTT_PORT}")
        client.subscribe(MQTT_TOPIC, qos=1)
        print(f"[{timestamp()}] Subscribed to topic: {MQTT_TOPIC}")
    else:
        print(f"[{timestamp()}] Connection failed — reason code: {reason_code}")

def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode("utf-8"))
        print(f"[{timestamp()}] ALERT received from {payload.get('node_id')}:")
        print(f"           event_type : {payload.get('event_type')}")
        print(f"           z_score    : {payload.get('z_score')}")
        print(f"           event_count: {payload.get('event_count')}")
        print(f"           cpu_percent: {payload.get('cpu_percent')}%")
        print(f"           ram_mb     : {payload.get('ram_mb')} MB")
        insert_alert(payload)
        print(f"[{timestamp()}] Alert saved to database.")
    except json.JSONDecodeError as e:
        print(f"[{timestamp()}] Failed to parse message: {e}")
    except Exception as e:
        print(f"[{timestamp()}] Error handling message: {e}")

def on_disconnect(client, userdata, flags, reason_code, properties):
    print(f"[{timestamp()}] Disconnected from broker (reason_code={reason_code})")

# ── Main ─────────────────────────────────────────────────────────
def main():
    print(f"[{timestamp()}] Central Manager starting...")
    init_db()

    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id="central-manager",
        protocol=mqtt.MQTTv311
    )
    client.on_connect    = on_connect
    client.on_message    = on_message
    client.on_disconnect = on_disconnect

    client.tls_set(
        ca_certs    = CA_CERT,
        tls_version = ssl.PROTOCOL_TLS
    )

    print(f"[{timestamp()}] Connecting to broker at {MQTT_BROKER}:{MQTT_PORT}...")
    client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)

    try:
        client.loop_forever()
    except KeyboardInterrupt:
        print(f"[{timestamp()}] Shutdown signal received. Exiting.")
        client.disconnect()

if __name__ == "__main__":
    main()
