# Federated-threat-monitor

A lightweight, federated SIEM for resource-constrained networks. Edge agents
detect DDoS volumetric anomalies locally using **Z-score statistical baseline
profiling** and publish compact JSON alerts over **MQTT**; a central manager
persists them to **SQLite** and shows them on a **Streamlit** dashboard. Raw
logs never leave the edge.

```
 EDGE (xN)                  TRANSPORT              MANAGER
 edge-agent/agent.py --MQTT--> Mosquitto --MQTT--> central-manager/manager.py -> SQLite
 count -> Z-score              broker              dashboard/app.py (Streamlit)
```

## Layout
| Path | Role |
|------|------|
| `edge-agent/agent.py` | Counts log events per window, Z-score, publishes alerts (QoS 1) |
| `central-manager/manager.py` | Subscribes to `alerts/#`, writes to SQLite |
| `dashboard/app.py` | Streamlit dashboard (auto-refresh) |
| `scripts/traffic_gen.py` | Synthetic normal traffic + labelled attack spikes |
| `scripts/evaluate.py` | TPR/FPR vs. ground truth |
| `scripts/resource_monitor.py` | psutil CPU/RAM sampling (verify < 20 MB) |

## Install
Every node:
```bash
sudo apt update && sudo apt install -y git python3 python3-venv python3-pip
git clone https://github.com/kibiribiri/Federated-threat-monitor.git
cd Federated-threat-monitor
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```
Manager node additionally:
```bash
sudo apt install -y mosquitto mosquitto-clients
echo -e "listener 1883 0.0.0.0\nallow_anonymous true" | sudo tee /etc/mosquitto/conf.d/siem.conf
sudo systemctl restart mosquitto
```

## Configuration (environment variables)
No code edits needed per node — set env vars:

| Variable | Default | Notes |
|----------|---------|-------|
| `FTM_NODE_ID` | `edge-node-01` | unique per edge node |
| `FTM_BROKER` | `192.168.10.10` | manager broker IP |
| `FTM_USE_TLS` | `false` | `true` = MQTT over TLS (port 8883) |
| `FTM_PORT` | `1883` / `8883` | overrides port |
| `FTM_LOG_FILE` | `/var/log/syslog` | log to monitor |
| `FTM_CA_CERT` | `/etc/mosquitto/certs/ca.crt` | CA cert when TLS on |
| `FTM_WINDOW_SIZE` | `30` | training observations |
| `FTM_Z_THRESHOLD` | `3.0` | alert threshold |
| `FTM_POLL_INTERVAL` | `5` | seconds between reads |
| `FTM_EVENT_WINDOW` | `10` | counting window seconds |
| `FTM_DB_PATH` | `central-manager/alerts.db` | manager/dashboard DB |

## Run (plain MQTT on 1883)
**Manager node:**
```bash
python3 central-manager/manager.py
streamlit run dashboard/app.py --server.address 0.0.0.0   # browse http://<host-only-ip>:8501
```
**Each edge node:**
```bash
FTM_NODE_ID=edge-node-01 python3 edge-agent/agent.py
# generate test traffic (point the agent at the same file):
FTM_NODE_ID=edge-node-01 FTM_LOG_FILE=/tmp/ftm_synth.log python3 edge-agent/agent.py
python3 scripts/traffic_gen.py --log /tmp/ftm_synth.log --duration 300 --attack-every 60
```

## Evaluate
```bash
python3 scripts/evaluate.py --labels ground_truth.csv
python3 scripts/resource_monitor.py --name agent.py --out metrics.csv   # on an edge node
```

## Enabling TLS (later hardening step)
Set `FTM_USE_TLS=true` on the agent and manager and generate a CA + broker
certificate for Mosquitto (`listener 8883`, `cafile`/`certfile`/`keyfile`).
The proposal's security requirement expects MQTT-over-TLS in the final system.

## Detection logic
1. **TRAINING:** observe `FTM_WINDOW_SIZE` windows, build μ/σ — no alerts.
2. **MONITORING:** `Z = (x − μ)/σ` each window.
   - `Z > FTM_Z_THRESHOLD` → publish alert (anomaly is **not** folded into baseline).
   - otherwise → adaptively update μ/σ.
