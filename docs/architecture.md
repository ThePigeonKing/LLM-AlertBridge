# Architecture

## System Overview

LLM-AlertBridge is a research prototype for analyzing SOC/SIEM security alerts using a locally deployed LLM. The backend, database, and Wazuh all run centrally on `core-compute` in Yandex Cloud, while the LLM runs on the analyst's laptop via LM Studio. Communication between the cloud and the laptop is secured through an OpenVPN tunnel.

## Infrastructure Topology

```
  ┌──────────────────────────────────────────────────────────────────────┐
  │                    Yandex Cloud (Internal Network)                   │
  │                                                                      │
  │   ┌──────────────────────────────────────────────────┐               │
  │   │              core-compute                        │               │
  │   │                                                  │               │
  │   │   ┌────────────┐  ┌─────────────────┐           │               │
  │   │   │ PostgreSQL │  │ FastAPI Backend  │           │               │
  │   │   │ (port 5432)│  │ (port 8000)     │           │               │
  │   │   └────────────┘  └────────┬────────┘           │               │
  │   │                            │                     │               │
  │   │   ┌────────────────────────┘                     │               │
  │   │   │  Wazuh Manager (port 55000)                  │◄── alerts ─┐ │
  │   └───┼──────────────────────────────────────────────┘            │ │
  │       │                                                           │ │
  │   ┌───┼──────────────┐  ┌───────────────┐                        │ │
  │   │ target-1-compute │  │target-2-compute│────────────────────────┘ │
  │   │ (Wazuh Agent)    │  │(Wazuh Agent)   │                          │
  │   └──────────────────┘  └───────────────┘                           │
  │                                  ▲                                   │
  │   ┌──────────────────┐           │                                   │
  │   │ attacker-compute │───attacks─┘                                   │
  │   │ (Event Simulator)│                                               │
  │   └──────────────────┘                                               │
  │                                                                      │
  │   ┌──────────────────┐                                               │
  │   │ openvpn-access-  │                                               │
  │   │ server           │                                               │
  │   └────────┬─────────┘                                               │
  └────────────┼─────────────────────────────────────────────────────────┘
               │ VPN Tunnel
  ┌────────────┼─────────────────────────────────────────────────────────┐
  │            │                Analyst Laptop (Local)                    │
  │   ┌────────▼─────────┐                                               │
  │   │  VPN Client       │                                               │
  │   └────────┬─────────┘                                               │
  │            │                                                          │
  │   ┌────────▼──────────────────────────────┐                          │
  │   │  LM Studio (port 1234)               │                          │
  │   │  Local LLM on Apple Silicon / GPU    │                          │
  │   └──────────────────────────────────────┘                          │
  └──────────────────────────────────────────────────────────────────────┘
```

## Node Roles

| Node | Role | Details |
|------|------|---------|
| `core-compute` | Backend + DB + Wazuh | Hosts the FastAPI backend, PostgreSQL, and Wazuh Manager. All services run in Docker Compose. The backend connects to LM Studio on the analyst's laptop via VPN. |
| `target-1-compute` | Wazuh Agent (Linux host) | Monitored endpoint. Runs Wazuh agent reporting to core-compute. |
| `target-2-compute` | Wazuh Agent (Linux host) | Second monitored endpoint for diverse alert scenarios. |
| `attacker-compute` | Attack simulator | Generates security events against target hosts (SSH brute-force, file tampering, privilege escalation, web attacks). |
| `openvpn-access-server` | VPN gateway | Provides secure connectivity between the analyst's laptop and the cloud internal network. |
| Analyst laptop | LM Studio (Local LLM) | Runs the LLM locally via LM Studio to leverage Apple Silicon / GPU acceleration. Exposes an OpenAI-compatible API on port 1234. |

## Communication Model

- All cloud nodes communicate via **internal IPv4 addresses** (stable, used as primary addressing).
- The **VPN tunnel** bridges the analyst's laptop into the cloud network.
- **FastAPI backend** and **PostgreSQL** run on `core-compute` in Docker Compose, alongside the Wazuh Manager. The backend connects to Wazuh locally (same host) and reaches the LLM on the analyst's laptop via VPN.
- **LM Studio** runs natively on the laptop (not in Docker) to leverage GPU/Apple Silicon acceleration. The backend on `core-compute` reaches it via the laptop's VPN IP on port 1234.
- The analyst accesses the web UI by connecting to `core-compute:8000` through the VPN.

## Data Flow

1. `attacker-compute` generates security events against `target-1-compute` and `target-2-compute`.
2. Wazuh agents on targets detect events and forward alerts to `core-compute` (Wazuh Manager).
3. The FastAPI backend (on `core-compute`) queries the Wazuh API locally.
4. Alerts are normalized and stored in PostgreSQL (on `core-compute`).
5. Upon analyst request, the alert context is sent to LM Studio on the analyst's laptop via VPN.
6. The LLM returns a structured JSON analysis back to the backend over VPN.
7. The result is stored in PostgreSQL and displayed in the web UI.

## Security Considerations

- The LLM runs on the analyst's personal laptop, keeping model weights and inference fully under analyst control.
- Alert data is transmitted to the laptop only during LLM inference, over an encrypted VPN tunnel.
- Wazuh API communication is local to `core-compute` (no network traversal).
- The backend and database are centralized on `core-compute`, simplifying access control and data management.
- The LLM does not have autonomous action capabilities.
