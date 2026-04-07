# Fixed internal IPv4 addresses (Yandex Cloud)

All VMs are in **ru-central1-a** on subnet **10.128.0.0/24**.

| Host name               | Internal IPv4  | Role                                      |
|-------------------------|----------------|-------------------------------------------|
| `core-compute`          | **10.128.0.29**| Wazuh manager, Docker (FastAPI + Postgres)|
| `target-1-compute`      | **10.128.0.35**| Wazuh agent / monitored host              |
| `target-2-compute`      | **10.128.0.14**| Wazuh agent / monitored host              |
| `attacker-compute`      | **10.128.0.36**| Attack / scenario simulation              |
| `openvpn-access-server` | **10.128.0.7** | VPN gateway for laptop access             |

**LM Studio:** in `.env`, set `LM_STUDIO_BASE_URL` to whatever **core-compute** can reach—the laptop’s **VPN client IP** (LM Studio on **:1234**), or an **SSH tunnel** endpoint (e.g. **10.128.0.7:8080** on `openvpn-access-server`). See [deployment.md](deployment.md).

**AlertBridge UI (after VPN):** `http://10.128.0.29:8000/alerts`

Docker Compose publishes the API as **`10.128.0.29:8000`** on `core-compute` only (not on `0.0.0.0:8000`), so the service is not bound to all interfaces on the host for that port mapping.
