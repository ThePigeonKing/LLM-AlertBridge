# Deployment and startup guide

This matches the intended topology: **PostgreSQL + FastAPI + Wazuh stack on `core-compute` (10.128.0.29)**, **LM Studio on your laptop** (you set its VPN IP in `.env`). See [network.md](network.md) for all fixed internal addresses.

### Wazuh in Docker Compose

Root **`docker-compose.yml`** starts **Wazuh indexer**, **manager**, and **dashboard** (images **4.9.2**) next to Postgres and the backend. **One-time**: generate TLS certs, then `docker compose up`. Details, sysctl, ports, and passwords: [docs/wazuh.md](wazuh.md).

**If Wazuh is down**, the backend still starts; use sample alerts: `uv run python scripts/seed_alerts.py` (from the repo on `core-compute`, with DB available).

### `LM_STUDIO_BASE_URL` — how core-compute reaches LM Studio

The backend on **10.128.0.29** must use an address it can **route to** on the internal network. Pick one of these patterns:

**A — Direct (no tunnel)**  
LM Studio listens on your laptop’s **VPN client IP** (the address OpenVPN assigns to the Mac), default port **1234**:

`LM_STUDIO_BASE_URL=http://<laptop-vpn-client-ip>:1234/v1`

**B — SSH tunnel (your setup)**  
You forward LM Studio from the laptop so it appears on a host the cloud can reach—e.g. **openvpn-access-server** **10.128.0.7** on port **8080** (or whatever you chose). Then:

`LM_STUDIO_BASE_URL=http://10.128.0.7:8080/v1`

The path must still end with **`/v1`** (OpenAI-compatible API). Use the **same port** the tunnel exposes on the VPN/OpenVPN side.

**C — Other jump host**  
Any internal IP:port where your tunnel or proxy terminates is valid, as long as `core-compute` can open a TCP connection to it.

Do **not** wrap `LM_STUDIO_MODEL` in quotes in `.env` (use `qwen/qwen3.5-9b`, not `'qwen/qwen3.5-9b'`).

---

## 1. One-time setup on `core-compute` (10.128.0.29)

1. Install **Docker** and **Docker Compose** (plugin or standalone `docker compose`).
2. Clone the repo and configure the environment:

```bash
git clone <your-repo-url> LLM-AlertBridge && cd LLM-AlertBridge
cp .env.example .env
```

3. Edit `.env`:

| Variable | What to set |
|----------|-------------|
| `LM_STUDIO_BASE_URL` | Laptop VPN IP + LM Studio port, **or** tunnel endpoint (e.g. `http://10.128.0.7:8080/v1` if SSH exposes LM Studio on the OpenVPN host). Must end with `/v1`. |
| `LM_STUDIO_MODEL` | Exact model id as shown in LM Studio (must match the loaded model). |
| `WAZUH_API_URL` | Compose sets **`https://wazuh.manager:55000`** for the backend container. For local `uvicorn` without Compose, use e.g. `https://10.128.0.29:55000`. |
| `WAZUH_API_USER` / `WAZUH_API_PASSWORD` | Must match the Wazuh manager API and `deploy/wazuh/config/wazuh_dashboard/wazuh.yml`. If set, the password must meet Wazuh strength rules (see [wazuh.md](wazuh.md#error-5007--insecure-user-password-provided-manager-logs)); weak values like `changeme` cause error **5007**. |
| `WAZUH_VERIFY_SSL` | `false` with the generated demo certs. |
| `WAZUH_PUBLISH_IP` | Optional. Default **`10.128.0.29`** for agent/API/dashboard ports. On a laptop: **`127.0.0.1`**. |
| `ALERTBRIDGE_HTTP_PUBLISH` | Optional. Default in Compose is **`10.128.0.29:8000:8000`** (API only on internal IP). |

Leave `DATABASE_URL` as in `.env.example` for **local** runs; **Docker Compose** overrides it to use the `db` service (`postgresql+asyncpg://alertbridge:alertbridge@db:5432/alertbridge`).

4. Build and start the stack:

```bash
docker compose up --build -d
```

5. Check health **on core-compute**:

```bash
curl -s http://10.128.0.29:8000/health
```

You should see `"database":"ok"`.

6. **Yandex Cloud security group:** deny inbound **8000**, **8443**, **55000**, **1514**–**1515**, **5432** from `0.0.0.0/0` as appropriate; allow **8000** (and dashboard **8443** if you use it) from VPN / your subnet (e.g. `10.128.0.0/24`) only. Postgres is **not** published by Compose, so nothing listens on host **5432** for the database container.

---

## 2. Every time on your laptop

1. **Connect OpenVPN** (to `openvpn-access-server` at **10.128.0.7** on the internal network).
2. **LM Studio** — load model, start the local server (port **1234** by default). Either allow **LAN / all interfaces** so **10.128.0.29** can reach your laptop’s VPN IP **or** keep **SSH tunnel** active so LM Studio is reachable via **10.128.0.7** (or your chosen endpoint).
3. **Browser:** `http://10.128.0.29:8000/alerts`

Optional: `http://10.128.0.29:8000/docs` for OpenAPI.

---

## 3. Ingest alerts and run analysis

1. On the alerts page, use **Sync from Wazuh** (or `POST /api/alerts/sync`).
2. Open an alert → **Analyze with LLM**.

---

## 4. Useful commands on `core-compute`

```bash
docker compose logs -f backend
docker compose down
docker compose down -v   # removes DB volume
```

---

## 5. Local development (laptop only)

If you run Docker on your **laptop** (no `10.128.0.29` on this machine), set in `.env`:

```bash
ALERTBRIDGE_HTTP_PUBLISH=8000:8000
WAZUH_PUBLISH_IP=127.0.0.1
LM_STUDIO_BASE_URL=http://127.0.0.1:1234/v1
```

Then:

```bash
docker compose up db -d
uv sync && uv run alembic upgrade head
uv run python scripts/seed_alerts.py   # optional
uv run uvicorn backend.app.main:app --reload --port 8000
```

Or full stack with Compose using `ALERTBRIDGE_HTTP_PUBLISH=8000:8000`.

---

## Troubleshooting (short)

| Symptom | Check |
|--------|--------|
| `502` on analyze | LM Studio running? SSH tunnel up? `LM_STUDIO_BASE_URL` = reachable **from core-compute** (tunnel endpoint or laptop VPN IP)? Port/path `/v1` correct? Model id matches (no extra quotes in `.env`)? |
| Sync fails | Certs generated? `docker compose ps`; from host: `curl -sk -u wazuh-wui:… https://127.0.0.1:55000/security/user/authenticate?raw=true` |
| Cannot open UI | VPN up? Use **http://10.128.0.29:8000**? Security group allows 8000 from VPN? |
| Docker bind error on laptop | Set `ALERTBRIDGE_HTTP_PUBLISH=8000:8000` — your machine has no `10.128.0.29`. |
