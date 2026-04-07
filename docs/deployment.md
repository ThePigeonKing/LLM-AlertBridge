# Deployment and startup guide

This matches the intended topology: **PostgreSQL + FastAPI on `core-compute`**, **LM Studio only on your laptop**, **Wazuh on `core-compute`** (same VM as the stack or reachable from it). Traffic between laptop and cloud uses **OpenVPN**.

---

## 1. One-time setup on `core-compute`

1. Install **Docker** and **Docker Compose** (plugin or standalone `docker compose`).
2. Clone the repo and configure the environment:

```bash
git clone <your-repo-url> LLM-AlertBridge && cd LLM-AlertBridge
cp .env.example .env
```

3. Edit `.env`:

| Variable | What to set |
|----------|-------------|
| `LM_STUDIO_BASE_URL` | `http://<YOUR_LAPTOP_VPN_IP>:1234/v1` — the IP your laptop gets on the VPN (not `localhost` from the server’s point of view). |
| `LM_STUDIO_MODEL` | Exact model id as shown in LM Studio (must match the loaded model). |
| `WAZUH_API_URL` | Usually `https://127.0.0.1:55000` if the Wazuh manager API is on the same host; use the real URL if Wazuh is elsewhere. |
| `WAZUH_API_USER` / `WAZUH_API_PASSWORD` | Wazuh API credentials. |
| `WAZUH_VERIFY_SSL` | `false` if you use the default self-signed cert. |

Leave `DATABASE_URL` as in `.env.example` for **local** runs; **Docker Compose** overrides it to use the `db` service (`postgresql+asyncpg://alertbridge:alertbridge@db:5432/alertbridge`).

4. Build and start the stack:

```bash
docker compose up --build -d
```

5. Check health:

```bash
curl -s http://127.0.0.1:8000/health
```

You should see `"database":"ok"`.

6. **Firewall / security group:** allow TCP **8000** (and **5432** only if you need direct DB access) from the VPN subnet or from IPs that should reach the UI/API.

---

## 2. Every time on your laptop

1. **Connect OpenVPN** so you are on the same internal network as `core-compute`.
2. **LM Studio**
   - Load your model.
   - Start the **local server** (default port **1234**).
   - **Important:** the server must accept connections **from the VPN**, not only `127.0.0.1`. In LM Studio, enable serving on the LAN / all interfaces (or bind to `0.0.0.0`) so `core-compute` can reach `http://<laptop-vpn-ip>:1234`.
3. **Browser:** open `http://<core-compute-internal-ip>:8000/alerts` (use the VM’s internal IP as you use for other cloud services).

Optional: `http://<core-compute-internal-ip>:8000/docs` for the OpenAPI UI.

---

## 3. Ingest alerts and run analysis

1. On the alerts page, use **Sync from Wazuh** (or `POST /api/alerts/sync`) once Wazuh has alerts.
2. Open an alert → **Analyze with LLM** (backend calls LM Studio on your laptop over VPN).

---

## 4. Useful commands on `core-compute`

```bash
# Logs
docker compose logs -f backend

# Stop
docker compose down

# Stop and remove DB volume (wipes data)
docker compose down -v
```

---

## 5. Optional: dev on one machine only

If everything runs on the same host (e.g. laptop + local Postgres in Docker + LM Studio on localhost):

```bash
docker compose up db -d
cp .env.example .env
# LM_STUDIO_BASE_URL=http://127.0.0.1:1234/v1
uv sync && uv run alembic upgrade head
uv run python scripts/seed_alerts.py   # optional
uv run uvicorn backend.app.main:app --reload --port 8000
```

Note: `DATABASE_URL` in `.env` must point at Postgres (e.g. `postgresql+asyncpg://alertbridge:alertbridge@localhost:5432/alertbridge`) when not using the full `docker compose` stack for the backend.

---

## Troubleshooting (short)

| Symptom | Check |
|--------|--------|
| `502` on analyze | LM Studio running? Model id correct? Laptop VPN IP correct in `LM_STUDIO_BASE_URL`? LM Studio listening on `0.0.0.0`, not only localhost? |
| Sync fails | `WAZUH_API_URL`, credentials, SSL flag; from inside backend container/host, `curl` the Wazuh API. |
| Cannot open UI from laptop | VPN up? Firewall on `core-compute` allows 8000 from VPN? Using **internal** IP of `core-compute`. |
