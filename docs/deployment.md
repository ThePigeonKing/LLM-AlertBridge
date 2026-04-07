# Deployment and startup guide

This matches the intended topology: **PostgreSQL + FastAPI on `core-compute` (10.128.0.29)**, **LM Studio on your laptop** (you set its VPN IP in `.env`), **Wazuh on `core-compute`**. See [network.md](network.md) for all fixed internal addresses.

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
| `LM_STUDIO_BASE_URL` | `http://<YOUR_LAPTOP_VPN_IP>:1234/v1` — replace `YOUR_LAPTOP_VPN_IP` with the address your Mac gets on OpenVPN. |
| `LM_STUDIO_MODEL` | Exact model id as shown in LM Studio (must match the loaded model). |
| `WAZUH_API_URL` | Default `https://host.docker.internal:55000` (works with `extra_hosts` in Compose). If not, try `https://10.128.0.29:55000`. |
| `WAZUH_API_USER` / `WAZUH_API_PASSWORD` | Wazuh API credentials. |
| `WAZUH_VERIFY_SSL` | `false` if you use the default self-signed cert. |
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

6. **Yandex Cloud security group:** deny inbound **8000** and **5432** from `0.0.0.0/0`; allow **8000** from VPN / your subnet (e.g. `10.128.0.0/24`) only. Postgres is **not** published by Compose, so nothing listens on host **5432** for the database container.

---

## 2. Every time on your laptop

1. **Connect OpenVPN** (to `openvpn-access-server` at **10.128.0.7** on the internal network).
2. **LM Studio** — load model, start server on **1234**, allow **LAN / all interfaces** so **10.128.0.29** can reach your laptop’s VPN IP.
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
| `502` on analyze | LM Studio running? Laptop VPN IP in `LM_STUDIO_BASE_URL`? LM Studio listening on all interfaces? |
| Sync fails | `WAZUH_API_URL`; from host: `curl -k https://127.0.0.1:55000/...` |
| Cannot open UI | VPN up? Use **http://10.128.0.29:8000**? Security group allows 8000 from VPN? |
| Docker bind error on laptop | Set `ALERTBRIDGE_HTTP_PUBLISH=8000:8000` — your machine has no `10.128.0.29`. |
