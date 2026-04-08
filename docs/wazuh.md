# Wazuh on `core-compute` (Docker Compose)

The **single-node Wazuh stack** (indexer, manager, dashboard) runs next to AlertBridge via the root **`docker-compose.yml`**. Config and TLS layout live under **`deploy/wazuh/config/`** (based on [wazuh-docker](https://github.com/wazuh/wazuh-docker) v4.9.2 single-node).

**Agents** on **target-1-compute** / **target-2-compute** still enroll against the manager at **`10.128.0.29`** (ports **1514** / **1515**), not against a container-only address.

---

## Prerequisites

1. **Host sysctl** (Linux): OpenSearch needs a higher virtual-memory map limit:

   ```bash
   sudo sysctl -w vm.max_map_count=262144
   ```

   Make it persistent if your distro uses `/etc/sysctl.d/`.

2. **RAM**: Indexer JVM is capped at **512 MiB** in Compose for an ~8 GiB VM. Increase `OPENSEARCH_JAVA_OPTS` in `docker-compose.yml` only if you have headroom.

---

## First-time TLS material

Indexer, manager, and dashboard expect PEM files under **`deploy/wazuh/config/wazuh_indexer_ssl_certs/`**. They are **not** committed (see `.gitignore`).

From the **repository root**:

```bash
docker compose -f docker-compose.wazuh-certs.yml run --rm generator
```

Alternatively, from **`deploy/wazuh/`**:

```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

`deploy/wazuh/config/certs.yml` names nodes **`wazuh.indexer`**, **`wazuh.manager`**, **`wazuh.dashboard`** — these must match Compose **hostnames**.

---

## Start the stack

```bash
docker compose up --build -d
```

**Published on `core-compute`** (default bind address **`10.128.0.29`**, overridable with **`WAZUH_PUBLISH_IP`** in `.env`):

| Service | Ports / URL |
|--------|-------------|
| Wazuh manager (agents, syslog, API) | **1514**, **1515**, **514/udp**, **55000** |
| Wazuh dashboard | **https://10.128.0.29:8443** (HTTPS to container **5601**) |
| Wazuh indexer | **not** published on the host; reachable inside the Compose network as **`https://wazuh.indexer:9200`** |

**Default passwords** (change for production; keep files in sync if you change API credentials):

- Indexer **`admin`**: **`SecretPassword`** (see `internal_users.yml` demo hashes).
- Dashboard OpenSearch user **`kibanaserver`**: **`kibanaserver`**.
- Wazuh API user (Compose **`API_USERNAME`**, default **`wazuh-wui`**): **`WAZUH_API_PASSWORD`** in `.env` (optional; if unset, Compose uses default **`MyS3cr37P450r.*-`**). Password must satisfy Wazuh’s strength rules (see troubleshooting below). It must match **`deploy/wazuh/config/wazuh_dashboard/wazuh.yml`** `password` and the manager’s API password.

The **backend** container uses **`WAZUH_API_URL=https://wazuh.manager:55000`** (set in Compose). **`WAZUH_VERIFY_SSL=false`** is typical with the demo certs.

---

## AlertBridge without a healthy Wazuh

If indexer or manager fails to start, **Postgres + backend** still come up; **Sync from Wazuh** fails until the manager API answers. You can seed sample alerts: see [deployment.md](deployment.md).

---

## Verify the API (on `core-compute`)

From the **host** (replace user/password if you changed them):

```bash
curl -sk -u wazuh-wui:'MyS3cr37P450r.*-' \
  https://127.0.0.1:55000/security/user/authenticate?raw=true
```

You should get a JWT. From inside the **backend** container the same URL is **`https://wazuh.manager:55000`**.

---

## Error 5007 — “Insecure user password provided” (manager logs)

Compose substitutes **`API_PASSWORD`** from **`WAZUH_API_PASSWORD`** in the project **`.env`** (if present). Wazuh enforces **8–64 characters** with at least one **uppercase**, **lowercase**, **digit**, and **non-alphanumeric** symbol (see `framework/wazuh/security.py` in Wazuh). Generic placeholders like **`changeme`** fail and abort API user setup; the manager container may then exit messily (s6 / filebeat errors).

**Fix:** Set a compliant `WAZUH_API_PASSWORD` in `.env`, set the same value in **`deploy/wazuh/config/wazuh_dashboard/wazuh.yml`** (`password:`), then recreate **`wazuh.manager`** and **`wazuh.dashboard`**. If a failed first run left bad state, remove the **`wazuh_api_configuration`** named volume only after you understand that API config will be reset.

---

## References

- [Wazuh Docker deployment](https://documentation.wazuh.com/current/deployment-options/docker/index.html)
- [wazuh/wazuh-docker](https://github.com/wazuh/wazuh-docker)
