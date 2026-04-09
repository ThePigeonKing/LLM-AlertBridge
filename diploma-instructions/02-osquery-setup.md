# Step 2: Set Up osquery on Target Hosts

For the enrichment subsystem to work in SSH mode (not mock), you need osquery installed on the target hosts.

## Option A: Using mock mode (for development and evaluation)

If you can't install osquery on the hosts, the system works in mock mode by default. Mock mode returns built-in sample data that is realistic enough for the evaluation framework.

Set in your `.env`:
```
OSQUERY_TRANSPORT=mock
```

The evaluation framework (`experiments/run_evaluation.py`) uses `simulated_enrichment` data from the corpus regardless of transport, so **you can run the full evaluation without installing osquery**.

## Option B: Install osquery on target hosts (for live deployment)

### On target-1-compute and target-2-compute (Ubuntu/Debian):

```bash
# Add osquery repository
export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys $OSQUERY_KEY
sudo add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'
sudo apt-get update
sudo apt-get install osquery

# Start osqueryd
sudo systemctl enable osqueryd
sudo systemctl start osqueryd

# Verify
osqueryi "SELECT version FROM osquery_info;"
```

### Configure SSH access from core-compute

The backend runs on core-compute and needs SSH access to target hosts:

```bash
# On core-compute, generate a key (if you haven't already)
ssh-keygen -t ed25519 -f ~/.ssh/osquery_key -N ""

# Copy to target hosts
ssh-copy-id -i ~/.ssh/osquery_key root@10.128.0.35  # target-1
ssh-copy-id -i ~/.ssh/osquery_key root@10.128.0.14  # target-2

# Verify
ssh -i ~/.ssh/osquery_key root@10.128.0.35 "osqueryi --json 'SELECT version FROM osquery_info;'"
```

### Update .env

```
OSQUERY_TRANSPORT=ssh
OSQUERY_SSH_USER=root
OSQUERY_SSH_KEY_PATH=/root/.ssh/osquery_key
OSQUERY_SSH_TIMEOUT=10
```

## Testing the setup

After configuring either mode:

1. Open the UI at `http://10.128.0.29:8000/alerts`
2. Click on any alert
3. Click "Enrich with osquery"
4. Verify that host context data appears

For SSH mode, check the backend logs if enrichment fails:
```bash
docker compose logs -f backend | grep osquery
```
