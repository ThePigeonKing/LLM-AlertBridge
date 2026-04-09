# Step 1: Run Database Migrations

The new code adds an `enrichments` table and extends the `analyses` table with criticality/response columns. You need to run the migration.

## If using Docker Compose (deployed on core-compute)

The migration runs automatically on container startup (the backend container's command includes `alembic upgrade head`). Just rebuild:

```bash
ssh core-compute
cd LLM-AlertBridge
git pull
docker compose up --build -d
```

## If running locally

```bash
cd LLM-AlertBridge

# Make sure PostgreSQL is running
docker compose up db -d

# Run migration
uv run alembic upgrade head
```

## Verify

```bash
# Check migration status
uv run alembic current
# Should show: a1b2c3d4e5f6 (head)

# Or check via psql
docker compose exec db psql -U alertbridge -c "\dt"
# Should show: alerts, analyses, enrichments, alembic_version
```

## If you get errors

If you have existing data and the migration fails, you can:

```bash
# Check current revision
uv run alembic current

# If stuck, stamp to the previous revision and retry
uv run alembic stamp c034ee325edf
uv run alembic upgrade head
```

## After migration

Seed sample data if you don't have any:

```bash
uv run python scripts/seed_alerts.py
```
