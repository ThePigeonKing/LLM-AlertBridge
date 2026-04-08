import logging
from typing import Any

import httpx

from backend.app.config import settings

logger = logging.getLogger(__name__)


class WazuhClient:
    """Async client for the Wazuh stack.

    * Manager API (port 55000) — auth healthcheck, agent management.
    * Indexer / OpenSearch (port 9200) — alert retrieval via ``wazuh-alerts-*``.
    """

    def __init__(self) -> None:
        self._api_url = settings.wazuh_api_url.rstrip("/")
        self._api_user = settings.wazuh_api_user
        self._api_password = settings.wazuh_api_password
        self._verify_ssl = settings.wazuh_verify_ssl
        self._token: str | None = None

        self._indexer_url = settings.wazuh_indexer_url.rstrip("/")
        self._indexer_user = settings.wazuh_indexer_user
        self._indexer_password = settings.wazuh_indexer_password

    # ------------------------------------------------------------------
    # Manager API helpers
    # ------------------------------------------------------------------

    async def _api_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._api_url,
            verify=self._verify_ssl,
            timeout=httpx.Timeout(30.0, connect=10.0),
        )

    async def authenticate(self) -> str:
        """Obtain a JWT token from the Wazuh Manager API."""
        async with await self._api_client() as client:
            resp = await client.post(
                "/security/user/authenticate",
                auth=(self._api_user, self._api_password),
            )
            resp.raise_for_status()
            self._token = resp.json()["data"]["token"]
            logger.info("Authenticated with Wazuh Manager API")
            return self._token

    # ------------------------------------------------------------------
    # Indexer (OpenSearch) helpers
    # ------------------------------------------------------------------

    async def _indexer_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._indexer_url,
            auth=(self._indexer_user, self._indexer_password),
            verify=self._verify_ssl,
            timeout=httpx.Timeout(30.0, connect=10.0),
        )

    async def get_alerts(
        self,
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict]:
        """Fetch recent alerts from the Wazuh Indexer (OpenSearch)."""
        body: dict[str, Any] = {
            "size": limit,
            "from": offset,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"match_all": {}},
        }

        async with await self._indexer_client() as client:
            resp = await client.post(
                "/wazuh-alerts-*/_search",
                json=body,
            )
            resp.raise_for_status()
            data = resp.json()

        hits = data.get("hits", {}).get("hits", [])
        alerts = []
        for hit in hits:
            alert = hit.get("_source", {})
            alert["_id"] = hit.get("_id", "")
            alerts.append(alert)

        logger.info("Fetched %d alerts from Wazuh Indexer", len(alerts))
        return alerts

    async def get_alert(self, alert_id: str) -> dict | None:
        """Fetch a single alert document by OpenSearch ``_id``."""
        async with await self._indexer_client() as client:
            resp = await client.post(
                "/wazuh-alerts-*/_search",
                json={
                    "size": 1,
                    "query": {"ids": {"values": [alert_id]}},
                },
            )
            resp.raise_for_status()
            data = resp.json()

        hits = data.get("hits", {}).get("hits", [])
        if not hits:
            return None
        alert = hits[0].get("_source", {})
        alert["_id"] = hits[0].get("_id", "")
        return alert


wazuh_client = WazuhClient()
