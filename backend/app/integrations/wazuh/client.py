import logging
from typing import Any

import httpx

from backend.app.config import settings

logger = logging.getLogger(__name__)


class WazuhClient:
    """Async client for the Wazuh Manager REST API."""

    def __init__(self) -> None:
        self._base_url = settings.wazuh_api_url.rstrip("/")
        self._user = settings.wazuh_api_user
        self._password = settings.wazuh_api_password
        self._verify_ssl = settings.wazuh_verify_ssl
        self._token: str | None = None

    async def _get_http_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._base_url,
            verify=self._verify_ssl,
            timeout=httpx.Timeout(30.0, connect=10.0),
        )

    async def authenticate(self) -> str:
        """Obtain a JWT token from the Wazuh API."""
        async with await self._get_http_client() as client:
            resp = await client.post(
                "/security/user/authenticate",
                auth=(self._user, self._password),
            )
            resp.raise_for_status()
            self._token = resp.json()["data"]["token"]
            logger.info("Authenticated with Wazuh API")
            return self._token

    async def _ensure_token(self) -> str:
        if self._token is None:
            await self.authenticate()
        return self._token  # type: ignore[return-value]

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict:
        token = await self._ensure_token()
        async with await self._get_http_client() as client:
            resp = await client.request(
                method,
                path,
                headers={"Authorization": f"Bearer {token}"},
                **kwargs,
            )
            if resp.status_code == 401:
                await self.authenticate()
                token = self._token
                resp = await client.request(
                    method,
                    path,
                    headers={"Authorization": f"Bearer {token}"},
                    **kwargs,
                )
            resp.raise_for_status()
            return resp.json()

    async def get_alerts(
        self,
        limit: int = 20,
        offset: int = 0,
        select: str | None = None,
    ) -> list[dict]:
        """Fetch alerts from the Wazuh indexer API."""
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if select:
            params["select"] = select

        data = await self._request("GET", "/alerts", params=params)
        return data.get("data", {}).get("affected_items", [])

    async def get_alert(self, alert_id: str) -> dict | None:
        """Fetch a single alert by ID."""
        data = await self._request("GET", f"/alerts/{alert_id}")
        items = data.get("data", {}).get("affected_items", [])
        return items[0] if items else None


wazuh_client = WazuhClient()
