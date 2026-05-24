"""Minimal TAXII 2.1 client for pushing STIX bundles upstream.

We do not pull a heavyweight TAXII SDK. The protocol is straightforward
HTTP+JSON. Methods provided:
  - discovery()
  - api_root() / collections()
  - add_objects() — push a STIX bundle to a collection
  - get_objects()

Auth is HTTP Basic or Bearer (`token=` overrides `username/password`).
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

import requests


_HEADERS = {
    "Accept": "application/taxii+json;version=2.1",
    "Content-Type": "application/taxii+json;version=2.1",
}


class TaxiiClient:
    def __init__(
        self,
        base_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        token: Optional[str] = None,
        verify: bool | str = True,
        timeout: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.token = token
        self.verify = verify
        self.timeout = timeout

    def _auth(self) -> dict[str, str]:
        if self.token:
            return {"Authorization": f"Bearer {self.token}"}
        return {}

    def _get(self, path: str) -> Any:
        from digger.opsec.airgap import assert_network_allowed
        assert_network_allowed(f"taxii-get:{self.base_url}")
        url = f"{self.base_url}{path}"
        headers = {**_HEADERS, **self._auth()}
        auth = (self.username, self.password) if self.username and not self.token else None
        r = requests.get(url, headers=headers, auth=auth, verify=self.verify, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def _post(self, path: str, body: Any) -> Any:
        from digger.opsec.airgap import assert_network_allowed
        assert_network_allowed(f"taxii-post:{self.base_url}")
        url = f"{self.base_url}{path}"
        headers = {**_HEADERS, **self._auth()}
        auth = (self.username, self.password) if self.username and not self.token else None
        r = requests.post(url, headers=headers, json=body, auth=auth, verify=self.verify, timeout=self.timeout)
        r.raise_for_status()
        return r.json() if r.text else {}

    def discovery(self) -> dict:
        return self._get("/taxii2/")

    def api_root(self, api_root_path: str) -> dict:
        return self._get(f"/{api_root_path}/")

    def collections(self, api_root_path: str) -> dict:
        return self._get(f"/{api_root_path}/collections/")

    def add_objects(self, api_root_path: str, collection_id: str, bundle: dict) -> dict:
        return self._post(
            f"/{api_root_path}/collections/{collection_id}/objects/",
            bundle,
        )

    def get_objects(self, api_root_path: str, collection_id: str, params: dict | None = None) -> dict:
        from urllib.parse import urlencode
        qs = ("?" + urlencode(params)) if params else ""
        return self._get(f"/{api_root_path}/collections/{collection_id}/objects/{qs}")
