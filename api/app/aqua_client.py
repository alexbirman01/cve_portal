"""Aqua Security CSP API client (read-only)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from api.app.config import settings

_ENCODING = "utf-8"


@dataclass(frozen=True)
class AquaImageRef:
    registry: str
    repository: str
    tag: str


class AquaClient:
    """HMAC-authenticated Aqua CSP client; token and CSP base URL are cached."""

    def __init__(self) -> None:
        self._token: str | None = None
        self._token_exp: float = 0.0
        self._csp_url: str | None = None
        self._http = httpx.Client(timeout=60.0)

    def close(self) -> None:
        self._http.close()

    def configured(self) -> bool:
        return bool((settings.aqua_api_key or "").strip() and (settings.aqua_api_secret or "").strip())

    def _authenticate(self) -> tuple[str, str]:
        if not self.configured():
            raise RuntimeError("Aqua API credentials not configured")
        now = time.time()
        if self._token and self._csp_url and now < self._token_exp - 60:
            return self._csp_url, self._token

        key = settings.aqua_api_key.strip()
        secret = settings.aqua_api_secret.strip()
        url = settings.aqua_token_url.strip()
        method = "POST"
        body = json.dumps(
            {"validity": 240, "allowed_endpoints": ["ANY"], "csp_roles": ["Viewer"]},
            separators=(",", ":"),
        )
        path = "/v2/tokens"
        timestamp = str(int(time.time() * 1000))
        sign_str = timestamp + method + path + body
        sig = hmac.new(
            secret.encode(_ENCODING),
            msg=sign_str.encode(_ENCODING),
            digestmod=hashlib.sha256,
        ).hexdigest()
        headers = {
            "accept": "application/json",
            "x-api-key": key,
            "x-signature": sig,
            "x-timestamp": timestamp,
            "content-type": "application/json",
        }
        r = self._http.post(url, content=body, headers=headers)
        r.raise_for_status()
        data = r.json()
        token = data.get("data") or ""
        if not token:
            raise RuntimeError("Aqua token response missing data")

        parts = token.split(".")
        if len(parts) < 2:
            raise RuntimeError("Invalid Aqua JWT")
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(padded))
        ese = (decoded.get("csp_metadata") or {}).get("urls", {}).get("ese_url", "")
        if not ese:
            raise RuntimeError("Aqua JWT missing csp_metadata.urls.ese_url")
        csp_url = f"https://{ese}"
        exp = decoded.get("exp")
        self._token = token
        self._csp_url = csp_url
        self._token_exp = float(exp) if exp else now + 240 * 60
        return csp_url, token

    def _get(self, path: str) -> dict[str, Any]:
        csp_url, token = self._authenticate()
        r = self._http.get(
            f"{csp_url}{path}",
            headers={"Authorization": f"Bearer {token}", "accept": "application/json"},
        )
        r.raise_for_status()
        return r.json()

    def resolve_image(self, repository: str, tag: str) -> AquaImageRef | None:
        """Find registry/repository/tag in Aqua (search param does not filter — scan pages)."""
        repo_lower = repository.lower()
        tag_lower = tag.lower()
        from api.app.portal_settings import get_aqua_preferred_registry
        preferred = get_aqua_preferred_registry()
        page = 1
        candidates: list[dict[str, Any]] = []
        while page <= 20:
            data = self._get(f"/api/v2/images?pagesize=100&page={page}")
            batch = data.get("result") or []
            if not batch:
                break
            for img in batch:
                if not isinstance(img, dict):
                    continue
                if (img.get("repository") or "").lower() != repo_lower:
                    continue
                if (img.get("tag") or "").lower() != tag_lower:
                    continue
                candidates.append(img)
            total = int(data.get("count") or 0)
            if page * 100 >= total:
                break
            page += 1

        if not candidates:
            return None

        def score(img: dict[str, Any]) -> tuple[int, str]:
            reg = str(img.get("registry") or "")
            pref = 1 if preferred and reg == preferred else 0
            scan = str(img.get("scan_date") or "")
            return (pref, scan)

        best = max(candidates, key=score)
        return AquaImageRef(
            registry=str(best.get("registry") or ""),
            repository=str(best.get("repository") or repository),
            tag=str(best.get("tag") or tag),
        )

    def fetch_all_resources(self, image: AquaImageRef) -> list[dict[str, str]]:
        reg = quote(image.registry, safe="")
        repo = quote(image.repository, safe="")
        tag = quote(image.tag, safe="")
        base = f"/api/v2/images/{reg}/{repo}/{tag}/resources"
        out: list[dict[str, str]] = []
        page = 1
        while page <= 50:
            data = self._get(f"{base}?pagesize=100&page={page}")
            batch = data.get("result") or []
            for res in batch:
                if not isinstance(res, dict):
                    continue
                name = str(res.get("name") or "").strip()
                if not name:
                    continue
                out.append(
                    {
                        "name": name,
                        "version": str(res.get("version") or "").strip() or None,
                        "fix_version": str(res.get("fix_version") or "").strip() or "",
                    }
                )
            total = int(data.get("count") or 0)
            if page * 100 >= total or not batch:
                break
            page += 1
        return out
