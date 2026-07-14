from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


MODRINTH_VERSION_FILE_URL = "https://api.modrinth.com/v2/version_file/{digest}?algorithm=sha512"
USER_AGENT = "Xien-Control/1.0 (local mod hash verification)"


@dataclass(frozen=True)
class ModrinthMatch:
    project_id: str
    version_id: str
    version_name: str
    version_number: str
    project_url: str


class ModrinthVerifier:
    """Resolve SHA-512 hashes through Modrinth without uploading file contents."""

    def __init__(self, timeout: float = 4.0, enabled: bool | None = None):
        self.timeout = timeout
        self.enabled = _env_enabled() if enabled is None else enabled
        self.unavailable = False
        self._cache: dict[str, ModrinthMatch | None] = {}

    def lookup(self, sha512: str) -> ModrinthMatch | None:
        digest = sha512.strip().lower()
        if not self.enabled or self.unavailable or len(digest) != 128:
            return None
        if digest in self._cache:
            return self._cache[digest]

        url = MODRINTH_VERSION_FILE_URL.format(digest=urllib.parse.quote(digest, safe=""))
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                self._cache[digest] = None
                return None
            self.unavailable = True
            return None
        except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            self.unavailable = True
            return None

        project_id = str(payload.get("project_id") or "")
        version_id = str(payload.get("id") or "")
        if not project_id or not version_id:
            self._cache[digest] = None
            return None
        match = ModrinthMatch(
            project_id=project_id,
            version_id=version_id,
            version_name=str(payload.get("name") or ""),
            version_number=str(payload.get("version_number") or ""),
            project_url=f"https://modrinth.com/project/{project_id}",
        )
        self._cache[digest] = match
        return match


def _env_enabled() -> bool:
    return os.environ.get("XIEN_CONTROL_MODRINTH_VERIFY", "1").strip().lower() not in {"0", "false", "no", "off"}
