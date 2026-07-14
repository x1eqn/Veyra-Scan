from __future__ import annotations

import datetime as dt
import io
import json

from xien_control.modrinth_verifier import ModrinthVerifier
from xien_control.models import LauncherLocation
from xien_control.scan_orchestrator import _modrinth_verified_result


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def test_modrinth_hash_match(monkeypatch, tmp_path):
    payload = {"project_id": "project-1", "id": "version-1", "name": "Release", "version_number": "1.2.3"}
    calls = []

    def fake_open(request, timeout):
        calls.append((request.full_url, timeout))
        return _Response(json.dumps(payload).encode("utf-8"))

    monkeypatch.setattr("urllib.request.urlopen", fake_open)
    verifier = ModrinthVerifier(enabled=True)
    modrinth_digest = "a" * 128
    match = verifier.lookup(modrinth_digest)
    assert match is not None
    assert match.project_id == "project-1"
    assert match.version_number == "1.2.3"
    assert verifier.lookup(modrinth_digest) is match
    assert len(calls) == 1

    jar = tmp_path / "example.jar"
    jar.write_bytes(b"jar")
    location = LauncherLocation("test", "instance", tmp_path, "test")
    result = _modrinth_verified_result(jar, location, "c" * 64, match)
    assert result.modrinth_verified is True
    assert result.verdict == "CLEAN"
    assert result.analysis_status == "SKIPPED_MODRINTH_VERIFIED"


def test_modrinth_can_be_disabled(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("network used")))
    assert ModrinthVerifier(enabled=False).lookup("b" * 128) is None
