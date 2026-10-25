"""Regression tests for encrypted speech-provider token requests.

These tests exercise the token-signing methods independently of optional speech
and model dependencies so they also run in the lightweight CI environment.
"""
import ast
import base64
import hashlib
import hmac
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from urllib import parse

import pytest


ROOT = Path(__file__).resolve().parents[1]
TOKEN_PROVIDERS = [
    ("core/providers/asr/aliyun.py", False),
    ("core/providers/asr/aliyun_stream.py", False),
    ("core/providers/tts/aliyun.py", True),
    ("core/providers/tts/aliyun_stream.py", True),
]


@pytest.mark.parametrize("relative_path,takes_timeout", TOKEN_PROVIDERS)
def test_access_token_calls_use_https_and_timeout(monkeypatch, relative_path, takes_timeout):
    """Call the actual token implementation with a fake HTTP transport."""
    path = ROOT / relative_path
    source = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    token_class = next(
        item for item in source.body
        if isinstance(item, ast.ClassDef) and item.name == "AccessToken"
    )
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return SimpleNamespace(
            ok=True, json=lambda: {"Token": {"Id": "test-token", "ExpireTime": 12345}}
        )

    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(get=fake_get))
    namespace = {
        "parse": parse, "uuid": uuid, "time": time, "hmac": hmac,
        "base64": base64, "hashlib": hashlib,
        "requests": SimpleNamespace(get=fake_get),
    }
    module = ast.fix_missing_locations(ast.Module(body=[token_class], type_ignores=[]))
    exec(compile(module, str(path), "exec"), namespace)
    args = ("test-access-key", "test-secret", 10) if takes_timeout else (
        "test-access-key", "test-secret"
    )
    token, expiry = namespace["AccessToken"].create_token(*args)

    assert (token, expiry) == ("test-token", 12345)
    assert len(calls) == 1
    url, options = calls[0]
    assert url.startswith("https://nls-meta.cn-shanghai.aliyuncs.com/")
    assert "AccessKeyId=test-access-key" in url
    assert options.get("timeout", 0) > 0


def test_ragflow_client_does_not_disable_certificate_verification():
    """The RAGFlow API client must keep HTTPX's secure TLS defaults."""
    path = ROOT / "plugins_func/functions/search_from_ragflow.py"
    source = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    client_calls = [
        node for node in ast.walk(source)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "AsyncClient"
    ]
    assert client_calls
    for call in client_calls:
        for keyword in call.keywords:
            if keyword.arg == "verify":
                assert isinstance(keyword.value, ast.Constant)
                assert keyword.value.value is True
