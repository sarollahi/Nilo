"""Security regression coverage for the remote FunASR WebSocket transport."""
import ast
import ssl
from pathlib import Path
from types import SimpleNamespace


def _provider_class():
    source = Path(__file__).resolve().parents[1] / "core/providers/asr/fun_server.py"
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    original = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ASRProvider")
    constructor = next(node for node in original.body if isinstance(node, ast.FunctionDef) and node.name == "__init__")
    isolated = ast.ClassDef(
        name="ASRProvider",
        bases=[ast.Name(id="ASRProviderBase", ctx=ast.Load())],
        keywords=[],
        body=[constructor],
        decorator_list=[],
    )
    context = {
        "ASRProviderBase": type("ASRProviderBase", (), {}),
        "InterfaceType": SimpleNamespace(NON_STREAM="non_stream"),
        "ssl": ssl,
    }
    code = ast.fix_missing_locations(ast.Module(body=[isolated], type_ignores=[]))
    exec(compile(code, str(source), "exec"), context)
    return context["ASRProvider"]


def test_secure_websocket_checks_certificate_and_hostname():
    provider = _provider_class()({"host": "speech.example", "is_ssl": True}, False)
    assert provider.uri == "wss://speech.example:10095"
    assert provider.ssl_context.verify_mode == ssl.CERT_REQUIRED
    assert provider.ssl_context.check_hostname is True


def test_non_tls_websocket_does_not_require_ssl_context():
    provider = _provider_class()({"host": "localhost", "is_ssl": False}, False)
    assert provider.uri == "ws://localhost:10095"
    assert provider.ssl_context is None
