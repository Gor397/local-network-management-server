"""Opt-in plaintext RouterOS API: reads work over plain TCP, writes are impossible, registration is gated."""
import asyncio
import json
from types import SimpleNamespace
import pytest
from app.mikrotik.native import PlainRouterOS, encode_length
from app.models import Router
from app.services.safety import router_write_block
from app.services.inventory import access_points
from app.config import Settings


async def fake_router(rows):
    """Minimal RouterOS API server on loopback: accepts /login, answers /print, records every sentence."""
    seen = []

    async def read_word(reader):
        first = (await reader.readexactly(1))[0]
        return (await reader.readexactly(first)).decode(errors="replace")  # test words are < 128 bytes

    async def handle(reader, writer):
        def send(*words):
            for w in words:
                writer.write(encode_length(len(w.encode())) + w.encode())
            writer.write(b"\0")
        try:
            while True:
                sentence = []
                while (word := await read_word(reader)):
                    sentence.append(word)
                seen.append(sentence)
                if "=count-only=" in sentence:
                    send("!done", "=ret=100001")
                elif sentence[0].endswith("/print"):
                    for row in rows.get(sentence[0][1:-6], []):
                        send("!re", *[f"={k}={v}" for k, v in row.items()])
                    if sentence[0] == "/ip/dhcp-server/lease/print":  # legacy-encoded host name (cp1251 bytes)
                        raw = b"=host-name=\xcf\xca-01"
                        writer.write(encode_length(3) + b"!re" + encode_length(len(raw)) + raw + b"\0")
                send("!done")
                await writer.drain()
        except asyncio.IncompleteReadError:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, seen


async def test_plain_api_reads_without_tls_and_never_writes():
    server, seen = await fake_router({"caps-man/remote-cap": [{".id": "*1", "identity": "AP-Hall", "address": "4C:5E:0C:11:22:33/1"}]})
    port = server.sockets[0].getsockname()[1]
    async with PlainRouterOS(f"https://127.0.0.1:{port}", "reader", "secret") as api:
        assert (await api.read("caps-man/remote-cap"))[0]["identity"] == "AP-Hall"
        assert (await api.read("ip/dhcp-server/lease"))[0]["host-name"] == "\\xcf\\xca-01"
        assert await api.read("log", optional=True) == []  # 100001 lines: skipped, never streamed
        for call in (api.apply({"path": "caps-man/access-list", "method": "DELETE", "id": "*1"}),
                     api.configure("caps-man/interface", "*1", {}), api.command("system/reboot")):
            with pytest.raises(ValueError, match="plaintext_read_only"):
                await call
    server.close()
    assert [s[0] for s in seen] == ["/login", "/caps-man/remote-cap/print", "/ip/dhcp-server/lease/print", "/log/print"]


def test_plaintext_transport_is_never_writable_even_in_production():
    router = SimpleNamespace(id="r", name="ctl", base_url="https://192.168.0.1:8728", archived=False, write_enabled=True, transport="API")
    assert router_write_block(Settings(encryption_key="x", operation_mode="production"), router) == "network.plaintext_read_only"


def test_registration_requires_opt_in_and_rejects_network_address(admin, app):
    body = {"name": "Controller", "base_url": "https://192.168.0.1:8728", "username": "reader", "password": "x", "transport": "API"}
    assert admin.post("/api/v1/mikrotik/routers", json=body).json()["error"]["code"] == "network.plaintext_api_disabled"
    app.state.settings.router_plaintext_api_allowed = True
    assert admin.post("/api/v1/mikrotik/routers", json=body).status_code == 201
    wrong = {**body, "base_url": "https://192.168.0.0:8728"}
    assert admin.post("/api/v1/mikrotik/routers", json=wrong).json()["error"]["code"] == "network.network_address"


def test_capsman_access_points_are_listed_from_stored_snapshot():
    controller = SimpleNamespace(name="ctl")
    snapshot = {"caps-man/remote-cap": [{"identity": "AP-Hall", "address": "4C:5E:0C:11:22:33/1", "board": "cAP ac", "state": "Run"}]}
    assert access_points([(controller, snapshot)]) == [{"controller": "ctl", "identity": "AP-Hall", "address": "4C:5E:0C:11:22:33/1",
        "mac": "4C:5E:0C:11:22:33", "board": "cAP ac", "version": None, "serial": None, "state": "Run", "radios": None}]
