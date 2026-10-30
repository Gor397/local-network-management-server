"""RouterOS API-SSL transport for legacy routers, plus an opt-in read-only plaintext API (port 8728).

API-SSL never falls back to anonymous TLS or plaintext. The plaintext adapter is a separate, explicitly
selected transport that sends the password unencrypted, so it can only read.
"""

import asyncio
import ssl
from urllib.parse import urlparse
from app.mikrotik.connector import RouterOS


LOG_READ_LIMIT = 2000


def encode_length(number):
    if number < 0x80:
        return bytes([number])
    if number < 0x4000:
        return (number | 0x8000).to_bytes(2, "big")
    if number < 0x200000:
        return (number | 0xC00000).to_bytes(3, "big")
    if number < 0x10000000:
        return (number | 0xE0000000).to_bytes(4, "big")
    return b"\xf0" + number.to_bytes(4, "big")


class NativeRouterOS(RouterOS):
    def __init__(self, base_url, username, password, ca_file=None):
        url = urlparse(base_url)
        self.host, self.port = url.hostname, url.port or 8729
        self.username, self.password = username, password
        self.context = ssl.create_default_context(cafile=ca_file)

    async def __aenter__(self):
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(
                self.host,
                self.port,
                ssl=self.context,
                server_hostname=self.host if self.context else None,
            ),
            10,
        )
        try:
            await self.sentence(
                ["/login", "=name=" + self.username, "=password=" + self.password]
            )
        except BaseException:
            self.writer.close()
            await self.writer.wait_closed()
            raise
        return self

    async def __aexit__(self, *args):
        self.writer.close()
        await self.writer.wait_closed()

    async def word(self):
        first = (await self.reader.readexactly(1))[0]
        if first < 0x80:
            length = first
        elif first < 0xC0:
            length = ((first & 0x3F) << 8) | (await self.reader.readexactly(1))[0]
        elif first < 0xE0:
            length = ((first & 0x1F) << 16) | int.from_bytes(
                await self.reader.readexactly(2), "big"
            )
        elif first < 0xF0:
            length = ((first & 0xF) << 24) | int.from_bytes(
                await self.reader.readexactly(3), "big"
            )
        elif first == 0xF0:
            length = int.from_bytes(await self.reader.readexactly(4), "big")
        else:
            raise ValueError("router.invalid_api_word")
        if length > 4 * 1024**2:
            raise ValueError("router.response_limit")
        # RouterOS 6 stores some values (e.g. DHCP host names) in legacy encodings; never fail on them.
        return (await self.reader.readexactly(length)).decode(errors="backslashreplace")

    async def sentence(self, words):
        for word in words:
            encoded = word.encode()
            self.writer.write(encode_length(len(encoded)) + encoded)
        self.writer.write(b"\0")
        await self.writer.drain()
        rows, failure, received = [], None, 0
        for _ in range(10000):
            values = []
            while True:
                value = await asyncio.wait_for(self.word(), 15)
                if not value:
                    break
                received += len(value.encode())
                if received > 8 * 1024**2 or len(values) >= 256:
                    raise ValueError("router.response_limit")
                values.append(value)
            if not values:
                continue
            properties = dict(
                v[1:].split("=", 1)
                for v in values[1:]
                if v.startswith("=") and "=" in v[1:]
            )
            if values[0] in ("!trap", "!fatal"):
                failure = properties.get("message", "router.api_error")
                if values[0] == "!fatal":
                    raise ConnectionError(failure)
            elif values[0] == "!re":
                rows.append(properties)
            elif values[0] == "!done":
                if failure:
                    raise ValueError(failure)
                return rows or properties
        raise ValueError("router.response_limit")

    async def read(self, path, optional=False, properties=None):
        if path == "log":
            # Routers may keep 100k+ memory log lines and the API cannot return only the tail.
            # Count first and skip a large log instead of streaming megabytes on every poll.
            count = await self.sentence(["/log/print", "=count-only="])
            if int(count.get("ret", 0) if isinstance(count, dict) else 0) > LOG_READ_LIMIT:
                return []
        try:
            result = await self.sentence(
                ["/" + path + "/print"]
                + (["=.proplist=" + properties] if properties else [])
            )
            return result if isinstance(result, list) else ([result] if result else [])
        except ValueError as exc:
            if optional and "no such command" in str(exc):
                return None
            raise

    async def command(self, path, data=None):
        if path not in {
            "system/reboot",
            "system/backup/save",
            "system/backup/load",
            "ping",
            "interface/monitor-traffic",
            "file/read",
        }:
            raise ValueError("network.operation_not_allowed")
        return await self.sentence(
            ["/" + path] + [f"={k}={v}" for k, v in (data or {}).items()]
        )

    async def configure(self, path, record_id, data):
        if path not in {
            "interface/wifi",
            "interface/wireless",
            "caps-man/interface",
            "system/identity",
        }:
            raise ValueError("network.operation_not_allowed")
        return await self.sentence(
            ["/" + path + "/set"]
            + ([] if path == "system/identity" else ["=.id=" + record_id])
            + [f"={k}={v}" for k, v in data.items()]
        )

    async def apply(self, operation):
        from app.mikrotik.connector import STACKS

        if operation["path"] not in {
            "ip/dhcp-server/lease",
            "ip/firewall/address-list",
            "ip/firewall/filter",
            "ipv6/firewall/filter",
        } | {s[1] for s in STACKS.values()} | {s[2] for s in STACKS.values()}:
            raise ValueError("network.operation_not_allowed")
        verb = {"PUT": "add", "PATCH": "set", "DELETE": "remove"}[operation["method"]]
        args = ["/" + operation["path"] + "/" + verb]
        if operation.get("id"):
            args.append("=.id=" + operation["id"])
        return await self.sentence(
            args + [f"={k}={v}" for k, v in operation.get("data", {}).items()]
        )


class PlainRouterOS(NativeRouterOS):
    """Unencrypted RouterOS API for routers without an API-SSL certificate. Read-only by construction."""

    READ_COMMANDS = frozenset({"ping", "interface/monitor-traffic"})

    def __init__(self, base_url, username, password, ca_file=None):
        url = urlparse(base_url)
        self.host, self.port = url.hostname, url.port or 8728
        self.username, self.password = username, password
        self.context = None  # asyncio.open_connection(ssl=None) is a plain TCP connection

    async def command(self, path, data=None):
        if path not in self.READ_COMMANDS:
            raise ValueError("network.plaintext_read_only")
        return await super().command(path, data)

    async def configure(self, path, record_id, data):
        raise ValueError("network.plaintext_read_only")

    async def apply(self, operation):
        raise ValueError("network.plaintext_read_only")
