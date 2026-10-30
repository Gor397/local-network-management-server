"""Process-wide limits for the single configured API process, without holding SQL connections."""

import asyncio
import secrets
import time
from fastapi import HTTPException


class TransferBudget:
    def __init__(self):
        self.lock = asyncio.Lock()
        self.active = {}
        self.next_slot = 0.0

    async def reserve(self, device_id, limit):
        async with self.lock:
            if len(self.active) >= limit or device_id in self.active.values():
                raise HTTPException(
                    429, "package.transfer_busy", headers={"Retry-After": "5"}
                )
            token = secrets.token_hex(16)
            self.active[token] = device_id
            return token

    async def release(self, token):
        async with self.lock:
            self.active.pop(token, None)

    async def throttle(self, count, rate):
        async with self.lock:
            now = time.monotonic()
            self.next_slot = max(now, self.next_slot) + count / max(65536, rate)
            delay = self.next_slot - now
        await asyncio.sleep(delay)
