from __future__ import annotations

import asyncio
from typing import Protocol

from argus_transport.security import Redactor


class Trap(Protocol):
    redactor: Redactor | None

    async def open(self, html_or_render) -> str: ...
    async def close(self, *, terminal: bool) -> dict: ...
    def public_url(self) -> str: ...


class LocalTrap:
    redactor = None

    def __init__(self, server, cleanup_s):
        self.server = server
        self.cleanup_s = cleanup_s
        self._opened = False
        self._url = ""
        self._evidence = None

    async def open(self, html_or_render) -> str:
        self._url = await self.server.start()
        self._opened = True
        return self._url

    async def close(self, *, terminal: bool) -> dict:
        if self._evidence is not None:
            return self._evidence
        try:
            if self._opened:
                try:
                    await asyncio.wait_for(self.server.settle(), timeout=self.cleanup_s)
                except TimeoutError:
                    pass
            self._evidence = self.server.evidence() if self._opened else {}
            return self._evidence
        finally:
            await self.server.stop()

    def public_url(self) -> str:
        return self._url
