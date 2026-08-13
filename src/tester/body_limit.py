"""Pure-ASGI request-body limit for the suite evaluation endpoint."""

from __future__ import annotations

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class EvaluateBodyLimitMiddleware:
    """Reject oversized evaluation bodies before FastAPI parses them."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_bytes: int,
        max_chunks: int,
    ) -> None:
        self.app = app
        self.max_bytes = max_bytes
        self.max_chunks = max_chunks

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if not self._applies(scope):
            await self.app(scope, receive, send)
            return

        content_length = self._content_length(scope)
        if content_length is not None and content_length > self.max_bytes:
            await self._send_too_large(scope, receive, send)
            return

        consumed = 0
        request_chunks = 0
        buffered: list[Message] = []
        while True:
            message = await receive()
            buffered.append(message)
            if message["type"] != "http.request":
                break
            request_chunks += 1
            consumed += len(message.get("body", b""))
            if consumed > self.max_bytes:
                await self._send_too_large(scope, receive, send)
                return
            if request_chunks > self.max_chunks:
                await self._send_too_many_chunks(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        buffered_index = 0

        async def replay_receive() -> Message:
            nonlocal buffered_index
            if buffered_index < len(buffered):
                message = buffered[buffered_index]
                buffered_index += 1
                return message
            return await receive()

        await self.app(scope, replay_receive, send)

    @staticmethod
    def _applies(scope: Scope) -> bool:
        return (
            scope["type"] == "http"
            and scope.get("method") == "POST"
            and scope.get("path") == "/v1/evaluate"
        )

    @staticmethod
    def _content_length(scope: Scope) -> int | None:
        for name, value in scope.get("headers", []):
            if name.lower() != b"content-length":
                continue
            try:
                return int(value)
            except ValueError:
                return None
        return None

    async def _send_too_large(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        response = JSONResponse(
            status_code=413,
            content={
                "detail": (
                    "request body exceeds "
                    f"{self.max_bytes} bytes"
                )
            },
        )
        await response(scope, receive, send)

    async def _send_too_many_chunks(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        response = JSONResponse(
            status_code=413,
            content={
                "detail": (
                    "request body exceeds "
                    f"{self.max_chunks} ASGI request chunks"
                )
            },
        )
        await response(scope, receive, send)
