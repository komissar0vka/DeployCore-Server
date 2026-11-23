from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

AGENT_BODY_LIMIT = 2 * 1024 * 1024


class AgentBodyLimit:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not (scope["path"].startswith("/api/v1/agent/") or scope["path"] == "/api/v1/licenses/import"):
            await self.app(scope, receive, send)
            return

        limit = 24 * 1024 if scope["path"] == "/api/v1/licenses/import" else AGENT_BODY_LIMIT
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > limit:
                response = JSONResponse({"detail": "body_too_large"}, status_code=413,
                                        headers={"Cache-Control": "no-store"})
                await response(scope, receive, send)
                return
            body.extend(chunk)
            if not message.get("more_body"):
                break

        async def replay():
            nonlocal body
            if body is not None:
                message = {"type": "http.request", "body": bytes(body)}
                body = None
                return message
            return await receive()

        await self.app(scope, replay, send)
