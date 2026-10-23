"""Entry point: the app over HTTPS, plus a plain-HTTP listener that only redirects.

The HTTP listener also serves /healthz (for the container healthcheck) and the
Let's Encrypt HTTP-01 challenge files. With TLS_ENABLED=false (e.g. behind a
reverse proxy that terminates TLS) the app itself is served over plain HTTP.
"""
import asyncio
import contextlib
import logging
import re

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse
from starlette.routing import Route

from . import acme, config, tls, vault

log = logging.getLogger("server")


async def _health(request: Request):
    return JSONResponse({"ok": True})


async def _challenge(request: Request):
    token = request.path_params["token"]
    path = acme.WEBROOT / ".well-known" / "acme-challenge" / token
    if not re.fullmatch(r"[A-Za-z0-9_-]+", token) or not path.is_file():
        return PlainTextResponse("not found", status_code=404)
    return FileResponse(path, media_type="text/plain")


async def _redirect(request: Request):
    host = request.url.hostname or "localhost"
    port = "" if config.HTTPS_PUBLIC_PORT == 443 else f":{config.HTTPS_PUBLIC_PORT}"
    query = f"?{request.url.query}" if request.url.query else ""
    return RedirectResponse(f"https://{host}{port}{request.url.path}{query}", status_code=308)


redirect_app = Starlette(
    routes=[
        Route("/healthz", _health),
        Route("/.well-known/acme-challenge/{token}", _challenge),
        Route("/{path:path}", _redirect, methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]),
    ]
)


class _SecondaryServer(uvicorn.Server):
    """Leaves signal handling to the main server, which stops this one on exit."""

    @contextlib.contextmanager
    def capture_signals(self):
        yield


def _uvicorn_config(app, port: int, **kw) -> uvicorn.Config:
    return uvicorn.Config(
        app, host="0.0.0.0", port=port, proxy_headers=True, server_header=False, log_level="info", **kw
    )


async def main() -> None:
    if not config.TLS_ENABLED:
        await uvicorn.Server(_uvicorn_config("app.main:app", config.HTTP_PORT)).serve()
        return

    config.validate()
    vault.get()
    tls.ensure_certificate()
    https = _uvicorn_config("app.main:app", config.HTTPS_PORT)
    https.load()
    https.ssl = tls.server_context()  # shared context: certificate changes apply without restart
    http = _uvicorn_config(redirect_app, config.HTTP_PORT, lifespan="off")

    secondary = _SecondaryServer(http)
    http_task = asyncio.create_task(secondary.serve())
    renew_task = asyncio.create_task(acme.renew_loop())
    log.info("HTTPS on :%d, HTTP redirect on :%d", config.HTTPS_PORT, config.HTTP_PORT)
    try:
        await uvicorn.Server(https).serve()
    finally:
        secondary.should_exit = True
        renew_task.cancel()
        await http_task


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    asyncio.run(main())
