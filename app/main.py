import asyncio
import logging
import re
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import acme, auth, config, oidc, patches, scanner, sources, store, tls, vault

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
config.validate()

BASE = Path(__file__).parent
MAX_UPLOAD = 1024 * 1024
UPLOAD_KINDS = {"talosconfig": "talosconfig", "controlplane": "controlplane.yaml", "worker": "worker.yaml"}
STATUSES = ("in-sync", "drift", "unreachable", "patch-error", "no-baseline")


@asynccontextmanager
async def lifespan(app: FastAPI):
    vault.get()
    store.migrate_legacy()
    task = asyncio.create_task(scanner.loop())
    yield
    task.cancel()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    SessionMiddleware,
    secret_key=auth.session_secret(),
    session_cookie="talos_config_manager_session",
    max_age=12 * 3600,
    # "lax" so the cookie survives the redirect back from the OIDC provider;
    # state-changing requests are protected by CSRF tokens.
    same_site="lax",
    https_only=config.COOKIE_SECURE,
)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    if request.url.scheme == "https" and tls.hsts_allowed(request.url.hostname):
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


@app.exception_handler(auth.LoginRequired)
async def _login_redirect(request: Request, exc):
    return RedirectResponse("/login", status_code=303)


def render(request: Request, name: str, cluster: dict | None = None, **ctx):
    running = scanner.is_running(cluster["id"]) if cluster else bool(scanner.running())
    return templates.TemplateResponse(
        request,
        name,
        {
            "csrf": request.session.get("csrf", ""),
            "user_name": request.session.get("name"),
            "running": running,
            "cluster": cluster,
            "clusters": store.clusters() if auth.is_logged_in(request) else [],
            **ctx,
        },
    )


def cluster_or_404(cid: str) -> dict:
    cluster = store.get_cluster(cid)
    if not cluster:
        raise HTTPException(404, "Cluster not found")
    return cluster


def _summary(nodes: list[dict]) -> dict:
    out = {}
    for role in ("controlplane", "worker"):
        group = [n for n in nodes if n.get("role") == role]
        out[role] = {"total": len(group), **{s.replace("-", "_"): sum(n["status"] == s for n in group) for s in STATUSES}}
    return out


def _health(scan: dict | None, missing: list[str]) -> str:
    """Overall status of a cluster, worst first."""
    if missing or not scan:
        return "setup"
    if scan.get("error") or not scan["nodes"]:
        return "error"
    statuses = {n["status"] for n in scan["nodes"]}
    if statuses & {"unreachable", "patch-error"}:
        return "error"
    if statuses & {"drift", "no-baseline"}:
        return "drift"
    return "in-sync"


def _missing(cid: str) -> list[str]:
    return [label for kind, label in UPLOAD_KINDS.items() if not sources.exists(cid, kind)]


def _back(cid: str, anchor: str = "", **params) -> RedirectResponse:
    return RedirectResponse(f"/settings/{cid}?{urlencode(params)}{anchor}", status_code=303)


def _public_node(n: dict) -> dict:
    return {k: v for k, v in n.items() if k not in ("diff", "changes", "ignored", "config")}


# --- auth ----------------------------------------------------------------


@app.get("/healthz")
async def healthz():
    return {"ok": True}


def _login(request: Request, error: str | None = None, status_code: int = 200):
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "csrf": "",
            "error": error,
            "password_enabled": config.PASSWORD_ENABLED,
            "oidc_enabled": config.OIDC_ENABLED,
            "provider": config.OIDC_PROVIDER_NAME,
        },
        status_code=status_code,
    )


@app.get("/login")
async def login_page(request: Request):
    if auth.is_logged_in(request):
        return RedirectResponse("/", status_code=303)
    return _login(request)


@app.post("/login")
async def login(request: Request, password: str = Form(...)):
    if not config.PASSWORD_ENABLED:
        raise HTTPException(404)
    if auth.rate_limited(request):
        return _login(request, "Too many attempts, try again in a few minutes.", 429)
    if not auth.check_password(request, password):
        return _login(request, "Incorrect password.", 401)
    return RedirectResponse("/", status_code=303)


@app.get("/auth/login")
async def oidc_login(request: Request):
    if not config.OIDC_ENABLED:
        raise HTTPException(404)
    try:
        return await oidc.login_redirect(request)
    except Exception:
        logging.getLogger("oidc").exception("cannot reach OIDC provider")
        return _login(request, f"{config.OIDC_PROVIDER_NAME} is unreachable.", 502)


@app.get("/auth/callback", name="oidc_callback")
async def oidc_callback(request: Request):
    if not config.OIDC_ENABLED:
        raise HTTPException(404)
    try:
        user, name, id_token = await oidc.handle_callback(request)
    except oidc.AccessDenied as e:
        return _login(request, f"{e} has no access to this app (required role or group missing).", 403)
    except oidc.OAuthError as e:
        logging.getLogger("oidc").warning("OIDC login failed: %s", e)
        return _login(request, f"Login via {config.OIDC_PROVIDER_NAME} failed. Please try again.", 400)
    auth.start_session(request, user, name, "oidc")
    # Only kept as logout hint; a small JWT, and the session cookie is signed.
    if id_token and len(id_token) < 2500:
        request.session["id_token"] = id_token
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
async def logout(request: Request):
    method = request.session.get("method")
    id_token = request.session.get("id_token")
    request.session.clear()
    if method == "oidc" and config.OIDC_ENABLED:
        url = await oidc.logout_url(request, id_token)
        if url:
            return RedirectResponse(url, status_code=303)
    return RedirectResponse("/login", status_code=303)


# --- overview & clusters -------------------------------------------------


@app.get("/", dependencies=[Depends(auth.require_login)])
async def overview(request: Request):
    cards = []
    for c in store.clusters():
        scan = store.latest(c["id"])
        nodes = scan["nodes"] if scan else []
        missing = _missing(c["id"])
        cards.append(
            {
                **c,
                "scan": scan,
                "nodes": nodes,
                "summary": _summary(nodes),
                "missing": missing,
                "health": _health(scan, missing),
                "running": scanner.is_running(c["id"]),
            }
        )
    totals = {s.replace("-", "_"): sum(n["status"] == s for c in cards for n in c["nodes"]) for s in STATUSES}
    totals["nodes"] = sum(len(c["nodes"]) for c in cards)
    totals["healthy_clusters"] = sum(c["health"] == "in-sync" for c in cards)
    return render(request, "overview.html", cards=cards, totals=totals)


@app.get("/settings", dependencies=[Depends(auth.require_login)])
async def settings_home(request: Request, new: bool = False):
    """Settings start page: the first cluster, or the form for a new one."""
    cs = store.clusters()
    if cs and not new:
        return RedirectResponse(f"/settings/{cs[0]['id']}", status_code=303)
    return render(request, "settings_new.html")


# --- HTTPS certificate (defined before /settings/{cid}) ---------------------


def _https_back(**params) -> RedirectResponse:
    return RedirectResponse(f"/settings/https?{urlencode(params)}", status_code=303)


@app.get("/settings/https", dependencies=[Depends(auth.require_login)])
async def https_page(request: Request, msg: str | None = None, err: str | None = None):
    info = tls.meta() if config.TLS_ENABLED else None
    return render(
        request,
        "settings_https.html",
        page="https",
        tls_enabled=config.TLS_ENABLED,
        cert=info,
        days_left=tls.days_left(info) if info else None,
        acme=acme.settings(),
        acme_status=acme.status(),
        acme_running=acme.is_running(),
        default_names=tls.default_names(),
        msg=msg,
        err=err,
    )


@app.post("/settings/https/selfsigned", dependencies=[Depends(auth.require_login)])
async def https_selfsigned(request: Request, names: str = Form(...), csrf: str = Form(...)):
    auth.check_csrf(request, csrf)
    wanted = [n.strip() for n in names.replace(",", "\n").splitlines() if n.strip()]
    if not wanted:
        return _https_back(err="Enter at least one hostname or IP address.")
    fullchain, key_pem, chain = tls.self_signed(wanted)
    tls.install(fullchain, key_pem, tls.describe(chain, "selfsigned"))
    return _https_back(msg="New self-signed certificate active.")


async def _pem_field(upload: UploadFile | None, text: str) -> bytes:
    if upload is not None and upload.filename:
        return await upload.read(MAX_UPLOAD)
    return text.encode()


@app.post("/settings/https/upload", dependencies=[Depends(auth.require_login)])
async def https_upload(
    request: Request,
    csrf: str = Form(...),
    cert_file: UploadFile | None = File(None),
    cert_text: str = Form(""),
    key_file: UploadFile | None = File(None),
    key_text: str = Form(""),
    chain_file: UploadFile | None = File(None),
    chain_text: str = Form(""),
    passphrase: str = Form(""),
):
    auth.check_csrf(request, csrf)
    cert_pem = await _pem_field(cert_file, cert_text)
    key_pem = await _pem_field(key_file, key_text)
    chain_pem = await _pem_field(chain_file, chain_text)
    if not cert_pem.strip() or not key_pem.strip():
        return _https_back(err="Certificate and private key are required.")
    try:
        fullchain, key_out, chain = tls.prepare(cert_pem, key_pem, chain_pem, passphrase or None)
        tls.install(fullchain, key_out, tls.describe(chain, "upload"))
    except tls.CertError as e:
        return _https_back(err=str(e))
    return _https_back(msg=f"Certificate for {tls.meta()['subject']} active.")


@app.post("/settings/https/acme", dependencies=[Depends(auth.require_login)])
async def https_acme(
    request: Request,
    csrf: str = Form(...),
    domains: str = Form(""),
    email: str = Form(""),
    challenge: str = Form("http"),
    dns_provider: str = Form(""),
    dns_env: str = Form(""),
    dns_file: str = Form(""),
    staging: bool = Form(False),
    action: str = Form("request"),
):
    auth.check_csrf(request, csrf)
    s = acme.settings()
    s.update(
        domains=[d.strip().lower() for d in domains.replace(",", "\n").splitlines() if d.strip()],
        email=email.strip(),
        challenge="dns" if challenge == "dns" else "http",
        dns_provider=dns_provider.strip().lower(),
        dns_env=dns_env,
        staging=staging,
    )
    if dns_file.strip():  # keep the stored credential file unless a new one is pasted
        s["dns_file"] = dns_file
    error = acme.validate(s)
    if error:
        return _https_back(err=error)
    acme.save_settings(s)
    if action == "save":
        return _https_back(msg="Let's Encrypt settings saved.")
    if acme.is_running():
        return _https_back(err="A request is already running.")
    asyncio.create_task(acme.obtain(force=action == "force"))
    return _https_back(msg="Let's Encrypt request started; this can take a few minutes.")


@app.get("/api/acme/status", dependencies=[Depends(auth.require_login)])
async def api_acme_status():
    return {"running": acme.is_running(), **acme.status()}


@app.get("/api/acme/dnshelp", dependencies=[Depends(auth.require_login)])
async def api_acme_dnshelp(provider: str = ""):
    return {"help": await acme.dns_help(provider)}


@app.post("/settings/new", dependencies=[Depends(auth.require_login)])
async def create_cluster(request: Request, name: str = Form(...), csrf: str = Form(...)):
    auth.check_csrf(request, csrf)
    name = name.strip()[:60]
    if not name:
        return RedirectResponse("/settings?new=1", status_code=303)
    cluster = store.add_cluster(name)
    return _back(cluster["id"], msg=f"Cluster {name} created. Choose a base folder and link the files.")


@app.post("/settings/{cid}/rename", dependencies=[Depends(auth.require_login)])
async def rename_cluster(request: Request, cid: str, name: str = Form(...), csrf: str = Form(...)):
    auth.check_csrf(request, csrf)
    cluster_or_404(cid)
    if name.strip():
        store.rename_cluster(cid, name.strip()[:60])
    return _back(cid, msg="Name saved")


@app.post("/settings/{cid}/delete", dependencies=[Depends(auth.require_login)])
async def delete_cluster(request: Request, cid: str, csrf: str = Form(...)):
    auth.check_csrf(request, csrf)
    cluster_or_404(cid)
    store.delete_cluster(cid)
    return RedirectResponse("/", status_code=303)


# --- cluster pages -------------------------------------------------------


@app.get("/c/{cid}", dependencies=[Depends(auth.require_login)])
async def dashboard(request: Request, cid: str):
    cluster = cluster_or_404(cid)
    scan = store.latest(cid)
    nodes = scan["nodes"] if scan else []
    return render(
        request,
        "dashboard.html",
        cluster=cluster,
        scan=scan,
        summary=_summary(nodes),
        controlplanes=[n for n in nodes if n.get("role") == "controlplane"],
        workers=[n for n in nodes if n.get("role") == "worker"],
        others=[n for n in nodes if n.get("role") not in ("controlplane", "worker")],
        missing=_missing(cid),
    )


def _latest_node(cid: str, address: str) -> tuple[dict | None, dict]:
    scan = store.latest(cid)
    node = next((n for n in (scan or {}).get("nodes", []) if n["address"] == address), None)
    if not node:
        raise HTTPException(404, "Node not found in latest scan")
    return scan, node


@app.get("/c/{cid}/node/{address}", dependencies=[Depends(auth.require_login)])
async def node_detail(request: Request, cid: str, address: str):
    cluster = cluster_or_404(cid)
    scan, node = _latest_node(cid, address)
    return render(request, "node.html", cluster=cluster, node=node, scan=scan)


@app.get("/c/{cid}/node/{address}/config.yaml", dependencies=[Depends(auth.require_login)])
async def node_config(cid: str, address: str):
    cluster_or_404(cid)
    _, node = _latest_node(cid, address)
    if not node.get("config"):
        raise HTTPException(404, "No config for this node in the latest scan")
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", node.get("hostname") or address)
    return PlainTextResponse(
        node["config"],
        media_type="application/yaml",
        headers={"Content-Disposition": f'attachment; filename="{name}.yaml"'},
    )


@app.get("/settings/{cid}", dependencies=[Depends(auth.require_login)])
async def settings_page(request: Request, cid: str, msg: str | None = None, err: str | None = None):
    cluster = cluster_or_404(cid)
    files = {kind: {"label": label, "info": sources.info(cid, kind)} for kind, label in UPLOAD_KINDS.items()}
    scan = store.latest(cid)
    known = sorted({n["hostname"] for n in (scan or {}).get("nodes", [])})
    host_files = sources.list_files(cid)
    linked_patches = patches.linked_paths(cid)
    return render(
        request,
        "settings.html",
        cluster=cluster,
        files=files,
        settings=store.settings(cid),
        patches=[patches.describe(cid, p) for p in patches.all_patches(cid)],
        known_nodes=known,
        config_dir=sources.available(),
        base_dir=sources.base_dir(cid),
        base_ok=sources.base_path(cid) is not None,
        host_files=host_files,
        patch_candidates=[f for f in host_files if f not in linked_patches],
        msg=msg,
        err=err,
    )


@app.post("/settings/{cid}/upload/{kind}", dependencies=[Depends(auth.require_login)])
async def upload(request: Request, cid: str, kind: str, file: UploadFile = File(...), csrf: str = Form(...)):
    auth.check_csrf(request, csrf)
    cluster_or_404(cid)
    if kind not in UPLOAD_KINDS:
        raise HTTPException(404)
    data = await file.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        return _back(cid, err="File too large (max 1 MB)")
    error = scanner.validate_upload(kind, data)
    if error:
        return _back(cid, err=error)
    sources.save_upload(cid, kind, data)
    del data
    scanner.request(cid)
    return _back(cid, msg=f"{UPLOAD_KINDS[kind]} stored encrypted")


@app.post("/settings/{cid}/base_dir", dependencies=[Depends(auth.require_login)])
async def set_base_dir(request: Request, cid: str, path: str = Form(""), csrf: str = Form(...)):
    auth.check_csrf(request, csrf)
    cluster_or_404(cid)
    try:
        sources.list_dirs(path)
    except sources.SourceError as e:
        return _back(cid, err=str(e))
    sources.set_base_dir(cid, path)
    scanner.request(cid)
    return _back(cid, msg=f"Base folder set to ~/{sources.base_dir(cid).lstrip('.')}")


@app.post("/settings/{cid}/link/{kind}", dependencies=[Depends(auth.require_login)])
async def link_file(request: Request, cid: str, kind: str, path: str = Form(...), csrf: str = Form(...)):
    auth.check_csrf(request, csrf)
    cluster_or_404(cid)
    if kind not in UPLOAD_KINDS:
        raise HTTPException(404)
    try:
        data = sources.read(cid, path)
    except sources.SourceError as e:
        return _back(cid, err=str(e))
    error = scanner.validate_upload(kind, data)
    if error:
        return _back(cid, err=f"{path}: {error}")
    sources.remove(cid, kind)  # the linked file replaces any earlier upload
    sources.link(cid, kind, path)
    scanner.request(cid)
    return _back(cid, msg=f"{UPLOAD_KINDS[kind]} linked to {path}")


@app.post("/settings/{cid}/delete/{kind}", dependencies=[Depends(auth.require_login)])
async def delete_file(request: Request, cid: str, kind: str, csrf: str = Form(...)):
    auth.check_csrf(request, csrf)
    cluster_or_404(cid)
    if kind not in UPLOAD_KINDS:
        raise HTTPException(404)
    sources.remove(cid, kind)
    return _back(cid, msg=f"{UPLOAD_KINDS[kind]} removed")


def _target(target: str, node_name: str) -> str:
    return f"node:{node_name.strip()}" if target == "node" else target


def _node_role(cid: str, target: str) -> str | None:
    """Role of the node a patch targets, from the latest scan."""
    if not target.startswith("node:"):
        return None
    wanted = target.removeprefix("node:")
    scan = store.latest(cid)
    return next((n.get("role") for n in (scan or {}).get("nodes", []) if wanted in (n["hostname"], n["address"])), None)


@app.post("/settings/{cid}/patches/upload", dependencies=[Depends(auth.require_login)])
async def upload_patches(
    request: Request,
    cid: str,
    files: list[UploadFile] = File(...),
    target: str = Form("all"),
    node_name: str = Form(""),
    csrf: str = Form(...),
):
    auth.check_csrf(request, csrf)
    cluster_or_404(cid)
    target = _target(target, node_name)
    if not patches.valid_target(target):
        return _back(cid, "#patches", err="Choose a valid target (for a specific node: enter the hostname or IP).")
    node_role = _node_role(cid, target)
    added = []
    for f in files:
        data = await f.read(MAX_UPLOAD + 1)
        name = Path(f.filename or "patch.yaml").name
        if len(data) > MAX_UPLOAD:
            return _back(cid, "#patches", err=f"{name}: file too large (max 1 MB)")
        error = patches.check_yaml(data) or await patches.try_apply(cid, data, target, node_role)
        if error:
            return _back(cid, "#patches", err=f"{name}: {error}")
        patches.add(cid, name, data, target)
        added.append(name)
    scanner.request(cid)
    return _back(cid, "#patches", msg=f"{', '.join(added)} added for {patches.target_label(target).lower()}; rescan started")


@app.post("/settings/{cid}/patches/link", dependencies=[Depends(auth.require_login)])
async def link_patches(
    request: Request,
    cid: str,
    paths: list[str] = Form([]),
    target: str = Form("all"),
    node_name: str = Form(""),
    csrf: str = Form(...),
):
    auth.check_csrf(request, csrf)
    cluster_or_404(cid)
    target = _target(target, node_name)
    if not paths:
        return _back(cid, "#patches", err="Select at least one file.")
    if not patches.valid_target(target):
        return _back(cid, "#patches", err="Choose a valid target (for a specific node: enter the hostname or IP).")
    node_role = _node_role(cid, target)
    for rel in paths:
        try:
            data = sources.read(cid, rel)
        except sources.SourceError as e:
            return _back(cid, "#patches", err=str(e))
        error = patches.check_yaml(data) or await patches.try_apply(cid, data, target, node_role)
        if error:
            return _back(cid, "#patches", err=f"{rel}: {error}")
    for rel in paths:
        patches.add_link(cid, rel, target)
    scanner.request(cid)
    return _back(cid, "#patches", msg=f"{len(paths)} patch(es) linked for {patches.target_label(target).lower()}; rescan started")


@app.post("/settings/{cid}/patches/{patch_id}/{action}", dependencies=[Depends(auth.require_login)])
async def patch_action(
    request: Request,
    cid: str,
    patch_id: str,
    action: str,
    csrf: str = Form(...),
    target: str = Form(""),
    node_name: str = Form(""),
):
    auth.check_csrf(request, csrf)
    cluster_or_404(cid)
    if action == "delete":
        patches.delete(cid, patch_id)
    elif action in ("up", "down"):
        patches.move(cid, patch_id, -1 if action == "up" else 1)
    elif action == "target":
        target = _target(target, node_name)
        if not patches.valid_target(target):
            return _back(cid, "#patches", err="Invalid target")
        patches.set_target(cid, patch_id, target)
    else:
        raise HTTPException(404)
    scanner.request(cid)
    return _back(cid, "#patches", msg="Patches updated; rescan started")


@app.post("/settings/{cid}/general", dependencies=[Depends(auth.require_login)])
async def save_general(
    request: Request,
    cid: str,
    csrf: str = Form(...),
    ignore: str = Form(""),
    nodes: str = Form(""),
    discovery_node: str = Form(""),
    scan_interval: int = Form(...),
):
    auth.check_csrf(request, csrf)
    cluster_or_404(cid)
    s = store.settings(cid)
    s["ignore"] = [line.strip() for line in ignore.splitlines() if line.strip()]
    s["nodes"] = [line.strip() for line in nodes.replace(",", "\n").splitlines() if line.strip()]
    s["discovery_node"] = discovery_node.strip()
    s["scan_interval"] = max(60, scan_interval)
    store.save_settings(cid, s)
    scanner.request(cid)
    return _back(cid, msg="Settings saved")


# --- api -----------------------------------------------------------------


@app.get("/api/dirs", dependencies=[Depends(auth.require_login)])
async def api_dirs(path: str = ""):
    try:
        return sources.list_dirs(path)
    except sources.SourceError as e:
        raise HTTPException(404, str(e))


@app.post("/api/scan", dependencies=[Depends(auth.require_login)])
async def api_scan_all(request: Request, x_csrf_token: str | None = Header(None)):
    auth.check_csrf(request, x_csrf_token)
    for c in store.clusters():
        scanner.request(c["id"])
    return {"started": [c["id"] for c in store.clusters()]}


@app.get("/api/status", dependencies=[Depends(auth.require_login)])
async def api_status():
    return {"running": scanner.running()}


@app.post("/api/c/{cid}/scan", dependencies=[Depends(auth.require_login)])
async def api_scan(request: Request, cid: str, x_csrf_token: str | None = Header(None)):
    auth.check_csrf(request, x_csrf_token)
    cluster_or_404(cid)
    scanner.request(cid)
    return {"started": [cid]}


@app.get("/api/c/{cid}/nodes", dependencies=[Depends(auth.require_login)])
async def api_nodes(cid: str):
    cluster_or_404(cid)
    scan = store.latest(cid)
    if not scan:
        return {"finished_at": None, "error": None, "nodes": []}
    return {
        "finished_at": scan.get("finished_at"),
        "error": scan.get("error"),
        "nodes": [_public_node(n) for n in scan["nodes"]],
    }


@app.get("/api/c/{cid}/history", dependencies=[Depends(auth.require_login)])
async def api_history(cid: str):
    cluster_or_404(cid)
    return [
        {"finished_at": s.get("finished_at"), "summary": _summary(s["nodes"]), "error": s.get("error")}
        for s in store.history(cid)
    ]


@app.post("/api/c/{cid}/ignore", dependencies=[Depends(auth.require_login)])
async def api_ignore(request: Request, cid: str, x_csrf_token: str | None = Header(None)):
    auth.check_csrf(request, x_csrf_token)
    cluster_or_404(cid)
    body = await request.json()
    path = str(body.get("path", "")).strip()
    if not path:
        raise HTTPException(400, "path required")
    s = store.settings(cid)
    if path not in s["ignore"]:
        s["ignore"].append(path)
        store.save_settings(cid, s)
    scanner.request(cid)
    return JSONResponse({"ignore": s["ignore"]})
