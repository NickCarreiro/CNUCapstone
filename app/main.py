import logging
from collections import defaultdict, deque
from time import monotonic
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.config import settings
from app.db_init import init_db
from app.routers import auth, files, groups, health, ui

_IS_PRODUCTION = settings.environment.strip().lower() in {"prod", "production"}

app = FastAPI(
    title=settings.app_name,
    docs_url=None if _IS_PRODUCTION else "/docs",
    redoc_url=None if _IS_PRODUCTION else "/redoc",
    openapi_url=None if _IS_PRODUCTION else "/openapi.json",
)

_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_AUTH_RATE_LIMIT_PATHS = {
    "/auth/login",
    "/auth/register",
    "/ui/login",
    "/ui/login/mfa",
    "/ui/register",
    "/ui/forgot-password",
    "/ui/forgot-password/mfa",
}
_CSRF_EXEMPT_PATHS = {
    "/auth/login",
    "/auth/register",
    "/ui/login",
    "/ui/login/mfa",
    "/ui/register",
    "/ui/forgot-password",
    "/ui/forgot-password/mfa",
}
_AUTH_RATE_BUCKETS: dict[str, deque[float]] = defaultdict(deque)
_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "base-uri 'self'; "
    "connect-src 'self'; "
    "font-src 'self' data:; "
    "form-action 'self'; "
    "frame-ancestors 'self'; "
    "frame-src 'self' blob:; "
    "img-src 'self' data: blob:; "
    "object-src 'none'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'"
)


class _AccessFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        args = getattr(record, "args", ())
        if len(args) >= 3:
            path = str(args[2])
            if path.startswith("/ui/activity"):
                return False
        return True


def _request_is_secure(request: Request) -> bool:
    forwarded_proto = (request.headers.get("x-forwarded-proto") or "").split(",", 1)[0].strip().lower()
    if forwarded_proto:
        return forwarded_proto == "https"
    return request.url.scheme == "https"


def _has_session_cookie(request: Request) -> bool:
    value = (request.cookies.get("pfv_session") or "").strip().strip('"')
    return bool(value)


def _same_origin(request: Request) -> bool:
    candidate = (request.headers.get("origin") or "").strip()
    if not candidate:
        candidate = (request.headers.get("referer") or "").strip()
    if not candidate:
        return False

    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False

    request_hosts: set[str] = set()
    host = (request.headers.get("host") or "").strip().lower()
    if host:
        request_hosts.add(host)
    forwarded_host = (request.headers.get("x-forwarded-host") or "").split(",", 1)[0].strip().lower()
    if forwarded_host:
        request_hosts.add(forwarded_host)
    netloc = request.url.netloc.strip().lower()
    if netloc:
        request_hosts.add(netloc)
    if not request_hosts:
        return False

    return parsed.netloc.strip().lower() in request_hosts


def _apply_security_headers(request: Request, response) -> None:
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")

    content_type = response.headers.get("content-type", "").lower()
    if "text/html" in content_type:
        response.headers.setdefault("Content-Security-Policy", _CONTENT_SECURITY_POLICY)

    path = request.url.path or "/"
    if path.startswith("/ui") or path.startswith("/files") or path.startswith("/auth"):
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Pragma", "no-cache")

    if _request_is_secure(request):
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")


logging.getLogger("uvicorn.access").addFilter(_AccessFilter())

trusted_hosts = [host.strip() for host in settings.trusted_hosts.split(",") if host.strip()]
if not trusted_hosts:
    configured_origin = (settings.public_base_url or "").strip()
    if configured_origin:
        parsed = urlsplit(configured_origin)
        if parsed.netloc:
            trusted_hosts = [parsed.netloc]
        elif parsed.path:
            trusted_hosts = [parsed.path]
if trusted_hosts:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts)

if settings.enforce_https:
    app.add_middleware(HTTPSRedirectMiddleware)


@app.middleware("http")
async def _security_middleware(request: Request, call_next):
    path = request.url.path or "/"
    method = request.method.upper()

    if settings.auth_rate_limit_enabled and method == "POST" and path in _AUTH_RATE_LIMIT_PATHS:
        attempts = max(1, int(settings.auth_rate_limit_attempts))
        window_seconds = max(10, int(settings.auth_rate_limit_window_seconds))
        client_ip = request.client.host if request.client else "unknown"
        bucket_key = f"{client_ip}:{path}"
        now = monotonic()

        bucket = _AUTH_RATE_BUCKETS[bucket_key]
        while bucket and now - bucket[0] > window_seconds:
            bucket.popleft()
        if len(bucket) >= attempts:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many authentication attempts. Try again shortly."},
            )
        bucket.append(now)

    if (
        settings.csrf_protection_enabled
        and method in _MUTATING_METHODS
        and _has_session_cookie(request)
        and path not in _CSRF_EXEMPT_PATHS
        and (path.startswith("/ui") or path.startswith("/auth") or path.startswith("/files"))
    ):
        if not _same_origin(request):
            return JSONResponse(status_code=403, content={"detail": "CSRF validation failed."})

    response = await call_next(request)
    _apply_security_headers(request, response)
    return response


@app.on_event("startup")
def _startup():
    # Dev-friendly: keep schema in sync without needing Alembic yet.
    init_db()


app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", include_in_schema=False)
def _root_redirect():
    return RedirectResponse(url="/ui/login", status_code=302)


app.include_router(health.router)
app.include_router(auth.router)
app.include_router(files.router)
app.include_router(ui.router)
app.include_router(groups.router)
