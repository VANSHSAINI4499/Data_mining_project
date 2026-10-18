"""A local demo shop that only *looks* attackable, for demonstrating the CTI pipeline.

``cti demo-site`` serves a few pages with query-string inputs (search, product filters, a
"download" and a "ping" page, a GET login form) on 127.0.0.1 and writes every request to an
Nginx "combined" access log, followed by a unique request id. ``cti tail`` then imports that
log live, and the web payload classifier and correlation rules analyse it.

Safety: nothing here executes, queries, opens, or fetches anything derived from a request.
Inputs are only echoed back HTML-escaped, so the site is not vulnerable to the payloads sent
to it; they just end up in the access log, which is the point of the demo. It binds to the
loopback interface only.

``X-Forwarded-For`` is trusted so the traffic generator can simulate distinct visitors; that is
acceptable only because the site is local and fake. Never put this app behind a real proxy.
"""

from __future__ import annotations

import html
import ipaddress
import threading
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse

MAX_TARGET_CHARS = 8192
MAX_HEADER_CHARS = 512

_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} - DemoShop</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem}}
body{{color:#1f2933}}
nav a{{margin-right:1rem}} form{{margin:1rem 0}} input{{padding:.3rem;min-width:16rem}}
.note{{background:#fff7e6;border:1px solid #f0c36d;padding:.6rem;border-radius:4px}}
code{{background:#f1f3f5;padding:.1rem .3rem}}
</style></head><body>
<p class="note">Demo target for the CTI Warehouse project. It runs only on this computer and
does not execute anything you type; inputs are logged and shown back as plain text.</p>
<nav><a href="/">Home</a><a href="/search">Search</a><a href="/products">Products</a>
<a href="/download">Downloads</a><a href="/ping">Status</a><a href="/login">Login</a></nav>
<h1>{title}</h1>
{body}
</body></html>"""

PRODUCTS = [
    ("1", "Notebook", "books"),
    ("2", "Fountain pen", "stationery"),
    ("3", "Desk lamp", "home"),
    ("4", "Travel mug", "home"),
    ("5", "Data mining textbook", "books"),
]


def _page(title: str, body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(_PAGE.format(title=html.escape(title), body=body), status_code=status)


def _echo(label: str, value: str | None) -> str:
    if not value:
        return ""
    return f"<p>{html.escape(label)}: <code>{html.escape(value)}</code></p>"


def _form(action: str, name: str, placeholder: str, button: str) -> str:
    return (
        f'<form action="{action}" method="get"><input name="{name}" '
        f'placeholder="{html.escape(placeholder)}"> <button>{html.escape(button)}</button></form>'
    )


def client_ip(request: Request) -> str:
    """First valid X-Forwarded-For address (demo only), else the socket peer."""
    forwarded = request.headers.get("x-forwarded-for", "")
    first = forwarded.split(",")[0].strip()
    try:
        return str(ipaddress.ip_address(first))
    except ValueError:
        return request.client.host if request.client else "127.0.0.1"


def _quoted(value: str | None) -> str:
    if not value:
        return "-"
    text = value[:MAX_HEADER_CHARS]
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "").replace("\n", "")


def log_line(request: Request, status: int, size: int, when: datetime, request_id: str) -> str:
    """One Nginx 'combined' line (as parsed by the ``nginx_access`` adapter) plus a request id."""
    scope = request.scope
    raw_path = scope.get("raw_path") or request.url.path.encode()
    target = raw_path.decode("latin-1")
    if scope.get("query_string"):
        target += "?" + scope["query_string"].decode("latin-1")
    target = target[:MAX_TARGET_CHARS].replace(" ", "%20")
    version = scope.get("http_version", "1.1")
    request_line = _quoted(f"{request.method} {target} HTTP/{version}")
    return (
        f"{client_ip(request)} - - [{when.strftime('%d/%b/%Y:%H:%M:%S %z')}] "
        f'"{request_line}" {status} {size} '
        f'"{_quoted(request.headers.get("referer"))}" '
        f'"{_quoted(request.headers.get("user-agent"))}" '
        f'"req_id={request_id}"\n'
    )


def create_demo_app(log_path: Path) -> FastAPI:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    lock = threading.Lock()
    app = FastAPI(title="DemoShop (CTI demo target)", docs_url=None, redoc_url=None)

    @app.middleware("http")
    async def access_log(request: Request, call_next):  # type: ignore[no-untyped-def]
        when = datetime.now().astimezone()
        response: Response = await call_next(request)
        size = int(response.headers.get("content-length", 0))
        line = log_line(request, response.status_code, size, when, uuid.uuid4().hex[:16])
        with lock, log_path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(line)
        return response

    @app.get("/", response_class=HTMLResponse)
    def home() -> HTMLResponse:
        items = "".join(
            f'<li><a href="/product?id={pid}">{html.escape(name)}</a></li>'
            for pid, name, _ in PRODUCTS
        )
        return _page(
            "Welcome to DemoShop",
            _form("/search", "q", "Search products", "Search") + f"<ul>{items}</ul>",
        )

    @app.get("/search", response_class=HTMLResponse)
    def search(q: str | None = None, sort: str | None = None) -> HTMLResponse:
        hits = [n for _, n, _ in PRODUCTS if q and q.lower() in n.lower()]
        results = "".join(f"<li>{html.escape(n)}</li>" for n in hits) or "<li>No results</li>"
        body = _form("/search", "q", "Search products", "Search")
        if q is not None:
            body += _echo("You searched for", q) + _echo("Sort", sort) + f"<ul>{results}</ul>"
        return _page("Search", body)

    @app.get("/products", response_class=HTMLResponse)
    def products(category: str | None = None, page: str | None = None) -> HTMLResponse:
        rows = [(p, n) for p, n, c in PRODUCTS if not category or c == category]
        items = "".join(f'<li><a href="/product?id={p}">{html.escape(n)}</a></li>' for p, n in rows)
        links = " ".join(
            f'<a href="/products?category={c}&page=1">{c}</a>'
            for c in ("books", "stationery", "home")
        )
        return _page(
            "Products",
            f"<p>Categories: {links}</p>{_echo('Category', category)}{_echo('Page', page)}"
            f"<ul>{items or '<li>None</li>'}</ul>",
        )

    @app.get("/product", response_class=HTMLResponse)
    def product(id: str | None = None) -> HTMLResponse:
        match = next((n for p, n, _ in PRODUCTS if p == id), None)
        if match is None:
            return _page("Product not found", _echo("Requested id", id), status=404)
        return _page(match, f"<p>A fine {html.escape(match.lower())}.</p>")

    @app.get("/download", response_class=HTMLResponse)
    def download(file: str | None = None) -> HTMLResponse:
        body = _form("/download", "file", "brochure.pdf", "Download")
        if file is not None:
            # Never touches the filesystem: the name is only echoed.
            body += _echo("Requested file", file) + "<p>Downloads are disabled in the demo.</p>"
        return _page("Downloads", body)

    @app.get("/ping", response_class=HTMLResponse)
    def ping(host: str | None = None) -> HTMLResponse:
        body = _form("/ping", "host", "example.com", "Check status")
        if host is not None:
            # Never runs a command: the value is only echoed.
            body += _echo("Host", host) + "<p>Network diagnostics are disabled in the demo.</p>"
        return _page("Service status", body)

    @app.get("/login", response_class=HTMLResponse)
    def login(username: str | None = None, password: str | None = None) -> HTMLResponse:
        # A GET form on purpose, so the demo values appear in the access log (real sites must
        # never send credentials in a URL). Use made-up values only.
        body = (
            '<form action="/login" method="get"><p><input name="username" placeholder="username">'
            '</p><p><input name="password" type="password" placeholder="password (demo only)">'
            "</p><button>Sign in</button></form>"
        )
        if username is not None:
            body += _echo("Login failed for", username)
            return _page("Login", body, status=401)
        return _page("Login", body)

    return app
