"""Demo access-log generator (``cti demo-traffic``).

Writes synthetic Nginx "combined" access-log lines — a mix of ordinary browsing and the kind
of attack payloads already present in ``data/samples/web-access/`` — into a log file, either
all at once or a few per second so ``cti tail`` ingests them live during a demonstration.

This produces *log data*; it does not send any network request anywhere. All addresses are
documentation ranges (RFC 5737) and domains are ``.test`` (RFC 6761), as in ``synthetic.py``.
Attack payloads are URL-encoded exactly as a browser would place them in a query string, so
the ``nginx_access`` adapter decodes them and the web payload classifier labels them.
"""

from __future__ import annotations

import random
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import quote_plus

BENIGN_VISITORS = [f"192.0.2.{i}" for i in range(10, 30)]
BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Version/17.5 Safari/605",
    "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
]
REFERER = "https://demoshop.test/"

# Benign query-string requests: (path, param, value, status).
BENIGN: list[tuple[str, str, str, int]] = [
    ("/search", "q", "notebook", 200),
    ("/search", "q", "desk lamp", 200),
    ("/search", "q", "travel mug", 200),
    ("/products", "category", "books", 200),
    ("/products", "category", "home", 200),
    ("/product", "id", "5", 200),
    ("/login", "username", "demo_user", 401),
    ("/download", "file", "brochure.pdf", 200),
    ("/ping", "host", "status.demoshop.test", 200),
]
NO_QUERY = [("/", 200), ("/favicon.ico", 404), ("/products", 200)]

# Attacker payloads by family: (source IP, tool, path, param, raw value, status).
ATTACKS: list[tuple[str, str, str, str, str, int]] = [
    ("198.51.100.23", "sqlmap/1.8", "/search", "q", "1' OR '1'='1' --", 500),
    (
        "198.51.100.23",
        "sqlmap/1.8",
        "/product",
        "id",
        "1 UNION SELECT username,password FROM users",
        500,
    ),
    (
        "198.51.100.77",
        "Nikto/2.5.0",
        "/search",
        "q",
        "<script>alert(document.cookie)</script>",
        200,
    ),
    ("198.51.100.77", "Nikto/2.5.0", "/search", "q", "<img src=x onerror=alert(1)>", 200),
    ("203.0.113.50", "curl/8.5.0", "/download", "file", "../../../../etc/passwd", 403),
    ("203.0.113.50", "curl/8.5.0", "/download", "file", "..\\..\\..\\windows\\win.ini", 403),
    ("203.0.113.51", "curl/8.5.0", "/ping", "host", "127.0.0.1; cat /etc/passwd", 200),
    ("203.0.113.51", "curl/8.5.0", "/ping", "host", "localhost | whoami", 200),
]


@dataclass
class Request:
    ip: str
    agent: str
    path: str
    param: str | None
    value: str | None
    status: int
    attack: bool = False


def _line(req: Request, when: datetime, rng: random.Random) -> str:
    target = req.path
    if req.param is not None and req.value is not None:
        target += f"?{req.param}={quote_plus(req.value)}"
    stamp = when.strftime("%d/%b/%Y:%H:%M:%S %z")
    size = rng.randint(120, 8192) if req.status < 400 else rng.randint(0, 400)
    return (
        f'{req.ip} - - [{stamp}] "GET {target} HTTP/1.1" {req.status} {size} '
        f'"{REFERER}" "{req.agent}"\n'
    )


def plan(count: int, attack_ratio: float, rng: random.Random) -> Iterator[Request]:
    """Yield ``count`` requests, roughly ``attack_ratio`` of them attack-like, shuffled."""
    requests: list[Request] = []
    attacks = min(count, round(count * attack_ratio))
    for _ in range(attacks):
        ip, tool, path, param, value, status = rng.choice(ATTACKS)
        requests.append(Request(ip, tool, path, param, value, status, attack=True))
    for _ in range(count - attacks):
        agent = rng.choice(BROWSERS)
        if rng.random() < 0.3:
            path, status = rng.choice(NO_QUERY)
            requests.append(Request(rng.choice(BENIGN_VISITORS), agent, path, None, None, status))
        else:
            path, param, value, status = rng.choice(BENIGN)
            requests.append(Request(rng.choice(BENIGN_VISITORS), agent, path, param, value, status))
    rng.shuffle(requests)
    return iter(requests)


def generate(
    append_line: Callable[[str], None],
    *,
    count: int,
    attack_ratio: float = 0.25,
    seed: int = 42,
    now: Callable[[], datetime] = lambda: datetime.now().astimezone(),
) -> dict[str, int]:
    """Write ``count`` log lines via ``append_line``; returns per-outcome counts."""
    rng = random.Random(seed)  # noqa: S311 (deterministic demo data, not security)
    written = {"total": 0, "attack_payloads": 0, "benign": 0}
    for req in plan(count, attack_ratio, rng):
        append_line(_line(req, now(), rng))
        written["total"] += 1
        written["attack_payloads" if req.attack else "benign"] += 1
    return written
