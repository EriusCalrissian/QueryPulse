#!/usr/bin/env python3
"""QueryPulse — DNS resolver latency benchmark with connection reuse.

Every endpoint gets one long-lived session (UDP socket, TLS stream, HTTP/2
client, QUIC connection). Untimed setup queries open it, then each scored
domain is timed on the warm session. Broken sessions are reopened untimed.
Built with dnspython (+ httpx2 for DoH, aioquic for DoQ/DoH3).
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import random
import re
import shutil
import socket
import ssl
import statistics
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

try:
    import dns.quic

    HAVE_QUIC = bool(dns.quic.have_quic)
except ImportError:  # pragma: no cover
    HAVE_QUIC = False

HAVE_DOH = bool(dns.query.have_doh)
if HAVE_DOH:
    import httpx2

ROOT = Path(__file__).resolve().parent
SERVERS_DIR = ROOT / "servers"
DOMAINS_FILE = ROOT / "domains.txt"
RESULTS_DIR = ROOT / "results"
CSV_FILE = ROOT / "results.csv"
ADGUARD_FILE = ROOT / "adguardhome-dns.yaml"
ADGUARD_CONFIG = Path("/mnt/dietpi_userdata/adguardhome/AdGuardHome.yaml")  # DietPi default
ADGUARD_SERVICE = "adguardhome"
RUN_FILE_RE = re.compile(r"^run_(\d+)(?:_\d{2}-\d{2}-\d{2}_\d{2}-\d{2})?\.json$", re.IGNORECASE)

CATEGORY_FILES = {
    "no-logging.txt": "No Logging",
    "anonymized.txt": "Anonymized",
    "logging.txt": "Logging",
}
PRIVACY_LEVELS = [Path(name).stem for name in CATEGORY_FILES]  # CLI names, most private first

# scheme -> (protocol, default port)
SCHEMES = {
    "tls": ("DoT", 853),
    "https": ("DoH", 443),
    "quic": ("DoQ", 853),
    "h3": ("DoH3", 443),
}
PROTO_AVAILABLE = {"UDP": True, "DoT": True, "DoH": HAVE_DOH, "DoQ": HAVE_QUIC, "DoH3": HAVE_QUIC}

# Setup queries (not scored) — open the session before timed measurements.
SETUP_DOMAINS = ("example.com", "cloudflare.com", "google.com")
MIN_CONNECT_S = 2.0
MAX_CONSECUTIVE_FAILS = 3
# Endpoints answering fewer queries than this rank below all reliable ones.
MIN_SUCCESS = 0.95

Query = Callable[[dns.message.Message, float], dns.message.Message]
Session = tuple[Query, Callable[[], None]]


@dataclass(slots=True)
class Endpoint:
    category: str
    provider: str
    url: str
    proto: str
    host: str | None  # None for plain UDP
    port: int
    ip: str | None = None
    ip_source: str | None = None


# --------------------------------------------------------------------------- input


def read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8-sig").splitlines()


def parse_endpoint(line: str, category: str, provider: str) -> Endpoint | None:
    try:
        ip = str(ipaddress.ip_address(line.strip("[]")))
        return Endpoint(category, provider, line, "UDP", None, 53, ip)
    except ValueError:
        pass
    try:
        url = urlparse(line)
        scheme, host, port = url.scheme.lower(), url.hostname, url.port
    except ValueError:
        return None
    if scheme not in SCHEMES or not host:
        return None
    proto, default_port = SCHEMES[scheme]
    ep = Endpoint(category, provider, line, proto, host, port or default_port)
    try:
        ep.ip, ep.ip_source = str(ipaddress.ip_address(host)), "literal"
    except ValueError:
        pass
    return ep


def load_domains(path: Path) -> list[str]:
    if not path.is_file():
        raise SystemExit(f"Missing domains file: {path}")
    domains = [s for raw in read_lines(path) if (s := raw.strip()) and not s.startswith("#")]
    if not domains:
        raise SystemExit(f"No domains found in {path}")
    return domains


def load_servers(servers_dir: Path) -> list[Endpoint]:
    if not servers_dir.is_dir():
        raise SystemExit(f"Missing servers directory: {servers_dir}")
    endpoints: list[Endpoint] = []
    seen: set[str] = set()
    for filename, category in CATEGORY_FILES.items():
        path = servers_dir / filename
        if not path.is_file():
            continue
        provider: str | None = None
        for lineno, raw in enumerate(read_lines(path), 1):
            line = raw.strip()
            if not line or line.startswith("##"):
                continue
            if line.startswith("#"):
                provider = line[1:].strip() or provider
                continue
            if provider is None:
                raise SystemExit(f"{path}:{lineno}: endpoint before provider header (# Name): {line}")
            ep = parse_endpoint(line, category, provider)
            if ep is None:
                raise SystemExit(f"{path}:{lineno}: unsupported endpoint: {line}")
            if ep.url in seen:
                print(f"warn: {path}:{lineno}: duplicate endpoint skipped: {line}", file=sys.stderr)
                continue
            seen.add(ep.url)
            endpoints.append(ep)
    if not endpoints:
        raise SystemExit(f"No endpoints found under {servers_dir}")
    return endpoints


def resolve_ip(host: str) -> str | None:
    """System-resolve a hostname, preferring IPv4."""
    try:
        addrs = [info[4][0] for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)]
    except OSError:
        return None
    return next((a for a in addrs if ":" not in a), addrs[0] if addrs else None)


def prepare_bootstrap(endpoints: list[Endpoint]) -> None:
    """Resolve each encrypted endpoint's own hostname (untimed, in parallel)."""
    pending = [ep for ep in endpoints if ep.host and not ep.ip]
    hosts = list({ep.host for ep in pending})
    if not hosts:
        return
    with ThreadPoolExecutor(max_workers=min(16, len(hosts))) as pool:
        resolved = dict(zip(hosts, pool.map(resolve_ip, hosts)))
    for ep in pending:
        ep.ip = resolved[ep.host]
        ep.ip_source = "hostname_resolve" if ep.ip else None
        if not ep.ip:
            print(f"warn: no bootstrap IP for {ep.url}", file=sys.stderr)


# ------------------------------------------------------------------------ sessions


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["dot"])
    return ctx


TLS_CONTEXT = _tls_context()


def open_udp(ep: Endpoint, connect_s: float) -> Session:
    sock = socket.socket(socket.AF_INET6 if ":" in ep.ip else socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)

    def query(q: dns.message.Message, timeout: float) -> dns.message.Message:
        # ignore_unexpected drops late replies to earlier, timed-out queries.
        return dns.query.udp(q, ep.ip, timeout, ep.port, sock=sock, ignore_unexpected=True)

    return query, sock.close


def open_dot(ep: Endpoint, connect_s: float) -> Session:
    raw = socket.create_connection((ep.ip, ep.port), timeout=connect_s)
    try:
        sock = TLS_CONTEXT.wrap_socket(raw, server_hostname=ep.host)
    except BaseException:
        raw.close()
        raise
    sock.setblocking(False)  # dnspython enforces the per-query deadline itself

    def query(q: dns.message.Message, timeout: float) -> dns.message.Message:
        return dns.query.tls(q, ep.ip, timeout, ep.port, sock=sock)

    return query, sock.close


def open_doh(ep: Endpoint, connect_s: float) -> Session:
    # Connect to the bootstrap IP with the real name as SNI/Host. dnspython's
    # session mode would ignore bootstrap_address, and its bootstrap transport
    # adds ~40 ms per request (Nagle/delayed-ACK) — both skew the measurement.
    url = urlparse(ep.url)
    ip = f"[{ep.ip}]" if ":" in ep.ip else ep.ip
    target = f"https://{ip}:{ep.port}{url.path or '/dns-query'}" + (f"?{url.query}" if url.query else "")
    headers = {
        "host": url.netloc.rpartition("@")[2],
        "accept": "application/dns-message",
        "content-type": "application/dns-message",
    }
    extensions = {"sni_hostname": ep.host}
    client = httpx2.Client(http2=True, timeout=connect_s)

    def query(q: dns.message.Message, timeout: float) -> dns.message.Message:
        resp = client.post(target, content=q.to_wire(), headers=headers, extensions=extensions, timeout=timeout)
        resp.raise_for_status()
        reply = dns.message.from_wire(resp.content)
        if not q.is_response(reply):
            raise dns.query.BadResponse
        return reply

    return query, client.close


def _open_quic(ep: Endpoint, h3: bool) -> Session:
    manager = dns.quic.SyncQuicManager(server_name=ep.host, h3=h3)
    close = lambda: manager.__exit__(None, None, None)  # noqa: E731
    try:
        conn = manager.connect(ep.ip, ep.port)
    except BaseException:
        close()
        raise
    if h3:
        url = "https" + ep.url[ep.url.index(":"):]

        def query(q: dns.message.Message, timeout: float) -> dns.message.Message:
            return dns.query.https(
                q, url, timeout, bootstrap_address=ep.ip, session=conn,
                http_version=dns.query.HTTPVersion.HTTP_3,
            )
    else:

        def query(q: dns.message.Message, timeout: float) -> dns.message.Message:
            return dns.query.quic(q, ep.ip, timeout, ep.port, connection=conn, hostname=ep.host)

    return query, close


OPENERS: dict[str, Callable[[Endpoint, float], Session]] = {
    "UDP": open_udp,
    "DoT": open_dot,
    "DoH": open_doh,
    "DoQ": lambda ep, _: _open_quic(ep, h3=False),
    "DoH3": lambda ep, _: _open_quic(ep, h3=True),
}


def _close(session: Session | None) -> None:
    if session is not None:
        try:
            session[1]()
        except Exception:
            pass


def open_session(ep: Endpoint, connect_s: float) -> Session | None:
    """Open a session and warm it up with untimed setup queries (one retry)."""
    for _ in range(2):
        session = None
        try:
            session = OPENERS[ep.proto](ep, connect_s)
            for name in SETUP_DOMAINS:
                session[0](dns.message.make_query(name, dns.rdatatype.A), connect_s)
            return session
        except Exception:
            _close(session)
    return None


def answered(reply: dns.message.Message) -> bool:
    return reply.rcode() == dns.rcode.NOERROR and bool(reply.answer)


def probe(ep: Endpoint, domains: list[str], timeout_s: float) -> list[float | None]:
    samples: list[float | None] = [None] * len(domains)
    if not ep.ip or not PROTO_AVAILABLE[ep.proto]:
        return samples
    connect_s = max(timeout_s, MIN_CONNECT_S)
    session: Session | None = None
    fails = 0
    try:
        for i, name in enumerate(domains):
            if session is None and (session := open_session(ep, connect_s)) is None:
                break
            q = dns.message.make_query(name, dns.rdatatype.A)
            t0 = time.perf_counter()
            try:
                reply = session[0](q, timeout_s)
            except Exception:
                reply = None
            elapsed = time.perf_counter() - t0
            if reply is None:  # transport error: stream state unknown, reopen
                _close(session)
                session = None
            if reply is not None and elapsed <= timeout_s and answered(reply):
                samples[i] = elapsed * 1000.0
                fails = 0
            elif (fails := fails + 1) >= MAX_CONSECUTIVE_FAILS:
                break
    finally:
        _close(session)
    return samples


# ------------------------------------------------------------------------- results


def list_run_files(results_dir: Path) -> list[tuple[int, Path]]:
    if not results_dir.is_dir():
        return []
    files = [
        (int(m.group(1)), p) for p in results_dir.glob("run_*.json") if (m := RUN_FILE_RE.match(p.name))
    ]
    return sorted(files)


def load_runs(results_dir: Path) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    for _, path in list_run_files(results_dir):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"warn: skipping unreadable {path.name}: {exc}", file=sys.stderr)
            continue
        if isinstance(data, dict) and isinstance(data.get("endpoints"), dict):
            runs.append(data)
        else:
            print(f"warn: skipping malformed {path.name}", file=sys.stderr)
    return runs


def save_run(results_dir: Path, run: dict[str, Any]) -> Path:
    results_dir.mkdir(parents=True, exist_ok=True)
    when = datetime.fromisoformat(run["timestamp"])
    path = results_dir / f"run_{run['id']:04d}_{when:%y-%m-%d_%H-%M}.json"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(run, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(path)
    return path


def summarize(samples: list[float]) -> dict[str, float | None]:
    if not samples:
        return {"avg_ms": None, "median_ms": None, "p95_ms": None}
    p95 = statistics.quantiles(samples, n=20, method="inclusive")[-1] if len(samples) > 1 else samples[0]
    return {"avg_ms": statistics.fmean(samples), "median_ms": statistics.median(samples), "p95_ms": p95}


def success_rate(row: dict[str, Any]) -> float:
    total = row["ok"] + row["fail"]
    return row["ok"] / total if total else 0.0


def aggregate(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Pool samples per endpoint across runs; reliable first, then by median."""
    buckets: dict[str, dict[str, Any]] = {}
    for run in runs:
        for endpoint, data in run["endpoints"].items():
            b = buckets.setdefault(endpoint, {"endpoint": endpoint, "samples": [], "ok": 0, "fail": 0, "runs": 0})
            b.update(category=data["category"], provider=data["provider"], proto=data["proto"])
            b["samples"].extend(map(float, data.get("samples_ms", ())))
            b["ok"] += int(data.get("ok", 0))
            b["fail"] += int(data.get("fail", 0))
            b["runs"] += 1
    rows = [{**b, **summarize(b.pop("samples"))} for b in buckets.values()]
    inf = float("inf")
    rows.sort(
        key=lambda r: (
            success_rate(r) < MIN_SUCCESS,
            inf if r["median_ms"] is None else r["median_ms"],
            inf if r["avg_ms"] is None else r["avg_ms"],
            r["category"],
            r["provider"].lower(),
            r["endpoint"],
        )
    )
    return rows


COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
if COLOR and sys.platform == "win32":
    os.system("")  # enables ANSI escape processing in the Windows console
BOLD, DIM, GREEN, YELLOW, RED = "1", "2", "32", "33", "31"


def paint(text: str, style: str) -> str:
    return f"\x1b[{style}m{text}\x1b[0m" if COLOR and style else text


def fmt_ms(value: float | None) -> str:
    return "—" if value is None else f"{value:.1f}"


def fmt_rate(rate: float) -> str:
    return "100%" if rate >= 1 else f"{rate * 100:.1f}%"


def print_table(title: str, rows: list[dict[str, Any]], limit: int = 0) -> None:
    print(f"\n{paint(title, BOLD)}\n{'=' * len(title)}")
    if not rows:
        print("(no data)")
        return
    # Colour medians by tercile of the whole table, so tiers stay stable under --top.
    medians = sorted(m for r in rows if (m := r["median_ms"]) is not None)
    fast, mid = (medians[len(medians) // 3], medians[2 * len(medians) // 3]) if medians else (0, 0)

    def latency_style(v: float | None) -> str:
        return DIM if v is None else GREEN if v <= fast else YELLOW if v <= mid else RED

    headers = ("#", "Category", "Provider", "Endpoint", "Proto", "median", "avg", "p95", "success", "runs")
    right = {0, 5, 6, 7, 8, 9}
    body = []
    for rank, r in enumerate(rows[:limit] if limit else rows, 1):
        rate = success_rate(r)
        body.append((
            (str(rank), DIM), (r["category"], ""), (r["provider"], ""), (r["endpoint"], ""), (r["proto"], ""),
            (fmt_ms(r["median_ms"]), latency_style(r["median_ms"])),
            (fmt_ms(r["avg_ms"]), ""), (fmt_ms(r["p95_ms"]), ""),
            (fmt_rate(rate), "" if rate >= 1 else YELLOW if rate >= MIN_SUCCESS else RED),
            (str(r["runs"]), DIM),
        ))
    widths = [max(len(h), *(len(row[i][0]) for row in body)) for i, h in enumerate(headers)]

    def line(cells: tuple[tuple[str, str], ...]) -> str:
        return "  ".join(
            paint(text.rjust(w) if i in right else text.ljust(w), style)
            for i, ((text, style), w) in enumerate(zip(cells, widths))
        )

    print(line(tuple((h, BOLD) for h in headers)))
    print(line(tuple(("-" * w, DIM) for w in widths)))
    for cells in body:
        print(line(cells))
    if hidden := len(rows) - len(body):
        print(paint(f"… {hidden} more (use --top 0 to show all)", DIM))


def best_by(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    """First (best-ranked) row per distinct value of key, keeping rank order."""
    best: dict[str, dict[str, Any]] = {}
    for row in rows:
        best.setdefault(row[key], row)
    return list(best.values())


def best_per_provider(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fastest encrypted endpoint per provider, plus its fastest UDP if that ranks higher."""
    rank = {id(r): i for i, r in enumerate(rows)}
    udp = best_by([r for r in rows if r["proto"] == "UDP"], "provider")
    enc = {r["provider"]: r for r in best_by([r for r in rows if r["proto"] != "UDP"], "provider")}
    keep = {id(r) for r in enc.values()}
    keep |= {id(r) for r in udp if r["provider"] not in enc or rank[id(r)] < rank[id(enc[r["provider"]])]}
    return [r for r in rows if id(r) in keep]


def filter_rows(rows: list[dict[str, Any]], args: argparse.Namespace) -> list[dict[str, Any]]:
    protos = set(args.proto or ())
    return [r for r in rows if not protos or r["proto"].lower() in protos]


def runs_span(runs: list[dict[str, Any]]) -> str:
    first, last = (str(run.get("timestamp", "?"))[:16].replace("T", " ") for run in (runs[0], runs[-1]))
    return first if first == last else f"{first} → {last}"


def export_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    cols = ("median_ms", "avg_ms", "p95_ms", "category", "provider", "endpoint", "proto", "ok", "fail", "runs")
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(cols)
        for row in rows:
            writer.writerow(
                "" if row[c] is None else f"{row[c]:.3f}" if c.endswith("_ms") else row[c] for c in cols
            )


# ----------------------------------------------------------------------- benchmark


def status(text: str) -> None:
    if not sys.stdout.isatty():
        return
    width = max(shutil.get_terminal_size().columns - 1, 20)
    print("\r" + text[:width].ljust(width), end="" if text else "\r", flush=True)


def run_benchmark(endpoints: list[Endpoint], domains: list[str], timeout_ms: int) -> dict[str, Any]:
    prepare_bootstrap(endpoints)
    timeout_s = timeout_ms / 1000.0
    # Random order so no protocol systematically benefits from a cache warmed
    # by an earlier endpoint of the same provider.
    order = random.sample(endpoints, len(endpoints))
    timed: dict[str, list[float | None]] = {}
    for idx, ep in enumerate(order, 1):
        status(f"[{idx}/{len(order)}] {ep.provider}: {ep.url} ({ep.proto})")
        timed[ep.url] = probe(ep, domains, timeout_s)
    status("")

    results: dict[str, Any] = {}
    for ep in endpoints:
        values = timed[ep.url]
        samples = [v for v in values if v is not None]
        results[ep.url] = {
            "category": ep.category,
            "provider": ep.provider,
            "proto": ep.proto,
            "bootstrap_ip": ep.ip if ep.host else None,
            "bootstrap_source": ep.ip_source,
            "samples_ms": [round(v, 3) for v in samples],
            "by_domain": {d: None if v is None else round(v, 3) for d, v in zip(domains, values, strict=True)},
            **{k: None if v is None else round(v, 3) for k, v in summarize(samples).items()},
            "ok": len(samples),
            "fail": len(values) - len(samples),
        }
    return {
        "id": 0,
        "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
        "mode": "reuse",
        "timeout_ms": timeout_ms,
        "setup_domains": list(SETUP_DOMAINS),
        "domains": domains,
        "endpoints": results,
    }


def run_once(args: argparse.Namespace) -> dict[str, Any]:
    """Benchmark all endpoints once and save the run to the results folder."""
    if not HAVE_DOH:
        print("warn: httpx2 missing — DoH probes skipped (uv pip install httpx2)", file=sys.stderr)
    if not HAVE_QUIC:
        print("warn: aioquic missing — DoQ/DoH3 probes skipped (uv pip install aioquic)", file=sys.stderr)

    domains = load_domains(args.domains)
    endpoints = load_servers(args.servers_dir)
    encrypted = sum(1 for ep in endpoints if ep.host)
    print("mode:      connection reuse")
    print(f"domains:   {len(domains)} scored + {len(SETUP_DOMAINS)} setup")
    print(f"endpoints: {len(endpoints)} ({encrypted} encrypted)")
    print(f"timeout:   {args.timeout}ms per query")

    run = run_benchmark(endpoints, domains, args.timeout)
    files = list_run_files(args.results)
    run["id"] = files[-1][0] + 1 if files else 1
    print(f"Saved: {save_run(args.results, run)}")
    return run


def do_run_test(args: argparse.Namespace, show_results_after: bool = True) -> int:
    run = run_once(args)
    return show_results(args, latest=[run]) if show_results_after else 0


def show_results(args: argparse.Namespace, latest: list[dict[str, Any]] | None = None) -> int:
    """Show the latest run(s), if given, then totals over every stored run."""
    runs = load_runs(args.results)
    if not runs:
        print("No runs stored yet.")
        return 0
    if latest and len(runs) > len(latest):
        ids = f"#{latest[0]['id']}" + (f"–#{latest[-1]['id']}" if len(latest) > 1 else "")
        label = "This run" if len(latest) == 1 else f"This batch ({len(latest)} runs)"
        print_table(f"{label} {ids} · {runs_span(latest)}", filter_rows(aggregate(latest), args), args.top)
    rows = filter_rows(aggregate(runs), args)
    samples = sum(r["ok"] for r in rows)
    print_table(f"All {len(runs)} stored run(s) · {runs_span(runs)} · {samples} samples", rows, args.top)
    print_table("Best per protocol", best_by(rows, "proto"))
    print_table("Best per provider (fastest encrypted, plus UDP if faster)", best_per_provider(rows))
    print(paint(
        f"\nTotals include every run_*.json in {args.results} — move or delete old runs, "
        "or use --results DIR, to start fresh.\n"
        f"Ranked by median latency; endpoints below {MIN_SUCCESS:.0%} success rank last. "
        "Median colour: green/yellow/red = fastest/middle/slowest third.",
        DIM,
    ))
    return 0


def do_export_csv(args: argparse.Namespace) -> int:
    runs = load_runs(args.results)
    if not runs:
        print("No runs stored yet — nothing to export.")
        return 1
    export_csv(args.csv, filter_rows(aggregate(runs), args))
    print(f"CSV written: {args.csv}")
    return 0


def reliable(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in rows if r["median_ms"] is not None and success_rate(r) >= MIN_SUCCESS]


def encrypted_by_provider(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Reliable encrypted endpoints per provider; providers ordered by their fastest one."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for r in reliable(rows):
        if r["proto"] != "UDP":
            grouped.setdefault(r["provider"], []).append(r)
    return grouped


def adguard_selection(
    encrypted: dict[str, list[dict[str, Any]]],
    rows: list[dict[str, Any]],
    providers: int,
    per_provider: int,
    fallbacks: int = 2,
    min_bootstrap: int = 2,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Pick upstream / fallback (encrypted only) and bootstrap (plain from all rows)."""
    ranked = list(encrypted)
    chosen = set(ranked[:providers])
    upstream = [r for p in ranked[:providers] for r in encrypted[p][:per_provider]]
    fallback = [encrypted[p][0] for p in ranked[providers:providers + fallbacks]]
    plain = [r for r in reliable(rows) if r["proto"] == "UDP"]
    bootstrap = [r for r in plain if r["provider"] in chosen]
    # Any plain resolver can bootstrap; top up with the fastest others if needed.
    bootstrap += [r for r in plain if r["provider"] not in chosen][: max(0, min_bootstrap - len(bootstrap))]
    return upstream, fallback, bootstrap


def adguard_yaml(sections: dict[str, list[dict[str, Any]]], source: str) -> str:
    lines = [
        f"# QueryPulse export — {source}",
        "# Replace these keys in the dns: section of AdGuardHome.yaml",
        "# (or let QueryPulse do it: --adguard-config PATH).",
        "dns:",
    ]
    for key, rows in sections.items():
        if not rows:
            lines.append(f"  {key}: []")
            continue
        lines.append(f"  {key}:")
        width = max(len(json.dumps(r["endpoint"])) for r in rows)
        lines += [
            f"    - {json.dumps(r['endpoint']).ljust(width)}  # {r['provider']}, {r['proto']}, median {r['median_ms']:.1f} ms"
            for r in rows
        ]
    return "\n".join(lines) + "\n"


def merge_adguard_config(path: Path, lists: dict[str, list[str]]) -> Path:
    """Replace the given lists under dns: in AdGuardHome.yaml; returns the backup path.

    Line-based on purpose (no YAML library): AdGuard Home writes this file itself
    with a fixed layout — top-level keys at column 0, dns keys at 2 spaces.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    start = next((i + 1 for i, line in enumerate(lines) if line.rstrip() == "dns:"), None)
    if start is None:
        raise SystemExit(f"{path}: no top-level 'dns:' section — is this AdGuardHome.yaml?")
    end = next((i for i in range(start, len(lines)) if lines[i][:1] not in ("", " ", "#")), len(lines))
    section = lines[start:end]
    for key, values in lists.items():
        block = [f"  {key}:", *(f"    - {json.dumps(v)}" for v in values)] if values else [f"  {key}: []"]
        i = next((n for n, line in enumerate(section) if line.startswith(f"  {key}:")), None)
        if i is None:
            section += block
            continue
        j = i + 1
        while j < len(section) and section[j].startswith(("    ", "  - ")):
            j += 1
        # Keep domain-specific upstreams such as [/lan/]192.168.1.1.
        kept = [line for line in section[i + 1:j] if key == "upstream_dns" and "[/" in line]
        section[i:j] = ([f"  {key}:"] if kept and not values else block) + kept
    for n, line in enumerate(section):
        if line.startswith("  upstream_dns_file:") and line.split(":", 1)[1].strip() not in ("", '""', "''"):
            print(paint(f"warn: cleared '{line.strip()}' — it would override upstream_dns", YELLOW))
            section[n] = '  upstream_dns_file: ""'
    lines[start:end] = section
    backup = path.with_name(f"{path.name}.bak-{datetime.now():%Y%m%d-%H%M%S}")
    shutil.copy2(path, backup)
    # Rewrite in place (not tmp + rename) so the file keeps its owner and permissions.
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return backup


def systemctl(action: str, service: str) -> bool:
    cmd = ["systemctl", action, service]
    if hasattr(os, "geteuid") and os.geteuid() != 0 and shutil.which("sudo"):
        cmd.insert(0, "sudo")
    print(paint(f"$ {' '.join(cmd)}", DIM))
    try:
        subprocess.run(cmd, check=True)
        return True
    except (OSError, subprocess.CalledProcessError) as exc:
        print(paint(f"warn: '{' '.join(cmd)}' failed: {exc}", YELLOW))
        return False


def _config_path(raw: str) -> Path | None:
    raw = raw.strip().strip("\"'")
    if raw.lower() in {"", "n", "no", "skip"}:
        return None
    path = Path(raw).expanduser()
    if path.is_dir():
        path /= "AdGuardHome.yaml"
    if not path.is_file():
        raise ValueError
    return path


def apply_to_adguard(args: argparse.Namespace, interactive: bool, lists: dict[str, list[str]]) -> int:
    if args.adguard_config is not None:
        try:
            config = _config_path(str(args.adguard_config))
        except ValueError:
            raise SystemExit(f"AdGuardHome.yaml not found: {args.adguard_config}") from None
    elif interactive:
        default = str(ADGUARD_CONFIG) if ADGUARD_CONFIG.is_file() else "n"
        config = ask(
            "4. Update AdGuardHome.yaml now? Path, or 'n' to skip", default, _config_path,
            "File not found — enter the path to AdGuardHome.yaml (or its folder), or 'n'.",
        )
    else:
        config = None
    if config is None:
        return 0

    # AdGuard Home overwrites the file while running, so stop it around the edit.
    restart = not args.no_restart and shutil.which("systemctl") is not None
    if restart and not systemctl("stop", args.adguard_service):
        print("AdGuardHome.yaml not changed. Check the service name (--adguard-service) or use --no-restart.")
        return 1
    try:
        backup = merge_adguard_config(config, lists)
    finally:
        if restart:
            systemctl("start", args.adguard_service)
    print(f"Updated: {config}\nBackup:  {backup}")
    if not restart:
        print(paint("Note: AdGuard Home must be stopped while its config is edited — restart it now.", YELLOW))
    return 0


def do_export_adguard(args: argparse.Namespace) -> int:
    runs = load_runs(args.results)
    if not runs:
        print("No runs stored yet — run a test first.")
        return 1
    interactive = sys.stdin.isatty()

    def pick(value: int | None, prompt: str, default: int, maximum: int) -> int:
        if value is None:
            if not interactive:
                return min(default, maximum)
            value = ask(f"{prompt} (1-{maximum})", str(min(default, maximum)), _at_least(int, 1), "Please enter an integer >= 1.")
        return min(value, maximum)

    print("\nAdGuard Home export\n-------------------")
    levels = list(CATEGORY_FILES.values())  # most private first
    if args.privacy is None and interactive:
        print("1. Categories to export:")
        for i in range(1, len(levels) + 1):
            print(f"   {i}) {' + '.join(levels[:i])}")
    level = pick(PRIVACY_LEVELS.index(args.privacy) + 1 if args.privacy else None, "   Choice", 1, len(levels))
    allowed = levels[:level]
    rows = [r for r in aggregate(runs) if r["category"] in allowed]
    # --proto narrows upstream/fallback only; bootstrap always needs plain DNS.
    encrypted = encrypted_by_provider(filter_rows(rows, args))
    if not encrypted:
        print(f"No reliable encrypted endpoints in categories: {', '.join(allowed)}.")
        return 1

    providers = pick(args.providers, "2. Number of providers (fastest first)", 2, len(encrypted))
    most = max(len(endpoints) for endpoints in list(encrypted.values())[:providers])
    per_provider = pick(args.per_provider, "3. Encrypted endpoints per provider", 1, most)
    upstream, fallback, bootstrap = adguard_selection(encrypted, rows, providers, per_provider)
    text = adguard_yaml(
        {"upstream_dns": upstream, "fallback_dns": fallback, "bootstrap_dns": bootstrap},
        f"{len(runs)} run(s), {runs_span(runs)} · categories: {', '.join(allowed)}",
    )
    args.adguard_file.write_text(text, encoding="utf-8")
    print(f"\n{text}")
    if len(fallback) < 2:
        print(paint(f"warn: only {len(fallback)} fallback provider(s) left after the selected ones.", YELLOW))
    print(f"AdGuard Home snippet written: {args.adguard_file}\n")
    lists = {"upstream_dns": upstream, "fallback_dns": fallback, "bootstrap_dns": bootstrap}
    return apply_to_adguard(args, interactive, {k: [r["endpoint"] for r in v] for k, v in lists.items()})


# --------------------------------------------------------------------- interactive


def ask(prompt: str, default: str, parse: Callable[[str], Any], error: str) -> Any:
    while True:
        try:
            return parse(input(f"{prompt} [{default}]: ").strip() or default)
        except ValueError:
            print(error)


def _at_least(cast: Callable[[str], float], minimum: float) -> Callable[[str], Any]:
    def parse(raw: str) -> Any:
        value = cast(raw.replace(",", "."))
        if value < minimum:
            raise ValueError
        return value

    return parse


def _yes_no(raw: str) -> bool:
    raw = raw.lower()
    if raw in {"y", "yes"}:
        return True
    if raw in {"n", "no"}:
        return False
    raise ValueError


def multi_run_submenu(args: argparse.Namespace) -> int:
    print("\nMultiple tests\n--------------")
    count = ask("1. Number of tests", "3", _at_least(int, 1), "Please enter an integer >= 1.")
    pause_s = ask("2. Pause between tests (seconds)", "60", _at_least(float, 0), "Please enter a number >= 0.")
    show_after = ask("3. Show results afterwards (y/n)", "n", _yes_no, "Please enter y or n.")
    print(f"\nRunning {count} tests with {pause_s:g}s pause (results afterwards: {'yes' if show_after else 'no'})…\n")
    batch = []
    for i in range(1, count + 1):
        print(f"=== Batch run {i}/{count} ===")
        batch.append(run_once(args))
        if i < count and pause_s > 0:
            print(f"Pause {pause_s:g}s…")
            time.sleep(pause_s)
        print()
    if show_after:
        return show_results(args, latest=batch)
    print(f"Saved {count} run(s). Totals over all stored runs: menu 4 or --show-only.")
    return 0


def read_menu_key(prompt: str) -> str:
    print(prompt, end="", flush=True)
    if sys.platform == "win32" and sys.stdin.isatty():
        import msvcrt

        while True:
            ch = msvcrt.getwch()
            if ch == "\x03":
                raise KeyboardInterrupt
            if ch in {"\x00", "\xe0"}:  # function/arrow key prefix
                msvcrt.getwch()
            elif ch not in {"\r", "\n"}:
                print(ch)
                return ch
    return input().strip()


MENU = {
    "1": ("Run once (save only)", lambda a: do_run_test(a, show_results_after=False)),
    "2": ("Run once (show results)", lambda a: do_run_test(a, show_results_after=True)),
    "3": ("Run multiple tests", multi_run_submenu),
    "4": ("Show results", show_results),
    "5": ("Export CSV", do_export_csv),
    "6": ("Export to AdGuard Home", do_export_adguard),
}


def interactive_menu(args: argparse.Namespace) -> int:
    print("QueryPulse\n----------")
    for key, (label, _) in MENU.items():
        print(f"{key}) {label}")
    print()
    while (choice := read_menu_key(f"Choice [1-{len(MENU)}]: ")) not in MENU:
        print(f"Please choose {', '.join(MENU)}.")
    return MENU[choice][1](args)


# ----------------------------------------------------------------------------- cli


def int_at_least(minimum: int) -> Callable[[str], int]:
    def parse(raw: str) -> int:
        value = int(raw)
        if value < minimum:
            raise argparse.ArgumentTypeError(f"must be >= {minimum}")
        return value

    return parse


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="DNS resolver latency benchmark with connection reuse.")
    p.add_argument("--servers-dir", type=Path, default=SERVERS_DIR)
    p.add_argument("--domains", type=Path, default=DOMAINS_FILE)
    p.add_argument("--results", type=Path, default=RESULTS_DIR)
    p.add_argument("--csv", type=Path, default=CSV_FILE)
    p.add_argument("--timeout", type=int_at_least(1), default=500, help="Per-query timeout in ms (default: 500)")
    p.add_argument("--top", type=int_at_least(0), default=0, help="Show only the N best endpoints (0 = all)")
    p.add_argument(
        "--proto", nargs="+", type=str.lower, choices=[proto.lower() for proto in PROTO_AVAILABLE],
        help="Limit results, CSV and AdGuard upstreams to these protocols",
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--run", action="store_true", help="Run one benchmark and show results")
    mode.add_argument("--show-only", action="store_true", help="Show stored results")
    mode.add_argument("--export-csv", action="store_true", help="Export stored results to CSV")
    mode.add_argument("--export-adguard", action="store_true", help="Export an AdGuardHome.yaml dns snippet")
    p.add_argument("--adguard-file", type=Path, default=ADGUARD_FILE, help="Where to write the YAML snippet")
    p.add_argument("--adguard-config", type=Path, help="AdGuardHome.yaml to update in place (asks if omitted)")
    p.add_argument("--adguard-service", default=ADGUARD_SERVICE, help="systemd unit stopped/started around the update")
    p.add_argument("--no-restart", action="store_true", help="Do not stop/start AdGuard Home around the update")
    p.add_argument("--providers", type=int_at_least(1), help="AdGuard export: number of providers (asks if omitted)")
    p.add_argument("--per-provider", type=int_at_least(1), help="AdGuard export: endpoints per provider (asks if omitted)")
    p.add_argument(
        "--privacy", choices=PRIVACY_LEVELS,
        help="AdGuard export: least private category to include, e.g. 'anonymized' = no-logging + anonymized",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.export_csv:
            return do_export_csv(args)
        if args.export_adguard:
            return do_export_adguard(args)
        if args.show_only:
            return show_results(args)
        if args.run:
            return do_run_test(args)
        code = interactive_menu(args)
        if sys.stdin.isatty():
            input("\nPress Enter to exit...")
        return code
    except (KeyboardInterrupt, EOFError):
        print("\nAborted.", file=sys.stderr)
        return 130
    except PermissionError as exc:
        print(f"Permission denied: {exc.filename} — run with sudo, or fix the file's ownership.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
