# QueryPulse

DNS resolver latency benchmark for **UDP**, **DoT**, **DoH**, **DoQ**, and **DoH3**, measured from your own network.

It works as a plain benchmark. Exporting the fastest servers to AdGuard Home is optional.

## Quick start

Python 3.10+, one script, three packages (`dnspython`, `httpx2`, `aioquic`). Prefer [uv](https://docs.astral.sh/uv/):

```bash
# DietPi: dietpi-software install 217
# elsewhere: curl -LsSf https://astral.sh/uv/install.sh | sh
uv venv
uv pip install -r requirements.txt
uv run python querypulse.py
```

Without `httpx2` or `aioquic`, the matching protocols are skipped with a warning.

Fallback without uv (e.g. system `pip` blocked on Debian):

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python querypulse.py
```

## Why

I wanted a multi-protocol DNS benchmark from *my* network, not brochure numbers. Resolvers differ a lot by protocol and location, and testing them by hand in AdGuard Home is slow. QueryPulse measures them and can optionally write the winners into `AdGuardHome.yaml`.

## Usage

Menu:

1. Run once (save only)
2. Run once (show results)
3. Run multiple tests (count, pause, show results afterwards?)
4. Show results
5. Export CSV
6. Export to AdGuard Home (optional)

Same without the menu:

```bash
python querypulse.py --run                # run once, show results
python querypulse.py --show-only          # show stored results
python querypulse.py --show-only --top 15 --proto dot doq
python querypulse.py --export-csv
python querypulse.py --export-adguard
```

| Flag | Meaning |
|------|---------|
| `--timeout MS` | Per-query timeout (default `500`) |
| `--top N` | Show only the N best (`0` = all) |
| `--proto …` | Filter: `udp` `dot` `doh` `doq` `doh3` |
| `--servers-dir` `--domains` `--results` `--csv` | Paths |
| `--privacy` | AdGuard: `no-logging` / `anonymized` / `logging` |
| `--providers` `--per-provider` | AdGuard selection counts (asked if omitted) |
| `--adguard-file` `--adguard-config` `--adguard-service` `--no-restart` | AdGuard apply |

## How it measures

- One session per endpoint is opened and reused, as long-lived DNS clients do. Handshakes are not timed.
- Each session first resolves untimed setup names (`example.com`, `cloudflare.com`, `google.com`), then times every name in `domains.txt`.
- Hostnames of encrypted endpoints are resolved once; queries go to that pinned IP.
- Endpoints are probed in random order, so no endpoint is always first or last.
- Success = `NOERROR` with an answer within the timeout.
- A broken session is reopened (untimed). After 3 failures in a row, the rest of that endpoint's queries are skipped and count as failures.

## Runs and totals

Every run is saved as its own file, `results/run_XXXX_YY-MM-DD_HH-MM.json`. That includes each pass of a multi-run.

**All totals use every `run_*.json` in `results/`**, not just the latest run or batch. This applies to the results view, CSV export and AdGuard export. Example: 2 older runs + a 3-run batch → totals over 5 runs.

| Action | Shows |
|--------|-------|
| Run once + show (menu 2, `--run`) | This run, then totals over all stored runs |
| Multi-run with results (menu 3) | This batch, then totals over all stored runs |
| Show results (menu 4, `--show-only`) | Totals over all stored runs |

The "this run / batch" table is skipped when it covers all stored runs anyway.

To start fresh, move or delete old `run_*.json` files. To keep separate sets (e.g. home vs. VPN), use `--results DIR`.

## Results

Per endpoint: median, mean, p95, success rate, and the number of runs it appears in. Samples are pooled across all domains and all stored runs. Below the main table:

- **Best per protocol**: fastest endpoint of each protocol.
- **Best per provider**: fastest encrypted endpoint, plus the fastest UDP endpoint if that is faster.

Sorted by median; endpoints below 95% success rank last. Median colours mark the fastest / middle / slowest third. `NO_COLOR=1` disables colours.

CSV columns: `median_ms,avg_ms,p95_ms,category,provider,endpoint,proto,ok,fail,runs`

## Configuration

```text
domains.txt                 # names to time
servers/no-logging.txt      # resolvers, one file per privacy category
servers/anonymized.txt
servers/logging.txt
```

Generated (git-ignored): `results/`, `results.csv`, `adguardhome-dns.yaml`.

### `domains.txt`

One domain per line; blank lines and `#` comments are ignored. More domains give steadier stats but longer runs.

```text
wikipedia.org
google.de
github.com
```

### `servers/*.txt`

The filename is the privacy category (`No Logging` / `Anonymized` / `Logging`); missing files are skipped. `# Name` starts a provider, and every endpoint until the next `# Name` belongs to it. `##` lines are comments. Duplicate endpoints are skipped.

```text
## comment
# Provider Name
1.2.3.4                          # UDP :53
tls://dns.example                # DoT :853
https://dns.example/dns-query    # DoH :443
quic://dns.example               # DoQ :853
h3://dns.example/dns-query       # DoH3 :443
tls://dns.example:8853           # custom port
```

## AdGuard Home (optional)

Menu 6 or `--export-adguard`. It ranks providers from all stored runs, then asks for:

1. privacy level: `no-logging` only, or also `anonymized`, or also `logging`
2. number of providers
3. endpoints per provider
4. path to `AdGuardHome.yaml` (optional; DietPi: `/mnt/dietpi_userdata/adguardhome/AdGuardHome.yaml`)

| Key | Gets |
|-----|------|
| `upstream_dns` | Fastest N providers × M encrypted endpoints (never plain DNS) |
| `fallback_dns` | Fastest encrypted endpoint of the next 2 providers |
| `bootstrap_dns` | Plain IPs of the chosen providers (topped up to at least 2) |

The snippet is always written to `adguardhome-dns.yaml`. If you give a config path, run with `sudo` on the AdGuard host. The tool then does the following, using no extra libraries:

1. stops the service
2. backs up the config to `AdGuardHome.yaml.bak-YYYYMMDD-HHMMSS`
3. replaces only those three keys, keeping `[/lan/]…` rules and clearing `upstream_dns_file`
4. starts the service again

Use `--no-restart` if you manage the service yourself. `--proto` narrows upstream/fallback only; bootstrap always uses plain DNS.

```bash
sudo uv run python querypulse.py --export-adguard --privacy no-logging \
  --providers 2 --per-provider 1 \
  --adguard-config /mnt/dietpi_userdata/adguardhome/AdGuardHome.yaml
```

## License / disclaimer

[MIT](LICENSE) — Copyright (c) 2026 EriusCalrissian

Provided **as is**, without warranty. Measurements and generated configs may be wrong for your network. Use them at your own risk: keep backups, review before applying, verify afterwards.

## AI disclosure

Written with [Cursor](https://cursor.com) against author-defined requirements; human-reviewed and tested. AI output can still be wrong, so verify before production use.
