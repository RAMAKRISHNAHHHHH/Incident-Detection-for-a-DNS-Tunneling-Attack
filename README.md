# Signal Watch — DNS Tunneling Incident Detection

A self-contained, client-side web dashboard that analyzes DNS query logs and
flags domains showing behavioral signs of **DNS tunneling** (e.g. tools like
iodine, dnscat2, dns2tcp, or custom C2/exfiltration channels that abuse DNS
as a covert transport).

No build step, no backend, no external dependencies at runtime — it's plain
HTML/CSS/JS, so it opens straight in a browser and is easy to read, extend,
or grade as a learning project.

## Running it in VS Code

1. Open the `dns-tunnel-detector` folder in VS Code (`File → Open Folder…`).
2. Easiest option: install the **Live Server** extension (by Ritwick Dey),
   right-click `index.html` → **Open with Live Server**.
3. No-extension option: just double-click `index.html` to open it directly
   in a browser — everything runs client-side, so `file://` works fine.
4. Alternative: run a tiny local server from the integrated terminal:
   ```bash
   python3 -m http.server 8000
   ```
   then open `http://localhost:8000`.

## What it does

On load, it generates a synthetic 20-minute capture window of DNS queries:
normal browsing noise (github.com, slack.com, etc.) plus two injected
tunneling incidents at different volumes, so you can see the detector both
catch an obvious high-volume exfil channel and correctly rank a smaller,
quieter one above the noise.

- **Query stream** — a replay of the raw log, with entries belonging to a
  flagged domain highlighted.
- **Domains by risk score** — every apex domain seen, ranked by a 0–100
  composite risk score, colored by severity.
- **Detail panel** — pick any domain to see its metrics, per-signal
  breakdown, and the highest-entropy sample queries that drove the score.
- **Generate new sample traffic** — reshuffles the synthetic dataset (new
  random encoded payloads, timings, and source IPs) so it's a working
  detector, not a fixed screenshot.
- **Load log file (.json)** — swap in your own log. See
  `data/sample-log-schema.json` for the expected shape (`timestamp`,
  `srcIp`, `queryName`, `queryType`).

## Detection logic

DNS tunneling doesn't look suspicious query-by-query — the tell is in the
*pattern* across many queries to the same apex domain. `js/detector.js`
scores each domain by combining independent signals:

| Signal | Why it matters |
|---|---|
| **Label entropy** | Encoded payloads (base32/base64/hex) look statistically close to random; human-chosen subdomains don't. |
| **Label length** | Tunneling tools pack data close to DNS's 63-byte label / 253-byte name limits. |
| **Charset shape** | Payload labels are vowel-starved and code-alphabet-heavy compared to real words. |
| **Query-type mix** | TXT and NULL records carry more payload per query and are favored by tunneling tools. |
| **Subdomain uniqueness** | Normal traffic re-requests a small set of names; tunneling mints a new, never-repeated label per data chunk. |
| **Query rate & volume** | Sustained high-frequency queries to one apex domain from a single host is unusual for ordinary resolution. |

These are normalized and combined into a weighted 0–100 score per domain
(see `scoreDomain()` in `detector.js`), then bucketed into **normal**
(<40), **suspicious** (40–69), and **likely tunneling** (≥70).

## Limitations — read before relying on this for anything real

This is an educational heuristic engine, intentionally kept simple and
readable:

- Apex-domain extraction is naive (last two labels) — it won't correctly
  handle multi-part public suffixes (e.g. `co.uk`) without extending
  `splitName()` with a public-suffix list.
- Thresholds are illustrative, not tuned against real production baselines.
  Legitimate high-cardinality services (CDNs, some anti-spam/greylisting
  schemes, certain IoT check-ins) can look superficially similar and would
  need allow-listing.
- It has no NXDOMAIN-rate analysis, no passive-DNS/threat-intel lookups, and
  no packet capture — it only sees whatever query records you feed it.
- All data by default is synthetically generated in the browser for
  demonstration; nothing here monitors a real network unless you wire in
  your own log source.

For production detection, pair heuristics like these with allow-lists,
threat intelligence feeds, NXDOMAIN ratio tracking, and proper baselining
against your own traffic.

## File structure

```
dns-tunnel-detector/
├── index.html                 Dashboard markup
├── css/style.css               Visual design
├── js/detector.js              Detection/scoring engine
├── js/data.js                  Synthetic traffic generator + log loader
├── js/app.js                   UI wiring and rendering
└── data/sample-log-schema.json Example log format for your own data
```
