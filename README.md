# OSI Explorer

Enter a URL, press **Run**, and see a **real** request dissected across the
**7 OSI layers** — DNS resolution, the TCP connection, the TLS handshake &
certificate, and the HTTP exchange.

**Live demo:** https://chrome.net.ua/osi/  ·  deep-link: `?url=https://example.com` auto-runs

![OSI Explorer — a real URL request dissected across the 7 OSI layers](docs/screenshot.png)

## What it shows

For every layer the UI shows *what information is added*, the real values, a
plain-English explanation, and an honesty badge:

| Layer | Shown | Source |
|------|-------|--------|
| **L7 Application** | DNS query (real bytes) + answers/TTL; HTTP request & response | 🟢 **real** |
| **L6 Presentation** | TLS version, negotiated cipher, X.509 certificate | 🟢 **real** |
| **L5 Session** | TLS handshake — SNI, ciphers **offered vs chosen** (the negotiation) | 🟢 **real** |
| **L4 Transport** | TCP ports, 3-way handshake | 🟠 facts real, packet bytes **reconstructed** |
| **L3 Network** | source/destination IP, TTL | 🟢 **real** |
| **L2 Data Link** | MAC framing / first hop | ⚪ **illustrated** |
| **L1 Physical** | bits on the medium | ⚪ **illustrated** |

**Honest by design:** a browser can't sniff L1–L4 off the wire, so the backend
performs a real request and reports the layers it genuinely can (L3–L7). Lower
layers are *reconstructed* from the real connection or *illustrated*, and
labeled as such. `http://` vs `https://` is a built-in teaching contrast — plain
HTTP shows the L7 body in the clear; HTTPS shows the full handshake but the body
is encrypted.

## Architecture

```
browser ──POST /osi/api/analyze──► nginx ──► osi.py (Python stdlib, 127.0.0.1:8091)
                                                │
             real UDP DNS query ────────────────┤  L7 DNS
             TCP connect (to validated IP) ──────┤  L4/L3
             TLS handshake via ssl module ───────┤  L6/L5  (cipher, cert)
             HTTP GET / read headers ────────────┘  L7 HTTP
```

- **Backend:** `server/osi.py` — **stdlib only** (`socket`, `ssl`, `struct`).
- **Frontend:** `web/` — static, renders the 7 layer cards; light/dark theme.

## Security (SSRF)

The URL is user-supplied, so the backend is SSRF-hardened:
- `http`/`https` only, ports **80/443** only;
- the hostname is resolved and **every** resulting IP must be public
  (private / loopback / link-local / reserved ranges are rejected — blocks cloud
  metadata `169.254.169.254`, `127.0.0.1`, etc.);
- it connects to the **exact validated IP** (no DNS-rebinding window);
- short timeouts.

## Setup

```bash
sudo mkdir -p /opt/osi && sudo cp server/osi.py /opt/osi/
sudo cp server/osi.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now osi
curl -s http://127.0.0.1:8091/api/health         # {"ok": true}
```

Serve `web/` statically and reverse-proxy `/osi/api/` to the backend — see
`nginx.conf.example`.

## API

`POST /osi/api/analyze` → `{"url": "https://example.com"}` → JSON with `dns`,
`tcp`, `tls`, `http` sections (or `{"ok": false, "error": "..."}`).

Try it from the shell:
```bash
curl -s -X POST https://chrome.net.ua/osi/api/analyze \
  -H 'Content-Type: application/json' -d '{"url":"https://example.com"}'
```

## License

[MIT](LICENSE) © 2026 Vladyslav Taran
