#!/usr/bin/env python3
"""
OSI Explorer backend.

Given a URL, it performs a REAL request and reports the per-layer detail:
  - L7 DNS  : real UDP DNS query/response (addresses + TTL)
  - L4/L3   : real TCP connection facts (src/dst IP + ports)
  - L6/L5   : real TLS handshake (version, negotiated cipher, certificate, SNI)
  - L7 HTTP : real request + response (status + headers)

L2/L1 are not capturable on a cloud VM — the frontend illustrates them.
Lower-layer packet *bytes* are reconstructed by the frontend from these real
facts (this is the "reconstructed" MVP, honestly labeled).

Stdlib only. SSRF-guarded: http/https + ports 80/443 only, public IPs only,
and we connect to the exact validated IP (no DNS-rebinding window).
"""
import os
import ssl
import json
import socket
import struct
import random
import ipaddress
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.environ.get("OSI_HOST", "127.0.0.1")
PORT = int(os.environ.get("OSI_PORT", "8091"))
TIMEOUT = 8
UA = "OSI-Explorer/1.0 (+https://chrome.net.ua/osi/)"


# ---------- SSRF validation ----------
def validate(raw_url):
    if "://" not in raw_url:
        raw_url = "http://" + raw_url
    u = urlparse(raw_url)
    if u.scheme not in ("http", "https"):
        raise ValueError("only http/https URLs are allowed")
    host = u.hostname
    if not host:
        raise ValueError("no hostname in URL")
    port = u.port or (443 if u.scheme == "https" else 80)
    if port not in (80, 443):
        raise ValueError("only ports 80 and 443 are allowed")
    # resolve and require ALL results to be public
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError("could not resolve hostname")
    ips = []
    for fam, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        a = ipaddress.ip_address(ip)
        if (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
                or a.is_multicast or a.is_unspecified):
            raise ValueError("blocked: resolves to a non-public address")
        ips.append((fam, ip))
    # prefer IPv4 for the actual connection (simpler to display)
    ips.sort(key=lambda x: 0 if x[0] == socket.AF_INET else 1)
    return u.scheme, host, port, (u.path or "/"), ips


# ---------- L7 DNS: real UDP query to the system resolver ----------
def _resolvers():
    out = []
    try:
        for line in open("/etc/resolv.conf"):
            line = line.strip()
            if line.startswith("nameserver"):
                ip = line.split()[1]
                try:
                    ipaddress.ip_address(ip)
                    out.append(ip)
                except ValueError:
                    pass
    except Exception:
        pass
    for pub in ("8.8.8.8", "1.1.1.1"):
        if pub not in out:
            out.append(pub)
    return out


def _encode_qname(host):
    return b"".join(bytes([len(p)]) + p.encode() for p in host.split(".")) + b"\x00"


def dns_query(host, qtype=1):
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)  # RD=1, 1 question
    question = _encode_qname(host) + struct.pack(">HH", qtype, 1)
    packet = header + question
    resolver = None
    data = None
    last_err = None
    for res in _resolvers():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(4)
            s.sendto(packet, (res, 53))
            data, _ = s.recvfrom(4096)
            s.close()
            resolver = res
            break
        except Exception as e:
            last_err = e
            try:
                s.close()
            except Exception:
                pass
    if data is None:
        raise ValueError("DNS query failed: %s" % last_err)
    ancount = struct.unpack(">H", data[6:8])[0]
    idx = 12
    while data[idx] != 0:                       # skip question qname
        idx += data[idx] + 1
    idx += 1 + 4                                # null + qtype + qclass
    answers = []
    for _ in range(ancount):
        if data[idx] & 0xC0:                    # compressed name pointer
            idx += 2
        else:
            while data[idx] != 0:
                idx += data[idx] + 1
            idx += 1
        atype, aclass, ttl, rdlen = struct.unpack(">HHIH", data[idx:idx + 10])
        idx += 10
        rdata = data[idx:idx + rdlen]
        idx += rdlen
        if atype == 1 and rdlen == 4:
            answers.append({"type": "A", "data": socket.inet_ntoa(rdata), "ttl": ttl})
        elif atype == 28 and rdlen == 16:
            answers.append({"type": "AAAA", "data": socket.inet_ntop(socket.AF_INET6, rdata), "ttl": ttl})
        elif atype == 5:
            answers.append({"type": "CNAME", "data": "(alias)", "ttl": ttl})
    return {
        "resolver": resolver,
        "transaction_id": tid,
        "question": {"name": host, "type": "A", "class": "IN"},
        "query_bytes": packet.hex(),
        "query_len": len(packet),
        "answers": answers,
    }


# ---------- L7 DNS: recursive walk (root -> TLD -> authoritative) ----------
_RTYPE = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 28: "AAAA"}
ROOTS = [("a.root-servers.net", "198.41.0.4"),
         ("f.root-servers.net", "192.5.5.241"),
         ("k.root-servers.net", "193.0.14.129")]


def _parse_name(data, idx):
    labels, jumped, start = [], False, idx
    while True:
        length = data[idx]
        if length == 0:
            idx += 1
            break
        if length & 0xC0 == 0xC0:                # compression pointer
            ptr = ((length & 0x3F) << 8) | data[idx + 1]
            if not jumped:
                start = idx + 2
            idx = ptr
            jumped = True
            continue
        idx += 1
        labels.append(data[idx:idx + length].decode("latin1"))
        idx += length
    return ".".join(labels), (start if jumped else idx)


def _parse_rr(data, idx):
    name, idx = _parse_name(data, idx)
    rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[idx:idx + 10])
    idx += 10
    val = None
    if rtype == 1 and rdlen == 4:
        val = socket.inet_ntoa(data[idx:idx + rdlen])
    elif rtype == 28 and rdlen == 16:
        val = socket.inet_ntop(socket.AF_INET6, data[idx:idx + rdlen])
    elif rtype in (2, 5):                        # NS / CNAME
        val, _ = _parse_name(data, idx)
    idx += rdlen
    return {"name": name, "type": _RTYPE.get(rtype, str(rtype)), "ttl": ttl, "data": val}, idx


def _parse_msg(data):
    _, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    idx = 12
    for _ in range(qd):
        _, idx = _parse_name(data, idx)
        idx += 4
    def sect(n):
        nonlocal idx
        out = []
        for _ in range(n):
            rr, idx = _parse_rr(data, idx)
            out.append(rr)
        return out
    return {"answers": sect(an), "authority": sect(ns), "additional": sect(ar)}


def _query_server(server_ip, host, qtype=1, rd=0):
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100 if rd else 0x0000, 1, 0, 0, 0)
    packet = header + _encode_qname(host) + struct.pack(">HH", qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(packet, (server_ip, 53))
        data, _ = s.recvfrom(4096)
    finally:
        s.close()
    return _parse_msg(data)


def dns_trace(host, qtype=1, max_hops=10):
    """Iteratively resolve host starting from a root server; return each step."""
    steps = []
    name, ip, level = ROOTS[0][0], ROOTS[0][1], "root"
    target = host
    for _ in range(max_hops):
        try:
            msg = _query_server(ip, target, qtype, rd=0)
        except Exception as e:
            steps.append({"level": level, "server": name, "server_ip": ip,
                          "result": "error", "detail": str(e)[:60]})
            break
        a = [r for r in msg["answers"] if r["type"] in ("A", "AAAA")]
        cn = [r for r in msg["answers"] if r["type"] == "CNAME"]
        if a:
            steps.append({"level": level, "server": name, "server_ip": ip, "result": "answer",
                          "records": [{"type": r["type"], "data": r["data"], "ttl": r["ttl"]} for r in a[:4]]})
            break
        if cn:
            steps.append({"level": level, "server": name, "server_ip": ip, "result": "cname",
                          "cname": cn[0]["data"]})
            target = cn[0]["data"]
            name, ip, level = ROOTS[0][0], ROOTS[0][1], "root"
            continue
        nslist = [r for r in msg["authority"] if r["type"] == "NS"]
        glue = {r["name"].rstrip("."): r["data"] for r in msg["additional"] if r["type"] == "A"}
        if not nslist:
            steps.append({"level": level, "server": name, "server_ip": ip, "result": "no-referral"})
            break
        zone = nslist[0]["name"].rstrip(".")
        chosen = nslist[0]["data"].rstrip(".")
        steps.append({"level": level, "server": name, "server_ip": ip, "result": "referral",
                      "zone": zone or "(root)",
                      "nameservers": [n["data"].rstrip(".") for n in nslist[:4]], "next": chosen})
        nxt = glue.get(chosen)
        if not nxt:
            try:
                nxt = socket.gethostbyname(chosen)
            except Exception:
                nxt = None
        if not nxt:
            break
        name, ip = chosen, nxt
        level = "tld" if zone.count(".") == 0 else "authoritative"
    return {"start": ROOTS[0][0], "hops": steps}


# ---------- L6/L5 TLS handshake ladder (canonical for the negotiated version) ----------
def build_handshake(version):
    if version and "1.3" in version:
        return {
            "summary": "1 round-trip · certificate is encrypted",
            "steps": [
                {"from": "client", "msg": "ClientHello", "detail": "offers ciphers, key_share, SNI, ALPN", "enc": False},
                {"from": "server", "msg": "ServerHello", "detail": "picks cipher + key_share", "enc": False},
                {"from": "server", "msg": "EncryptedExtensions · Certificate · CertificateVerify · Finished", "detail": "server proves identity — encrypted", "enc": True},
                {"from": "client", "msg": "Finished", "detail": "session established", "enc": True},
            ],
        }
    return {
        "summary": "2 round-trips · certificate sent in the clear",
        "steps": [
            {"from": "client", "msg": "ClientHello", "detail": "offers ciphers, SNI", "enc": False},
            {"from": "server", "msg": "ServerHello", "detail": "picks cipher", "enc": False},
            {"from": "server", "msg": "Certificate · ServerKeyExchange · ServerHelloDone", "detail": "cert in the clear", "enc": False},
            {"from": "client", "msg": "ClientKeyExchange · ChangeCipherSpec · Finished", "detail": "switch to encrypted", "enc": False},
            {"from": "server", "msg": "ChangeCipherSpec · Finished", "detail": "session established", "enc": False},
        ],
    }


# ---------- L6/L5 cert helper ----------
def _parse_cert(cert):
    if not cert:
        return None
    def flat(seq):
        out = {}
        for rdn in seq:
            for k, v in rdn:
                out[k] = v
        return out
    subj = flat(cert.get("subject", []))
    iss = flat(cert.get("issuer", []))
    sans = [v for (t, v) in cert.get("subjectAltName", []) if t == "DNS"]
    return {
        "subject_cn": subj.get("commonName"),
        "issuer_cn": iss.get("commonName"),
        "issuer_org": iss.get("organizationName"),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "sans": sans[:10],
        "san_count": len(sans),
    }


# ---------- L4/L3 + L6/L5 + L7: connect to the exact validated IP ----------
def inspect(host, ip, family, port, scheme, path):
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    sock.connect((ip, port))
    la, ra = sock.getsockname(), sock.getpeername()
    tcp = {"src_ip": la[0], "src_port": la[1], "dst_ip": ra[0], "dst_port": ra[1]}

    tls = None
    stream = sock
    if scheme == "https":
        ctx = ssl.create_default_context()
        offered = [c["name"] for c in ctx.get_ciphers()]
        ss = ctx.wrap_socket(sock, server_hostname=host)
        name, ver, bits = ss.cipher()
        tls = {
            "version": ss.version(),
            "cipher": name,
            "bits": bits,
            "sni": host,
            "alpn": ss.selected_alpn_protocol(),
            "offered_count": len(offered),
            "offered_sample": offered[:12],
            "cert": _parse_cert(ss.getpeercert()),
            "handshake": build_handshake(ss.version()),
        }
        stream = ss

    req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n"
           "Connection: close\r\n\r\n") % (path, host, UA)
    stream.sendall(req.encode())
    resp = b""
    while b"\r\n\r\n" not in resp and len(resp) < 65536:
        chunk = stream.recv(4096)
        if not chunk:
            break
        resp += chunk
    head = resp.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace")
    lines = head.split("\r\n")
    status = lines[0] if lines else ""
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip()] = v.strip()
    try:
        stream.close()
    except Exception:
        pass
    http = {
        "request": {"method": "GET", "path": path, "host": host,
                    "headers": {"Host": host, "User-Agent": UA, "Accept": "*/*"}},
        "status_line": status,
        "response_headers": headers,
    }
    return tcp, tls, http


def analyze(raw_url):
    scheme, host, port, path, ips = validate(raw_url)
    dns = dns_query(host)
    try:
        dns["trace"] = dns_trace(host)
    except Exception as e:
        dns["trace"] = {"error": str(e)[:80]}
    family, ip = ips[0]
    tcp, tls, http = inspect(host, ip, family, port, scheme, path)
    return {
        "ok": True,
        "url": raw_url,
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": path,
        "dns": dns,
        "tcp": tcp,
        "tls": tls,
        "http": http,
    }


# ---------- HTTP server ----------
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, obj):
        payload = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.rstrip("/") == "/api/health":
            return self._send(200, {"ok": True})
        self._send(404, {"error": "not_found"})

    def do_POST(self):
        if self.path.rstrip("/") != "/api/analyze":
            return self._send(404, {"error": "not_found"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(min(n, 8192)).decode("utf-8"))
            url = (body.get("url") or "").strip()[:2048]
            if not url:
                return self._send(400, {"ok": False, "error": "no URL provided"})
        except Exception:
            return self._send(400, {"ok": False, "error": "invalid request"})
        try:
            return self._send(200, analyze(url))
        except ValueError as e:
            return self._send(400, {"ok": False, "error": str(e)})
        except (socket.timeout, TimeoutError):
            return self._send(504, {"ok": False, "error": "connection timed out"})
        except ssl.SSLError as e:
            return self._send(502, {"ok": False, "error": "TLS error: %s" % (e.reason or e)})
        except Exception as e:
            return self._send(502, {"ok": False, "error": "could not complete request: %s" % str(e)[:120]})


def main():
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print("osi-explorer on %s:%d" % (HOST, PORT))
    srv.serve_forever()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:                       # CLI test mode
        try:
            print(json.dumps(analyze(sys.argv[1]), indent=2))
        except Exception as e:
            print(json.dumps({"ok": False, "error": str(e)}))
    else:
        main()
