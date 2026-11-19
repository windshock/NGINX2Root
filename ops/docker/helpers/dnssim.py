#!/usr/bin/env python3
"""dnssim — 응답 지연 제어 DNS 시뮬레이터 (CVE-2026-123634 대기목록 경합용).

동작:
  - DNS A 질의 수신 → 환경변수/인자로 지정한 지연 후 A 응답
  - 지연은 특수 도메인 suffix로 제어: <name>.d<N>.test → N 초 지연
    (예: host.d5.test → 5초) 그 외 도메인은 즉시 127.0.0.1 응답
  - NXDOMAIN 유도: <name>.nx.test → 지연 후 NXDOMAIN
의존성 없음 (struct로 최소 DNS 인코딩/디코딩).
수정 이력: 2026-11-19 — 서버/핸들러 클래스 구조 오류로 무응답이던 버그 수정 (ep01 실측).
"""
import socket
import socketserver
import struct
import time


def parse_query(data):
    """질의 이름·타입·클래스 추출 (최소 파서)."""
    if len(data) < 12:
        return None, None, None, None
    tid = data[0:2]
    qdcount = struct.unpack("!H", data[4:6])[0]
    if qdcount < 1:
        return tid, None, None, None
    pos = 12
    labels = []
    while pos < len(data):
        l = data[pos]
        if l == 0:
            pos += 1
            break
        labels.append(data[pos + 1:pos + 1 + l].decode("latin-1"))
        pos += 1 + l
    if pos + 4 > len(data):
        return tid, None, None, None
    qtype, qclass = struct.unpack("!HH", data[pos:pos + 4])
    name = ".".join(labels)
    return tid, name, qtype, qclass


def encode_name(name):
    out = b""
    for lbl in name.split("."):
        if lbl:
            out += bytes([len(lbl)]) + lbl.encode()
    return out + b"\x00"


def build_response(tid, name, rcode=0, ip="127.0.0.1"):
    flags = 0x8180 | rcode  # QR|RD|RA + rcode
    hdr = tid + struct.pack("!HHHHH", flags, 1, 1, 1 if rcode == 0 else 0, 0)
    q = encode_name(name) + struct.pack("!HH", 1, 1)  # A IN
    body = b""
    if rcode == 0:
        body += encode_name(name) + struct.pack("!HHIH", 1, 1, 5, 4) \
            + socket.inet_aton(ip)
    return hdr + q + body


class DnsHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request[0], self.request[1]
        tid, name, qtype, qclass = parse_query(data)
        if not name:
            return
        delay = 0.0
        rcode = 0
        if name.endswith(".nx.test"):
            rcode = 3  # NXDOMAIN
            base = name[: -len(".nx.test")]
            if ".d" in base:
                delay = float(base.split(".d")[-1].split(".")[0])
        elif ".d" in name:
            try:
                delay = float(name.split(".d")[-1].split(".")[0])
            except ValueError:
                delay = 0.0
        if delay:
            time.sleep(delay)
        resp = build_response(tid, name, rcode=rcode)
        sock.sendto(resp, self.client_address)


class DnsServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    srv = DnsServer(("0.0.0.0", 53), DnsHandler)
    print("[dnssim] listening :53/udp (delay via .dN. suffix, nx via .nx.test)", flush=True)
    srv.serve_forever()
