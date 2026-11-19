#!/usr/bin/env python3
"""dnssim — 응답 지연 제어 DNS 시뮬레이터 (CVE-2026-123634 대기목록 경합용).

동작:
  - DNS A 질의 수신 → 지연 후 A 응답 (127.0.0.1)
  - 지연 제어: <name>.d<N>.test → N 초 지연 (예: host.d5.test → 5초), 그 외 즉시
  - NXDOMAIN: <name>.nx.test → 지연 후 NXDOMAIN
  - CNAME (123634 재설계): <name>.c<N>.test → 즉시 CNAME → "<N>.d<기본지연>.test"
    → nginx가 별칭을 재질의 → 원 이름의 대기 ctx들이 CNAME 재시작 경로(8492a8b8a 인접)를
    통과 후 별칭 노드의 대기목록으로 이동. 별칭이 NXDOMAIN(nx 별칭)이면 에러 보고 경로.
의존성 없음 (struct로 최소 DNS 인코딩/디코딩).
수정 이력:
  2026-11-19 서버/핸들러 클래스 구조 오류(무응답) 수정 (ep01 실측).
  2026-11-20 CNAME 응답 지원 추가 (123634 가설 재설계 — RESEARCH-PLAN §4 허용분).
"""
import socket
import socketserver
import struct
import time

DEFAULT_CNAME_DELAY = "3"   # 별칭 대상의 기본 지연 (초)


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


def build_response(tid, name, rcode=0, ip="127.0.0.1", cname=None):
    flags = 0x8180 | rcode  # QR|RD|RA + rcode
    ancount = 1 if (rcode == 0 and (cname or ip)) else 0
    hdr = tid + struct.pack("!HHHHH", flags, 1, ancount, 0, 0)
    q = encode_name(name) + struct.pack("!HH", 1, 1)  # A IN
    body = b""
    if rcode == 0 and cname:
        # CNAME RR: type 5, class IN, ttl 0, rdata = 별칭 이름
        alias = encode_name(cname)
        body += encode_name(name) + struct.pack("!HHIH", 5, 1, 0, len(alias)) + alias
    elif rcode == 0 and ip:
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
        cname = None
        if name.endswith(".nx.test"):
            rcode = 3  # NXDOMAIN
            base = name[: -len(".nx.test")]
            if ".d" in base:
                delay = float(base.split(".d")[-1].split(".")[0])
        elif ".c" in name and name.endswith(".test"):
            # CNAME 경로: h1.c5.test → CNAME → "x.d5.test" (5초 지연 A)
            #   에러 변형: h1.c5nx.test → CNAME → "x.d5.nx.test" (5초 후 NXDOMAIN)
            #   → nginx가 별칭을 재질의하며 원 이름 대기 ctx들이 CNAME 재시작 경로를 통과
            try:
                d_part = name.split(".c", 1)[1].split(".")[0]  # "5" 또는 "5nx"
                if d_part.endswith("nx"):
                    cname = "x.d%s.nx.test" % d_part[:-2]
                else:
                    cname = "x.d%s.test" % d_part
                delay = 0.0
            except ValueError:
                pass
        elif ".d" in name:
            try:
                delay = float(name.split(".d")[-1].split(".")[0])
            except ValueError:
                delay = 0.0
        if delay:
            time.sleep(delay)
        resp = build_response(tid, name, rcode=rcode, cname=cname)
        sock.sendto(resp, self.client_address)


class DnsServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    srv = DnsServer(("0.0.0.0", 53), DnsHandler)
    print("[dnssim] listening :53/udp (delay .dN. / nx .nx.test / cname .cN.test)", flush=True)
    srv.serve_forever()
