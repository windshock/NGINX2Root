#!/usr/bin/env python3
"""ALPN 협상 검사 — 각 arm이 h2를 수용하는지 확인 (RESEARCH-PLAN §1-2 계층).

사용: python3 ops/check_alpn.py HOST:PORT [HOST:PORT ...]
출력: 호스트별 "h2" / "http/1.1" / "없음" — A3(완화)은 h2가 아니어야 정상.
의존성 없음 (호스트 python3, macOS LibreSSL 무관).
"""
import socket
import ssl
import sys


def alpn_probe(host, port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection((host, port), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.selected_alpn_protocol() or "(none)"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    for target in sys.argv[1:]:
        host, _, port = target.rpartition(":")
        try:
            proto = alpn_probe(host, int(port))
        except Exception as e:  # noqa: BLE001 — 진단 스크립트
            proto = "ERROR: %s" % e
        print("%-28s ALPN=%s" % (target, proto))
