# NGINX2Root 연구 랩 — nginx 소스 빌드 (linux/amd64 고정)
# 빌드 결정성을 위해 nginx.org 공개 tarball에서 빌드. 디버그 심볼/코어덤프 지향.
# BASE 기본 bookworm(glibc 2.36). QUIC(121810) 실습은 trixie(OpenSSL 3.5+) 권장.
ARG BASE=debian:bookworm-slim
FROM --platform=linux/amd64 ${BASE}

ARG NGX_VERSION=1.31.8
LABEL org.opencontainers.image.title="nginx2root-lab" \
      org.opencontainers.image.version="${NGX_VERSION}" \
      io.windshock.usage="vulnerability research lab (self-owned targets only)"

RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc make libc6-dev libpcre2-dev zlib1g-dev libssl-dev \
      openssl ca-certificates curl procps iproute2 \
    && rm -rf /var/lib/apt/lists/*

# --with-debug: h2 상태머신 디버그 로그 (트리거 개발용; e2e 프로파일 재현 시 conf로 level 조정)
RUN curl -fsSL "https://nginx.org/download/nginx-${NGX_VERSION}.tar.gz" -o /tmp/nginx.tar.gz \
    && tar zxf /tmp/nginx.tar.gz -C /tmp/ \
    && cd /tmp/nginx-${NGX_VERSION} \
    && ./configure \
        --prefix=/usr/local/nginx \
        --with-debug \
        --with-http_ssl_module \
        --with-http_v2_module \
        --with-http_v3_module \
        --with-http_stub_status_module \
        --with-mail \
        --with-mail_ssl_module \
        --with-stream \
        --with-stream_ssl_module \
        --with-stream_ssl_preread_module \
    && make -j"$(nproc)" \
    && make install \
    && rm -rf /tmp/nginx*

# 정적 파일 타깃: 본문 정확히 896바이트 (Rapid7 프로파일 전제 — 74 요청으로
# 커넥션 윈도우 65,535 소진 방정식이 성립하고 max_concurrent_streams 128 이내 유지)
RUN { echo '<h1>nginx2root-lab</h1>'; head -c 900 /dev/zero | tr '\0' 'x'; } \
    > /usr/local/nginx/html/index.html \
    && truncate -s 896 /usr/local/nginx/html/index.html

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /cores

EXPOSE 443 143

ENTRYPOINT ["/entrypoint.sh"]
