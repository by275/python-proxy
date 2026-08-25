ARG ALPINE_VER=3.24

FROM alpine:${ALPINE_VER} AS alpine
RUN apk add --no-cache \
    py3-pycryptodome \
    py3-uvloop \
    tini \
    tzdata

FROM alpine AS builder
ARG PPROXY_VERSION=0.0.0
ENV SETUPTOOLS_SCM_PRETEND_VERSION=${PPROXY_VERSION}
RUN apk add --no-cache py3-pip
WORKDIR /src
COPY pyproject.toml README.rst LICENSE MANIFEST.in ./
COPY pproxy ./pproxy
RUN pip install --root=/bar --no-cache-dir --no-deps .
COPY --chmod=775 docker/entrypoint.sh /bar/entrypoint.sh

FROM alpine AS release
LABEL maintainer="by275"
LABEL org.opencontainers.image.source=https://github.com/by275/python-proxy
COPY --from=builder /bar/ /
USER root
ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
