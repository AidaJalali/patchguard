FROM --platform=linux/amd64 ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    ASAN_OPTIONS=detect_leaks=0:symbolize=1:abort_on_error=1 \
    UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
    LANG=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        g++ \
        clang \
        make \
        cmake \
        autoconf \
        automake \
        libtool \
        pkg-config \
        gdb \
        llvm \
        binutils \
        git \
        python3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN if ! getent group 1000 >/dev/null; then groupadd -g 1000 sandbox; fi \
    && if ! getent passwd 1000 >/dev/null; then useradd -m -u 1000 -g 1000 -s /bin/bash sandbox; fi

WORKDIR /work
USER 1000:1000
