# Sandbox environment for building and executing C/C++ targets.
# Target platform: linux/amd64 (x86_64 ELF).
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

# Non-root sandbox user (UID/GID 1000) for unprivileged binary execution.
RUN groupadd -g 1000 sandbox \
    && useradd -m -u 1000 -g 1000 -s /bin/bash sandbox

WORKDIR /work
USER sandbox
