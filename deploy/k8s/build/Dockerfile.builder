ARG BUILDER_BASE
FROM ${BUILDER_BASE}
ARG GO_VERSION
ARG GO_SHA256
ARG RUST_TOOLCHAIN
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates clang cmake curl git libclang-dev \
    libssl-dev llvm-dev make openssh-client perl pkg-config protobuf-compiler xz-utils \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz \
    && printf '%s  /tmp/go.tar.gz\n' "${GO_SHA256}" | sha256sum -c - \
    && tar -C /usr/local -xzf /tmp/go.tar.gz && rm /tmp/go.tar.gz
RUN rustup toolchain install "${RUST_TOOLCHAIN}" --profile minimal --component rust-src
ENV PATH="/usr/local/go/bin:/usr/local/cargo/bin:${PATH}"
ENV GOTOOLCHAIN=local GOAMD64=v1
