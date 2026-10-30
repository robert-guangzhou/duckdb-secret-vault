# secret_vault 构建容器(复用 duckdb-nats-rw 模式,见其 docs/notes-build.md)
# 基线 rust:1.90-bookworm:glibc 2.36。
# 用法:docker build -t secret-vault-builder -f docker/dev.Dockerfile docker/
#      docker run -d --name secret-vault-builder \
#        -v $PWD:/workspace -v sv-cargo-registry:/usr/local/cargo/registry \
#        -v sv-cargo-git:/usr/local/cargo/git secret-vault-builder sleep infinity
#      docker exec secret-vault-builder bash -c \
#        'export PATH=/usr/local/cargo/bin:$PATH; cd /workspace && make reldebug'
FROM rust:1.90-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        ninja-build \
        git \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# cbindgen CLI:供 rust/regen-header.sh 重新生成 C 头文件
RUN cargo install --locked cbindgen

WORKDIR /workspace
