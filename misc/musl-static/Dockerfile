ARG ARCH=x86_64

FROM messense/rust-musl-cross:${ARCH}-musl
ARG ARCH=x86_64
ARG RUST_TOOLCHAIN=1.52.1

RUN echo '[source.crates-io] \n\
  replace-with = "ustc" \n\
  [source.ustc] \n\
  registry = "https://mirrors.ustc.edu.cn/crates.io-index"'\
  >> /root/.cargo/config

ENV RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static

# Below is a trick to replace rust tool-chain from base image which is always the newest version.
RUN rustup toolchain install ${RUST_TOOLCHAIN} && rustup default ${RUST_TOOLCHAIN} && \
  rustup target add ${ARCH}-unknown-linux-musl && rustup component add clippy && rustup component add rustfmt

RUN echo '#!/bin/bash \n chmod 400 /root/.ssh/id_rsa && eval `ssh-agent` && ssh-add; exec "$@"' > /entrypoint.sh; chmod +x /entrypoint.sh

WORKDIR /nydus-rs

CMD make static-release

ENTRYPOINT ["/entrypoint.sh"]
