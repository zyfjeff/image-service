FROM clux/muslrust:1.49.0

RUN echo '[source.crates-io] \n\
  replace-with = "ustc" \n\
  [source.ustc] \n\
  registry = "https://mirrors.ustc.edu.cn/crates.io-index"'\
  >> /root/.cargo/config

ENV RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static

RUN rustup component add clippy
RUN rustup component add rustfmt
RUN rustup target add x86_64-unknown-linux-musl

RUN echo '#!/bin/bash \n chmod 400 /root/.ssh/id_rsa && eval `ssh-agent` && ssh-add; exec "$@"' > /entrypoint.sh; chmod +x /entrypoint.sh

WORKDIR /nydus-rs

CMD make static-release

ENTRYPOINT ["/entrypoint.sh"]
