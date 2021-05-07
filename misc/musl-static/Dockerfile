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

WORKDIR /nydus-rs

CMD chmod 400 /root/.ssh/id_rsa && eval `ssh-agent` && ssh-add && make static-release
