FROM docker:dind

ENV NYDUS_IMAGE=/nydus-rs/target-fusedev/x86_64-unknown-linux-musl/release/nydus-image
ENV NYDUSD=/nydus-rs/target-fusedev/x86_64-unknown-linux-musl/release/nydusd
WORKDIR /nydus-rs/contrib/nydusify/tests
ENTRYPOINT [ "/bin/sh", "-c" ]

CMD [ "dockerd-entrypoint.sh --registry-mirror=https://docker.mirrors.ustc.edu.cn/ & sleep 5 && mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2 && ../nydusify-smoke" ]
