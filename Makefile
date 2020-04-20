build: pre-build post-check

release: pre-release post-check

pre-build:
	cargo build

pre-release:
	cargo build --release

post-check:
	cargo clippy && \
	cargo fmt
