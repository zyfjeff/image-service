build:
	cargo build
	cargo clippy
	cargo fmt -- --check

release:
	cargo build --release
	cargo clippy
	cargo fmt -- --check

test: build
	RUST_BACKTRACE=1 cargo test -- --nocapture
