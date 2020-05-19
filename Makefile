build:
	cargo build
	cargo clippy -- -Dclippy::all
	cargo fmt -- --check

release:
	cargo build --release

test: build
	RUST_BACKTRACE=1 cargo test -- --nocapture
