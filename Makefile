build: build-virtiofsd build-fusedev
	cargo fmt -- --check

build-virtiofsd:
	# TODO: switch to --out-dir when it moves to stable
	# For now we build with separate target directories
	cargo build --features=virtiofsd --target-dir target-virtiofsd
	cargo clippy --features=virtiofsd --target-dir target-virtiofsd -- -Dclippy::all

build-fusedev:
	cargo build --features=fusedev --target-dir target-fusedev
	cargo clippy --features=fusedev --target-dir target-fusedev -- -Dclippy::all

release:
	cargo build --features=virtiofsd --release --target-dir target-virtiofsd
	cargo build --features=fusedev --release --target-dir target-fusedev

test: build
	RUST_BACKTRACE=1 cargo test --features=virtiofsd --target-dir target-virtiofsd -- --nocapture
	RUST_BACKTRACE=1 cargo test --features=fusedev --target-dir target-fusedev -- --nocapture

docker-smoke:
	docker build -t nydus-rs-smoke misc/
	docker run -it --rm --privileged -v ${PWD}:/nydus-rs -v ~/.ssh/id_rsa:/root/.ssh/id_rsa -v ~/.cargo:/usr/local/cargo nydus-rs-smoke
