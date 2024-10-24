all: check build test

export RUSTFLAGS=-Dwarnings

test:
	cargo test

build:
	cargo build --target wasm32-unknown-unknown --release
	CARGO_TARGET_DIR=target-tiny cargo +nightly build --target wasm32-unknown-unknown --release \
		-Z build-std=std,panic_abort \
		-Z build-std-features=panic_immediate_abort
	cd target/wasm32-unknown-unknown/release/ && \
		for i in *.wasm ; do \
			wasm-opt -Oz "$$i" -o "$$i.tmp" && mv "$$i.tmp" "$$i"; \
			ls -l "$$i"; \
		done
	cd target-tiny/wasm32-unknown-unknown/release/ && \
		for i in *.wasm ; do \
			wasm-opt -Oz "$$i" -o "$$i.tmp" && mv "$$i.tmp" "$$i"; \
			ls -l "$$i"; \
		done

check:
	cargo check --all-targets
	cargo check --target wasm32-unknown-unknown

watch:
	cargo watch --clear --watch-when-idle --shell '$(MAKE)'

fmt:
	rustfmt $$(find . -type f -name '*.rs' -print)

clean:
	cargo clean
	CARGO_TARGET_DIR=target-tiny cargo +nightly clean
