.PHONY: build format

build:
	npm run build

format:
	npx prettier --write .
	cargo fmt --all --manifest-path crates/wasm/Cargo.toml
