#!/bin/bash

# Build the binary
cargo build --release --manifest-path ./key-manager/Cargo.toml

# Build the docker file
docker build -t vt-key-manager -f veronymous-token-key-manager.Dockerfile ./target/release/