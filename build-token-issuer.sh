#!/bin/bash

# Build the binary
cargo build --release --manifest-path ./token-issuer/Cargo.toml

# Build the docker file
docker build -t vt-issuer -f veronymous-token-issuer.Dockerfile ./target/release/