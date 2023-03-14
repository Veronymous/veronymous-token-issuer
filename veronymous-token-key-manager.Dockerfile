FROM ubuntu:22.04

WORKDIR /opt/vt-key-manager

# Build context is target/release
ADD ./vt-key-manager ./bin/vt-key-manager

ENTRYPOINT ["./bin/vt-key-manager"]