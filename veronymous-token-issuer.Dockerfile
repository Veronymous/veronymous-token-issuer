FROM ubuntu:22.04

WORKDIR /opt/vt-issuer

# Build context is target/release
ADD ./vt-issuer ./bin/vt-issuer

ENTRYPOINT ["./bin/vt-issuer"]