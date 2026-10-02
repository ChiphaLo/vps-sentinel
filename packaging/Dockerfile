# Build the Linux release binary first. Use a context containing only that binary.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY vps-sentinel /usr/local/bin/vps-sentinel
ENTRYPOINT ["/usr/local/bin/vps-sentinel"]
CMD ["--help"]
