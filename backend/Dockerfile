FROM golang:1.25 AS builder

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 go build -o /out/sophon-server ./cmd/server \
    && CGO_ENABLED=1 go build -o /out/sophon-mcp-tools ./cmd/mcp-tools \
    && CGO_ENABLED=1 go build -o /out/sophon-process-supervisor ./cmd/process-supervisor

FROM debian:bookworm-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       chromium fonts-droid-fallback \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 10001 --create-home sophon
WORKDIR /app
COPY --from=builder /out/sophon-server /usr/local/bin/sophon-server
COPY --from=builder /out/sophon-mcp-tools /usr/local/bin/sophon-mcp-tools
COPY --from=builder /out/sophon-process-supervisor /usr/local/bin/sophon-process-supervisor

USER sophon
EXPOSE 18080
ENTRYPOINT ["/usr/local/bin/sophon-server"]
