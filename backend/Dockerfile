FROM golang:1.25 AS builder

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 go build -o /out/sophon-server ./cmd/server \
    && CGO_ENABLED=1 go build -o /out/sophon-mcp-tools ./cmd/mcp-tools

FROM debian:bookworm-slim

RUN useradd --system --uid 10001 --create-home sophon
WORKDIR /app
COPY --from=builder /out/sophon-server /usr/local/bin/sophon-server
COPY --from=builder /out/sophon-mcp-tools /usr/local/bin/sophon-mcp-tools

USER sophon
EXPOSE 18080
ENTRYPOINT ["/usr/local/bin/sophon-server"]
