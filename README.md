# xtunnel

QUIC tunnel proxy:

```text
user -> local port -> client -> QUIC server -> target
```

## Build

```bash
go build -o xtunnel ./cmd/xtunnel
```

## Config

See `internal/config/sample.yaml`.

```yaml
server:
  listen: ":8443"

client:
  server_addr: "127.0.0.1:8443"

routes:
  - local_port: 8080
    target: "127.0.0.1:80"
    protocol: "tcp"
  - local_port: 5353
    target: "8.8.8.8:53"
    protocol: "udp"
```

## Run

Server:

```bash
./xtunnel -s -f ./config.yaml
```

Client:

```bash
./xtunnel -c -f ./config.yaml
```

The receiver and connector packages expose interfaces so more tunnel transports can be added later. The current implementations are `QuicReceiver` and `QuicConnector`.
