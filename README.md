# xtunnel

QUIC tunnel proxy:

```text
routes:          user -> client local port -> client -> QUIC server -> target
reverse_routes:  user -> server remote port -> QUIC server -> client -> target
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

reverse_routes:
  - remote_port: 9000
    target: "127.0.0.1:3000"
    protocol: "tcp"
```

`reverse_routes` are configured only on the client. The client keeps a connection to the
server and asks it to listen on `remote_port` (all interfaces); traffic arriving there is tunneled
back and dialed to `target` from the client machine. The server releases the port when the client
disconnects, and the client re-binds automatically after reconnecting. A new bind for a port that
is already bound replaces the previous one.

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
