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

# QUIC servers the client connects to.
tunnels:
  - name: "sg"
    server_addr: "1.2.3.4:443"
    secret_key: "change-me"
  - name: "hk"
    server_addr: "5.6.7.8:443"
    secret_key: "change-me-too"
    socks5:
      listen: "127.0.0.1:1081"   # SOCKS5 proxy whose connections go out through "hk"

routes:
  - local_port: 8080
    target: "127.0.0.1:80"
    protocol: "tcp"
    tunnel: "sg"
  - local_port: 5353
    target: "8.8.8.8:53"
    protocol: "udp"
    tunnel: "hk"

reverse_routes:
  - remote_port: 9000       # opened on the "sg" server
    target: "127.0.0.1:3000"
    protocol: "tcp"
    tunnel: "sg"
```

- `tunnel` picks the server a route goes through; it may be left out when there is only one tunnel.
  Each tunnel connects, reconnects and restarts on its own, and can be turned off with
  `disabled: true`.
- `socks5` on a tunnel runs a SOCKS5 proxy (TCP CONNECT) whose connections go through that tunnel:
  its server dials the target, as for a route, for any host the application asks for. It is optional:
  `socks5.disabled: true` turns it off and keeps its settings (VPN proxies work the same way).
  Turning a proxy on or off does not restart its tunnel or VPN.
- The older single `client:` section still works; it is read as a tunnel named `default`, and saving
  from the dashboard writes it as `tunnels:`.

`reverse_routes` are configured only on the client. The client keeps a connection to the
server and asks it to listen on `remote_port` (all interfaces); traffic arriving there is tunneled
back and dialed to `target` from the client machine. The server releases the port when the client
disconnects, and the client re-binds automatically after reconnecting. A new bind for a port that
is already bound replaces the previous one.

## FortiVPN

xtunnel has a built-in FortiGate SSL VPN client. It speaks the gateway's PPP-over-TLS protocol
(as [openfortivpn](https://github.com/adrienverge/openfortivpn) does) and routes connections through
a userspace TCP/IP stack ([gVisor netstack](https://gvisor.dev)), so the VPN is only used by xtunnel's
own connections: no root, no ppp device, and the OS routes and DNS are left untouched.

Name each VPN and pick one per route with `fortivpn: <name>`:

```yaml
fortivpns:
  - name: "office"
    host: "vpn.example.com"
    port: 443
    username: "user"
    password: "${OFFICE_VPN_PASSWORD}"   # ${NAME} is read from the environment
    # SHA256 digest of a self-signed gateway certificate; the first failed
    # connection logs the value to use.
    trusted_cert: "bb6022...6675"
    # insecure_skip_verify: true   # accept any certificate (not recommended)
  - name: "lab"
    host: "vpn2.example.com"
    username: "user2"
    password: "${LAB_VPN_PASSWORD}"
    socks5:
      listen: "127.0.0.1:1080"   # SOCKS5 proxy through "lab" for other apps
      # username: "me"
      # password: "${SOCKS_PASSWORD}"

routes:
  - local_port: 3389
    target: "10.10.0.5:3389"   # dialed from the client through "office", not via the server
    protocol: "tcp"
    fortivpn: "office"
  - local_port: 8080
    target: "127.0.0.1:80"     # normal route through the QUIC server
    protocol: "tcp"

reverse_routes:
  - remote_port: 9001
    target: "intranet.lab:8080" # server:9001 -> client -> "lab" -> target
    protocol: "tcp"
    fortivpn: "lab"
```

- VPNs connect in the background; a route using a VPN that is not up yet fails its connection with
  "tunnel is down". Dropped tunnels reconnect, reusing the session so no new OTP is needed while the
  gateway keeps it; failed attempts back off from `reconnect_interval_sec` (default 5s) up to 5 minutes.
- `socks5.listen` exposes a VPN as a SOCKS5 proxy (TCP CONNECT) for other applications, e.g.
  `curl --socks5-hostname 127.0.0.1:1080 http://intranet/`. Hostnames sent to the proxy are resolved
  by the VPN's DNS. Add `socks5.username`/`password` to require authentication; without them anyone
  who can reach the port can use the VPN, so keep it on localhost.
- Hostnames are resolved with the DNS servers the gateway assigns, then the system resolver.
  Only IPv4 targets are supported.
- Any `${NAME}` in the config file is replaced by the environment variable `NAME`, to keep
  passwords and tokens out of the file.
- Two-factor codes sent by email/SMS are collected through the `otp` section (below). FortiToken
  Mobile push is supported too: approve the notification on the phone.

### Two-factor codes (OTP)

When the gateway asks for a one-time code (email/SMS token), xtunnel
asks a person through the enabled channels; the first code entered is used:

```yaml
web:
  listen: ":18099"              # dashboard + OTP pages
  public_url: "http://my-host:18099"
otp:
  timeout_sec: 600              # give up on the login attempt after 10 minutes
  telegram:
    enabled: true
    bot_token: "123456:ABC..."  # from @BotFather
    # chat_id: 123456789        # optional: without it, the first chat that sends /start is linked
    # chat_id_file: "telegram_chat_id"  # where the linked chat is remembered (default: next to the config)
```

- **web**: the request shows up on the dashboard, and the console logs a link such as
  `http://my-host:18099/otp/<random id>` to submit the code. The link is single-use, expires with the
  request and needs no dashboard login.
- **telegram**: send `/start` to the bot once to link your chat (or a group); it is remembered in
  `chat_id_file` and other chats are refused. The bot then sends each request (with the web link when web is enabled) and takes your
  reply as the code. With several VPNs waiting, reply directly to the matching request message.
  The bot uses long polling (`getUpdates`), so it must not have a webhook set.
- If no code arrives in time, that login attempt fails and is retried later, which makes the gateway
  send a new code and xtunnel a new request. FortiGate codes usually expire after 60 seconds
  (`two-factor-email-expiry`/`two-factor-sms-expiry`), so enter them promptly.

## Dashboard

`web.listen` serves a dashboard at `http://<listen>/`:

- **Overview**: QUIC connection, each VPN's state (address, DNS, last error), pending OTP requests
  with a box to confirm the code, and all routes.
- **Routes / Reverse routes / VPNs / Settings**: edit the config with forms. *Save & apply* validates,
  writes the config file (keeping its comments and `${NAME}` references) and applies it without
  restarting: only what changed restarts, so an untouched VPN keeps its session and needs no new OTP.
  Secrets are shown masked; leave them as is to keep the stored value.
- **YAML**: edit the config file text directly.

- **VPN on/off**: each VPN has a switch. Off disconnects it (and its SOCKS5 proxy) and is saved as
  `disabled: true`; routes using it fail until it is turned back on.

Set `web.password` to require an admin password (login page, 24h session cookie); without it the
dashboard is open. The dashboard can read and change the whole config, passwords included, so keep it
on localhost or set a password. The config file must be writable for saving; in Docker, mount it
without `:ro`. Routes added from the dashboard are only reachable from the host on published ports:
the bundled `docker-compose.yml` publishes 20000-20049 (TCP and UDP) for that.

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
