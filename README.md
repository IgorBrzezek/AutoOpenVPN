# autoovpn.py

Download VPNBook OpenVPN configs with dynamic website scanning.

## Usage

```
autoovpn --scan                     # scan & display only
autoovpn --get all                  # scan & download all server/protocol combos
autoovpn --get ca                   # download only Canadian servers
autoovpn --get all --proto tcp      # TCP only
autoovpn --get all --port 443       # port 443 only
autoovpn --getlogin FILE            # save login/password to file
autoovpn --get all --inject         # inject auth-user-pass with full path
autoovpn --run us16,tcp443          # download & run server+protocol combo
autoovpn --run file.ovpn --user vpnbook --pwd secret
autoovpn --run file.ovpn --addroute 192.168.53.0/24,10.10.10.1
```

## Options

| Option | Description |
|--------|-------------|
| `--scan` | Only scan and display servers, protocols, credentials |
| `--get {all,ca,us,uk,fr,de}` | Download configs by country |
| `--proto {tcp,udp}` | Protocol filter |
| `--port {443,80,53,25000}` | Port filter |
| `--getlogin FILENAME` | Save login/password to file |
| `--inject` | Inject auth-user-pass with file path into ovpn configs |
| `--run SERVER,PROTOCOL \| file.ovpn` | Download & run a config or run a local .ovpn |
| `--dev N` | TUN device number (1-10) |
| `--timeout HH:MM:SS` | Automatically stop VPN after time |
| `--user USERNAME` | Username for VPN auth (with --run) |
| `--pwd PASSWD` | Password for VPN auth (with --run) |
| `--datafile FILENAME` | Path to auth file (with --run) |
| `--addroute NET/MASK,GATEWAY` | Add route after VPN connects, remove on disconnect |

## --addroute

Adds a static route after the VPN connection is established and removes it when the VPN disconnects.

Example:
```
autoovpn --run us16,tcp443 --addroute 192.168.53.0/24,10.10.10.1
```

The route is added via `ip route add NET/MASK via GATEWAY` after OpenVPN reports "Initialization Sequence Completed". On disconnect (timeout, Ctrl+C, or normal exit), the route is removed via `ip route del NET/MASK via GATEWAY`.
