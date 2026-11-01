# mc-tarpit — Minecraft antibot tarpit for server owners

[![Version](https://img.shields.io/github/v/release/SergeLeon/minecraft-antibot-tarpit)](https://github.com/SergeLeon/minecraft-antibot-tarpit/releases)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://github.com/SergeLeon/minecraft-antibot-tarpit/actions/workflows/ci.yml/badge.svg)](https://github.com/SergeLeon/minecraft-antibot-tarpit/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.7%2B-3776ab)](https://www.python.org)

Drops Minecraft bots that scan and probe your server. A passive sniffer watches
the Minecraft port, parses the handshake and the `Login Start` packet, and puts
unknown sources into [nftables](https://www.netfilter.org/) sets that silently
drop their traffic — scanners cannot even tell the server is alive.

No mods, no plugins, no proxy. `tcpdump` hands over copies of packets, the
kernel enforces the decision, and a broken parse blocks nobody.

Bot fleets like `FishNet`, `IcyOwl1855` or `iNHABITors74961` (adjective-animal
nickname generators) hammer port `25565` around the clock, ping it, then try a
login with a random nickname. This tool makes that pointless.

## Features

- **Nickname tarpit** — a login with a name outside `whitelist.json`/`ops.json`
  puts the IP into an nftables set for a day; the client gets a timeout, not a
  rejection, so it cannot even confirm the server exists.
- **Optional ping filter** — `ping_policy = sink` also blocks status pings from
  addresses that never logged in with a known nickname, which keeps the server
  out of bot lists. Off by default: a ping and a login share one port, so it
  also costs the first join from a new address.
- **Trusted players** — once an IP logs in with a whitelisted name it is trusted
  for 30 days, so its server-list pings keep working.
- **No mods, no plugins, no proxy** — vanilla, Fabric, Paper, lazymc or plain.
- **IPv4 and IPv6** — separate `tarpit6`/`pingsink6` sets, IPv6 frames parsed.
- **Any number of ports** — `ports = 25565,25566,25567` on one host.
- **Three config sources** — file < `MC_TARPIT_*` environment < CLI flags.
- **Policies** — `ping_policy=ignore` and `login_policy=log` decouple the two
  protections, `trust_subnets` exempts LAN or a proxy.
- **Dry run and replay** — `mode=log` and `mc_tarpit.py replay capture.pcap`
  show every decision without blocking anything.
- **Fail-open** — every parse failure means "no decision", never "block".

## Installation

```bash
curl -fsSLO https://github.com/SergeLeon/minecraft-antibot-tarpit/releases/latest/download/install.sh
sudo bash install.sh --server-dir /home/mc/server
```

The installer writes the tool, the config, the systemd unit and one nftables
table, starts the service and prints the first log lines. The server directory
is auto-detected (`~/mcserver`, `/srv/minecraft`, `/opt/minecraft`, …) when
`--server-dir` is omitted.

Two optional extras, if you prefer to look before you leap:

```bash
curl -fsSLO https://github.com/SergeLeon/minecraft-antibot-tarpit/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing   # verify the installer
sudo bash install.sh --check               # print the plan, change nothing
```

`install.sh --help` lists every flag; `--no-start` installs without starting the
service, `--uninstall` removes everything.

## Quick example

```bash
# dry run: prints decisions, blocks nothing
sudo mc_tarpit.py --mode log watch

# production config
sudo tee /etc/mc-tarpit.conf >/dev/null <<'CONF'
[mc-tarpit]
server_dir    = /home/mc/server
ports         = 25565
ping_policy   = ignore
login_policy  = tarpit
trust_subnets = 192.168.0.0/24
CONF
sudo systemctl restart mc-tarpit
```

Real output from a machine running this with `ping_policy = sink`:

```
watching ports=25565 mode=drop ping_policy=sink login_policy=tarpit linktype=276 trusted=1
ping 176.65.148.253 -> pingsink 1m (not trusted)
login 45.153.34.119 name='iNHABITors74961' not-whitelisted
tarpit 45.153.34.119 -> tarpit 1d
```

## Requirements

- Linux with nftables (`nft`) and `tcpdump`
- Python 3.7+, no third-party packages
- a whitelist on the server (`whitelist.json`, with `ops.json` next to it)
- root, or `CAP_NET_RAW` + `CAP_NET_ADMIN` (block in `contrib/mc-tarpit.service`)

## Limitations

- **The first ping of a new IP is always answered** — the reply is already on
  the wire when the sniffer sees the packet. With `ping_policy = sink` every
  following connection from that IP, including the join, is dropped until
  `ping_ttl` expires.
- **Trust is IP based.** A dynamic address means the server shows as offline in
  the multiplayer list until the next successful login.
- **IPv6 extension headers are not followed** — such packets are ignored.

## Links

- [DOCUMENTATION.md](DOCUMENTATION.md) — every config key, environments, nftables, troubleshooting
- [CHANGELOG.md](CHANGELOG.md) — Keep a Changelog + SemVer history
- [SECURITY.md](SECURITY.md) — what runs as root, what the installer touches
- [Releases](https://github.com/SergeLeon/minecraft-antibot-tarpit/releases) — archives and `SHA256SUMS`
- [contrib/](contrib) — nftables table, systemd unit, example config
- [LICENSE](LICENSE) — MIT
