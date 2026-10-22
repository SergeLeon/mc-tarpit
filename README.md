# mc-tarpit — Minecraft antibot tarpit for server owners

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-0.2.1-blue">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="tests" src="https://github.com/SergeLeon/minecraft-antibot-tarpit/actions/workflows/ci.yml/badge.svg">
  <img alt="Python" src="https://img.shields.io/badge/python-3.7%2B-3776ab">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Linux-lightgrey">
</p>

Drops Minecraft bots that scan and probe the server. A passive sniffer watches
the Minecraft port, parses the handshake and the `Login Start` packet, and puts
unknown sources into [nftables](https://www.netfilter.org/) sets that silently
drop their traffic — scanners cannot even tell the server is alive. No mods, no
server-side plugins, no changes to the live connection path: `tcpdump` hands
over copies of packets, the kernel enforces the decision, and a broken parse
blocks nobody.

Bot fleets like `FishNet`, `IcyOwl1855` or `iNHABITors74961` (adjective-animal
nickname generators) hammer port `25565` around the clock, ping it, then try a
login with a random nickname. This tool makes that pointless.

## Features

- **Nickname tarpit** — a login with a name outside `whitelist.json`/`ops.json`
  puts the IP into an nftables set for a day; the client gets a timeout, not a
  rejection, so it cannot even confirm the server exists.
- **Ping filter** — a status ping from an IP that never logged in with a known
  nickname is dropped for 15 minutes, which keeps the server out of bot lists.
- **Trusted players** — once an IP logs in with a whitelisted name it is trusted
  for 30 days, so its server-list pings keep working.
- **No mods, no plugins** — works with vanilla, Fabric, Paper, with lazymc or
  without any proxy.
- **IPv4 and IPv6** — separate `tarpit6`/`pingsink6` sets, IPv6 frames parsed.
- **Any number of ports** — `ports = 25565,25566,25567` on one host.
- **Three config sources** — file < `MC_TARPIT_*` environment < CLI flags.
- **Policies** — `ping_policy=ignore` and `login_policy=log` decouple the two
  protections, `trust_subnets` exempts LAN or a proxy.
- **Dry run and replay** — `mode=log` and `mc_tarpit.py replay capture.pcap`
  show every decision without blocking anything.
- **Fail-open** — every parse failure means "no decision", never "block".

## Installation

Nothing is piped into a root shell: a script that goes straight from `curl` into
`bash` cannot be inspected or verified. Download it, check the published
checksum, look at the plan, then run it.

```bash
# 1. download the installer and the checksums of the latest release
curl -fsSLO https://github.com/SergeLeon/minecraft-antibot-tarpit/releases/latest/download/install.sh
curl -fsSLO https://github.com/SergeLeon/minecraft-antibot-tarpit/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing

# 2. see what it is going to touch (nothing is changed)
sudo bash install.sh --server-dir /home/mc/server --check

# 3. install
sudo bash install.sh --server-dir /home/mc/server
```

The server directory is auto-detected (`~/mcserver`, `/srv/minecraft`,
`/opt/minecraft`, …) if `--server-dir` is omitted. `install.sh --help` lists
every flag; `--no-start` installs without starting the service and
`--uninstall` removes everything.

### What the installer touches

| Path | Action |
| --- | --- |
| `/usr/local/bin/mc_tarpit.py` | the tool (mode 0755) |
| `/etc/mc-tarpit.conf` | config, previous copy kept as `*.bak-<timestamp>` |
| `/etc/systemd/system/mc-tarpit.service` | systemd unit |
| `/etc/nftables.conf` | adds one table, previous copy kept as `*.bak-<timestamp>` |
| `<server_dir>/tarpit-trusted.json` | trusted IP list (only with `--trust`) |

No network access at runtime, no tokens, no keys, no third-party Python
packages. root is needed only for raw packet capture and nftables; a
capability-based setup is documented in [DOCUMENTATION.md](DOCUMENTATION.md).

## Quick example

```bash
# dry run: prints decisions, blocks nothing
sudo mc_tarpit.py --mode log watch

# production config
sudo tee /etc/mc-tarpit.conf >/dev/null <<'CONF'
[mc-tarpit]
server_dir    = /home/mc/server
ports         = 25565
ping_policy   = sink
login_policy  = tarpit
trust_subnets = 192.168.0.0/24
CONF
sudo systemctl restart mc-tarpit
```

Real output from a machine running this:

```
watching ports=25565 mode=drop ping_policy=sink login_policy=tarpit linktype=276 trusted=1
ping 176.65.148.253 -> pingsink 15m (not trusted)
login 45.153.34.119 name='iNHABITors74961' not-whitelisted
tarpit 45.153.34.119 -> tarpit 1d
```

## Requirements

- Linux with nftables (`nft`) and `tcpdump`
- Python 3.7+, no third-party packages
- a whitelist on the server (`whitelist.json`, with `ops.json` next to it)
- root, or `CAP_NET_RAW` + `CAP_NET_ADMIN`

## Limitations

- **The first ping of a new IP is always answered** — the reply is already on
  the wire when the sniffer sees the packet. Every following connection from
  that IP is dropped.
- **Trust is IP based.** A dynamic address means the server shows as offline in
  the multiplayer list until the next successful login.
- **IPv6 extension headers are not followed** — such packets are ignored.

## Links

- [DOCUMENTATION.md](DOCUMENTATION.md) — every config key, environments, nftables, troubleshooting
- [CHANGELOG.md](CHANGELOG.md) — Keep a Changelog + SemVer history
- [SECURITY.md](SECURITY.md) — what runs as root, what the installer touches
- [Releases](https://github.com/SergeLeon/minecraft-antibot-tarpit/releases) — archives, `SHA256SUMS`
- [contrib/](contrib) — nftables table, systemd unit, example config
- [LICENSE](LICENSE) — MIT
