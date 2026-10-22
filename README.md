# mc-tarpit

[![tests](https://github.com/SergeLeon/mc-tarpit/actions/workflows/ci.yml/badge.svg)](https://github.com/SergeLeon/mc-tarpit/actions/workflows/ci.yml)

Drops Minecraft bots that probe your server. A passive sniffer watches the
Minecraft ports, parses the handshake and the `Login Start` packet, and puts
unknown sources into [nftables](https://www.netfilter.org/) sets that silently
drop their traffic — scanners cannot even tell the server is alive.

Nothing is inserted into the live connection path: `tcpdump` hands over copies
of packets, decisions are enforced by the kernel. A parser bug can lose a
decision, never a player — every failure mode is fail-open.

```
bot                         kernel (nftables)              your server
 |  SYN 25565                     |                              |
 |------------------------------->|  ip in @tarpit / @pingsink ? |
 |                                |---- silent drop ------------>|
 |                                |                              |
 |  handshake + Login Start        |        (sniffer sees a copy) |
 |------------------------------->|                              |
                                   mc-tarpit: name in whitelist? |
                                   no  -> add IP to @tarpit      |
                                   yes -> trust IP for 30 days   |
```

## Decisions

| Event | Condition | Action |
| --- | --- | --- |
| any | source is in `trust_subnets` | always allowed, ignored |
| login | nickname is in `whitelist.json`, `ops.json` or `names_file` | allowed, IP trusted for `trust_ttl` |
| login | nickname is unknown | IP goes to set `tarpit`/`tarpit6` for `tarpit_ttl` |
| status ping | IP is not trusted | IP goes to set `pingsink`/`pingsink6` for `ping_ttl` |
| anything else | — | ignored |

Two knobs change that behaviour without touching code:

- `ping_policy = ignore` — never act on pings, the server stays visible in
  multiplayer lists (only login protection is left);
- `login_policy = log` — never block logins, only log them and let the
  Minecraft whitelist decide.

Status pings carry no username, so the very first ping of a stranger is always
answered (the reply is already on the wire when the sniffer sees the packet).
Every following connection from that IP is dropped, which keeps the server out
of bot server lists. IPs that logged in with a whitelisted nickname are
trusted, so existing players keep normal pings.

Both IPv4 and IPv6 are supported, and any number of ports.

## Requirements

- Linux with nftables (`nft`) and `tcpdump`
- Python 3.7+, no third-party packages
- A whitelist on your server (`whitelist.json`, `ops.json` next to it)
- root (or `CAP_NET_RAW` + `CAP_NET_ADMIN`) for capture and nftables

## Install

```bash
sudo ./install.sh --server-dir /home/mc/server \
                  --ports 25565 \
                  --trust-subnets 192.168.0.0/24 \
                  --trust 192.168.0.78
```

What it does: copies `mc_tarpit.py` to `/usr/local/bin`, writes
`/etc/mc-tarpit.conf`, appends the nftables table to `/etc/nftables.conf`
(with a timestamped backup, ports substituted), installs and starts
`mc-tarpit.service`, and trusts the given IPs.

Options: `--ports LIST`, `--trust IP` (repeatable), `--trust-subnets CIDR`,
`--table NAME`, `--config PATH`, `--no-start`.

Manual install: copy the script, append `contrib/nftables.conf` to
`/etc/nftables.conf`, copy `contrib/mc-tarpit.conf` to `/etc/mc-tarpit.conf`,
install `contrib/mc-tarpit.service` and `systemctl enable --now mc-tarpit`.

## Configuration

Defaults < config file < `MC_TARPIT_*` environment < command line flags.
The config file is `/etc/mc-tarpit.conf` (or `--config PATH` /
`MC_TARPIT_CONFIG`); see [contrib/mc-tarpit.conf](contrib/mc-tarpit.conf) for a
commented example.

| Key | Default | Meaning |
| --- | --- | --- |
| `server_dir` | `.` | directory with `whitelist.json` and `ops.json` |
| `ports` | `25565` | Minecraft ports to watch, comma separated |
| `mode` | `drop` | `drop` = real nftables drops, `log` = dry run |
| `ping_policy` | `sink` | `sink` = block untrusted pings, `ignore` = leave pings alone |
| `login_policy` | `tarpit` | `tarpit` = block unknown logins, `log` = only log them |
| `tarpit_ttl` | `1d` | how long an unknown login blocks an IP |
| `ping_ttl` | `15m` | how long an untrusted ping blocks an IP |
| `trust_ttl` | `2592000` | seconds an IP stays trusted after a known login |
| `trust_file` | `tarpit-trusted.json` | trusted IP list, relative to `server_dir` |
| `names_file` | `tarpit-names.txt` | extra allowed nicknames, one per line, `#` comments |
| `trust_subnets` | *(empty)* | CIDRs that are never blocked (LAN, proxies) |
| `table` | `mc_tarpit` | nftables table name |
| `iface` | `any` | capture interface |
| `protocol` | `776` | protocol version used by the `ping`/`login` test clients |
| `log_level` | `info` | `debug` (every decision), `info` (actions), `warn` (errors) |
| `log_file` | *(stdout)* | append log lines to this file instead of stdout |

TTLs use nftables syntax (`30s`, `15m`, `1h`, `1d`, `7d`).

## Different environments

**systemd** (default): the unit reads `/etc/mc-tarpit.conf`, restarts on
failure, logs to the journal.

**tmux / container / no systemd**: run it directly, optionally to a log file:

```bash
MC_TARPIT_SERVER_DIR=/srv/mc MC_TARPIT_LOG_FILE=/var/log/mc-tarpit.log \
  ./mc_tarpit.py watch
```

**Several servers on one host**: `ports = 25565,25566,25567`; the shared
sets cover all of them, `set ports` in nftables is what the chain matches.

**IPv6**: nothing to configure, `tarpit6`/`pingsink6` are used automatically
for IPv6 sources.

**Behind a proxy (lazymc, Velocity, BungeeCord)** — important: every player
then arrives from the proxy address, so the tool would see the proxy IP only.
Put the proxy into `trust_subnets` (or run mc-tarpit on the proxy itself,
where the real client IPs are visible). Example: `trust_subnets =
192.168.0.0/24,10.8.0.0/24`.

**Unprivileged operation**: create a `mc-tarpit` user, `chown` the server
directory's `tarpit-trusted.json`, and use the `User=` +
`AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` block that is commented out in
`contrib/mc-tarpit.service`.

**Dry run first**: `mode = log` (or `--mode log`) prints every decision and
touches nothing. `mc_tarpit.py replay capture.pcap` does the same offline for
a saved capture.

## Operations

```bash
sudo mc_tarpit.py status                 # effective config, sets, trusted IPs
sudo mc_tarpit.py trust 203.0.113.9      # add to the trusted list
sudo mc_tarpit.py untrust 203.0.113.9    # remove from it
sudo journalctl -u mc-tarpit -f          # live decisions
sudo mc_tarpit.py ping                   # send a status ping to test the path
sudo mc_tarpit.py login TestBot          # send a login attempt with a fake nick
sudo mc_tarpit.py replay capture.pcap    # offline replay of a capture
```

Unblock an IP immediately:

```bash
sudo nft delete element inet mc_tarpit tarpit   { 203.0.113.9 }
sudo nft delete element inet mc_tarpit pingsink { 203.0.113.9 }
sudo nft delete element inet mc_tarpit tarpit6  { 2001:db8::42 }
```

A player whose IP changed shows as offline in the multiplayer list until they
join once (the login itself is always checked by nickname), or until you
`trust` their new IP.

## Tests

```bash
python3 tests/test_parse.py     # 31 unit tests, no network, no nftables
python3 mc_tarpit.py selftest   # parser + IPv6 + config self-check
```

## Limitations

- **The first ping of a new IP is always answered** — the reply is already on
  the wire when the sniffer sees the packet. Every following connection from
  that IP is dropped.
- **Trust is IP based.** A dynamic address means the server shows as offline in
  the multiplayer list until the next successful login.
- **IPv6 extension headers are not followed** — such packets are ignored.

## Быстрый старт (по-русски)

```bash
sudo ./install.sh --server-dir /home/sl/mcserver --trust-subnets 192.168.0.0/24
sudo mc_tarpit.py --config /etc/mc-tarpit.conf status
sudo journalctl -u mc-tarpit -f
```

Логин с ником из вайтлиста — IP запоминается на 30 дней; логин с незнакомым
ником — в `tarpit` на сутки; статус-пинг с недоверенного IP — в `pingsink` на
15 минут. Ключи настройки: `/etc/mc-tarpit.conf` (или `MC_TARPIT_*`, или
флаги `--`). Политики `ping_policy=ignore` и `login_policy=log` отключают
соответствующую блокировку, `mode=log` — полностью «сухой прогон».

## License

MIT, see [LICENSE](LICENSE).
