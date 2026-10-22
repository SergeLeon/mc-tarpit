# mc-tarpit — reference

Decisions, configuration, operation and troubleshooting. Overview and
installation: [README.md](README.md).

## 1. How a decision is made

```
tcpdump -i any 'tcp dst port 25565'         <- copies of packets, live traffic untouched
   | pcap: SLL2 / Ethernet -> IPv4/IPv6 -> TCP -> payload
new flow? -- no (already established connection) --> ignored forever
   | yes (SYN seen, seq+1 is the base)
   | reassemble the client payload by sequence number
Handshake: id 0x00, protocol, address, port, next_state
   |-- next_state != 2 (status ping) --> ping_policy
   |-- next_state  = 2 (login)       --> Login Start: id 0x00, len, nickname
                                         login_policy
```

| Event | Condition | Action |
| --- | --- | --- |
| any | source is inside `trust_subnets` | always allowed, nothing happens |
| login | nickname in `whitelist.json`, `ops.json` or `names_file` | allowed, IP trusted for `trust_ttl` |
| login | unknown nickname, `login_policy=tarpit` | IP into `tarpit`/`tarpit6` for `tarpit_ttl` |
| login | unknown nickname, `login_policy=log` | logged only |
| ping | IP not trusted, `ping_policy=sink` | IP into `pingsink`/`pingsink6` for `ping_ttl` |
| ping | `ping_policy=ignore` | logged at `debug` only |
| garbage | handshake or login failed to parse | ignored (fail-open) |

"Trusted" means the IP is present in `trust_file` (`{"<ip>": <unixtime>}`) and
has not expired. Entries are added by any login with a known nickname, by
`mc_tarpit.py trust IP`, or by the installer (`--trust`).

## 2. Configuration

Precedence: **defaults < config file < `MC_TARPIT_*` environment < CLI flags**.
The config file is INI, located with `--config PATH` or `MC_TARPIT_CONFIG`
(the systemd unit reads `/etc/mc-tarpit.conf`).

| Key | Default | Meaning |
| --- | --- | --- |
| `server_dir` | `.` | directory with `whitelist.json` and `ops.json` |
| `ports` | `25565` | Minecraft ports, comma separated |
| `mode` | `drop` | `drop` = real blocks, `log` = dry run |
| `ping_policy` | `sink` | `sink` = block untrusted pings, `ignore` = leave pings alone |
| `login_policy` | `tarpit` | `tarpit` = block unknown logins, `log` = log only |
| `tarpit_ttl` | `1d` | how long an unknown login blocks an IP |
| `ping_ttl` | `15m` | how long an untrusted ping blocks an IP |
| `trust_ttl` | `2592000` | seconds an IP stays trusted after a known login |
| `trust_file` | `tarpit-trusted.json` | trusted IP list, relative to `server_dir` |
| `names_file` | `tarpit-names.txt` | extra allowed nicknames, one per line, `#` comments |
| `trust_subnets` | *(empty)* | CIDRs that are never blocked (LAN, proxy) |
| `table` | `mc_tarpit` | nftables table name |
| `iface` | `any` | capture interface |
| `protocol` | `776` | protocol version used by the `ping`/`login` test clients |
| `log_level` | `info` | `debug` every decision, `info` actions, `warn` errors |
| `log_file` | *(stdout)* | append log lines to a file instead of stdout/journal |

TTLs use nftables syntax: `30s`, `15m`, `1h`, `1d`, `7d`.
A fully commented example: [contrib/mc-tarpit.conf](contrib/mc-tarpit.conf).

## 3. Commands

```bash
mc_tarpit.py watch                 # production mode (what the service runs)
mc_tarpit.py status                # effective config, sets, trusted IPs, names
mc_tarpit.py selftest              # offline parser self-check (11 checks)
mc_tarpit.py replay capture.pcap   # decisions for a saved capture, no blocking
mc_tarpit.py ping  [--host H]      # send a status ping
mc_tarpit.py login NAME [--host H] # send a login with a fake nickname
mc_tarpit.py trust IP...           # add IPs to the trusted list
mc_tarpit.py untrust IP...         # remove them
```

Flags override the config: `--config`, `--server-dir`, `--ports`, `--mode`,
`--ping-policy`, `--login-policy`, `--trust-subnets`, `--trust-ttl`,
`--tarpit-ttl`, `--ping-ttl`, `--table`, `--iface`, `--log-level`,
`--log-file`, `--protocol`, `--version`.

## 4. Install and uninstall

```bash
curl -fsSLO https://github.com/SergeLeon/minecraft-antibot-tarpit/releases/latest/download/install.sh
sudo bash install.sh --server-dir /home/mc/server

sudo bash install.sh --uninstall      # remove service, config, script, table
```

Optional, when you want to inspect before running: `curl -fsSLO
.../SHA256SUMS && sha256sum -c SHA256SUMS --ignore-missing` verifies the
installer, `sudo bash install.sh --check` prints the plan and changes nothing,
and `--sha256 HASH` makes the installer verify the release archive it downloads.

Installer flags:

| Flag | Meaning |
| --- | --- |
| `--server-dir DIR` | server with `whitelist.json` (auto-detected when omitted) |
| `--ports LIST` | comma separated Minecraft ports (default `25565`) |
| `--trust IP` | trust an IP right away, repeatable |
| `--trust-subnets CIDR` | subnets that are never blocked |
| `--table NAME` | nftables table name (default `mc_tarpit`) |
| `--config PATH` | where to write the config (default `/etc/mc-tarpit.conf`) |
| `--check` | print the plan and exit, change nothing |
| `--no-start` | install but do not start the service |
| `--sha256 HASH` | expected sha256 of the downloaded release archive |
| `--yes` | do not ask for confirmation |
| `--uninstall` | remove everything except the trusted IP list |

The installer is idempotent: a second run updates the script, config, ports and
unit, and keeps timestamped backups of `/etc/nftables.conf` and
`/etc/mc-tarpit.conf`. When it runs without local sources it downloads
`mc-tarpit.tar.gz` from the latest release, prints its sha256 and verifies it
when `--sha256` is given.

## 5. Environments

**systemd** (default): the unit reads `/etc/mc-tarpit.conf`, `Restart=always`,
logs to the journal.

**tmux / container / no systemd**:

```bash
MC_TARPIT_SERVER_DIR=/srv/mc MC_TARPIT_LOG_FILE=/var/log/mc-tarpit.log \
  ./mc_tarpit.py watch
```

**Several servers on one host**: `ports = 25565,25566,25567`; the nftables chain
matches `set ports`, the sets are shared.

**IPv6**: nothing to configure, `tarpit6` and `pingsink6` are used for IPv6
sources automatically.

**Behind a proxy (lazyc, Velocity, BungeeCord)**: if the proxy runs on another
host, all players arrive from the proxy address — put it into `trust_subnets` or
run mc-tarpit on the proxy itself. A local proxy (lazymc on the same host)
needs no configuration: the sniffer sees the real client IPs.

**Without root**: create a `mc-tarpit` user, give it write access to the
directory holding `trust_file`, and use the commented `User=mc-tarpit` +
`AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` block in
`contrib/mc-tarpit.service`.

**Before going live**: `mode = log` (or `--mode log`) prints decisions and
blocks nothing; `replay` does the same offline for a saved capture.

## 6. Operation and troubleshooting

```bash
sudo journalctl -u mc-tarpit -f                      # live decisions
sudo mc_tarpit.py status                             # config + sets + trusted
sudo nft list set inet mc_tarpit tarpit              # who is blocked
sudo nft list set inet mc_tarpit pingsink6            # IPv6 ping blocks
sudo nft -a list table inet mc_tarpit | grep counter  # packets dropped
sudo nft delete element inet mc_tarpit tarpit { 1.2.3.4 }   # forgive now
sudo nft delete element inet mc_tarpit pingsink { 1.2.3.4 }
```

Log lines and what they mean:

| Line | Meaning |
| --- | --- |
| `watching ports=... mode=... trusted=N` | service started, number of trusted IPs loaded |
| `login IP name='X' ok` | known player, IP becomes trusted |
| `login IP name='X' not-whitelisted` | unknown nickname |
| `tarpit IP -> tarpit 1d` | blocked for an unknown login |
| `ping IP -> pingsink 15m (not trusted)` | blocked for a ping from an untrusted IP |
| `ignore IP (trust_subnets)` | IP is inside a trusted subnet |
| `nft tarpit failed for IP: ...` | no permission or no table — check `nft list ruleset` |

Set contents are lost on reboot (rules and the trusted file survive). A player
whose IP changed shows as offline in the multiplayer list until the next
successful login; the login itself is checked by nickname and always works.

## 7. Protocol and parser limits

- Only two packets are read: the handshake (`next_state`) and `Login Start`
  (first 1–16 bytes of the nickname), so the protocol version is almost
  irrelevant.
- Only the client-to-server stream is parsed; server responses are not read.
- A connection is parsed only after its SYN was seen. Otherwise packets from the
  middle of an established session could be mistaken for a handshake (this
  happened in the first build and blocked a real player).
- IPv6 extension headers are not followed; such packets are ignored
  (fail-open, no false blocks).
- Reassembly is bounded: a sequence gap aborts the flow, buffer up to 4 KB,
  a flow expires after 60 seconds.

## 8. Security

See [SECURITY.md](SECURITY.md) for what runs as root, what the installer
touches and how to report a problem. Short version: the tool needs no tokens,
no network access at runtime and no third-party packages; it only reads local
files and packets and adds members to two nftables sets.
