# mc-tarpit

Drops Minecraft bots that probe your server. A passive sniffer watches the
Minecraft port, parses the handshake and the `Login Start` packet, and puts
unknown sources into [nftables](https://www.netfilter.org/) sets that silently
drop their traffic — so scanners cannot even tell the server is alive.

Nothing is inserted into the live connection path: `tcpdump` hands over copies
of packets, decisions are enforced by the kernel. A parser bug can lose a
decision, never a player — every failure mode is fail-open.

```
bot                         kernel (nftables)              your server
 |  SYN 25565                     |                              |
 |------------------------------->|  ip in @tarpit / @pingsink ? |
 |                                |---- drop (timeout) --------->|
 |                                |                              |
 |  handshake + Login Start        |        (sniffer sees a copy) |
 |------------------------------->|                              |
                                   mc-tarpit: name in whitelist? |
                                   no  -> add IP to @tarpit      |
                                   yes -> trust IP for 30 days   |
```

## Decision table

| Event | Condition | Action |
| --- | --- | --- |
| login | name is in `whitelist.json` / `ops.json` | allowed, IP remembered in the trusted list for `MC_TARPIT_TRUST_TTL` |
| login | name is unknown | IP goes to set `tarpit` for `MC_TARPIT_TARPIT_TTL` (default 1 day) |
| status ping | IP is not trusted | IP goes to set `pingsink` for `MC_TARPIT_PING_TTL` (default 15 minutes) |
| anything else | — | ignored |

Status pings carry no username, so the very first ping of a stranger is always
answered (the reply is already on the wire when the sniffer sees the packet).
Every following connection from that IP is dropped, which is what keeps the
server out of bot server lists. IPs that logged in with a whitelisted name are
trusted, so existing players keep normal server-list pings.

## Requirements

- Linux with nftables (`nft`) and `tcpdump`
- Python 3.7+, no third-party packages
- A whitelist on your server (`whitelist.json`, `ops.json` next to it)
- root for the service (raw packet capture and nftables access)

## Install

```bash
sudo ./install.sh --server-dir /home/mc/server --port 25565
```

The installer copies `mc_tarpit.py` to `/usr/local/bin`, adds the nftables
table to `/etc/nftables.conf` (with a timestamped backup), installs and starts
`mc-tarpit.service`, and trusts the IPs passed with `--trust` (your own
player's IP, so the ping filter does not lock them out before their first
login).

Manual install is three steps: copy the script, drop
[contrib/nftables.conf](contrib/nftables.conf) into `/etc/nftables.conf`,
install [contrib/mc-tarpit.service](contrib/mc-tarpit.service) as
`/etc/systemd/system/mc-tarpit.service` and `systemctl enable --now mc-tarpit`.

## Configuration

Everything is an environment variable (see `CONFIG` in the script):

| Variable | Default | Meaning |
| --- | --- | --- |
| `MC_TARPIT_SERVER_DIR` | `.` | directory with `whitelist.json` and `ops.json` |
| `MC_TARPIT_PORT` | `25565` | Minecraft port to watch |
| `MC_TARPIT_MODE` | `drop` | `drop` = real nftables drops, `log` = dry run |
| `MC_TARPIT_TARPIT_TTL` | `1d` | how long an unknown login blocks an IP |
| `MC_TARPIT_PING_TTL` | `15m` | how long an untrusted ping blocks an IP |
| `MC_TARPIT_TRUST_TTL` | `2592000` | how long a known player's IP stays trusted (30 days) |
| `MC_TARPIT_TRUST_FILE` | `tarpit-trusted.json` | trusted IP list (relative to the server dir) |
| `MC_TARPIT_TABLE` | `mc_tarpit` | nftables table name |
| `MC_TARPIT_IFACE` | `any` | capture interface |
| `MC_TARPIT_PROTOCOL` | `776` | protocol version used by the built-in test clients |

Use `log` mode first to see what it would do:

```bash
sudo systemctl stop mc-tarpit
sudo MC_TARPIT_MODE=log MC_TARPIT_SERVER_DIR=/home/mc/server /usr/local/bin/mc_tarpit.py watch
```

## Commands

```bash
mc_tarpit.py watch          # run as a service
mc_tarpit.py status         # blocked and trusted IPs
mc_tarpit.py selftest       # offline parser self-check
mc_tarpit.py ping           # send a status ping to 127.0.0.1:25565
mc_tarpit.py login TestBot  # send a login attempt with a fake nickname
```

Unblock an IP or trust one by hand:

```bash
sudo nft delete element inet mc_tarpit tarpit   { 203.0.113.9 }
sudo nft delete element inet mc_tarpit pingsink { 203.0.113.9 }
# trusted IPs live in tarpit-trusted.json: {"203.0.113.9": 1790000000}
```

## Tests

```bash
python3 tests/test_parse.py                # 13 unit tests, no network
python3 mc_tarpit.py selftest              # parser self-check
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
sudo ./install.sh --server-dir /home/mc/server --trust 192.168.0.78
sudo journalctl -u mc-tarpit -f        # видно решения: ping / login / trust
sudo mc_tarpit.py status               # кто заблокирован, кто в доверенных
```

Работает так: логин с ником из `whitelist.json` — IP запоминается на 30 дней;
логин с незнакомым ником — IP в `tarpit` на сутки; статус-пинг с недоверенного
IP — в `pingsink` на 15 минут. Живой трафик не проксируется, снайфер только
читает копии пакетов, поэтому сломать игру он может лишь ложной блокировкой
(лечится `nft delete element`).

## License

MIT, see [LICENSE](LICENSE).
