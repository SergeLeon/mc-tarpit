# Security policy

## What privileges are needed

The daemon (`mc_tarpit.py watch`) runs as root by default, because it needs:

- raw packet capture (`tcpdump` / `AF_PACKET`) to see copies of packets;
- nftables access to add members to the `tarpit`, `tarpit6`, `pingsink` and
  `pingsink6` sets.

No other privilege is used. The commented block in
`contrib/mc-tarpit.service` shows the unprivileged alternative:
`User=mc-tarpit` with `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` and a few
`Protect*` hardening options.

## What the tool touches

- reads `<server_dir>/whitelist.json`, `ops.json`, `tarpit-names.txt`;
- reads and writes `<server_dir>/tarpit-trusted.json`;
- reads packet copies from the interface in `iface`;
- runs `nft add element inet <table> <set> { <ip> timeout <ttl> }`.

It never writes to the Minecraft server files, never proxies or terminates
player connections, never sends packets and never makes outbound network
requests. There are no tokens, keys or telemetry of any kind.

## Installation

The release assets (`install.sh`, `mc-tarpit.tar.gz`) are published together
with `SHA256SUMS`; verify the checksum before running anything:

```bash
curl -fsSLO https://github.com/SergeLeon/minecraft-antibot-tarpit/releases/latest/download/install.sh
curl -fsSLO https://github.com/SergeLeon/minecraft-antibot-tarpit/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

Piping a script directly into a root shell (`curl ... | sudo bash`) is
deliberately **not** the documented path: such a script cannot be inspected or
verified. `install.sh --check` prints exactly which files it would create or
modify and changes nothing.

The installer uses only POSIX shell, `curl`, `tar`, `sed`, `python3` and the
utilities it checks for (`nft`, `tcpdump`, `python3`). It does not use `eval`,
does not source remote content, and keeps timestamped backups of
`/etc/nftables.conf` and `/etc/mc-tarpit.conf` before editing them.

## Reporting a vulnerability

Open a private security advisory on GitHub
(Security -> Advisories -> "Report a vulnerability") or mail the maintainer in
the repository profile. Please include the version (`mc_tarpit.py --version`),
your distribution and the steps to reproduce.

## Scope

In scope: parser bugs that could block a legitimate player, privilege
escalation, unchecked downloads, path traversal in the installer, command
injection through config values.
