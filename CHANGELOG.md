# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added

- `install.sh --tarpit-ttl` and `--ping-ttl`, so a reinstall no longer resets
  the block durations.
- Tests for the parser length checks, the flow cap, the nft decision cache and
  the fail-open paths; CI runs the suite on Python 3.9 and 3.12.

### Changed

- `ping_policy` defaults to `ignore`. A status ping and a login share one port
  and nftables cannot tell them apart, so the old `sink` default dropped the
  first join attempt of a new or changed address for up to 15 minutes. `sink`
  stays available as opt-in, with `ping_ttl` shortened to `1m`.
- The parser validates every length field (IPv4 header, IP total length, TCP
  data offset, varint width) and skips VLAN and QinQ tags.
- A SYN flood no longer grows the flow table without limit: 8192 flows at most,
  oldest evicted first, expired flows swept once a second.
- The installer keeps an existing `/etc/mc-tarpit.conf` and rewrites only the
  keys passed on the command line; a reinstall keeps the contents of the
  nftables sets instead of reloading the ruleset; curl and tar are only
  required when the release archive has to be downloaded.
- The systemd unit restarts on failure with a start limit instead of
  `Restart=always`, and the unprivileged recipe works now.
- The config file is read without `%` interpolation and TTL values are
  validated when the config is read.

### Fixed

- A repeated ping or login from an address already in a set forked `nft` and
  logged a warning per packet; each address is added once per TTL window now.
- A missing `nft` or `tcpdump`, and an unwritable trusted list, raised a
  traceback instead of logging and carrying on (fail-open).
- `--help` printed a fixed line range of the installer, and `--uninstall` left
  the installer's comments behind in `/etc/nftables.conf`.

## [0.2.1] - 2026-10-22

### Added

- `SHA256SUMS` release asset; the installer prints the sha256 of the archive it
  downloads and verifies it when `--sha256` is given.
- `install.sh --check` prints the exact plan (paths, config values, nftables
  table) and changes nothing; `--yes` skips the confirmation prompt.
- `SECURITY.md` documenting privileges, files touched and the reporting process.
- English documentation: README, DOCUMENTATION.md, CHANGELOG.md.

### Changed

- Installation is a verified flow (download, `sha256sum -c`, `--check`, install)
  instead of piping a script into a root shell.

## [0.2.0] - 2026-10-22

### Added

- Configuration from an INI file, `MC_TARPIT_*` environment variables and CLI
  flags (precedence: file < environment < CLI); the installer writes
  `/etc/mc-tarpit.conf`.
- IPv6 support: `tarpit6` and `pingsink6` sets, IPv6 frames parsed.
- Multiple ports: `ports = 25565,25566`; nftables matches `set ports`.
- `ping_policy` (`sink`/`ignore`) and `login_policy` (`tarpit`/`log`).
- `trust_subnets` — CIDRs that are never blocked (LAN, proxies).
- `names_file` — extra allowed nicknames outside `whitelist.json`/`ops.json`.
- `log_level` (`debug`/`info`/`warn`) and `log_file` for non-systemd setups.
- Commands `status`, `trust`, `untrust`, `replay capture.pcap`.
- Offline self-checks for IPv6, port lists, subnets and config precedence.
- 31 unit tests, run by GitHub Actions on every push.
- `DOCUMENTATION.md`, `CHANGELOG.md`, `contrib/mc-tarpit.conf`.

### Changed

- The sniffer parses a flow only after seeing its SYN; the false block of a real
  player that 0.1.0 could produce is gone.
- Decision logic moved into `Decider`, shared by `watch` and `replay`.
- The installer is idempotent and supports `--uninstall` and server dir
  auto-detection.

## [0.1.0] - 2026-10-22

### Added

- Passive `tcpdump` sniffer with handshake and `Login Start` parsing.
- Tarpit for unknown logins and untrusted status pings through the
  `tarpit`/`pingsink` nftables sets.
- Trusted IPs: a login with a whitelisted nickname grants 30 days of trust.
- systemd unit, nftables table and `install.sh`.
- `ping`/`login` test clients and `selftest`.

[Unreleased]: https://github.com/SergeLeon/minecraft-antibot-tarpit/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/SergeLeon/minecraft-antibot-tarpit/releases/tag/v0.2.1
[0.2.0]: https://github.com/SergeLeon/minecraft-antibot-tarpit/releases/tag/v0.2.0
[0.1.0]: https://github.com/SergeLeon/minecraft-antibot-tarpit/releases/tag/v0.1.0
