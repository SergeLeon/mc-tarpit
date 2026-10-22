# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning: [SemVer](https://semver.org/).

## [Unreleased]

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
