# Changelog

Формат — [Keep a Changelog](https://keepachangelog.com/ru/1.0.0/),
версии — [SemVer](https://semver.org/lang/ru/).

## [Unreleased]

## [0.2.0] - 2026-10-22

### Added

- Конфигурация из INI-файла, переменных `MC_TARPIT_*` и флагов CLI
  (приоритет: файл < env < CLI); установщик пишет `/etc/mc-tarpit.conf`.
- Поддержка IPv6: сеты `tarpit6`/`pingsink6`, разбор IPv6-кадров.
- Несколько портов: `ports = 25565,25566`; nftables матчит `set ports`.
- Политики `ping_policy` (`sink`/`ignore`) и `login_policy` (`tarpit`/`log`).
- `trust_subnets` — CIDR-ы, которые не блокируются никогда (LAN, прокси).
- `names_file` — дополнительные разрешённые ники вне `whitelist.json`/`ops.json`.
- `log_level` (`debug`/`info`/`warn`) и `log_file` — работа без systemd.
- Команды `status`, `trust`, `untrust`, `replay capture.pcap`.
- Оффлайн-проверки в `selftest`: IPv6, список портов, подсети, приоритет конфига.
- Тесты: 31 юнит-тест, GitHub Actions прогоняет их на каждый push.
- Документация: `DOCUMENTATION.md`, `CHANGELOG.md`, пример `contrib/mc-tarpit.conf`.

### Changed

- Снайфер разбирает поток только при виде SYN; ложная блокировка игрока,
  пойманная в 0.1.0, устранена.
- Тарпит-логика вынесена в `Decider`, общая для `watch` и `replay`.
- Установщик идемпотентен, умеет `--uninstall` и автопоиск каталога сервера.

## [0.1.0] - 2026-10-22

### Added

- Пассивный снайфер `tcpdump` → разбор handshake и `Login Start`.
- Тарпит чужих логинов и статус-пингов через nftables-сеты `tarpit`/`pingsink`.
- Доверенные IP: вход с ником из вайтлиста даёт 30 дней доверия.
- systemd-юнит, nftables-таблица, `install.sh`.
- Тест-клиенты `ping`/`login` и `selftest`.

[Unreleased]: https://github.com/SergeLeon/minecraft-antibot-tarpit/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/SergeLeon/minecraft-antibot-tarpit/releases/tag/v0.2.0
[0.1.0]: https://github.com/SergeLeon/minecraft-antibot-tarpit/releases/tag/v0.1.0
