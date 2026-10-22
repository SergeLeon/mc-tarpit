# mc-tarpit — антибот для Minecraft-сервера / Minecraft antibot tarpit

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-0.2.0-blue">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="tests" src="https://github.com/SergeLeon/minecraft-antibot-tarpit/actions/workflows/ci.yml/badge.svg">
  <img alt="Python" src="https://img.shields.io/badge/python-3.7%2B-3776ab">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Linux-lightgrey">
</p>

Антибот для Minecraft-сервера: тарпит ботов-сканеров через nftables, без модов и
правок сервера. Ловит масс-сканеры (`FishNet`, `IcyOwl1855`, `iNHABITors74961` —
никнеймы из генератора adjective-animal), которые перебирают порт `25565`,
пингуют его и ломятся под случайными никами.

A passive sniffer watches the Minecraft port, parses the handshake and the
`Login Start` packet, and drops unknown sources in the kernel — scanners cannot
even tell the server is alive. Ни один мод не ставится, живой трафик не
проксируется, ошибаться нечем: сломанный парсинг ничего не блокирует.

## Возможности

- **Тарпит по нику** — логин с ником вне `whitelist.json`/`ops.json` → IP в
  nftables-set на сутки, молчаливый `drop` вместо отказа.
- **Фильтр пингов** — статус-пинг с IP, который ни разу не заходил своим ником,
  блокируется на 15 минут, и сервер пропадает из бот-каталогов.
- **Доверенные игроки** — IP, зашедший с ником из вайтлиста, доверен 30 дней,
  его пинги отвечаются как обычно.
- **Никаких модов** — работает с vanilla/fabric/paper, с lazymc и без него.
- **IPv4 + IPv6** — отдельные сеты `tarpit6`/`pingsink6`, разбор IPv6-кадров.
- **Любое число портов** — `ports = 25565,25566,25567` на одном хосте.
- **Три источника конфига** — файл < `MC_TARPIT_*` env < флаги CLI.
- **Политики** — `ping_policy=ignore` (пинги не трогать) и `login_policy=log`
  (только логировать) развязывают две защиты друг от друга.
- **Сухой прогон и реплей** — `mode=log` и `mc_tarpit.py replay capture.pcap`
  показывают решения, ничего не блокируя.
- **Честные ограничения** — fail-open, доверенные подсети, следы в journald.

## Установка (3 шага)

1. Одна команда — скачивает последний релиз, ставит nftables-таблицу, сервис и
   конфиг (нужен root, `curl`, `tcpdump`, `python3`, `nft`):

   ```bash
   curl -fsSL https://github.com/SergeLeon/minecraft-antibot-tarpit/releases/latest/download/install.sh \
     | sudo bash -s -- --server-dir /home/mc/server
   ```

2. Проверить, что видит и что решил:

   ```bash
   sudo mc_tarpit.py status        # эффективный конфиг, сеты, доверенные IP
   sudo journalctl -u mc-tarpit -f # ping 203.0.113.9 -> pingsink 15m (not trusted)
   ```

3. Своих игроков — в доверенные заранее (иначе первый пинг на 15 минут закроет
   им список серверов): `--trust-subnets 192.168.0.0/24` при установке или
   `sudo mc_tarpit.py trust 203.0.113.9` после.

Папку сервера установщик умеет находить сам (`~/mcserver`, `/srv/minecraft`,
`/opt/minecraft`, …), тогда `--server-dir` можно не указывать. Полный набор
флагов: `install.sh --help`.

## Минимальный рабочий пример

```bash
# сухой прогон: ничего не блокируем, смотрим решения
sudo mc_tarpit.py --mode log watch

# боевой режим через конфиг
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

Реальный вывод на сервере, где это стоит:

```
watching ports=25565 mode=drop ping_policy=sink login_policy=tarpit linktype=276 trusted=1
ping 176.65.148.253 -> pingsink 15m (not trusted)
login 45.153.34.119 name='iNHABITors74961' not-whitelisted
tarpit 45.153.34.119 -> tarpit 1d
```

## Требования

- Linux с nftables (`nft`) и `tcpdump`;
- Python 3.7+, сторонних пакетов нет;
- вайтлист на сервере (`whitelist.json`, рядом `ops.json`);
- root либо `CAP_NET_RAW` + `CAP_NET_ADMIN` (готовый блок в unit-е).

## Что не решает

- **Подмену ника в offline-mode.** `online-mode=false` — любой, кто знает ник из
  вайтлиста, зайдёт под ним. Нужен `online-mode=true`, пароль-плагин или
  закрытый порт.
- **Первый пинг** от нового IP всегда отвечается: ответ уже улетел, когда
  снайфер увидел пакет. Дальше IP закрыт.
- **IP-адреса как идентификатор**: смена IP = потеря записи в списке серверов
  до первого успешного входа.

## Ссылки

- [DOCUMENTATION.md](DOCUMENTATION.md) — все ключи конфига, среды, nftables, диагностика
- [CHANGELOG.md](CHANGELOG.md) — история версий (Keep a Changelog, SemVer)
- [Releases](https://github.com/SergeLeon/minecraft-antibot-tarpit/releases) — архивы и заметки
- [contrib/](contrib) — nftables-таблица, systemd-unit, пример конфига
- [LICENSE](LICENSE) — MIT

## Быстрый старт (RU, коротко)

```bash
curl -fsSL https://github.com/SergeLeon/minecraft-antibot-tarpit/releases/latest/download/install.sh \
  | sudo bash -s -- --server-dir /home/sl/mcserver --trust-subnets 192.168.0.0/24
sudo mc_tarpit.py status && sudo journalctl -u mc-tarpit -f
```
