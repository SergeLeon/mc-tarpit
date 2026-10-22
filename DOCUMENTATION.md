# mc-tarpit — справочник

Полная документация: решения, конфиг, режимы, эксплуатация, диагностика.
Короткий обзор и установка — в [README.md](README.md).

## 1. Как принимается решение

```
tcpdump -i any 'tcp dst port 25565'        ← копия пакетов, живой трафик не трогаем
   ↓ pcap: SLL2 / Ethernet → IPv4/IPv6 → TCP → payload
новый поток? ─ нет (уже установленное соединение) → игнорируем навсегда
   │ да (увидели SYN, seq+1 — база)
   ↓ склейка полезной нагрузки по seq
Handshake: id 0x00, protocol, address, port, next_state
   ├─ next_state ≠ 2 (status-пинг) → политика ping_policy
   └─ next_state = 2 (login)      → Login Start: id 0x00, len, ник
                                     политика login_policy
```

| Событие | Условие | Действие |
|---|---|---|
| любое | IP входит в `trust_subnets` | всегда пропускаем, ничего не делаем |
| login | ник в `whitelist.json`, `ops.json` или `names_file` | пропускаем, IP доверен на `trust_ttl` |
| login | ник неизвестен, `login_policy=tarpit` | IP → `tarpit`/`tarpit6` на `tarpit_ttl` |
| login | ник неизвестен, `login_policy=log` | только запись в лог |
| ping | IP не доверен, `ping_policy=sink` | IP → `pingsink`/`pingsink6` на `ping_ttl` |
| ping | `ping_policy=ignore` | только запись в лог (на уровне `debug`) |
| мусор | handshake/логин не разобрался | игнорируем (fail-open) |

«Доверен» — IP есть в `trust_file` (JSON `{"<ip>": <unixtime>}`) и срок не вышел.
Запись добавляется при логине с известным ником, вручную через
`mc_tarpit.py trust IP` или установщиком (`--trust`).

## 2. Конфигурация

Приоритет: **значения по умолчанию < конфиг-файл < `MC_TARPIT_*` < флаги CLI**.
Конфиг-файл — INI, путь задаётся `--config PATH` или `MC_TARPIT_CONFIG`
(по умолчанию systemd-юнит читает `/etc/mc-tarpit.conf`).

| Ключ | По умолчанию | Смысл |
|---|---|---|
| `server_dir` | `.` | каталог с `whitelist.json` и `ops.json` |
| `ports` | `25565` | порты через запятую: `25565,25566` |
| `mode` | `drop` | `drop` — реальные блокировки, `log` — сухой прогон |
| `ping_policy` | `sink` | `sink` — блокировать недоверенные пинги, `ignore` — не трогать |
| `login_policy` | `tarpit` | `tarpit` — блокировать чужие логины, `log` — только логировать |
| `tarpit_ttl` | `1d` | сколько держать блок за чужой логин |
| `ping_ttl` | `15m` | сколько держать блок за недоверенный пинг |
| `trust_ttl` | `2592000` | секунд доверия после входа с известным ником |
| `trust_file` | `tarpit-trusted.json` | список доверенных IP, относительно `server_dir` |
| `names_file` | `tarpit-names.txt` | дополнительные разрешённые ники, по одному в строке, `#` — комментарий |
| `trust_subnets` | *(пусто)* | CIDR-ы, которые не блокируются никогда (LAN, прокси) |
| `table` | `mc_tarpit` | имя nftables-таблицы |
| `iface` | `any` | интерфейс захвата |
| `protocol` | `776` | версия протокола для тест-клиентов `ping`/`login` |
| `log_level` | `info` | `debug` — каждое решение, `info` — действия, `warn` — ошибки |
| `log_file` | *(stdout)* | писать строки в файл вместо stdout/journal |

TTL — в синтаксисе nftables: `30s`, `15m`, `1h`, `1d`, `7d`.

Пример полного файла: [contrib/mc-tarpit.conf](contrib/mc-tarpit.conf).

## 3. Команды

```bash
mc_tarpit.py watch                 # боевой режим (так работает сервис)
mc_tarpit.py status                # эффективный конфиг, сеты, доверенные IP, ники
mc_tarpit.py selftest              # оффлайн-самопроверка парсера (11 проверок)
mc_tarpit.py replay capture.pcap   # решения по сохранённому дампу, без блокировок
mc_tarpit.py ping  [--host H]      # отправить статус-пинг
mc_tarpit.py login NAME [--host H] # отправить логин с ником NAME
mc_tarpit.py trust IP...           # добавить в доверенные
mc_tarpit.py untrust IP...         # убрать из доверенных
```

Флаги (перебивают конфиг): `--config`, `--server-dir`, `--ports`, `--mode`,
`--ping-policy`, `--login-policy`, `--trust-subnets`, `--trust-ttl`,
`--tarpit-ttl`, `--ping-ttl`, `--table`, `--iface`, `--log-level`,
`--log-file`, `--protocol`, `--version`.

## 4. Установка и удаление

```bash
curl -fsSL https://github.com/SergeLeon/minecraft-antibot-tarpit/releases/latest/download/install.sh \
  | sudo bash -s -- [флаги]

install.sh --server-dir DIR   # каталог с whitelist.json (иначе автопоиск)
           --ports LIST       # порты (25565)
           --trust IP         # доверенный IP, можно повторять
           --trust-subnets S  # CIDR-ы, которые не блокируются
           --table NAME       # имя nftables-таблицы
           --config PATH      # куда писать конфиг (/etc/mc-tarpit.conf)
           --no-start         # поставить, но не запускать
           --uninstall        # удалить сервис, конфиг, скрипт и таблицу

sudo ./install.sh --uninstall
```

Установщик идемпотентен: повторный запуск обновляет скрипт, конфиг, порты в
nftables и unit, бэкапит `/etc/nftables.conf` и `/etc/mc-tarpit.conf`.

## 5. Разные среды

**systemd** — штатный вариант: юнит читает `/etc/mc-tarpit.conf`,
`Restart=always`, логи в journald.

**tmux / контейнер / без systemd**:

```bash
MC_TARPIT_SERVER_DIR=/srv/mc MC_TARPIT_LOG_FILE=/var/log/mc-tarpit.log \
  ./mc_tarpit.py watch
```

**Несколько серверов на хосте**: `ports = 25565,25566,25567`; nftables-цепочка
матчит `set ports`, сеты общие.

**IPv6**: настраивать нечего — для IPv6-источников используются `tarpit6` и
`pingsink6`.

**За прокси (lazyc/Velocity/BungeeCord)**: если прокси на другом хосте, все
игроки приходят с его IP — внесите прокси в `trust_subnets` или запускайте
mc-tarpit на самом прокси. Если прокси локальный (как lazymc на том же хосте),
снайфер видит настоящие IP клиентов и настраивать ничего не нужно.

**Без root**: создайте пользователя `mc-tarpit`, дайте ему запись в каталог с
`trust_file`, и в юните используйте закомментированный блок с
`User=mc-tarpit` + `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`.

**Проверка перед боем**: `mode = log` (или `--mode log`) печатает решения и
ничего не блокирует; `replay` делает то же оффлайн по дампу.

## 6. Эксплуатация и диагностика

```bash
sudo journalctl -u mc-tarpit -f                      # живой поток решений
sudo mc_tarpit.py status                             # конфиг + сеты + доверенные
sudo nft list set inet mc_tarpit tarpit              # кто заблокирован
sudo nft list set inet mc_tarpit pingsink6           # блокировки IPv6 за пинги
sudo nft -a list table inet mc_tarpit | grep counter # сколько пакетов отсёк
sudo nft delete element inet mc_tarpit tarpit { 1.2.3.4 }   # простить сейчас
sudo nft delete element inet mc_tarpit pingsink { 1.2.3.4 }
```

Типичные строки журнала:

| Строка | Что значит |
|---|---|
| `watching ports=… mode=… trusted=N` | сервис поднялся, сколько доверенных IP загружено |
| `login IP name='X' ok` | вход известного игрока, IP попадает в доверенные |
| `login IP name='X' not-whitelisted` | чужой ник |
| `tarpit IP -> tarpit 1d` | блок за чужой логин |
| `ping IP -> pingsink 15m (not trusted)` | блок за пинг с недоверенного IP |
| `ignore IP (trust_subnets)` | IP из доверенной подсети, ничего не делаем |
| `nft tarpit failed for IP: …` | нет прав/таблицы — проверьте `nft list ruleset` |

Содержимое сетов не сохраняется при перезагрузке (правила и `trust_file` —
сохраняются). Если игрок сменил IP, в списке серверов он будет «недоступен» до
первого входа — сам вход проверяется по нику и работает.

## 7. Протокол и ограничения парсера

- Читаются два пакета: handshake (`next_state`) и `Login Start` (первые 1–16
  байт ника). Остальное не нужно, поэтому версия протокола почти не важна.
- Парсится только поток клиент→сервер; серверные ответы не читаются.
- Соединение разбирается, только начиная с его SYN: иначе пакеты из середины
  установленной сессии могли бы быть приняты за handshake (реальный случай —
  ложная блокировка игрока в первой версии).
- IPv6: заголовки расширения не разбираются, такие пакеты игнорируются
  (fail-open, ложных блокировок нет).
- TCP-пересклейка ограничена: пакеты с дырой в последовательности сбрасывают
  разбор потока, буфер до 4 КБ, поток живёт 60 секунд.

## 8. Безопасность

- Тарпит **не заменяет** аутентификацию: при `online-mode=false` ник можно
  подделать, и утилита этого не поймает (она фильтрует сканеров, а не людей).
- Установщик требует root; боевой процесс — тоже (raw-сокеты + nftables).
  Вариант с capabilities описан в `contrib/mc-tarpit.service`.
- Токены и ключи утилите не нужны вообще: она работает только с локальными
  файлами, пакетами и nftables.
- Все блокировки — по IP и с TTL, «вечных» банов утилита не ставит.
