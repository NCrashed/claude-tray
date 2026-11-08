# Claude Tunnel

Отдельный tray-менеджер для запуска Claude Code только через выделенный
WireGuard/AmneziaWireGuard-туннель. Архитектура взята из `awg-tray`, но из неё
удалены VLESS, split tunneling и общий системный VPN: здесь изолируется только
Claude Code.

## Гарантия fail-closed

`claude-tunnel run` запускает Claude в Linux network namespace `claude-code`.
В namespace есть два сетевых пути:

- `ct-wg` — маршрут всего рабочего трафика через выбранный туннель;
- `ct-ns` — транспорт до хоста, где отдельная первая firewall-цепочка разрешает
  только UDP-пакеты к точному WireGuard endpoint и отбрасывает всё остальное.

Поэтому при падении `ct-wg` соединения Claude не уходят через обычный интерфейс:
они перестают работать. DNS берётся из VPN-конфига и доступен только внутри
namespace. Конфиги с hostname в `Endpoint`, root hooks (`PreUp`, `PostUp` и
аналоги), без DNS или без `0.0.0.0/0` отвергаются.

Claude Code и выделенный Chromium получают фиксированные `TZ=UTC`,
`LANG=C.UTF-8` и `LC_ALL=C.UTF-8`; `/etc/localtime` внутри namespace также
подменён на UTC. Для Claude Code приложение принудительно задаёт
`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`, отключая отдельную телеметрию,
error reporting, feedback и прочие необязательные сетевые запросы клиента.
Это убирает очевидные региональные сигналы и побочный трафик, не меняя
настройки основной системы.

Это не анонимизирует Claude-аккаунт и не скрывает содержимое штатной сессии:
сервер по-прежнему получает OAuth-идентичность, prompts, model outputs и
результаты tools, которые Claude Code отправляет модели. Туннель скрывает IP
хоста, но не разрывает связь с историей, подпиской или платёжными данными
аккаунта.

Граница гарантии: запускайте Claude командой `claude-tunnel run -- ...` (или
сделайте её единственным shell-wrapper с именем `claude`). Прямой запуск
настоящего бинарника Claude вне приложения не может быть перехвачен обычным
пользовательским tray-процессом.

## Установка на NixOS

```sh
nix profile install path:$PWD
mkdir -p ~/.config/claude-tunnel/tunnels
cp examples/tunnel.example.conf ~/.config/claude-tunnel/tunnels/tunnel.conf
cp config.example.toml ~/.config/claude-tunnel/config.toml
```

Заполните ключи, адреса и endpoint в `tunnel.conf`. Локальные `*.conf`
исключены через `.gitignore` и не должны добавляться в Git.

AmneziaWG (`awg`, `awg-quick`) должен быть установлен в системе. Для иконки в
GNOME нужен AppIndicator, как и в исходном `vpn`.

Разрешите только внутренний привилегированный интерфейс установленного бинарника:

```nix
security.sudo.extraRules = [{
  users = [ "user" ];
  commands = [{
    command = "/home/user/.nix-profile/bin/claude-tunnel";
    options = [ "NOPASSWD" ];
  }];
}];
```

После изменения конфигурации выполните `sudo nixos-rebuild switch`.

## Использование

```sh
claude-tunnel tray                 # отдельная иконка Claude в трее
claude-tunnel status               # connected / protected offline
claude-tunnel steam status         # enabled / disabled
claude-tunnel steam up             # включить узкий Steam IPC bridge
claude-tunnel steam down           # убрать Steam IPC bridge
claude-tunnel run --               # интерактивный Claude Code
claude-tunnel run -- --continue    # аргументы передаются без shell
```

В трее можно выбрать любой `.conf` из `tunnels_dir`, переключить туннель,
отключить его или включить автозапуск. Отключение туннеля означает для Claude
режим `Protected: offline`, а не прямой доступ.

Опция `Прокинуть Steam IPC` доступна при активном туннеле. Она находит только
IPv4 loopback TCP-порты, которые в этот момент слушает процесс `steam` текущего
пользователя, и создаёт для каждого пару локальных прокси: с `127.0.0.1` внутри
namespace на адрес veth и с veth на `127.0.0.1` хоста. Claude не получает host
network namespace, доступ к произвольным портам хоста или обход VPN. Публичный
Steam listener `0.0.0.0:27036` также не прокидывается.

Сначала запустите Steam на хосте, затем включите опцию в трее или выполните
`claude-tunnel steam up`. После перезапуска Steam выключите и снова включите
мост: его IPC-порты динамические. Отключение основного туннеля автоматически
удаляет все Steam-прокси; по умолчанию мост выключен.

Пункт `Открыть браузер` доступен только при активном туннеле. Он запускает
Chromium в том же network namespace с отдельным профилем из
`browser_profile_dir` и открывает страницу входа Claude. Если OAuth-ссылка
появилась в терминале Claude Code, вставьте её в этот Chromium. Профиль не
делит cookies или уже запущенный процесс с обычным браузером; при падении
туннеля его сеть также блокируется. Chromium запускается с фиксированным
`en-US`, размером окна, запретом permission prompts и прямого WebRTC UDP, а
также без background networking, component updates и sync. Эти настройки
уменьшают пассивный региональный fingerprint страницы входа, но не скрывают
тип ОС, версию браузера или аппаратный fingerprint полностью. То же действие
доступно командой `claude-tunnel browser`.

OAuth-ссылки, которые Claude Code открывает сам (например, команда `/login`),
также перехватываются. Для процесса Claude приложение задаёт защищённый
`BROWSER` и подменяет `xdg-open`; оба пути запускают только выделенный профиль
Chromium внутри namespace. Системный браузер для таких ссылок не используется.

Чтобы обычная команда `claude` всегда шла через приложение, положите wrapper
раньше настоящего бинарника в `PATH`:

```sh
mkdir -p ~/.local/bin
printf '%s\n' '#!/bin/sh' 'exec claude-tunnel run -- "$@"' > ~/.local/bin/claude
chmod 0755 ~/.local/bin/claude
```

В `config.toml` при этом обязательно оставьте абсолютный путь к настоящему
Claude Code, иначе получится рекурсия wrapper-а.

## HBS2

Публичное зеркало и децентрализованный hub доступны по адресу:

```text
hbs23://HGx6vZBNnC54T57VULJKb4bZYuxUa5qUkrYxFZpgA7VZ
```

Клонирование и синхронизация:

```sh
git clone hbs23://HGx6vZBNnC54T57VULJKb4bZYuxUa5qUkrYxFZpgA7VZ claude-tunnel
hbs2-hub sync
hbs2-hub status
```

## Разработка и проверки

```sh
nix develop
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
```
