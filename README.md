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
claude-tunnel run --               # интерактивный Claude Code
claude-tunnel run -- --continue    # аргументы передаются без shell
```

В трее можно выбрать любой `.conf` из `tunnels_dir`, переключить туннель,
отключить его или включить автозапуск. Отключение туннеля означает для Claude
режим `Protected: offline`, а не прямой доступ.

Пункт `Открыть браузер` доступен только при активном туннеле. Он запускает
Chromium в том же network namespace с отдельным профилем из
`browser_profile_dir` и открывает страницу входа Claude. Если OAuth-ссылка
появилась в терминале Claude Code, вставьте её в этот Chromium. Профиль не
делит cookies или уже запущенный процесс с обычным браузером; при падении
туннеля его сеть также блокируется. То же действие доступно командой
`claude-tunnel browser`.

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
