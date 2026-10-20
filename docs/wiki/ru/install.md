# Установка

## Пакеты

В [последнем релизе](https://github.com/Trendorin/pkgscope/releases/latest) есть пакеты для
Arch Linux, Debian 13+ и Fedora 44+ и AppImage для любого дистрибутива с glibc 2.35+.

```sh
sudo pacman -U ./pkgscope-*-x86_64.pkg.tar.zst     # Arch, CachyOS, Manjaro
sudo apt install ./pkgscope_*_amd64.deb             # Debian, Ubuntu
sudo dnf install ./pkgscope-*.x86_64.rpm            # Fedora
```

Пакеты ставят `strace` и `squashfs-tools`, загружают модуль `overlay` при старте, а в Debian и
Ubuntu ещё и профиль AppArmor, который нужен песочнице в Ubuntu 24.04+.

Проверить загрузку по `SHA256SUMS` из релиза:

```sh
sha256sum --ignore-missing -c SHA256SUMS
```

## Из исходников

`install.sh` собирает исходники через CMake и ставит в `~/.local`. Для самой установки `sudo` не
используется.

| дистрибутив | зависимости для сборки |
|---|---|
| Arch | `base-devel cmake ninja qt6-base libarchive strace squashfs-tools` |
| Debian, Ubuntu | `build-essential cmake ninja-build qt6-base-dev libarchive-dev strace squashfs-tools` |
| Fedora | `gcc-c++ cmake ninja-build qt6-qtbase-devel libarchive-devel strace squashfs-tools` |

```sh
./install.sh                    # с вопросами: куда ставить, нужно ли окно, настройка песочницы
./install.sh --yes              # без вопросов, по умолчанию
./install.sh --prefix /opt/pkgscope
./install.sh --no-gui           # только pkgscope-cli и помощник песочницы
./install.sh --setup            # ещё и подготовить систему к трассировке (спросит пароль)
```

Если чего-то не хватает, установщик остановится и покажет команду, которая это поставит в вашем
дистрибутиве.

`--setup` делает только то, что нужно этой системе: в Ubuntu 24.04+ ставит профиль AppArmor,
разрешающий помощнику создавать user namespaces, а если нет `overlay`, загружает модуль.

## Обновление

Скачайте новую версию и снова запустите `./install.sh`. Он увидит установленную версию и
предложит обновить её на месте.

## Удаление

```sh
./install.sh --uninstall           # удалит ровно те файлы, что поставил
./install.sh --uninstall --purge   # и ещё настройки и кэш
```

Список установленных файлов хранится в `<prefix>/share/pkgscope/installed-files`. Пакеты
удаляются менеджером пакетов.

## Файлы

| что | где |
|---|---|
| настройки | `~/.config/pkgscope/PkgScope.conf` (общие для окна и `pkgscope-cli`) |
| рабочие каталоги песочницы | `~/.cache/pkgscope/work` (удаляются после каждого запуска, если не попросить оставить) |
