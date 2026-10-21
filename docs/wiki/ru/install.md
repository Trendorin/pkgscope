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

## AppImage

```sh
chmod +x PkgScope-*-x86_64.AppImage
./PkgScope-*-x86_64.AppImage              # окно
./PkgScope-*-x86_64.AppImage --cli FILE   # командная строка
```

В AppImage свои `strace` и `unsquashfs`, так что разбор и трассировка работают без доустановки.
Двум системам нужен один разовый шаг, его делает `--setup-sandbox` (спросит пароль;
`--remove-sandbox` всё откатит):

- Ubuntu 24.04+ разрешает создавать user namespaces только программам с профилем AppArmor.
  Профиль для файла внутри AppImage или в домашней папке позволил бы любой вашей программе
  подменить этот файл и получить то же право, поэтому помощник копируется в
  `/usr/local/libexec/pkgscope/pkgscope-sandbox` (владелец root), и профиль указывает на копию.
- Если модуль `overlay` не загружен, он загружается сейчас и при каждом старте.

Проверить загрузку по `SHA256SUMS` из релиза:

```sh
sha256sum --ignore-missing -c SHA256SUMS
```

## Из исходников

`install.sh` собирает исходники через CMake и ставит в `~/.local`. Сам PkgScope ставится без
`sudo`; пароль понадобится только для недостающих пакетов дистрибутива и для `--setup`. Нужен
Qt 6.4 или новее (Debian 12, Ubuntu 24.04, Fedora 38 и новее); на более старых системах берите
AppImage.

| дистрибутив | пакеты, которые предложит поставить установщик |
|---|---|
| Arch | `base-devel cmake ninja qt6-base libarchive strace squashfs-tools` |
| Debian, Ubuntu | `build-essential cmake ninja-build qt6-base-dev libarchive-dev strace squashfs-tools` |
| Fedora | `gcc-c++ cmake ninja-build qt6-qtbase-devel libarchive-devel strace squashfs-tools` |
| openSUSE | `gcc-c++ cmake ninja qt6-base-devel libarchive-devel strace squashfs` |

```sh
./install.sh                    # с вопросами: куда ставить, нужно ли окно, настройка песочницы
./install.sh --yes              # без вопросов, по умолчанию
./install.sh --prefix /opt/pkgscope
./install.sh --no-gui           # только pkgscope-cli и помощник песочницы
./install.sh --setup            # ещё и подготовить систему к трассировке (спросит пароль)
./install.sh --no-packages      # ничего не ставить, только назвать недостающие пакеты
```

Если чего-то не хватает, установщик назовёт это и предложит поставить (по умолчанию «да», в том
числе с `--yes`). Без терминала и без `sudo` без пароля он просто покажет команду. Инструменты
сборки обязательны; без `strace` и `unsquashfs` PkgScope всё равно разбирает пакеты, но не
трассирует и не распаковывает AppImage.

`--setup` делает только то, что нужно этой системе. В Ubuntu 24.04+ копирует помощник в
`/usr/local/libexec/pkgscope/pkgscope-sandbox` (владелец root, ни одна ваша программа его не
подменит) и ставит для этой копии профиль AppArmor `pkgscope-sandbox-local`; PkgScope берёт копию,
когда AppArmor ограничивает user namespaces. Если нет `overlay`, загружает модуль и добавляет
`/etc/modules-load.d/pkgscope.conf`. При обновлении установщик предложит обновить копию, если
помощник изменился; `--uninstall` предложит всё это убрать.

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
| язык | **Настройки → Язык** (английский, русский или как в системе; применяется после перезапуска) или `PKGSCOPE_LANG=ru` на один запуск |
| рабочие каталоги песочницы | `~/.cache/pkgscope/work` (удаляются после каждого запуска, если не попросить оставить) |
