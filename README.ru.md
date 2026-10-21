<div align="center">

<img src=".github/assets/logo.svg" width="88" alt="">

# PkgScope

Загляните внутрь Linux-пакета до установки.

[![Релиз](https://img.shields.io/badge/release-v1.1.1-0b8f7a)](https://github.com/Trendorin/pkgscope/releases/latest)
[![Лицензия](https://img.shields.io/badge/license-MIT-0b8f7a)](LICENSE)
![Qt](https://img.shields.io/badge/Qt-6-0b8f7a)
![Платформа](https://img.shields.io/badge/platform-Linux-0b8f7a)

[Скачать](https://github.com/Trendorin/pkgscope/releases/latest) · [Установка](#установка) · [Вики](docs/wiki/ru/README.md) · [Изменения](CHANGELOG.md) · [English](README.md)

</div>

<img src=".github/assets/screenshot-overview.png" width="100%" alt="PkgScope с подозрительным демо-пакетом: риск 100 из 100, находки по важности, сведения о файле и пакете">

PkgScope распаковывает пакет, не устанавливая его, показывает, что куда ляжет, отмечает
подозрительное и объясняет, почему это важно. Ещё он может запустить установщик в одноразовой
песочнице и записать каждый затронутый файл и каждый хост, к которому тот обращался. Система не
меняется, после проверки ничего не остаётся.

## Возможности

- Читает deb и ipk, rpm, пакеты pacman, Alpine apk, Void xbps, Slackware, AppImage, Snap,
  SquashFS, ELF-файлы, модули ядра, скрипты и установщики makeself.
- Дерево файлов с путями установки, правами, владельцами и SHA-256; setuid, доступные всем на
  запись, скрытые файлы и устройства выделены.
- Скрипты установки (postinst, `%post`, `.INSTALL`, `doinst.sh`) с отмеченными опасными строками.
- Проверки ELF: PIE, NX, RELRO, защита стека, FORTIFY, RPATH, заметные импорты, упаковщики и
  библиотеки, которые выдают себя за libc.
- Больше 100 правил: скачать-и-запустить, обратные шеллы, закрепление через cron, systemd, PAM и
  udev, кража учётных данных, майнеры, разрушительные команды. У каждой находки есть важность,
  объяснение и доказательство.
- Каждый файл сверяется с контрольными суммами самого пакета.
- По желанию — трассировка установщика в песочнице без root.
- Отчёты в JSON, HTML и Markdown и командная строка, которая умеет валить сборку в CI.

## Установка

| ваша система | файл из [последнего релиза](https://github.com/Trendorin/pkgscope/releases/latest) |
|---|---|
| Arch Linux, CachyOS, Manjaro | `pkgscope-1.1.1-1-x86_64.pkg.tar.zst` |
| Debian 13 и новее | `pkgscope_1.1.1-1_amd64.deb` |
| Fedora 44 и новее | `pkgscope-1.1.1-1.fc44.x86_64.rpm` |
| любой дистрибутив с glibc 2.35+ | `PkgScope-1.1.1-x86_64.AppImage` |

```sh
sudo pacman -U ./pkgscope-1.1.1-1-x86_64.pkg.tar.zst    # Arch
sudo apt install ./pkgscope_1.1.1-1_amd64.deb            # Debian
sudo dnf install ./pkgscope-1.1.1-1.fc44.x86_64.rpm      # Fedora
chmod +x PkgScope-1.1.1-x86_64.AppImage && ./PkgScope-1.1.1-x86_64.AppImage
```

Каждый пакет собирается в чистом контейнере своего дистрибутива, затем ставится и запускается
там до публикации. Проверить файлы: `sha256sum --ignore-missing -c SHA256SUMS`.
`./PkgScope-*.AppImage --cli FILE` запускает командную строку. Доустанавливать ничего не нужно:
пакеты ставят `strace` и `squashfs-tools`, в AppImage они свои. В Ubuntu 24.04+ один раз запустите
AppImage с `--setup-sandbox`, чтобы разрешить трассировку (спросит пароль).

### Из исходников

`install.sh` проверит CMake, компилятор C++20, Qt 6.4+ и libarchive и предложит доставить
недостающее через pacman, apt, dnf или zypper.

```sh
git clone https://github.com/Trendorin/pkgscope && cd pkgscope
./install.sh                 # задаст пару вопросов, соберёт и поставит в ~/.local
./install.sh --uninstall     # удалит ровно то, что поставил
```

`./install.sh --help` покажет параметры (`--yes`, `--prefix`, `--no-gui`, `--setup`,
`--no-packages`).

## Начало работы

Откройте файл или перетащите его в окно и нажмите **Inspect**. **Inspect & Trace** ещё и запустит
установщик в песочнице. У каждой находки есть важность, объяснение и доказательство.

<img src=".github/assets/screenshot-findings.png" width="49%" alt="Находки по важности"> <img src=".github/assets/screenshot-scripts.png" width="49%" alt="Скрипт postinst с подсвеченными строками, сработавшими на правила">

Из терминала или в CI:

```sh
pkgscope-cli FILE                                # статическая проверка
pkgscope-cli --trace FILE                        # плюс запуск в песочнице
pkgscope-cli FILE --json out.json --html out.html
pkgscope-cli --trace --fail-on high FILE         # код выхода 3 при находке High
```

## Песочница

**Inspect & Trace** повторяет работу менеджера пакетов (dpkg `preinst → unpack → postinst`, rpm
`%pre → unpack → %post`, pacman `pre_install → post_install`) от имени фиктивного root внутри:

- пространств имён user, mount, PID, IPC, UTS, cgroup и по умолчанию network: без root и без
  setuid;
- copy-on-write overlay поверх `/usr`, `/etc`, `/opt` и `/var`, поэтому на диске ничего не
  меняется;
- урезанного набора capabilities, rlimits и фильтра seccomp (загрузка модулей, `bpf`, `kexec`,
  монтирование, новые пространства имён, `io_uring` и другое запрещены);
- на Linux 6.12+ — Landlock: нет доступа к абстрактным сокетам хоста (X11, D-Bus) и сигналам
  наружу.

В отчёте — дерево процессов, работа с файлами с чтением чувствительных, diff файловой системы,
сетевые соединения с хостами DNS, SNI и HTTP и файлы, созданные и запущенные во время установки.
Если трассировка не запускается, см. [Песочница](docs/wiki/ru/sandbox.md).

## Как устроено

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/flow-ru-dark.svg"><img src=".github/assets/flow-ru-light.svg" width="100%" alt="Пакет проходит статический анализ и, по желанию, трассировку в песочнице; находки собираются в отчёт"></picture>

`src/core` без интерфейса: определение формата, разбор ELF и RPM, распаковка, правила и
управление песочницей. `src/sandbox` — `pkgscope-sandbox`, маленький помощник без Qt и без
setuid. Окно (`src/gui`) и `pkgscope-cli` — две оболочки над одним ядром.

## Безопасность

PkgScope читает враждебные файлы и сделан под это. Статический анализ никогда не запускает файл.
Каждый разборщик проверяет границы, и для каждого есть фаззер libFuzzer, который CI гоняет под
AddressSanitizer и UndefinedBehaviorSanitizer. Распаковка отказывается от выхода за каталог,
абсолютных путей и побегов через симлинки и жёсткие ссылки, снимает setuid и не создаёт
устройства. Помощник песочницы без setuid и сбрасывает всё до запуска.

Чистый результат значит, что ничего очевидного не нашлось, а не что файл безопасен: один
статический проход и один запуск в песочнице этого не докажут. Об уязвимостях сообщайте приватно,
см. [SECURITY.md](SECURITY.md).

## Документация

| | |
|---|---|
| [Установка](docs/wiki/ru/install.md) | пакеты, параметры установщика, обновление, удаление |
| [Форматы и проверки](docs/wiki/ru/checks.md) | что читается и что отмечается |
| [Песочница](docs/wiki/ru/sandbox.md) | как работает трассировка, что ей нужно, если не запускается |
| [Командная строка](docs/wiki/ru/cli.md) | параметры, отчёты, коды выхода |

[Участие](CONTRIBUTING.md) · [Безопасность](SECURITY.md) · [Изменения](CHANGELOG.md)

<div align="center"><sub>MIT · <a href="https://github.com/Trendorin">Trendorin</a></sub></div>
