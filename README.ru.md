<div align="center">

[![English](https://img.shields.io/badge/English-0a0a0a?style=for-the-badge)](README.md)
[![Русский](https://img.shields.io/badge/%D0%A0%D1%83%D1%81%D1%81%D0%BA%D0%B8%D0%B9-e4e4e4?style=for-the-badge)](README.ru.md)

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/header-ru-dark.svg"><img src=".github/assets/header-ru-light.svg" alt="PKGSCOPE: загляните в пакет до установки"></picture>

**Загляните внутрь Linux-пакетов, AppImage и бинарников до установки.**<br>
Что куда ляжет, какие скрипты выполнятся от root и что установщик делает на самом деле — в песочнице без root.

[![release](https://img.shields.io/badge/release-v1.0.0-e4e4e4?style=flat-square&labelColor=0a0a0a)](https://github.com/Trendorin/pkgscope/releases/latest) [![license](https://img.shields.io/badge/license-MIT-e4e4e4?style=flat-square&labelColor=0a0a0a)](LICENSE) ![Qt](https://img.shields.io/badge/Qt-6-e4e4e4?style=flat-square&labelColor=0a0a0a) ![root](https://img.shields.io/badge/root-not_needed-e4e4e4?style=flat-square&labelColor=0a0a0a)<br>
[![packages](https://img.shields.io/badge/packages-pkg_%C2%B7_deb_%C2%B7_rpm_%C2%B7_AppImage-e4e4e4?style=flat-square&labelColor=0a0a0a)](#install) [![форматы](https://img.shields.io/badge/%D1%84%D0%BE%D1%80%D0%BC%D0%B0%D1%82%D1%8B-deb_%C2%B7_rpm_%C2%B7_pkg_%C2%B7_apk_%C2%B7_AppImage_%C2%B7_Snap_%C2%B7_ELF-e4e4e4?style=flat-square&labelColor=0a0a0a)](#features)

<img src=".github/assets/screenshot-overview.png" width="100%" alt="PkgScope with a suspicious demo package: risk 100 of 100, findings by severity, file and package details">

[![скачать](https://img.shields.io/badge/%D1%81%D0%BA%D0%B0%D1%87%D0%B0%D1%82%D1%8C-%D0%BF%D0%BE%D1%81%D0%BB%D0%B5%D0%B4%D0%BD%D0%B8%D0%B9_%D1%80%D0%B5%D0%BB%D0%B8%D0%B7-e4e4e4?style=for-the-badge&labelColor=0a0a0a)](https://github.com/Trendorin/pkgscope/releases/latest)
[![установка](https://img.shields.io/badge/%D1%83%D1%81%D1%82%D0%B0%D0%BD%D0%BE%D0%B2%D0%BA%D0%B0-4_%D1%81%D0%BF%D0%BE%D1%81%D0%BE%D0%B1%D0%B0-0a0a0a?style=for-the-badge&labelColor=0a0a0a)](#install)
[![cli](https://img.shields.io/badge/cli-%D0%B8_CI-0a0a0a?style=for-the-badge&labelColor=0a0a0a)](#docs)

</div>

<a id="about"></a>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/label-about-ru-dark.svg"><img src=".github/assets/label-about-ru-light.svg" alt="01 / О проекте"></picture>

</div>

PkgScope распаковывает пакет, не устанавливая его, строит дерево *что куда ляжет*, отмечает
подозрительное и объясняет, почему это важно. Ещё он может запустить установщик в одноразовой
песочнице и записать каждый затронутый файл и каждый хост, к которому тот обращался. Система не
меняется, после проверки ничего не остаётся.

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/mark-dark.svg"><img src=".github/assets/mark-light.svg" alt="Знак PkgScope: пакет под лупой"></picture> <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/spec-ru-dark.svg"><img src=".github/assets/spec-ru-light.svg" alt="pkgscope@linux: версия, стек, пакеты, образы, правила, изоляция, запуск, отчёты, лицензия"></picture>

</div>

<a id="features"></a>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/label-features-ru-dark.svg"><img src=".github/assets/label-features-ru-light.svg" alt="02 / Возможности"></picture>

</div>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/feature-formats-ru-dark.svg"><img src=".github/assets/feature-formats-ru-light.svg" alt="Форматы: deb, rpm, pacman, apk, AppImage, Snap, ELF"></picture> <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/feature-scripts-ru-dark.svg"><img src=".github/assets/feature-scripts-ru-light.svg" alt="Скрипты: опасные строки отмечены"></picture>
<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/feature-binaries-ru-dark.svg"><img src=".github/assets/feature-binaries-ru-light.svg" alt="Бинарники: защита ELF, импорты, подмена libc"></picture> <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/feature-sandbox-ru-dark.svg"><img src=".github/assets/feature-sandbox-ru-light.svg" alt="Песочница: без root, namespaces, overlay, seccomp"></picture>
<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/feature-trace-ru-dark.svg"><img src=".github/assets/feature-trace-ru-light.svg" alt="Трассировка: процессы, файлы и хосты установщика"></picture> <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/feature-reports-ru-dark.svg"><img src=".github/assets/feature-reports-ru-light.svg" alt="Отчёты: риск, HTML, JSON, Markdown, порог для CI"></picture>

</div>

<details>
<summary><b>Все форматы и проверки</b></summary>

| | |
|---|---|
| **Debian** | `.deb`, `.ipk` (OpenWrt) |
| **RPM** | `.rpm`, свой разборщик заголовка с проверкой границ |
| **Arch** | `.pkg.tar.zst` / `.xz` / `.gz` с `.INSTALL` и `.MTREE` |
| **Другие** | Alpine `.apk`, Void `.xbps`, Slackware `.txz` / `.tgz` с `doinst.sh` |
| **Образы** | AppImage (тип 1 и 2), Snap, SquashFS |
| **Отдельные файлы** | ELF-программы и библиотеки, модули ядра, скрипты shell / Python / Perl, установщики makeself |
| **Дерево файлов** | путь, права, владелец, размер, SHA-256; setuid, доступные всем на запись, скрытые и файлы устройств выделены |
| **Скрипты** | preinst / postinst, `%pre` / `%post`, `.INSTALL`, `doinst.sh` со строками, сработавшими на правила |
| **ELF** | PIE, NX, RELRO, canary, FORTIFY, RPATH / RUNPATH, заметные импорты, упаковщики, библиотеки, подменяющие libc (руткиты через `LD_PRELOAD`) |
| **Целостность** | каждый файл сверяется с контрольными суммами самого пакета (`md5sums`, дайджесты RPM, `.MTREE`) |
| **Эвристики** | больше 100 правил: скачать-и-выполнить, обратные шеллы, закрепление через cron / systemd / PAM / udev, кража учётных данных, майнеры, заметание следов, разрушительные команды |
| **Индикаторы** | URL, IP, домены и адреса `.onion`, ссылки на документацию отфильтрованы |

</details>

<a id="install"></a>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/label-install-ru-dark.svg"><img src=".github/assets/label-install-ru-light.svg" alt="03 / Установка"></picture>

</div>

| ваша система | файл из [последнего релиза](https://github.com/Trendorin/pkgscope/releases/latest) |
|---|---|
| **Arch Linux**, CachyOS, Manjaro | `pkgscope-1.0.0-1-x86_64.pkg.tar.zst` |
| **Debian 13** и новее | `pkgscope_1.0.0-1_amd64.deb` |
| **Fedora 44** и новее | `pkgscope-1.0.0-1.fc44.x86_64.rpm` |
| **любой дистрибутив** с glibc 2.35+ | `PkgScope-1.0.0-x86_64.AppImage`, без установки |

```sh
sudo pacman -U ./pkgscope-1.0.0-1-x86_64.pkg.tar.zst       # Arch
sudo apt install ./pkgscope_1.0.0-1_amd64.deb               # Debian
sudo dnf install ./pkgscope-1.0.0-1.fc44.x86_64.rpm       # Fedora
chmod +x PkgScope-1.0.0-x86_64.AppImage && ./PkgScope-1.0.0-x86_64.AppImage
```

Каждый пакет собирается в чистом контейнере своего дистрибутива, ставится и запускается там
до публикации. Проверить загрузку: `sha256sum --ignore-missing -c SHA256SUMS`.

`./PkgScope-*.AppImage --cli FILE` запускает командную строку. Для трассировки нужны `strace` и
`squashfs-tools` из вашего дистрибутива; пакеты ставят их сами.

<details>
<summary><b>Сборка из исходников</b></summary>

Нужны CMake 3.19+, компилятор C++20, заголовки Qt 6 и libarchive; для трассировки во время работы —
`strace` и `squashfs-tools`.

```sh
git clone https://github.com/Trendorin/pkgscope && cd pkgscope
./install.sh                     # сборка и установка в /usr/local
./install.sh --prefix ~/.local   # для одного пользователя, без root
./uninstall.sh                   # удалит ровно то, что поставил
```

</details>

<a id="quick-start"></a>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/label-quick-start-ru-dark.svg"><img src=".github/assets/label-quick-start-ru-light.svg" alt="04 / Быстрый старт"></picture>

</div>

Откройте файл (или перетащите его в окно) и нажмите **Inspect**. **Inspect & Trace** ещё и
запустит установщик в песочнице. У каждой находки есть важность, объяснение и доказательство.

<div align="center">

<img src=".github/assets/screenshot-findings.png" width="49%" alt="Находки по важности, с объяснением и доказательством выбранной"> <img src=".github/assets/screenshot-scripts.png" width="49%" alt="Скрипт postinst с подсвеченными строками, сработавшими на правила">

</div>

<a id="sandbox"></a>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/label-sandbox-ru-dark.svg"><img src=".github/assets/label-sandbox-ru-light.svg" alt="05 / Песочница"></picture>

</div>

**Inspect & Trace** повторяет работу менеджера пакетов (dpkg `preinst → unpack → postinst`, rpm
`%pre → unpack → %post`, pacman `pre_install → post_install`) от имени фиктивного root внутри:

- пространств имён user, mount, PID, IPC, UTS, cgroup и (по умолчанию) network: без root и без setuid;
- **copy-on-write overlay** поверх `/usr`, `/etc`, `/opt`, `/var` — на диске ничего не меняется;
- урезанного набора capabilities, rlimits и фильтра **seccomp** (загрузка модулей, `bpf`, `kexec`,
  монтирование, новые пространства имён, `io_uring` и другое запрещены);
- на Linux 6.12+ — **Landlock**: нет доступа к абстрактным сокетам хоста (X11, D-Bus) и сигналам наружу.

В отчёте — дерево процессов, работа с файлами с чтением чувствительных (в том числе
заблокированным), diff файловой системы, сетевые соединения с хостами DNS / SNI / HTTP и файлы,
созданные и запущенные во время установки.

| если трассировка не запускается | |
|---|---|
| Ubuntu 24.04+ | пакет Debian ставит профиль AppArmor; из исходников: `sudo install -Dm644 packaging/apparmor/pkgscope-sandbox /etc/apparmor.d/` и `sudo apparmor_parser -r /etc/apparmor.d/pkgscope-sandbox` |
| `overlay … read-only` | `sudo modprobe overlay` (пакеты загружают модуль при старте) |
| остальное | **Analyze → Check sandbox support** скажет, чего не хватает |

<a id="how-it-works"></a>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/label-how-it-works-ru-dark.svg"><img src=".github/assets/label-how-it-works-ru-light.svg" alt="06 / Как устроено"></picture>

</div>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/flow-ru-dark.svg"><img src=".github/assets/flow-ru-light.svg" alt="Пакет проходит статический анализ и песочницу и попадает в один отчёт"></picture>

</div>

```
src/core      без интерфейса: определение формата, разбор ELF и RPM, распаковка libarchive без
              выхода за каталог и через симлинки, правила, разбор strace, управление песочницей
src/sandbox   pkgscope-sandbox: маленький помощник без Qt и без setuid (namespaces, overlay, seccomp)
src/gui       окно на Qt 6 Widgets          src/cli_main.cpp   то же ядро без окна
```

<a id="security"></a>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/label-security-ru-dark.svg"><img src=".github/assets/label-security-ru-light.svg" alt="07 / Безопасность"></picture>

</div>

PkgScope читает враждебные файлы и сделан под это: статический анализ никогда не запускает
файл; каждый разборщик проверяет границы, и для каждого есть фаззер libFuzzer, который CI гоняет
под AddressSanitizer и UndefinedBehaviorSanitizer; распаковка отказывается от выхода за каталог,
абсолютных путей, побегов через симлинки и жёсткие ссылки, снимает setuid и не создаёт устройства
(проверено на специально собранных архивах); помощник песочницы без setuid и сбрасывает всё до запуска.

Чистый результат значит *ничего очевидного не нашлось*, а не «файл безопасен»: один статический
проход и один запуск в песочнице этого не докажут. Об уязвимостях — приватно, см. [SECURITY.md](SECURITY.md).

<a id="docs"></a>

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/label-docs-ru-dark.svg"><img src=".github/assets/label-docs-ru-light.svg" alt="08 / Документация"></picture>

</div>

<div align="center">

<a href="https://github.com/Trendorin/pkgscope/releases/latest"><picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/link-download-ru-dark.svg"><img src=".github/assets/link-download-ru-light.svg" alt="Скачать: pkg, deb, rpm, AppImage"></picture></a> <a href="#docs"><picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/link-cli-ru-dark.svg"><img src=".github/assets/link-cli-ru-light.svg" alt="Командная строка: скрипты и CI"></picture></a>
<a href="SECURITY.md"><picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/link-security-ru-dark.svg"><img src=".github/assets/link-security-ru-light.svg" alt="Безопасность: угрозы и как сообщить"></picture></a> <a href="CHANGELOG.md"><picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/link-changelog-ru-dark.svg"><img src=".github/assets/link-changelog-ru-light.svg" alt="Изменения: что и когда менялось"></picture></a>

</div>

### Командная строка

```sh
pkgscope-cli FILE                                # статическая проверка
pkgscope-cli --trace FILE                        # плюс запуск в песочнице
pkgscope-cli --trace --allow-network FILE
pkgscope-cli FILE --json out.json --html out.html --md out.md
pkgscope-cli --trace --fail-on high FILE         # код выхода 3 при находке High (для CI)
```

Также: [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · [CHANGELOG.md](CHANGELOG.md).

<div align="center">

<picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/eof-dark.svg"><img src=".github/assets/eof-light.svg" alt="EOF"></picture>

<img src=".github/assets/logo.svg" width="40" alt=""><br>
<sub>MIT · автор <a href="https://github.com/Trendorin">Trendorin</a></sub>

</div>
