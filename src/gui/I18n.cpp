// SPDX-License-Identifier: MIT
#include "I18n.h"

#include <QCoreApplication>
#include <QHash>
#include <QLibraryInfo>
#include <QLocale>
#include <QTranslator>

namespace ps::i18n {

namespace {

// Source (English) -> Russian. Keys must match the tr() strings exactly. Text produced by the
// analysis rules (finding titles and explanations) is not translated.
const QHash<QString, QString> &russian()
{
    static const QHash<QString, QString> table{
    {QStringLiteral("Format"), QStringLiteral("Формат")},
    {QStringLiteral("bytes"), QStringLiteral("байт")},
    {QStringLiteral("Entries"), QStringLiteral("Записи")},
    {QStringLiteral("Analysed"), QStringLiteral("Проанализировано")},
    {QStringLiteral("%1 files · %2 binaries · %3 scripts"), QStringLiteral("файлов: %1 · бинарников: %2 · скриптов: %3")},
    {QStringLiteral("%1 ms"), QStringLiteral("%1 мс")},
    {QStringLiteral(" MiB"), QStringLiteral(" МиБ")},
    {QStringLiteral(" s"), QStringLiteral(" с")},
    {QStringLiteral("%1 entries"), QStringLiteral("записей: %1")},
    {QStringLiteral("%1 shown"), QStringLiteral("показано: %1")},
    {QStringLiteral("%1 — %2 (risk %3/100)"), QStringLiteral("%1 — %2 (риск %3/100)")},
    {QStringLiteral("%1 — press Inspect, or Inspect & Trace to also run it in the sandbox"), QStringLiteral("%1 — нажмите «Inspect» или «Inspect & Trace», чтобы заодно запустить в песочнице")},
    {QStringLiteral("%1<span style='font-size:14px'> / 100</span>"), QStringLiteral("%1<span style='font-size:14px'> / 100</span>")},
    {QStringLiteral("&About PkgScope"), QStringLiteral("&О PkgScope")},
    {QStringLiteral("&Analyze"), QStringLiteral("&Анализ")},
    {QStringLiteral("&Cancel"), QStringLiteral("&Отмена")},
    {QStringLiteral("&Export report…"), QStringLiteral("&Экспорт отчёта…")},
    {QStringLiteral("&File"), QStringLiteral("&Файл")},
    {QStringLiteral("&Help"), QStringLiteral("&Справка")},
    {QStringLiteral("&Inspect"), QStringLiteral("&Inspect")},
    {QStringLiteral("&Open…"), QStringLiteral("&Открыть…")},
    {QStringLiteral("&Quit"), QStringLiteral("&Выход")},
    {QStringLiteral("&Settings…"), QStringLiteral("&Настройки…")},
    {QStringLiteral("&Tools"), QStringLiteral("&Инструменты")},
    {QStringLiteral("(fork)"), QStringLiteral("(fork)")},
    {QStringLiteral("(no output captured)"), QStringLiteral("(вывод не записан)")},
    {QStringLiteral("(none)"), QStringLiteral("(нет)")},
    {QStringLiteral("(not found)"), QStringLiteral("(не найден)")},
    {QStringLiteral(".deb  .rpm  .pkg.tar.zst  .apk  .AppImage  .snap  ELF  scripts — or click to browse"), QStringLiteral(".deb  .rpm  .pkg.tar.zst  .apk  .AppImage  .snap  ELF  скрипты — или нажмите, чтобы выбрать файл")},
    {QStringLiteral("<h2>PkgScope</h2><p style='%1'>Unpack and inspect a package without installing it, then optionally run it in an isolated sandbox to watch what it really does.</p>"), QStringLiteral("<h2>PkgScope</h2><p style='%1'>Распакуйте и изучите пакет, не устанавливая его, а затем при желании запустите в изолированной песочнице и посмотрите, что он делает на самом деле.</p>")},
    {QStringLiteral("<h3>PkgScope %1</h3><p>Inspects Linux packages, AppImages and binaries, and can run them inside an isolated, no-root sandbox to record exactly what they do — which files they touch and which hosts they contact.</p><p>Static heuristics and a single sandboxed run cannot prove a file is safe; they surface behaviour worth reviewing.</p><p>Native Qt&nbsp;%2 · libarchive. MIT licensed.</p>"), QStringLiteral("<h3>PkgScope %1</h3><p>Изучает пакеты Linux, AppImage и бинарники и может запускать их в изолированной песочнице без root, записывая, что именно они делают: какие файлы затрагивают и к каким хостам обращаются.</p><p>Статические эвристики и один запуск в песочнице не могут доказать, что файл безопасен; они лишь показывают поведение, которое стоит проверить.</p><p>Qt&nbsp;%2 · libarchive. Лицензия MIT.</p>")},
    {QStringLiteral("<p style='%1'>No medium or higher findings. Lower-severity items (if any) are in the Findings tab.</p>"), QStringLiteral("<p style='%1'>Находок уровня Medium и выше нет. Менее важные (если есть) — на вкладке «Findings».</p>")},
    {QStringLiteral("<span style='%1'>The sandbox runs the file as a fake root inside isolated namespaces with a copy-on-write overlay, dropped capabilities and a seccomp filter. Your real filesystem is never modified. Allowing network or display access weakens that isolation.</span>"), QStringLiteral("<span style='%1'>Песочница запускает файл от имени фиктивного root в изолированных пространствах имён с copy-on-write overlay, урезанными capabilities и фильтром seccomp. Ваша настоящая файловая система не меняется. Разрешение сети или дисплея ослабляет эту изоляцию.</span>")},
    {QStringLiteral("About &Qt"), QStringLiteral("О &Qt")},
    {QStringLiteral("About PkgScope"), QStringLiteral("О PkgScope")},
    {QStringLiteral("All supported (*.deb *.rpm *.pkg.tar.* *.apk *.AppImage *.appimage *.snap *.ipk *.xbps *.tgz *.txz *.tar.* *.run *.sh *.bash *.zsh *.py *.pl *.rb *.so *.ko *.bin *.install);;Packages (*.deb *.rpm *.pkg.tar.* *.apk *.snap *.ipk *.xbps *.tgz *.txz *.tar.*);;AppImages (*.AppImage *.appimage);;Scripts and installers (*.sh *.bash *.zsh *.py *.pl *.rb *.run *.bin *.install);;Libraries and kernel modules (*.so *.so.* *.ko);;All files (*)"), QStringLiteral("Все поддерживаемые (*.deb *.rpm *.pkg.tar.* *.apk *.AppImage *.appimage *.snap *.ipk *.xbps *.tgz *.txz *.tar.* *.run *.sh *.bash *.zsh *.py *.pl *.rb *.so *.ko *.bin *.install);;Пакеты (*.deb *.rpm *.pkg.tar.* *.apk *.snap *.ipk *.xbps *.tgz *.txz *.tar.*);;AppImage (*.AppImage *.appimage);;Скрипты и установщики (*.sh *.bash *.zsh *.py *.pl *.rb *.run *.bin *.install);;Библиотеки и модули ядра (*.so *.so.* *.ko);;Все файлы (*)")},
    {QStringLiteral("Allow network access (default: isolated, attempts recorded but fail)"), QStringLiteral("Разрешить доступ к сети (по умолчанию изолирована: попытки записываются, но не удаются)")},
    {QStringLiteral("An analysis is still running. Stop it and quit?"), QStringLiteral("Анализ ещё выполняется. Остановить его и выйти?")},
    {QStringLiteral("Analysis failed"), QStringLiteral("Не удалось выполнить анализ")},
    {QStringLiteral("Appearance"), QStringLiteral("Оформление")},
    {QStringLiteral("Arch"), QStringLiteral("Arch")},
    {QStringLiteral("Architecture"), QStringLiteral("Архитектура")},
    {QStringLiteral("Behaviour"), QStringLiteral("Поведение")},
    {QStringLiteral("Behaviour ✓"), QStringLiteral("Поведение ✓")},
    {QStringLiteral("Binaries"), QStringLiteral("Бинарники")},
    {QStringLiteral("Binaries (%1)"), QStringLiteral("Бинарники (%1)")},
    {QStringLiteral("Blocking issues:"), QStringLiteral("Что мешает:")},
    {QStringLiteral("C&lose result"), QStringLiteral("&Закрыть результат")},
    {QStringLiteral("Canary"), QStringLiteral("Canary")},
    {QStringLiteral("Cancelling…"), QStringLiteral("Отмена…")},
    {QStringLiteral("Category"), QStringLiteral("Категория")},
    {QStringLiteral("Change"), QStringLiteral("Изменение")},
    {QStringLiteral("Check &sandbox support…"), QStringLiteral("Проверить &поддержку песочницы…")},
    {QStringLiteral("Check <i>Analyze → Check sandbox support</i> if tracing is unavailable."), QStringLiteral("Если трассировка недоступна, откройте <i>Анализ → Проверить поддержку песочницы</i>.")},
    {QStringLiteral("Contents"), QStringLiteral("Содержимое")},
    {QStringLiteral("Contents (%1)"), QStringLiteral("Содержимое (%1)")},
    {QStringLiteral("Count"), QStringLiteral("Число")},
    {QStringLiteral("Dark"), QStringLiteral("Тёмная")},
    {QStringLiteral("Deep-scan file limit:"), QStringLiteral("Лимит файла для глубокого скана:")},
    {QStringLiteral("Default export format:"), QStringLiteral("Формат экспорта по умолчанию:")},
    {QStringLiteral("Depends"), QStringLiteral("Зависимости")},
    {QStringLiteral("Description"), QStringLiteral("Описание")},
    {QStringLiteral("Destination"), QStringLiteral("Назначение")},
    {QStringLiteral("Detail"), QStringLiteral("Подробности")},
    {QStringLiteral("Domain"), QStringLiteral("Домен")},
    {QStringLiteral("Drop a package, AppImage or binary here"), QStringLiteral("Перетащите сюда пакет, AppImage или бинарник")},
    {QStringLiteral("Evidence:"), QStringLiteral("Доказательство:")},
    {QStringLiteral("Export failed"), QStringLiteral("Не удалось экспортировать")},
    {QStringLiteral("Export report"), QStringLiteral("Экспорт отчёта")},
    {QStringLiteral("Extra arguments passed to executables, AppImages and scripts when traced."), QStringLiteral("Дополнительные аргументы для исполняемых файлов, AppImage и скриптов при трассировке.")},
    {QStringLiteral("Extra arguments:"), QStringLiteral("Дополнительные аргументы:")},
    {QStringLiteral("Field"), QStringLiteral("Поле")},
    {QStringLiteral("File"), QStringLiteral("Файл")},
    {QStringLiteral("File activity"), QStringLiteral("Работа с файлами")},
    {QStringLiteral("File activity (%1)"), QStringLiteral("Работа с файлами (%1)")},
    {QStringLiteral("Filesystem diff"), QStringLiteral("Изменения файловой системы")},
    {QStringLiteral("Filesystem diff (%1)"), QStringLiteral("Изменения файловой системы (%1)")},
    {QStringLiteral("Filter by path, kind or flag…"), QStringLiteral("Фильтр по пути, виду или признаку…")},
    {QStringLiteral("Filter file activity…"), QStringLiteral("Фильтр работы с файлами…")},
    {QStringLiteral("Filter findings (title, category, path, severity)…"), QStringLiteral("Фильтр находок (название, категория, путь, важность)…")},
    {QStringLiteral("Finding"), QStringLiteral("Находка")},
    {QStringLiteral("Findings"), QStringLiteral("Находки")},
    {QStringLiteral("Findings (%1)"), QStringLiteral("Находки (%1)")},
    {QStringLiteral("Flags"), QStringLiteral("Признаки")},
    {QStringLiteral("Follow system"), QStringLiteral("Как в системе")},
    {QStringLiteral("Grace period for daemons:"), QStringLiteral("Время жизни демонов:")},
    {QStringLiteral("HTML report (*.html);;JSON report (*.json);;Markdown report (*.md)"), QStringLiteral("Отчёт HTML (*.html);;Отчёт JSON (*.json);;Отчёт Markdown (*.md)")},
    {QStringLiteral("Homepage"), QStringLiteral("Сайт")},
    {QStringLiteral("How long background processes may keep running after the main process exits before they are stopped."), QStringLiteral("Сколько фоновые процессы могут работать после завершения главного, прежде чем их остановят.")},
    {QStringLiteral("Indicators"), QStringLiteral("Индикаторы")},
    {QStringLiteral("Indicators (%1)"), QStringLiteral("Индикаторы (%1)")},
    {QStringLiteral("Inspect && &Trace"), QStringLiteral("Inspect && &Trace")},
    {QStringLiteral("Inspecting…"), QStringLiteral("Анализ…")},
    {QStringLiteral("Keep the sandbox working directory for manual inspection"), QStringLiteral("Оставить рабочий каталог песочницы для ручного изучения")},
    {QStringLiteral("Kernel module info"), QStringLiteral("Сведения о модуле ядра")},
    {QStringLiteral("Kind"), QStringLiteral("Вид")},
    {QStringLiteral("Lang"), QStringLiteral("Язык")},
    {QStringLiteral("Language:"), QStringLiteral("Язык:")},
    {QStringLiteral("License"), QStringLiteral("Лицензия")},
    {QStringLiteral("Light"), QStringLiteral("Светлая")},
    {QStringLiteral("Loaded %1"), QStringLiteral("Загружено: %1")},
    {QStringLiteral("Location"), QStringLiteral("Расположение")},
    {QStringLiteral("Location:"), QStringLiteral("Расположение:")},
    {QStringLiteral("Log"), QStringLiteral("Журнал")},
    {QStringLiteral("Main"), QStringLiteral("Главный")},
    {QStringLiteral("Maintainer"), QStringLiteral("Сопровождающий")},
    {QStringLiteral("Max file size in sandbox:"), QStringLiteral("Макс. размер файла в песочнице:")},
    {QStringLiteral("Maximum extracted size:"), QStringLiteral("Макс. размер распаковки:")},
    {QStringLiteral("Maximum size of any single file the traced program may create."), QStringLiteral("Максимальный размер любого файла, который может создать запущенная программа.")},
    {QStringLiteral("Mode"), QStringLiteral("Режим")},
    {QStringLiteral("Most important findings"), QStringLiteral("Самые важные находки")},
    {QStringLiteral("NX"), QStringLiteral("NX")},
    {QStringLiteral("Name"), QStringLiteral("Имя")},
    {QStringLiteral("Needed libraries"), QStringLiteral("Нужные библиотеки")},
    {QStringLiteral("Network"), QStringLiteral("Сеть")},
    {QStringLiteral("Network (%1)"), QStringLiteral("Сеть (%1)")},
    {QStringLiteral("No sandbox run"), QStringLiteral("Запуска в песочнице не было")},
    {QStringLiteral("Not a readable file:\n%1"), QStringLiteral("Не удаётся прочитать файл:\n%1")},
    {QStringLiteral("Notable imports"), QStringLiteral("Заметные импорты")},
    {QStringLiteral("Notes:"), QStringLiteral("Заметки:")},
    {QStringLiteral("Op"), QStringLiteral("Оп.")},
    {QStringLiteral("Open package or binary"), QStringLiteral("Открыть пакет или бинарник")},
    {QStringLiteral("Operation"), QStringLiteral("Операция")},
    {QStringLiteral("Overview"), QStringLiteral("Обзор")},
    {QStringLiteral("Owner"), QStringLiteral("Владелец")},
    {QStringLiteral("PID"), QStringLiteral("PID")},
    {QStringLiteral("PIE"), QStringLiteral("PIE")},
    {QStringLiteral("Package metadata"), QStringLiteral("Сведения о пакете")},
    {QStringLiteral("Path"), QStringLiteral("Путь")},
    {QStringLiteral("Per-file limit for ELF parsing and string scanning."), QStringLiteral("Лимит размера файла для разбора ELF и поиска строк.")},
    {QStringLiteral("PkgScope"), QStringLiteral("PkgScope")},
    {QStringLiteral("Port"), QStringLiteral("Порт")},
    {QStringLiteral("Preparing sandbox…"), QStringLiteral("Подготовка песочницы…")},
    {QStringLiteral("Process / command"), QStringLiteral("Процесс / команда")},
    {QStringLiteral("Processes"), QStringLiteral("Процессы")},
    {QStringLiteral("Program output"), QStringLiteral("Вывод программы")},
    {QStringLiteral("Protocol"), QStringLiteral("Протокол")},
    {QStringLiteral("RELRO"), QStringLiteral("RELRO")},
    {QStringLiteral("RPATH"), QStringLiteral("RPATH")},
    {QStringLiteral("RUNPATH"), QStringLiteral("RUNPATH")},
    {QStringLiteral("Ready. Open a file to begin."), QStringLiteral("Готово. Откройте файл, чтобы начать.")},
    {QStringLiteral("Report saved to %1"), QStringLiteral("Отчёт сохранён: %1")},
    {QStringLiteral("Restart PkgScope to apply the language."), QStringLiteral("Перезапустите PkgScope, чтобы применить язык.")},
    {QStringLiteral("Result"), QStringLiteral("Результат")},
    {QStringLiteral("Sandbox"), QStringLiteral("Песочница")},
    {QStringLiteral("Sandbox is not available"), QStringLiteral("Песочница недоступна")},
    {QStringLiteral("Sandbox is ready"), QStringLiteral("Песочница готова")},
    {QStringLiteral("Sandbox support"), QStringLiteral("Поддержка песочницы")},
    {QStringLiteral("Sandboxed run"), QStringLiteral("Запуск в песочнице")},
    {QStringLiteral("Scan printable strings inside binaries"), QStringLiteral("Искать печатные строки внутри бинарников")},
    {QStringLiteral("Scripts"), QStringLiteral("Скрипты")},
    {QStringLiteral("Scripts (%1)"), QStringLiteral("Скрипты (%1)")},
    {QStringLiteral("Select a binary to see linked libraries, notable imports and RPATH."), QStringLiteral("Выберите бинарник, чтобы увидеть библиотеки, заметные импорты и RPATH.")},
    {QStringLiteral("Select a finding to see the explanation and evidence."), QStringLiteral("Выберите находку, чтобы увидеть объяснение и доказательство.")},
    {QStringLiteral("Settings"), QStringLiteral("Настройки")},
    {QStringLiteral("Settings saved."), QStringLiteral("Настройки сохранены.")},
    {QStringLiteral("Severity"), QStringLiteral("Важность")},
    {QStringLiteral("Share the display so GUI apps can start (reduces isolation)"), QStringLiteral("Дать доступ к дисплею, чтобы запускались GUI-программы (ослабляет изоляцию)")},
    {QStringLiteral("Show indicators that are likely benign (schema/doc URLs)"), QStringLiteral("Показывать индикаторы, скорее всего безвредные (ссылки на схемы и документацию)")},
    {QStringLiteral("Size"), QStringLiteral("Размер")},
    {QStringLiteral("Source"), QStringLiteral("Источник")},
    {QStringLiteral("Stage"), QStringLiteral("Этап")},
    {QStringLiteral("Start"), QStringLiteral("Начало")},
    {QStringLiteral("Static"), QStringLiteral("Статический")},
    {QStringLiteral("Stop extracting once the uncompressed payload reaches this size (protects against decompression bombs)."), QStringLiteral("Прекратить распаковку, когда данные достигнут этого размера (защита от архивных бомб).")},
    {QStringLiteral("Stripped"), QStringLiteral("Stripped")},
    {QStringLiteral("Summary"), QStringLiteral("Итог")},
    {QStringLiteral("Theme:"), QStringLiteral("Тема:")},
    {QStringLiteral("This package ships no install scripts."), QStringLiteral("В этом пакете нет скриптов установки.")},
    {QStringLiteral("Time"), QStringLiteral("Время")},
    {QStringLiteral("Time limit per stage:"), QStringLiteral("Лимит времени на этап:")},
    {QStringLiteral("Type"), QStringLiteral("Тип")},
    {QStringLiteral("Use <b>Inspect &amp; Trace</b> to execute this file in the isolated sandbox and record its behaviour."), QStringLiteral("Нажмите <b>Inspect &amp; Trace</b>, чтобы выполнить файл в изолированной песочнице и записать его поведение.")},
    {QStringLiteral("Value"), QStringLiteral("Значение")},
    {QStringLiteral("Verify files against the package's own checksums"), QStringLiteral("Сверять файлы с контрольными суммами самого пакета")},
    {QStringLiteral("Version"), QStringLiteral("Версия")},
    {QStringLiteral("e.g. --help"), QStringLiteral("например, --help")},
    {QStringLiteral("exit %1"), QStringLiteral("код %1")},
    {QStringLiteral("libc functions re-implemented"), QStringLiteral("переопределены функции libc")},
    {QStringLiteral("runtime"), QStringLiteral("runtime")},
    {QStringLiteral("static"), QStringLiteral("static")},
    {QStringLiteral("time limit"), QStringLiteral("лимит времени")},
    };
    return table;
}

class Translator : public QTranslator
{
public:
    bool isEmpty() const override { return false; }
    QString translate(const char *, const char *source, const char *, int) const override
    {
        return russian().value(QString::fromUtf8(source));
    }
};

} // namespace

bool wantsRussian(const QString &setting)
{
    const QString forced = qEnvironmentVariable("PKGSCOPE_LANG");
    const QString choice = forced.isEmpty() ? setting : forced;
    if (choice == QLatin1String("ru") || choice.startsWith(QLatin1String("ru_")))
        return true;
    if (choice == QLatin1String("en"))
        return false;
    return QLocale().language() == QLocale::Russian; // "auto"
}

void install(QCoreApplication &app, const QString &setting)
{
    if (!wantsRussian(setting))
        return;
    static Translator translator;
    app.installTranslator(&translator);
    // Standard Qt dialog buttons (Yes, Cancel, ...) follow when Qt's own translations are installed.
    static QTranslator qt;
    if (qt.load(QLocale(QLocale::Russian), QStringLiteral("qtbase"), QStringLiteral("_"),
                QLibraryInfo::path(QLibraryInfo::TranslationsPath)))
        app.installTranslator(&qt);
}

} // namespace ps::i18n
