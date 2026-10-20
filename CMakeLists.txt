cmake_minimum_required(VERSION 3.19)
project(PkgScope VERSION 1.0.1 DESCRIPTION "Package & binary inspector with sandboxed behaviour tracing" LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

include(GNUInstallDirs)

option(PKGSCOPE_WERROR "Treat warnings as errors" OFF)
option(PKGSCOPE_BUILD_GUI "Build the Qt Widgets application" ON)
option(PKGSCOPE_BUILD_TESTS "Build the tests (ctest)" OFF)
option(PKGSCOPE_FUZZ "Build the libFuzzer harness with ASan/UBSan (clang only)" OFF)

if(PKGSCOPE_BUILD_GUI)
  find_package(Qt6 6.2 REQUIRED COMPONENTS Core Gui Widgets)
else()
  find_package(Qt6 6.2 REQUIRED COMPONENTS Core)
endif()
find_package(LibArchive REQUIRED)
qt_standard_project_setup()

# Hardening flags for all targets
set(PKGSCOPE_HARDEN
  -Wall -Wextra -Wpedantic -Wno-missing-field-initializers
  -fstack-protector-strong -fPIE)
# Distribution flags (Fedora, Arch) usually bring their own _FORTIFY_SOURCE.
if(NOT CMAKE_CXX_FLAGS MATCHES "_FORTIFY_SOURCE")
  list(APPEND PKGSCOPE_HARDEN $<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=3>)
endif()
if(PKGSCOPE_WERROR)
  list(APPEND PKGSCOPE_HARDEN -Werror)
endif()
set(PKGSCOPE_LINK_HARDEN -Wl,-z,relro,-z,now -Wl,-z,noexecstack -pie)

# Install location of the sandbox helper. The absolute path is compiled in; paths
# relative to the binary are tried as well (AppImage, relocated trees).
set(PKGSCOPE_LIBEXECDIR "${CMAKE_INSTALL_LIBEXECDIR}/pkgscope")

# ---------------------------------------------------------------- core library
add_library(pkgscope_core STATIC
  src/core/Types.cpp src/core/Types.h
  src/core/Util.cpp src/core/Util.h
  src/core/SecureFs.cpp src/core/SecureFs.h
  src/core/ElfParser.cpp src/core/ElfParser.h
  src/core/RpmHeader.cpp src/core/RpmHeader.h
  src/core/ArchiveReader.cpp src/core/ArchiveReader.h
  src/core/ContentScanner.cpp src/core/ContentScanner.h
  src/core/Settings.cpp src/core/Settings.h
  src/core/Workspace.cpp src/core/Workspace.h
  src/core/StaticAnalyzer.cpp src/core/StaticAnalyzer.h
  src/core/StraceParser.cpp src/core/StraceParser.h
  src/core/DynamicTracer.cpp src/core/DynamicTracer.h
  src/core/ReportWriter.cpp src/core/ReportWriter.h
)
target_include_directories(pkgscope_core PUBLIC src)
target_link_libraries(pkgscope_core PUBLIC Qt6::Core LibArchive::LibArchive)
target_compile_options(pkgscope_core PRIVATE ${PKGSCOPE_HARDEN})
target_compile_definitions(pkgscope_core PUBLIC
  PKGSCOPE_VERSION="${PROJECT_VERSION}"
  PKGSCOPE_HELPER_DIR="${CMAKE_INSTALL_FULL_LIBEXECDIR}/pkgscope"
  QT_NO_CAST_FROM_ASCII QT_NO_URL_CAST_FROM_STRING QT_USE_QSTRINGBUILDER)
set_target_properties(pkgscope_core PROPERTIES AUTOMOC OFF POSITION_INDEPENDENT_CODE ON)

# ---------------------------------------------------------------- sandbox helper (no Qt)
add_executable(pkgscope-sandbox src/sandbox/sandbox_main.cpp)
target_compile_options(pkgscope-sandbox PRIVATE ${PKGSCOPE_HARDEN})
target_link_options(pkgscope-sandbox PRIVATE ${PKGSCOPE_LINK_HARDEN})
set_target_properties(pkgscope-sandbox PROPERTIES AUTOMOC OFF RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

# ---------------------------------------------------------------- CLI
qt_add_executable(pkgscope-cli src/cli_main.cpp)
target_link_libraries(pkgscope-cli PRIVATE pkgscope_core)
target_compile_options(pkgscope-cli PRIVATE ${PKGSCOPE_HARDEN})
target_link_options(pkgscope-cli PRIVATE ${PKGSCOPE_LINK_HARDEN})
set_target_properties(pkgscope-cli PROPERTIES AUTOMOC OFF RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
add_dependencies(pkgscope-cli pkgscope-sandbox)
install(TARGETS pkgscope-cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# ---------------------------------------------------------------- GUI application
if(PKGSCOPE_BUILD_GUI)
qt_add_executable(pkgscope
  src/main.cpp
  src/gui/MainWindow.cpp src/gui/MainWindow.h
  src/gui/SettingsDialog.cpp src/gui/SettingsDialog.h
  src/gui/Widgets.cpp src/gui/Widgets.h
  src/gui/Theme.cpp src/gui/Theme.h
  resources/pkgscope.qrc
)
target_link_libraries(pkgscope PRIVATE pkgscope_core Qt6::Gui Qt6::Widgets)
target_compile_options(pkgscope PRIVATE ${PKGSCOPE_HARDEN})
target_link_options(pkgscope PRIVATE ${PKGSCOPE_LINK_HARDEN})
set_target_properties(pkgscope PROPERTIES AUTORCC ON RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
add_dependencies(pkgscope pkgscope-sandbox)
install(TARGETS pkgscope RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

# ---------------------------------------------------------------- install
install(TARGETS pkgscope-sandbox RUNTIME DESTINATION ${PKGSCOPE_LIBEXECDIR})
install(FILES packaging/io.github.trendorin.PkgScope.desktop DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
install(FILES packaging/io.github.trendorin.PkgScope.metainfo.xml DESTINATION ${CMAKE_INSTALL_DATADIR}/metainfo)
install(FILES resources/icons/pkgscope.svg DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps RENAME io.github.trendorin.PkgScope.svg)
install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/pkgscope)
# Unprivileged overlayfs is what makes the sandbox copy-on-write; make sure the module loads at boot.
install(FILES packaging/modules-load.d/pkgscope.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/modules-load.d)

# ---------------------------------------------------------------- tests
if(PKGSCOPE_BUILD_TESTS)
  enable_testing()
  qt_add_executable(pkgscope-test-extract tests/test_extract.cpp)
  target_link_libraries(pkgscope-test-extract PRIVATE pkgscope_core)
  set_target_properties(pkgscope-test-extract PROPERTIES AUTOMOC OFF)
  add_test(NAME extract COMMAND pkgscope-test-extract)
  add_test(NAME cli-version COMMAND pkgscope-cli --version)
endif()

if(PKGSCOPE_FUZZ)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "PKGSCOPE_FUZZ needs clang (CC=clang CXX=clang++)")
  endif()
  set(PKGSCOPE_SAN -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer)
  target_compile_options(pkgscope_core PRIVATE ${PKGSCOPE_SAN})
  qt_add_executable(pkgscope-fuzz tests/fuzz/fuzz_parsers.cpp)
  target_link_libraries(pkgscope-fuzz PRIVATE pkgscope_core)
  target_compile_options(pkgscope-fuzz PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
  target_link_options(pkgscope-fuzz PRIVATE -fsanitize=fuzzer,address,undefined)
  set_target_properties(pkgscope-fuzz PROPERTIES AUTOMOC OFF)
endif()
