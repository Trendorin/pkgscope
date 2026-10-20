Name:           pkgscope
Version:        1.0.1
Release:        1%{?dist}
Summary:        Inspect Linux packages before installing them
License:        MIT
URL:            https://github.com/Trendorin/pkgscope
Source0:        %{url}/releases/download/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  cmake
BuildRequires:  ninja-build
BuildRequires:  gcc-c++
BuildRequires:  qt6-qtbase-devel
BuildRequires:  libarchive-devel
Requires:       strace
Requires:       squashfs-tools
Requires:       hicolor-icon-theme

%description
PkgScope unpacks deb, rpm, pacman, apk, xbps, Slackware and ipk packages,
AppImages, Snaps and ELF binaries without installing them, shows what goes
where, flags risky install scripts, setuid files, rootkit-style libraries and
network indicators, and can run the installer in a no-root sandbox to record
every process, file and host it touches.

%prep
%autosetup

%build
%cmake -G Ninja -DPKGSCOPE_BUILD_TESTS=ON
%cmake_build

%check
%ctest

%install
%cmake_install
# %%license below installs the licence.
rm -rf %{buildroot}%{_datadir}/licenses

%post
modprobe overlay >/dev/null 2>&1 || :

%files
%license LICENSE
%doc README.md CHANGELOG.md
%{_bindir}/pkgscope
%{_bindir}/pkgscope-cli
%{_libexecdir}/pkgscope/
%{_prefix}/lib/modules-load.d/pkgscope.conf
%{_datadir}/applications/io.github.trendorin.PkgScope.desktop
%{_datadir}/metainfo/io.github.trendorin.PkgScope.metainfo.xml
%{_datadir}/icons/hicolor/scalable/apps/io.github.trendorin.PkgScope.svg

%changelog
* Tue Oct 20 2026 Trendorin <193045225+Trendorin@users.noreply.github.com> - 1.0.1-1
- Security and correctness fixes, see CHANGELOG.md

* Tue Oct 20 2026 Trendorin <193045225+Trendorin@users.noreply.github.com> - 1.0.0-1
- First release
