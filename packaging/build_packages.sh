#!/usr/bin/env bash
set -euo pipefail

# Build .deb and/or .rpm packages for ClamAV Security Center.
# Usage:
#   ./packaging/build_packages.sh --type rpm --rpm-flavor rocky --version 1.2.0 --release 1
#   ./packaging/build_packages.sh --type deb --version 1.2.0 --release 1

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

PKG_NAME="clamav-security-center"
PKG_TYPE=""
RPM_FLAVOR="fedora"
DIST_TAG=""
VERSION=""
RELEASE="1"
OUT_DIR="${REPO_ROOT}/dist"

usage() {
  cat <<EOF
Usage: $0 --type <deb|rpm> --version <ver> [--release <rel>] [--rpm-flavor <fedora|rocky|opensuse>] [--dist-tag <tag>] [--out-dir <dir>]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --type)
      PKG_TYPE="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    --release)
      RELEASE="$2"
      shift 2
      ;;
    --rpm-flavor)
      RPM_FLAVOR="$2"
      shift 2
      ;;
    --dist-tag)
      DIST_TAG="$2"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "${PKG_TYPE}" || ( "${PKG_TYPE}" != "deb" && "${PKG_TYPE}" != "rpm" ) ]]; then
  echo "Error: --type must be 'deb' or 'rpm'" >&2
  exit 1
fi

if [[ -z "${VERSION}" ]] || [[ ! "${VERSION}" =~ ^[0-9]+(\.[0-9]+)*([~+-][0-9A-Za-z.]+)?$ ]]; then
  echo "Error: invalid or empty --version '${VERSION}' (expected e.g. 1.0.0)" >&2
  exit 1
fi

if [[ -z "${RELEASE}" ]] || [[ ! "${RELEASE}" =~ ^[0-9A-Za-z.]+$ ]]; then
  echo "Error: invalid --release '${RELEASE}'" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"

render_desktop_file() {
  local dest="$1"
  cat > "${dest}" <<'EOF'
[Desktop Entry]
Type=Application
Version=1.0
Name=ClamAV Security Center
Name[de]=ClamAV Sicherheitszentrum
GenericName=Antivirus Scanner GUI
GenericName[de]=Virenscanner-Oberfläche
Comment=Monitor and control ClamAV scans, quarantine, and virus signatures
Comment[de]=ClamAV-Scans, Quarantäne und Virensignaturen überwachen und steuern
Exec=/usr/bin/clamav-security-center
Icon=clamav-kde-gui
Terminal=false
Categories=System;Security;Qt;GTK;KDE;GNOME;
StartupWMClass=clamav-kde-gui
EOF
  chmod 0644 "${dest}"
  if command -v desktop-file-validate >/dev/null 2>&1; then
    desktop-file-validate "${dest}"
  fi
}

render_launcher_wrapper() {
  local dest="$1"
  cat > "${dest}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec /usr/share/clamav-security-center/run.sh "$@"
EOF
  chmod 0755 "${dest}"
}

build_deb() {
  command -v dpkg-deb >/dev/null 2>&1 || {
    echo "Error: dpkg-deb is required to build .deb packages" >&2
    exit 1
  }

  local workdir stage_dir deb_ver deb_file
  workdir="$(mktemp -d)"
  trap 'rm -rf "${workdir}"' RETURN

  deb_ver="${VERSION}-${RELEASE}"
  stage_dir="${workdir}/${PKG_NAME}_${deb_ver}_all"

  install -d "${stage_dir}/DEBIAN"
  install -d "${stage_dir}/usr/share/${PKG_NAME}"
  install -d "${stage_dir}/usr/bin"
  install -d "${stage_dir}/usr/share/applications"
  install -d "${stage_dir}/usr/share/icons/hicolor/scalable/apps"

  install -m 0755 "${REPO_ROOT}/clamav_gui.py" "${stage_dir}/usr/share/${PKG_NAME}/clamav_gui.py"
  install -m 0755 "${REPO_ROOT}/run.sh" "${stage_dir}/usr/share/${PKG_NAME}/run.sh"
  render_launcher_wrapper "${stage_dir}/usr/bin/${PKG_NAME}"
  ln -s "${PKG_NAME}" "${stage_dir}/usr/bin/clamav-kde-gui"
  render_desktop_file "${stage_dir}/usr/share/applications/clamav-kde-gui.desktop"
  install -m 0644 "${SCRIPT_DIR}/clamav-kde-gui.svg" "${stage_dir}/usr/share/icons/hicolor/scalable/apps/clamav-kde-gui.svg"

  local installed_kb
  installed_kb="$(du -sk "${stage_dir}/usr" | awk '{print $1}')"

  cat > "${stage_dir}/DEBIAN/control" <<EOF
Package: ${PKG_NAME}
Version: ${deb_ver}
Section: utils
Priority: optional
Architecture: all
Installed-Size: ${installed_kb}
Maintainer: Armin Schneider <JXS1985@users.noreply.github.com>
Homepage: https://github.com/JXS1985/ClamAV-GUI
Depends: python3 (>= 3.10), clamav, clamav-freshclam, findutils, procps, polkitd | policykit-1, libnotify-bin, python3-pyqt6 | python3-pyside6.qtwidgets
Description: ClamAV Security Center GUI for KDE Plasma and GNOME
 Qt6 desktop control center for running, monitoring, pausing, scheduling,
 and managing ClamAV antivirus scans, quarantine, and freshclam updates.
EOF

  cat > "${stage_dir}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v gtk-update-icon-cache >/dev/null 2>&1 && [ -d /usr/share/icons/hicolor ]; then
  gtk-update-icon-cache -q -f -t /usr/share/icons/hicolor || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database -q /usr/share/applications || true
fi
EOF
  chmod 0755 "${stage_dir}/DEBIAN/postinst"

  deb_file="${OUT_DIR}/${PKG_NAME}_${deb_ver}_all.deb"
  dpkg-deb --root-owner-group --build "${stage_dir}" "${deb_file}"
  echo "Built DEB: ${deb_file}"
  dpkg-deb --info "${deb_file}"
  dpkg-deb --contents "${deb_file}"
}

build_rpm() {
  command -v rpmbuild >/dev/null 2>&1 || {
    echo "Error: rpmbuild is required to build .rpm packages" >&2
    exit 1
  }

  local rpm_ver rpm_rel rpm_top src_dir src_tar spec_file dist_suffix requires_block recommends_block
  rpm_ver="${VERSION//-/.}"
  rpm_ver="${rpm_ver//\~/.}"
  if [[ -n "${DIST_TAG}" ]]; then
    dist_suffix=".${DIST_TAG#.}"
  else
    dist_suffix=""
  fi
  rpm_rel="${RELEASE}${dist_suffix}"

  case "${RPM_FLAVOR}" in
    fedora|rocky)
      requires_block=$'Requires:       python3 >= 3.10\nRequires:       clamav\nRequires:       clamav-freshclam\nRequires:       findutils\nRequires:       procps-ng\nRequires:       polkit\nRequires:       libnotify\nRequires:       (python3-pyside6 or python3-pyqt6)'
      recommends_block=""
      ;;
    opensuse)
      requires_block=$'Requires:       python3 >= 3.10\nRequires:       clamav\nRequires:       findutils\nRequires:       procps\nRequires:       polkit\nRequires:       libnotify-tools\nRequires:       (python3-pyside6 or python3-qt6 or python3-pyqt6)'
      recommends_block=""
      ;;
    *)
      echo "Error: unsupported --rpm-flavor '${RPM_FLAVOR}'" >&2
      exit 1
      ;;
  esac

  rpm_top="$(mktemp -d)"
  trap 'rm -rf "${rpm_top}"' RETURN
  mkdir -p "${rpm_top}"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

  src_dir="${rpm_top}/src_stage/${PKG_NAME}-${rpm_ver}"
  mkdir -p "${src_dir}/packaging"
  install -m 0755 "${REPO_ROOT}/clamav_gui.py" "${src_dir}/clamav_gui.py"
  install -m 0755 "${REPO_ROOT}/run.sh" "${src_dir}/run.sh"
  render_launcher_wrapper "${src_dir}/packaging/${PKG_NAME}"
  render_desktop_file "${src_dir}/packaging/clamav-kde-gui.desktop"
  install -m 0644 "${SCRIPT_DIR}/clamav-kde-gui.svg" "${src_dir}/packaging/clamav-kde-gui.svg"

  src_tar="${rpm_top}/SOURCES/${PKG_NAME}-${rpm_ver}.tar.gz"
  tar -C "${rpm_top}/src_stage" -czf "${src_tar}" "${PKG_NAME}-${rpm_ver}"

  spec_file="${rpm_top}/SPECS/${PKG_NAME}.spec"
  cat > "${spec_file}" <<EOF
Name:           ${PKG_NAME}
Version:        ${rpm_ver}
Release:        ${rpm_rel}
Summary:        ClamAV Security Center GUI for KDE Plasma and GNOME
License:        GPL-3.0-or-later
URL:            https://github.com/JXS1985/ClamAV-GUI
BuildArch:      noarch
Source0:        %{name}-%{version}.tar.gz

${requires_block}
${recommends_block}

%description
Qt6 desktop control center for running, monitoring, pausing, scheduling,
and managing ClamAV antivirus scans, quarantine, and freshclam updates
with automatic OS locale detection across 8 languages.

%prep
%setup -q

%build
python3 -m py_compile clamav_gui.py

%install
install -d -m 0755 %{buildroot}%{_datadir}/%{name}
install -d -m 0755 %{buildroot}%{_bindir}
install -d -m 0755 %{buildroot}%{_datadir}/applications
install -d -m 0755 %{buildroot}%{_datadir}/icons/hicolor/scalable/apps
install -m 0755 clamav_gui.py %{buildroot}%{_datadir}/%{name}/clamav_gui.py
install -m 0755 run.sh %{buildroot}%{_datadir}/%{name}/run.sh
install -m 0755 packaging/${PKG_NAME} %{buildroot}%{_bindir}/${PKG_NAME}
ln -s ${PKG_NAME} %{buildroot}%{_bindir}/clamav-kde-gui
install -m 0644 packaging/clamav-kde-gui.desktop %{buildroot}%{_datadir}/applications/clamav-kde-gui.desktop
install -m 0644 packaging/clamav-kde-gui.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/clamav-kde-gui.svg

%files
%dir %{_datadir}/%{name}
%{_datadir}/%{name}/clamav_gui.py
%{_datadir}/%{name}/run.sh
%{_bindir}/${PKG_NAME}
%{_bindir}/clamav-kde-gui
%{_datadir}/applications/clamav-kde-gui.desktop
%{_datadir}/icons/hicolor/scalable/apps/clamav-kde-gui.svg

%post
if command -v gtk-update-icon-cache >/dev/null 2>&1 && [ -d /usr/share/icons/hicolor ]; then
  gtk-update-icon-cache -q -f -t /usr/share/icons/hicolor || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database -q /usr/share/applications || true
fi

%postun
if command -v gtk-update-icon-cache >/dev/null 2>&1 && [ -d /usr/share/icons/hicolor ]; then
  gtk-update-icon-cache -q -f -t /usr/share/icons/hicolor || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database -q /usr/share/applications || true
fi

%changelog
* $(LC_ALL=C date +"%a %b %d %Y") Maintainer <noreply@localhost> - ${rpm_ver}-${rpm_rel}
- Package build ${VERSION}-${RELEASE}
EOF

  rpmbuild --define "_topdir ${rpm_top}" -bb "${spec_file}"
  find "${rpm_top}/RPMS" -type f -name "*.rpm" -exec cp -v {} "${OUT_DIR}/" \;
  for rpm_pkg in "${OUT_DIR}"/*"${rpm_ver}-${rpm_rel}"*.rpm; do
    echo "Built RPM: ${rpm_pkg}"
    rpm -qpi "${rpm_pkg}"
    rpm -qpl "${rpm_pkg}"
  done
}

case "${PKG_TYPE}" in
  deb) build_deb ;;
  rpm) build_rpm ;;
esac
