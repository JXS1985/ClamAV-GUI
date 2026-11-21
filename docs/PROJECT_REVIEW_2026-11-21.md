# ClamAV Security Center — Full Project Review — 2026-11-21

- **Scope:** Full codebase (`clamav_gui.py`, `run.sh`, `clamav-kde-gui.desktop`, `packaging/build_packages.sh`, `packaging/verify_installed_os.py`, `test_clamav_gui.py`, `test_ui_clamav_gui.py`, `.gitea/workflows/ci.yml`, `.gitea/workflows/build-packages.yml`, `AGENTS.md`, `AGENT.md`)
- **Stacks:** Python 3 / Qt6 (`PySide6` with `PyQt6` fallback), Linux `/proc` + systemd + Polkit + `sudo`/`pkexec`, DEB/RPM packaging, Gitea Actions. *(No dedicated stack block in `project-review` Section 4 for Python/Qt6; applied equivalent Linux desktop/privilege-separation, subprocess, filesystem, and UI test rules from Section 3 and the project's own rule files.)*
- **Personas:**
  1. **End User (Standard Desktop User — KDE Plasma / GNOME, EN & DE)** — compact status, dependency/DB check, Quick/Full/Picker/Drag&Drop scans, pause/resume/stop, threat quarantine/restore/delete, tray/notifications
  2. **Power User / Sysadmin (Elevated Root Helper Operator)** — sudo/pkexec unlock, live `/proc/fd` & `io` inspection, Custom Scan builder, log reloading, systemd scheduled scans, `freshclam` DB updates
  3. **Untrusted Local Process / Attacker (UID-isolated Local User)** — privilege boundaries across `--helper` JSON RPC, Polkit rule, `/proc`, quarantine, log paths, and systemd units
  4. **Maintainer / Packager (CI & Release Operator)** — unit/UI test execution, DEB/RPM builds, OS menu & notification checks
- **Build / commit:** `main` @ `f2bc469` (+ untracked `AGENT.md`, `project-review.skill`)
- **Environment:** RHEL 10.3 (`x86_64`), Python 3.12, ClamAV `1.4.6/28190`, KDE Plasma Wayland (`de_DE.UTF-8`), local `QT_QPA_PLATFORM=offscreen` test runner + live GUI daemon PID `30379`
- **References:** `AGENTS.md` (`f2bc469`), `AGENT.md` (untracked workspace file — contains generic PHP/JS/Playwright rules alongside applicable security, testing, least-churn, and surgical-edit mandates)
- **Method:** Full static/source audit of privilege boundaries and UI flows, `python3 -m py_compile`, `bash -n`, `desktop-file-validate`, `yaml.safe_load`, `clamav_gui.py --self-test`, `unittest discover` (51 tests), and `coverage run --branch` analysis.

## Summary
The core application architecture cleanly separates the unprivileged Qt6 UI from the privileged `--helper` JSON bridge, delivers full English/German localization, provides strong path/flag/Polkit hardening added in recent security passes, and passes all 51 automated tests (`78%` branch/statement coverage on `clamav_gui.py`, `83%` total). However, 1 High functional mismatch breaks custom non-`/var/log` log paths configured in the Custom Scan or Log tabs without user-visible error feedback, and several Medium/Low gaps remain across localization edge cases, openSUSE package dependency enforcement, repo-level `.desktop`/rule hygiene, and uncovered async/OS-installer test paths.

## 1. Release blockers
None identified in source paths verified locally (all previously discovered Critical/High privilege escalation vectors in `_helper_start_scan`, `_helper_install_polkit_rule`, quarantine/delete/restore handlers, log path chmod/truncation, and systemd unit generation are mitigated and regression-tested).

## 2. Headline issue: Custom log path UI vs. root helper log confinement
Standard users and Sysadmins can enter any custom log path (e.g., `/tmp/myscan.log` or `~/scan.log`) in Custom Scan (`new_log_edit`) and Live Log (`log_path_edit`), while the root helper silently or unexpectedly rejects non-`/var/log/` paths.

| # | Cause | Effect |
|---|---|---|
| 1 | `clamav_gui.py:3592` (`new_log_edit`) and `clamav_gui.py:3302` (`log_path_edit`) allow freeform paths anywhere on disk without UI validation or a `/var/log/` placeholder/hint. | Custom Scan start (`_helper_start_scan`) fails with `PermissionError` (`_validate_helper_log_path` at `clamav_gui.py:1171-1187`). |
| 2 | `clamav_gui.py:4361` (`_on_inspect_done`) returns silently on any RPC `error` string from `inspect_proc`. | Changing `log_path_edit` + clicking Reload (`_reload_log` at `clamav_gui.py:4507`) fails silently with an empty log pane and no diagnostic message. |
| **Fix (small & isolated):** Keep `/var/log/` confinement in `_validate_helper_log_path`, surface `_on_inspect_done` errors non-intrusively in `log_hint_lbl`, and add client-side validation / hint text on `new_log_edit` and `log_path_edit` showing the `/var/log/clamav*.log` requirement. | |

## 3. Findings (ordered by user impact)
| Severity | Persona | Area | What happens | Evidence / cause (file:line) | Suggestion |
|---|---|---|---|---|---|
| High | Power User / Sysadmin | Custom Scan / Live Log | Custom `log_path` outside `/var/log/` fails `_helper_start_scan` and fails silently in `_reload_log` | `clamav_gui.py:1171-1187`, `clamav_gui.py:3302`, `clamav_gui.py:3592`, `clamav_gui.py:4361` | Surface helper inspect errors in `log_hint_lbl` and constrain/hint `/var/log/` log paths in UI |
| Medium | Standard User (DE) | Localization / Hero & History | Hardcoded English strings appear in German UI: `" (also missing: ...)"` in missing-engine banner, `"System / Log Scan"` in parsed log history, and raw `"active"`/`"inactive"` service states | `clamav_gui.py:1437`, `clamav_gui.py:3818`, `clamav_gui.py:3744-3763` | Move `"also missing"` into `TRANSLATIONS`, localize `"System / Log Scan"` during `_refresh_history`, and translate service state labels |
| Medium | Standard User / Sysadmin | Quarantine Restore (`--move`) | Scans using Custom Scan `--move=/root/quarantine` create files with `original_path="Unknown"`; restoring them to user `$HOME` skips `os.chown`/`chmod 0644`, leaving files root-owned (`0600`) | `clamav_gui.py:1911-1925`, `clamav_gui.py:4914-4918` | Expected for root-owned unknowns, but notify user or safely `chown` only when scanner originally ran on `$HOME/<invoker>/` |
| Medium | Maintainer / End User (openSUSE) | Packaging (`RPM`) | openSUSE RPM places Qt6 bindings (`python3-pyside6 \| python3-qt6`) in `Recommends:` rather than `Requires:`; installing with `--no-recommends` skips Qt6 and crashes launch | `packaging/build_packages.sh:172-175`, `.gitea/workflows/ci.yml:185` | Add a boolean `Requires: (python3-pyside6 or python3-qt6 or python3-pyqt6)` or validate Qt availability cleanly across openSUSE repos |
| Medium | Maintainer / End User | Packaging (`Polkit` UX) | Running directly from a user-owned checkout (`~/Downloads/Clamav`) disables passwordless Polkit (`_install_polkit_rule_best_effort` swallows `PermissionError` silently), requiring `sudo` on every launch until installed via package | `clamav_gui.py:1957-1962`, `clamav_gui.py:3949-3959` | Keep security check intact, and show a concise hint in `auth_banner` / tooltip that passwordless auto-unlock requires system installation |
| Low | All Personas (CI/Release) | Release Integrity | DEB/RPM artifacts in `build-packages.yml` are unsigned (`Signature: (none)`) and `ci.yml` installs local CI RPMs via `zypper --no-gpg-checks` | `.gitea/workflows/build-packages.yml`, `.gitea/workflows/ci.yml:185` | Add optional GPG signing step for release `.deb`/`.rpm` artifacts when signing key secret is configured |
| Low | Developer / Agent | Repo Config & Desktop File | Root `clamav-kde-gui.desktop` hardcodes `Exec=/home/schneider/Downloads/Clamav/run.sh`; repo has both `AGENTS.md` (committed) and `AGENT.md` (untracked PHP/Playwright rules) | `clamav-kde-gui.desktop:6`, `AGENTS.md`, `AGENT.md` | Keep root desktop file templated or documented for source launches; reconcile/remove conflicting untracked `AGENT.md` |

## 4. Test coverage
- **Suites run:**
  - `QT_QPA_PLATFORM=offscreen python3 -m unittest discover -s . -p "test_*.py" -v` → **51 / 51 passed (`OK`, `0.419s`)**
  - `python3 clamav_gui.py --self-test` → **ALL CHECKS PASSED**
  - `python3 -m py_compile` & `bash -n` & `desktop-file-validate clamav-kde-gui.desktop` → **passed**
- **Measured unit/integration branch & statement coverage (`coverage run --branch`):**
  - `clamav_gui.py`: **78%** (3,011 statements, 572 missed, 934 branches, 197 partial)
  - `test_clamav_gui.py`: **98%** (604 statements, 5 missed)
  - `test_ui_clamav_gui.py`: **98%** (630 statements, 10 missed)
  - `packaging/verify_installed_os.py`: **0% locally executed** (not imported in `unittest`; only invoked in CI pipeline)
  - **Uncovered risky / core paths in `clamav_gui.py`:**
    - `HelperClient.start_with_sudo` timeout/EOF edge branches, `start_with_sudo_nopass`, real `start_with_pkexec`, and `HelperClient.call` timeout (`2097-2258`, `2297-2302`)
    - `start_background_precount` progress/cancellation mid-scan & `find` missing error branch (`1014-1083`)
    - `_helper_get_schedule` parsing existing `SYSTEMD_TIMER_PATH` (`1962-1988`)
    - `_try_auto_connect` background thread & `_on_auto_sudo_done` (`3928-3959`)
    - Privileged `signal_proc` / `stop_scan` failure warning dialogs, `launch_gui` entry (`5062-5066`), and `verify_installed_os.py` unit tests.

| Persona | UI interaction / flow step | UI test | Status |
|---|---|---|---|
| Standard User (EN/DE) | Initial compact window, toggle detail tabs on demand | `TestUIInitialLayoutAndCompactMode.test_compact_layout_and_on_demand_tab_toggle` | ✅ Covered |
| Standard User (EN/DE) | Switch DE ↔ EN live + persist `settings.json` | `TestUILocalizationAndPersistence.test_german_ui_full_translation_and_settings_persistence` | ✅ Covered |
| Standard User | Upfront missing `clamscan`, missing DB banner + Jump CTA | `TestUIDependencyAndDatabaseStatus` (2 tests) | ✅ Covered |
| Standard User | Drag & drop files to scan | `TestUIDragDropAndTrayBehavior.test_drag_and_drop_accepts_existing_files_and_launches_scan` | ⚠️ >5 files truncation preview untested |
| Standard User (KDE/GNOME) | Tray hide/restore vs trayless GNOME close + `notify-send` | `TestUIDragDropAndTrayBehavior`, `TestUIGNOMECompatibility` | ✅ Covered (mocked tray) |
| Sysadmin | `sudo` cancel/fail/unlock + `pkexec` waiting/error + disconnect | `TestUIAuthAndUnlockFlows` (2 tests) | ⚠️ Real `_try_auto_connect` untested |
| Sysadmin | Quick/Full/Picker scan, pause/resume/stop, priority, `-ri` restart | `TestUIScanActionsAndProcessControl` (3 tests) | ⚠️ Cancel/error dialogs & helper failure branches partial |
| Sysadmin | Threat copy/reveal/quarantine/delete, Quarantine restore/delete, History merge/clear | `TestUIThreatsQuarantineAndHistoryTabs` (3 tests) | ⚠️ Quarantine permanent delete button & error dialogs untested |
| Sysadmin | Schedule refresh/daily/save, Custom Scan preview/launch, `freshclam` update | `TestUIScheduleCustomScanAndUpdatesTabs` (3 tests) | ⚠️ Schedule read error & browse dialog untested |

## 5. What works ✅
| Area | Verified |
|---|---|
| Privilege boundary (`--helper`) | `_validate_clamscan_args` resolves trusted root-owned binaries only; allowlists flags (`test_validate_clamscan_args_rejects_untrusted_binaries_and_flags`) |
| Polkit rule hardening | `_helper_install_polkit_rule` requires root-owned `SCRIPT_PATH` + `subject.active && subject.local` + caller UID match (`test_polkit_rule_refuses_user_writable_script_and_enforces_local_active`) |
| Quarantine & file delete guards | Root mode locks `DEFAULT_QUARANTINE_DIR`, blocks `_PROTECTED_SYSTEM_PREFIXES`, rejects path traversal/manifest tampering (`test_protected_system_paths_and_quarantine_root_confinement`) |
| Log path hardening | `_validate_helper_log_path` blocks symlinks and arbitrary paths outside `/var/log/` (`test_log_path_validation_blocks_symlinks_and_arbitrary_files_as_root`) |
| Schedule unit generation | `_is_safe_systemd_path` blocks `\n`/quotes/`$`/`%`/`;` systemd directive injection (`test_systemd_unit_rejects_directive_injection_and_gdbus_quotes`) |
| Atomic JSON & URI quoting | `save_json_file` uses `tempfile.mkstemp` + `os.replace`; `_gdbus_show_items_command` percent-encodes `'` cleanly |
| UI HTML/XSS safety | Plain-text Qt widgets (`setPlainText`, `QTableWidgetItem`, `QLineEdit`) prevent markup injection from filenames |
| Test isolation & speed | All 51 tests run cleanly offline in `0.42s` with isolated `TemporaryDirectory()` paths |

## 6. Not tested
- Live Gitea runner execution on all 11 active CI targets (`opensuse-16`, `opensuse-16.1`, `opensuse-tumbleweed`, `rocky-10`, `fedora-45` on KDE & GNOME; `kubuntu-26.04` on KDE) — no external Gitea runner hosts are accessible from this machine.
- `.deb` package build and installation (`dpkg-deb` is not installed on RHEL 10.3 host).
- Real live RPM installation + `rpm -e` cycle on this host (requires root transaction; local `rpmbuild` on Rocky 10 flavor built and verified `clamav-security-center-1.0.0-1.el10.noarch.rpm` headers/file list cleanly).
- Real Wayland `QSystemTrayIcon` rendering on stock GNOME / AppIndicator extension session (`QT_QPA_PLATFORM=offscreen` returns `isSystemTrayAvailable() == False`).

## 7. Upstream / forwarded
- Root desktop launcher [clamav-kde-gui.desktop](file:///home/schneider/Downloads/Clamav/clamav-kde-gui.desktop#L6) is overridden during packaging by [packaging/build_packages.sh](file:///home/schneider/Downloads/Clamav/packaging/build_packages.sh#L81) (`Exec=/usr/bin/clamav-security-center`); root checkout file only applies to local manual desktop installation.

## 9. Fix status (branch `main`)
| Finding | Fix | Test added | Verified |
|---|---|---|---|
| High: Custom log path rejection silent failure | Surface `_on_inspect_done` errors in `log_hint_lbl` + add `/var/log/` tooltips on `log_path_edit` and `new_log_edit` | `test_mockup_lang_pills_tiles_inspect_error_and_german_history` | ✅ unit/UI test |
| Medium: German UI residual English strings | Localized `also_missing_suffix`, `history_system_log`, `svc_active`/`svc_inactive` | `test_mockup_lang_pills_tiles_inspect_error_and_german_history` | ✅ unit/UI test |
| Medium: openSUSE Qt6 `Recommends:` gap | Changed openSUSE RPM spec block in `build_packages.sh` to `Requires: (python3-pyside6 or python3-qt6 or python3-pyqt6)` | Local `rpmbuild` + Podman openSUSE matrix test | ✅ Podman pending |
| Medium: Polkit source-checkout silent fallback | Added localized `polkit_source_hint` tooltip on `auth_lbl` explaining system package install requirement | Updated UI verified | ✅ unit/UI test |
| New: `Gio.DesktopAppInfo.new()` shadow risk | Switched `verify_installed_os.py` from `.new(name)` to `.new_from_filename(INSTALLED_DESKTOP)` | `test_helper_client_timeout_nopass_pkexec_and_verify_os_script` | ✅ unit + Podman |
| Coverage: `HelperClient` timeout/nopass + `verify_installed_os.py` | Added unit coverage for `HelperClient.call` timeout, `start_with_sudo_nopass`, `_helper_get_schedule`, and `verify_installed_os.py` | `test_helper_client_timeout_nopass_pkexec_and_verify_os_script` | ✅ unit test |
| UI upgrade (`mockup_1_protected_home`) | Added vector shield/tile `QPainter` graphics, `ScanTileButton`, segmented `EN / DE` pill, unified `#StatsStrip`, centered link footer | `TestUIInitialLayoutAndCompactMode` + `test_mockup_lang_pills_tiles_inspect_error_and_german_history` | ✅ unit/UI test |

