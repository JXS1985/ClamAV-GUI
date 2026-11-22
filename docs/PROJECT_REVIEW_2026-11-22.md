# ClamAV Security Center — Full Project Review — 2026-11-22

- **Scope:** Full codebase (`clamav_gui.py`, `run.sh`, `clamav-kde-gui.desktop`, `packaging/clamav-kde-gui.svg`, `packaging/build_packages.sh`, `packaging/verify_installed_os.py`, `test_clamav_gui.py`, `test_ui_clamav_gui.py`, `.gitea/workflows/ci.yml`, `.gitea/workflows/build-packages.yml`, `AGENTS.md`, `docs/`)
- **Stacks:** Python 3 / Qt6 (`PySide6` with `PyQt6` fallback), Linux `/proc` + systemd + Polkit + `sudo`/`pkexec`, XDG desktop/hicolor SVG icon packaging, DEB/RPM packaging, Gitea Actions. *(No dedicated stack block in `project-review` Section 4 for Python/Qt6; applied Section 3 security/architecture/correctness/UX/test rules plus `AGENTS.md`.)*
- **Personas:**
  1. **End User (Standard Desktop User — KDE Plasma / GNOME across 8 OS-detected locales)** — Home protection status, Launchers/Taskbar/Tray/Notification shield icon, Quick/Full/Picker/Drag&Drop scans, pause/resume/cancel back to idle Start screen, Threat review, Tray minimize/quit
  2. **Power User / Sysadmin (Elevated Root Helper Operator)** — Passwordless Polkit / `sudo` / `pkexec`, live `/proc/fd` & `io` streaming, restart without `-i`, Custom Scan builder, Log reload, Quarantine/Restore/Delete, `systemd` schedule create/enable/disable/refresh, `freshclam` updates
  3. **Untrusted Local Process / User (UID-isolated Privilege Boundary)** — JSON RPC validation, binary/flag allowlists, symlink/TOCTOU confinement on logs/quarantine/restore, PID validation, Polkit subject confinement
  4. **Maintainer / Packager (CI & Release Operator)** — 59-test suite, `coverage`, DEB/RPM builds with SVG icon, `.desktop` validation, OS integration verifier
- **Build / commit:** `main` @ `f4f44b8` (+ untracked `AGENT.md`, `project-review.skill`)
- **Environment:** RHEL 10.3 (`x86_64`), Python 3.12, ClamAV `1.4.6/28190`, KDE Plasma Wayland (`de_DE.UTF-8`), `QT_QPA_PLATFORM=offscreen` + live Wayland Plasma session
- **References:** [AGENTS.md](file:///home/schneider/Downloads/Clamav/AGENTS.md), [docs/PROJECT_REVIEW_2026-11-21.md](file:///home/schneider/Downloads/Clamav/docs/PROJECT_REVIEW_2026-11-21.md), [docs/UX_MOCKUPS.md](file:///home/schneider/Downloads/Clamav/docs/UX_MOCKUPS.md)
- **Method:** Full source & attack-surface audit, translation/key completeness & UI overflow audit across all 8 languages, `python3 -m py_compile`, `bash -n`, `desktop-file-validate`, `clamav_gui.py --self-test`, `unittest discover` (59 tests), `coverage run --branch`, and live `--helper` + `clamscan` cancellation testing.

## Summary
Since the prior review (`f2bc469`), the project resolved its earlier issues, adopted the `mockup_1` Home UI with crisp HiDPI/SVG vector shield artwork across launcher/taskbar/tray/notifications, expanded OS-detected localization to 8 languages (`en`, `de`, `es`, `fr`, `pt`, `zh`, `ja`, `ru`), and fixed job cancellation + schedule state persistence (`f4f44b8`). All 59 tests pass (`84%` total branch/statement coverage; `80%` on `clamav_gui.py`), with **zero release blockers**. The current audit identified **1 High** symlink-traversal hardening gap during quarantine restore, **4 Medium** correctness/resource-lifecycle/UX defects (orphan `find` precount worker & exit cleanup, sub-second quarantine filename collision overwrite, `_restart_scan_without_i` losing background priority/label, and silent unprivileged log reload failure), and **1 Low** packaging/translation hygiene gap.

## 1. Release blockers
None identified.

## 2. Findings (ordered by user impact)
| Severity | Persona | Area | What happens | Evidence / cause (file:line) | Suggestion |
|---|---|---|---|---|---|
| High | Untrusted Local User / Sysadmin | Quarantine Restore (Symlink TOCTOU) | `_helper_restore_quarantine` calls `os.makedirs(parent, exist_ok=True)` **before** checking `os.path.islink(parent)`, allowing directory creation through pre-existing user symlinks when elevated (`euid == 0`) | [clamav_gui.py:3811-3816](file:///home/schneider/Downloads/Clamav/clamav_gui.py#L3811-L3816) | Walk path components from root before `makedirs` and reject any symlink ancestor; reject symlink `dest` |
| Medium | End User / Sysadmin | Precount Worker Lifecycle & Exit Leak | `start_background_precount._worker` does not re-check generation before `Popen`, leaves `proc.stdout` open / `proc` unreaped on early cancel (emitting `ResourceWarning`), and `closeEvent` does not stop `_PRECOUNT_PROC` (`find` outlives GUI exit) | [clamav_gui.py:2830-2849](file:///home/schneider/Downloads/Clamav/clamav_gui.py#L2830-L2849), [clamav_gui.py:5182-5185](file:///home/schneider/Downloads/Clamav/clamav_gui.py#L5182-L5185) | Check `_PRECOUNT_STATE["gen"]` under lock before spawning, close/reap `proc` in `finally`, and call `cancel_background_precount()` in `closeEvent` |
| Medium | Sysadmin / End User | Quarantine Collision Overwrite | Two identically named threats (e.g., `/tmp/a/x` and `/tmp/b/x`) quarantined within the same second generate the same `%Y%m%d_%H%M%S` name and overwrite the first sample and manifest record via `shutil.move` | [clamav_gui.py:3729-3733](file:///home/schneider/Downloads/Clamav/clamav_gui.py#L3729-L3733) | Append `_{n}` counter until `not os.path.lexists(dest)` |
| Medium | Power User / Sysadmin | Restart Scan Without `-i` | `_restart_scan_without_i` does not cancel precount, loses scan label for `new_pid`, leaves old PID label cached, and fails to re-apply `bg_mode_chk` idle priority to the restarted scan | [clamav_gui.py:7010-7054](file:///home/schneider/Downloads/Clamav/clamav_gui.py#L7010-L7054) | Call `cancel_background_precount()`, propagate scan label to `new_pid`, and apply `set_priority("idle")` if `bg_mode_chk.isChecked()` |
| Medium | End User | Live Log Reload (Unprivileged) | When root helper is disconnected, entering a missing or unreadable log path in `log_path_edit` and clicking Reload silently leaves `log_view` blank with no diagnostic notice | [clamav_gui.py:6496-6500](file:///home/schneider/Downloads/Clamav/clamav_gui.py#L6496-L6500), [clamav_gui.py:7005-7008](file:///home/schneider/Downloads/Clamav/clamav_gui.py#L7005-L7008) | Surface localized unreadable/missing log feedback in `log_hint_lbl` during disconnected reload/poll |
| Low | Maintainer / Packager | Packaging & Dead I18N Keys | RPM `%description` still says `"in both English and German"` despite 8 languages; DEB/RPM lack best-effort `gtk-update-icon-cache` / `update-desktop-database` hooks; `clamav_gui.py` has stale `'de' or 'en'` docstring and 9 unused legacy keys across 8 locales | [packaging/build_packages.sh:142-250](file:///home/schneider/Downloads/Clamav/packaging/build_packages.sh#L142-L250), [clamav_gui.py:2357](file:///home/schneider/Downloads/Clamav/clamav_gui.py#L2357) | Update RPM `%description`, add best-effort DEB/RPM icon cache triggers, update `tr()` docstring, and prune 9 unused translation keys |

## 3. Test coverage
- **Suites run:**
  - `QT_QPA_PLATFORM=offscreen python3 -m unittest discover -s . -p "test_*.py" -v` → **59 / 59 passed (`OK`, `2.43s`)**
  - `python3 clamav_gui.py --self-test` → **ALL CHECKS PASSED**
  - `python3 -m py_compile` & `bash -n` & `desktop-file-validate` → **passed**
- **Measured coverage (`coverage run --branch`):**
  - [clamav_gui.py](file:///home/schneider/Downloads/Clamav/clamav_gui.py): **80%** (`3555` stmts / `601` missed, `1064` branches / `215` partial)
  - [test_clamav_gui.py](file:///home/schneider/Downloads/Clamav/test_clamav_gui.py): **97%** (`759` stmts / `17` missed)
  - [test_ui_clamav_gui.py](file:///home/schneider/Downloads/Clamav/test_ui_clamav_gui.py): **97%** (`824` stmts / `14` missed)
  - **Total:** **84%** (`5138` stmts, `1172` branches)
- **Uncovered risky/error paths prior to fixes:**
  - `_helper_restore_quarantine` symlink ancestor creation race (`clamav_gui.py:3811-3816`)
  - `_helper_quarantine_file` sub-second filename collision (`clamav_gui.py:3729-3733`)
  - `start_background_precount` early-cancel teardown & `closeEvent` precount cancellation (`clamav_gui.py:2830-2849`, `5182-5185`)
  - `_restart_scan_without_i` priority/label preservation & disconnected `_reload_log` missing/unreadable error path
  - `dropEvent` >5 files truncation (`>5` branch) and Quarantine delete/restore/error dialogs

| Persona | UI interaction / flow step | UI test | Status |
|---|---|---|---|
| Standard User (8 Locales) | OS locale detection, button width & zero overflow across `en/de/es/fr/pt/zh/ja/ru` | `TestUILocalizationAndPersistence` (incl. `test_os_locale_detection_and_zero_text_overflow_across_all_8_languages`) | ✅ Covered |
| Standard User | Initial compact window, tile icons/subtitles, expandable tabs | `TestUIInitialLayoutAndCompactMode` | ✅ Covered |
| Standard User | Missing `clamscan` / missing DB banner & Jump CTA | `TestUIDependencyAndDatabaseStatus` | ✅ Covered |
| Standard User | Start Scan → elapsed timer → Pause (`SIGSTOP`) → Cancel (`SIGTERM`/`SIGKILL`) → back to Protected Start UI (incl. live `--helper` + real `clamscan`) | `TestUIScanActionsAndProcessControl.test_start_and_cancel_running_and_paused_job_returns_to_start`, `test_start_pause_then_cancel_real_helper_subprocess` | ✅ Covered |
| Standard User (KDE/GNOME) | Custom vector shield `windowIcon()` multi-size, tray hide/restore/quit, `notify-send` icon (`clamav-kde-gui`) | `TestUIDragDropAndTrayBehavior`, `TestUIGNOMECompatibility` | ✅ Covered |
| Standard User | Drag & drop files (`>5` preview truncation) | `TestUIDragDropAndTrayBehavior` | ⚠️ `>5` branch untested |
| Sysadmin | Schedule enable/disable/refresh + Home `SCHEDULE` card sync | `TestUIScheduleCustomScanAndUpdatesTabs.test_schedule_save_updates_idle_home_card_and_disable_clears_it` | ✅ Covered |
| Sysadmin | Restart without `-i` (`bg_mode` & label), Quarantine error/delete/restore-pick-dir, disconnected Log reload error | `TestUIScanActionsAndProcessControl`, `TestUIThreatsQuarantineAndHistoryTabs` | ⚠️ Partial (error & disconnected branches untested) |

## 4. What works ✅
| Area | Verified |
|---|---|
| Process termination & UI reset | `_terminate_pid_gracefully` unpauses `T` state across `SIGTERM`/`SIGKILL`, waits for `/proc/<pid>` exit, helper reaps child via `_SPAWNED_PROCS`, UI returns cleanly to Protected home screen with `ctrl_box` hidden (`test_start_pause_then_cancel_real_helper_subprocess`) |
| Schedule lifecycle | Weekly/daily unit generation, `_is_safe_systemd_path` injection guard, `# CLAMAV_GUI_CONFIG` enabled flag synced to Home `SCHEDULE` card (`test_schedule_enable_disable_roundtrip_and_sanitization`, `test_schedule_save_updates_idle_home_card_and_disable_clears_it`) |
| Security allowlists | `_validate_clamscan_args` rejects untrusted binaries and unallowlisted flags (`-l`, etc.); `_helper_install_polkit_rule` locks down script ownership & UID; `_validate_helper_log_path` restricts logs to `/var/log/` |
| KDE & GNOME icons | Vector shield `_build_app_icon()` & `packaging/clamav-kde-gui.svg` verified on Wayland Plasma & `Gio.DesktopAppInfo` (`Icon=clamav-kde-gui`) |
| 8-language UI fit | 0 text overflows measured across all 8 locales (`en`, `de`, `es`, `fr`, `pt`, `zh`, `ja`, `ru`) |

## 5. Not tested
- Multi-distro Gitea CI matrix containers (6 target distros previously verified at `534c6c6`; no external runner host reachable directly from local environment, local RPM build check still runnable).
- Real live `pkexec` GUI prompt interactive click & `root` `rpm -Uvh` install on host OS.

## 9. Fix status (branch `main`)
| Finding | Fix | Test added | Verified |
|---|---|---|---|
| High: Quarantine restore symlink-ancestor `os.makedirs` TOCTOU (`clamav_gui.py:3811-3816`) | Added `_ensure_no_symlink_ancestors_and_mkdir()` walking path segments from `/` before directory creation and rejecting any symlink ancestor | `test_quarantine_collision_same_second_and_restore_symlink_ancestor_guard` | ✅ unit test (`61/61`) |
| Medium: Precount worker early-cancel leak & missing `closeEvent` cleanup (`clamav_gui.py:2830-2849`, `5182-5185`) | Re-checked `_PRECOUNT_STATE["gen"]` before/after `Popen`, closed/reaped `proc` in `finally`, and invoked `cancel_background_precount()` in `closeEvent` | `test_cancel_background_precount_stops_worker` + `test_restart_without_i_preserves_bg_priority_and_disconnected_reload_log_errors` | ✅ unit/UI test (`0` `ResourceWarning`s) |
| Medium: Sub-second quarantine collision overwrite (`clamav_gui.py:3729-3733`) | Added deterministic `_{n}` collision counter in `_helper_quarantine_file()` when timestamped target exists | `test_quarantine_collision_same_second_and_restore_symlink_ancestor_guard` | ✅ unit test |
| Medium: `_restart_scan_without_i` drops priority/label/precount reset (`clamav_gui.py:7010-7054`) | Cancelled precount, transferred scan label to `new_pid`, and re-applied `set_priority("idle")` when `bg_mode_chk` checked | `test_restart_without_i_preserves_bg_priority_and_disconnected_reload_log_errors` | ✅ UI test |
| Medium: Disconnected `_reload_log` silent missing/unreadable log error (`clamav_gui.py:6496-6500`, `7005-7008`) | Tracked `_log_reload_error` across `_reload_log` / `_render_unprivileged_telemetry` / `_on_root_unlocked` and surfaced localized errors in `log_hint_lbl` | `test_restart_without_i_preserves_bg_priority_and_disconnected_reload_log_errors` | ✅ UI test |
| Low: Packaging `%description`, icon cache triggers & dead I18N keys (`build_packages.sh`, `clamav_gui.py`) | Updated RPM `%description` for 8 locales, added best-effort DEB `postinst` & RPM `%post`/`%postun` cache updates, updated `tr()` docstring, pruned 9 unused keys (`72` lines) | Local `rpmbuild` (`1.2.0-1.el10.noarch.rpm`) + `desktop-file-validate` + `test_translation_keys_placeholders_and_fallbacks` | ✅ verified locally (`61/61` tests, `--self-test` OK, `85%` total coverage) |
| Coverage gaps: Drop `>5` preview truncation (`TestUIDragDropAndTrayBehavior`) | Added assertion exercising `>5` dropped-file preview truncation (`dlg_drop_more`) | `test_drag_and_drop_accepts_existing_files_and_launches_scan` | ✅ UI test |

### Still open
- Remote 6-distro Podman/Gitea matrix verification on this commit (RPM local `rpmbuild` passed; container matrix run remains optional CI step).

