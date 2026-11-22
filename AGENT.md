# Repository & Agent Guidelines — ClamAV Security Center

You are working on **ClamAV Security Center**, a Python 3 / Qt6 (`PySide6` with `PyQt6` fallback) Linux desktop control center with an unprivileged GUI, `/proc` scan telemetry, a privileged `--helper` JSON-RPC bridge (`pkexec`/`sudo`/Polkit), `systemd` scheduled scan timers, 8-language OS-locale localization, KDE Plasma & GNOME integration, and `.deb`/`.rpm` packaging.

## Repository & Git Workflow Rules
- **Always commit changes directly to the `main` branch.**
- **Before every commit to `main`**, run the full test and diagnostic suite cleanly:
  ```bash
  QT_QPA_PLATFORM=offscreen python3 -m unittest discover -s tests -v
  QT_QPA_PLATFORM=offscreen python3 clamav_gui.py --self-test
  python3 -m compileall -q clamav_gui.py tests packaging/verify_installed_os.py
  bash -n run.sh && bash -n packaging/build_packages.sh && bash -n packaging/PKGBUILD
  ```

---

## Core Priorities (Ordered by Importance)

### 1. Absolute Security First (Highest Priority)
All code crossing the unprivileged UI and privileged root `--helper` boundary must enforce defensive security:
- **Privilege Separation (`--helper` JSON-RPC Bridge):** Validate every action parameter entering `run_helper()`. Enforce root-owned executable checks (`_is_secure_root_owned_path`) and strict `clamscan` argument allowlists (`_validate_clamscan_args`). Never accept arbitrary flags (`-l`, unvalidated `--move`, etc.) or relative binary paths.
- **Filesystem, Symlink & Path Confinement:** Prevent path traversal, symlink following (`O_NOFOLLOW`, `_ensure_no_symlink_ancestors_and_mkdir`), and protected system path modification (`_is_protected_system_path`). Confine root logs to `/var/log/` (`_validate_helper_log_path`) and root quarantine to `/root/quarantine` (`_resolve_quarantine_dir`). Use atomic temp-file replacement (`save_json_file`) and collision-safe naming (`_helper_quarantine_file`) for quarantine and state manifests.
- **Process & Command Hardening:** Never pass `shell=True` to `subprocess`. Verify target PIDs belong to a genuine `clamscan` binary (`_validate_clamscan_pid`) before sending signals (`_terminate_pid_gracefully`) or adjusting priority (`renice`/`ionice`). Sanitize `systemd` unit paths (`_is_safe_systemd_path`) and scope Polkit rules strictly (`subject.active && subject.local`, exact caller username, and root-owned script/interpreter paths).
- **Credential & UI Output Safety:** Never log, persist, or expose `sudo` passwords. Render untrusted file paths and ClamAV log output only through plain-text Qt APIs (`setPlainText`, `QTableWidgetItem`, `QLineEdit`) so markup or control characters in scanned paths cannot execute or inject HTML.

### 2. Testing, Desktop & Localization Requirements (Mandatory for New Features)
Write and update tests concurrently with every feature, bug fix, or security change:
- **Backend & Security Boundaries (`tests/test_clamav_gui.py`):** Test success paths, input validation failures, symlink/path confinement, `--helper` JSON protocol, `/proc` discovery/termination, and `systemd` schedule generation.
- **Headless Qt6 UI Tests (`tests/test_ui_clamav_gui.py`):** Test user and admin flows cleanly under `QT_QPA_PLATFORM=offscreen`, including KDE Plasma & GNOME (`TestUIGNOMECompatibility`) behaviors, job start/pause/cancel reset, and schedule state sync.
- **Isolate Host & Container State:** Use `tempfile.TemporaryDirectory()` and explicit mocks (`os.geteuid`, `subprocess`, `discover_clamscan_processes`) so tests run instantaneously, deterministically, and offline both locally (`uid != 0`) and inside root CI containers (`uid == 0`).
- **8-Language & Desktop Parity:** Maintain full key and placeholder parity in `TRANSLATIONS` across all 8 OS-detected locales (`en`, `de`, `es`, `fr`, `pt`, `zh`, `ja`, `ru`) with zero text overflow, keep vector shield/icon assets (`packaging/clamav-security-center.svg`) and `.desktop` entries (`desktop-file-validate clamav-security-center.desktop`) valid across KDE & GNOME, and validate `.deb`/`.rpm` packaging (`packaging/build_packages.sh`, `packaging/verify_installed_os.py`).

### 3. The Principle of Least Churn (Token & Regression Control)
- Treat existing code as a stable foundation. Do not refactor, rewrite, or style-optimize unrelated code unless a change strictly requires it.
- Prioritize **additive changes** (new helper functions, isolated guards, or targeted test cases) over modifying working code blocks.

### 4. Surgical Refactoring (When Modification Is Required)
If a feature or fix requires changing existing code:
- Choose the path that touches the fewest possible lines of working code.
- **Isolate & Encapsulate:** Extract self-contained logic into small, well-named helper functions rather than editing complex loops inline.
- Leave surrounding code untouched unless directly part of the fix.

### 5. File Operations & Output Rules
- **Patch Over Rewrite:** Use targeted search-and-replace edits (`edit_file`) rather than rewriting whole files.
- **Targeted Reads:** Search symbols first and read only the relevant line ranges (`StartLine`/`EndLine`).
- **Omit Boilerplate:** Present focused changes cleanly without unnecessary boilerplate.
- **Diff-First & Concise Reporting:** Summarize what changed, which exact checks ran, and their observed results concisely with clickable `file://` links.
