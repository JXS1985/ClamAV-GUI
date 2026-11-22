#!/usr/bin/env python3
"""ClamAV KDE/Qt6 GUI Controller with privileged helper bridge."""

from __future__ import annotations

import argparse
from collections import deque
import csv
import datetime
import getpass
import json
import locale
import os
import plistlib
try:
    import pwd
except ImportError:  # Windows has no POSIX pwd database
    pwd = None  # type: ignore[assignment]
import queue
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCRIPT_PATH = str(Path(__file__).resolve())
IS_WINDOWS = os.name == "nt"
IS_MACOS = sys.platform == "darwin"
_SUBPROCESS_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if IS_WINDOWS else 0


def _euid() -> int:
    return os.geteuid() if hasattr(os, "geteuid") else 0


def _uid() -> int:
    return os.getuid() if hasattr(os, "getuid") else 0


def _is_posix_root() -> bool:
    return (not IS_WINDOWS) and _euid() == 0


def _self_helper_cmd() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, "--helper"]
    return [sys.executable, SCRIPT_PATH, "--helper"]


def _system_root_target() -> str:
    if IS_WINDOWS:
        drive = os.environ.get("SystemDrive", "C:").rstrip("\\/")
        return f"{drive}\\"
    return "/"


def _win_clamav_dirs() -> list[str]:
    local_app = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    prog_files = os.environ.get("ProgramFiles") or r"C:\Program Files"
    prog_x86 = os.environ.get("ProgramFiles(x86)") or r"C:\Program Files (x86)"
    prog_data = os.environ.get("ProgramData") or r"C:\ProgramData"
    choco_tools = os.path.join(prog_data, "chocolatey", "lib", "clamav", "tools")
    candidates = [
        os.path.join(prog_files, "ClamAV"),
        os.path.join(prog_x86, "ClamAV"),
        r"C:\ClamAV",
        os.path.join(local_app, "Programs", "ClamAV"),
        os.path.join(local_app, "ClamAV"),
        os.path.join(prog_data, "chocolatey", "bin"),
        choco_tools,
    ]
    if os.path.isdir(choco_tools):
        try:
            for sub in sorted(os.listdir(choco_tools)):
                if sub.lower().startswith("clamav"):
                    sub_path = os.path.join(choco_tools, sub)
                    if os.path.isdir(sub_path):
                        candidates.append(sub_path)
        except OSError:
            pass
    return [p for i, p in enumerate(candidates) if p and p not in candidates[:i]]


def _mac_clamav_dirs() -> list[str]:
    return [
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/opt/local/bin",
        "/opt/local/sbin",
    ]


def _ensure_standard_path() -> None:
    """Include /usr/sbin and /sbin (or Windows / macOS Homebrew ClamAV dirs) so tools are found cleanly."""
    if IS_WINDOWS:
        extra = _win_clamav_dirs()
    elif IS_MACOS:
        extra = [*_mac_clamav_dirs(), "/usr/sbin", "/sbin"]
    else:
        extra = ["/usr/sbin", "/sbin", "/usr/local/bin", "/usr/local/sbin"]
    current = os.environ.get("PATH", "").split(os.pathsep) if os.environ.get("PATH") else []
    merged = current + [p for p in extra if p not in current]
    os.environ["PATH"] = os.pathsep.join(merged)


_ensure_standard_path()
APP_VERSION = "1.0.0"
APP_AUTHOR = "Armin Schneider (@JXS1985)"
APP_GITHUB_URL = "https://github.com/JXS1985/ClamAV-GUI"
APP_LICENSE = "GNU General Public License v3.0 (GPL-3.0)"
if IS_WINDOWS:
    APP_DATA_DIR = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")) / "clamav-kde-gui"
    DEFAULT_LOG_PATH = str(APP_DATA_DIR / "clamav-scan.log")
    DEFAULT_QUARANTINE_DIR = str(APP_DATA_DIR / "quarantine")
elif IS_MACOS:
    APP_DATA_DIR = Path.home() / "Library" / "Application Support" / "clamav-kde-gui"
    DEFAULT_LOG_PATH = str(APP_DATA_DIR / "clamav-scan.log")
    DEFAULT_QUARANTINE_DIR = str(APP_DATA_DIR / "quarantine")
else:
    APP_DATA_DIR = Path.home() / ".local" / "share" / "clamav-kde-gui"
    DEFAULT_LOG_PATH = "/var/log/clamav-scan.log"
    DEFAULT_QUARANTINE_DIR = "/root/quarantine"
QUARANTINE_MANIFEST = "manifest.json"
POLKIT_RULE_PATH = "/etc/polkit-1/rules.d/49-clamav-kde-gui.rules"
SYSTEMD_SERVICE_PATH = "/etc/systemd/system/clamav-gui-scan.service"
SYSTEMD_TIMER_PATH = "/etc/systemd/system/clamav-gui-scan.timer"
USER_SYSTEMD_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")) / "systemd" / "user"
USER_SYSTEMD_SERVICE_PATH = str(USER_SYSTEMD_DIR / "clamav-gui-scan.service")
USER_SYSTEMD_TIMER_PATH = str(USER_SYSTEMD_DIR / "clamav-gui-scan.timer")
WINDOWS_SCHEDULE_CONFIG_PATH = APP_DATA_DIR / "schedule.json"
WINDOWS_TASK_NAME = "ClamAVSecurityCenterScan"
MACOS_LAUNCH_AGENT_LABEL = "io.github.jxs1985.clamav-security-center.scan"
MACOS_LAUNCH_AGENT_PLIST = str(
    Path.home() / "Library" / "LaunchAgents" / f"{MACOS_LAUNCH_AGENT_LABEL}.plist"
)
MACOS_SCHEDULE_CONFIG_PATH = APP_DATA_DIR / "schedule.json"
HISTORY_FILE_PATH = APP_DATA_DIR / "history.json"
SETTINGS_FILE_PATH = APP_DATA_DIR / "settings.json"
THREAT_LINE_RE = re.compile(r"^(.+?):\s+(.+?)\s+FOUND\s*$")
EXCLUDED_FD_PREFIXES = (
    "/dev/",
    "/proc/",
    "/sys/",
    "/var/log/",
    "/var/lib/clamav/",
    "pipe:",
    "socket:",
    "anon_inode:",
    "memfd:",
)

TRANSLATIONS: dict[str, dict[str, str]] = {
    "en": {
        "window_title": "ClamAV Security Center",
        "app_title": "ClamAV Security Center",
        "detecting_clamav": "Detecting ClamAV...",
        "root_active_badge": "●  Protected Access Active",
        "user_mode_badge": "●  User Mode Active",
        "user_mode_btn": "User Mode",
        "continue_user_mode_btn": "Continue in User Mode",
        "quit_btn": "Quit",
        "about_btn": "About",
        "dlg_about_title": "About ClamAV Security Center",
        "about_desc": "Open-source Linux desktop control center for ClamAV antivirus scanning, quarantine, and scheduled background protection.",
        "about_version_lbl": "Version:",
        "about_creator_lbl": "Creator:",
        "about_license_lbl": "License:",
        "about_github_lbl": "GitHub:",
        "auth_banner_text": "Unlock admin access once for passwordless scans, quarantine & schedules.",
        "unlock_sudo_btn": "Unlock Password...",
        "unlock_polkit_btn": "Unlock via Polkit",
        "waiting_polkit": "Waiting for Polkit...",
        "hero_threats_title": "Action Required — {count} Threat(s) Detected",
        "hero_threats_sub": "Open the Detected Threats tab to review, quarantine, or remove infected files.",
        "hero_review_btn": "Review Threats",
        "hero_protected_title": "Your computer is protected",
        "hero_protected_sub": "No threats detected. Ready to scan anytime.",
        "hero_paused_title": "Scan Paused{pct}",
        "hero_paused_sub": "Click Resume Scan when you are ready to continue.",
        "hero_scanning_title": "Scanning Your Computer — {pct:.1f}% Complete",
        "hero_scanning_sub": "Estimated time remaining: {eta}  •  Checking: {file}",
        "hero_bg_title": "Scan Running in Background",
        "hero_bg_sub": "Unlock Root Access above to view exact percentage, time remaining, and live files.",
        "drop_hint": "Tip: Drag & drop files or folders here to scan",
        "card_status_title": "Scan Status",
        "card_cpu_title": "Elapsed / Activity",
        "card_io_title": "Memory / Disk Read",
        "card_threats_title": "Threats Found",
        "state_running": "RUNNING",
        "state_paused": "PAUSED",
        "idle_word": "Idle",
        "clean_so_far": "Clean so far",
        "action_recommended": "Action recommended",
        "pid_owner": "PID {pid} | Owner: {user}",
        "bg_mode_label": "Background Mode",
        "normal_speed_label": "Normal Speed",
        "unlock_live_io": "Unlock root for live disk read MB/s",
        "ram_value": "RAM {rss}",
        "read_value": "{amount} read",
        "io_sub": "{speed} | Disk {disk} | RAM {rss}",
        "ctrl_box_title": "Active Scan Progress && Controls",
        "progress_label": "Progress:",
        "eta_prefix": "ETA: {eta}",
        "eta_paused": "Paused",
        "eta_unlock_root": "Unlock Root",
        "eta_finishing": "Finishing...",
        "eta_calculating": "Calculating...",
        "no_active_scan": "No active scan",
        "no_active_scan_running": "No active scan running.",
        "currently_checking": "Currently Checking:",
        "pause_scan": "Pause Scan",
        "resume_scan": "Resume Scan",
        "stop_scan": "Stop Scan",
        "bg_mode_chk": "Background Mode (Keep PC responsive)",
        "bg_mode_tip": "Runs the scan at low CPU and idle disk priority so desktop apps stay smooth.",
        "progress_paused_unlock": "Paused (Unlock Root for %)",
        "progress_pct_paused": "{pct:.1f}% (Paused)",
        "progress_sub_unlock_ready": "Target: {elig_files:,} scannable files ({elig_bytes} <= {max_sz}; {all_files:,} total / {all_bytes}) — Unlock Root Access for live % & ETA",
        "progress_sub_unlock_counting": "Initial disk estimate: {statvfs} (counting files in background: {all_files:,} seen...) — Unlock Root Access for live % & ETA",
        "progress_sub_unlock_est": "Initial disk estimate: {statvfs} — Unlock Root Access for live % & ETA",
        "progress_sub_accurate": "Accurate pre-count: ~{eff} / {total} scannable ({elig_files:,} files <= {max_sz}; {all_files:,} total / {all_bytes} on disk)",
        "progress_sub_refining": "Initial disk estimate: ~{eff} / {total} (refining in background: {all_files:,} files seen...)",
        "progress_sub_est": "Initial disk estimate: ~{eff} / {total}",
        "scan_running_locked_file": "Scan running as {user} (PID {pid}). Unlock Root Access above to inspect the live scanned file.",
        "scanning_metadata": "(Scanning directory metadata / transitioning between files)",
        "archive_temp_suffix": "  (+{count} archive temp file)",
        "show_tabs_btn": "Show Logs, Quarantine && Settings ▾",
        "hide_tabs_btn": "Hide Logs, Quarantine && Settings ▴",
        "tab_log": "Live Log",
        "tab_threats": "Threats ({count})",
        "tab_quarantine": "Quarantine ({count})",
        "tab_history": "History",
        "tab_schedule": "Schedule",
        "tab_custom": "Custom Scan",
        "tab_db": "Virus Database",
        "log_path_lbl": "Log Path:",
        "reload_log_btn": "Reload Log",
        "filter_lbl": "Filter:",
        "log_filter_ph": "Filter lines (e.g. FOUND, ERROR, OK)...",
        "autoscroll_chk": "Auto-scroll",
        "stream_fd_chk": "Stream live /proc/fd scanned files when -i is active",
        "restart_verbose_btn": "Restart Scan Without -i (Log All Files)",
        "quiet_log_hint": "Active scan uses -i (--infected), so ClamAV only writes threats and the final summary to the log file. Live /proc/fd file activity is streamed below, or you can restart this scan without -i to log every file.",
        "col_file_path": "File Path",
        "col_threat_sig": "Threat Signature",
        "col_status": "Status",
        "reveal_dolphin_btn": "Reveal in File Manager",
        "copy_path_btn": "Copy Path",
        "move_quarantine_btn": "Move to Quarantine",
        "delete_file_btn": "Delete File",
        "quarantine_note": "Quarantined files are safely isolated in /root/quarantine with no execute permissions. You can restore false positives or delete them permanently.",
        "col_q_name": "File Name",
        "col_q_orig": "Original Location",
        "col_q_threat": "Threat",
        "col_q_date": "Date Quarantined",
        "col_q_size": "Size",
        "refresh_btn": "Refresh",
        "restore_orig_btn": "Restore to Original Location",
        "restore_to_btn": "Restore to Folder...",
        "delete_perm_btn": "Delete Permanently",
        "col_h_date": "Date Completed",
        "col_h_target": "Scan Target",
        "col_h_duration": "Duration",
        "col_h_scanned": "Files / Data Scanned",
        "col_h_threats": "Threats",
        "col_h_result": "Result",
        "refresh_history_btn": "Refresh History",
        "clear_history_btn": "Clear GUI History",
        "status_clean": "Clean",
        "status_threats_found": "Threats Found",
        "sched_desc": "Schedule automatic background antivirus scans using systemd timers. Scheduled scans always run in Background Mode so they do not slow down your computer.",
        "sched_enable_chk": "Enable Automatic Scheduled Scans",
        "sched_status_lbl": "Status:",
        "sched_type_lbl": "Scan Type:",
        "sched_freq_lbl": "Frequency:",
        "sched_day_lbl": "Day of Week:",
        "sched_time_lbl": "Time of Day:",
        "sched_info_lbl": "Timer Info:",
        "sched_type_quick": "Quick Scan (Home, Downloads & Temp)",
        "sched_type_full": "Full System Scan (Entire Drive /)",
        "sched_freq_daily": "Daily",
        "sched_freq_weekly": "Weekly",
        "day_mon": "Monday",
        "day_tue": "Tuesday",
        "day_wed": "Wednesday",
        "day_thu": "Thursday",
        "day_fri": "Friday",
        "day_sat": "Saturday",
        "day_sun": "Sunday",
        "sched_unlock_hint": "Unlock root access to read or change system scan schedule.",
        "save_sched_btn": "Save Schedule",
        "sched_enabled": "Enabled",
        "sched_disabled": "Disabled",
        "sched_timer_status": "Timer Status: {state}   |   Next / Schedule: {next_run}",
        "sched_saved_status": "Saved! Timer Status: {state}   |   {next_run}",
        "sched_saved_title": "Schedule Saved",
        "sched_saved_msg": "Automatic scans: {state}.",
        "sched_read_err": "Could not read schedule: {err}",
        "sched_save_err": "Save Schedule Failed",
        "adv_target_lbl": "Target Path:",
        "browse_btn": "Browse...",
        "adv_options_lbl": "Options:",
        "opt_recursive": "Recursive (-r)",
        "opt_infected_only": "Quiet mode: infected only (-i) [Unchecked = show all scanned files in Live Log]",
        "opt_exclude_virtual": "Exclude /sys, /proc, /dev, /run",
        "opt_cross_fs": "Stay on single filesystem (--cross-fs=no)",
        "adv_maxsize_lbl": "Max File/Scan Size:",
        "adv_action_lbl": "On Threat Found:",
        "action_report": "Report only (recommended for /)",
        "action_move": "Move infected files to /root/quarantine",
        "action_copy": "Copy infected files to /root/quarantine",
        "adv_log_lbl": "Log File:",
        "adv_cmd_lbl": "Command Preview:",
        "start_custom_btn": "Start Custom Scan",
        "db_checking": "Checking ClamAV database status...",
        "freshclam_btn": "Update Virus Signatures Now (freshclam)",
        "freshclam_updating": "Updating Signatures...",
        "freshclam_ph": "freshclam update output will appear here...",
        "freshclam_running_msg": "Running freshclam as root, please wait...\n",
        "freshclam_success": "SUCCESS",
        "freshclam_errors": "FINISHED WITH ERRORS",
        "tray_tip_idle": "ClamAV Security Center — Protected ({count} threats)",
        "tray_tip_paused": "ClamAV — Scan Paused ({pct:.1f}%)",
        "tray_tip_scanning": "ClamAV — Scanning {pct:.1f}% (ETA {eta})",
        "tray_tip_running": "ClamAV — Scan Running",
        "tray_open": "Open ClamAV Security Center",
        "tray_quick": "Start Quick Scan",
        "tray_minimized_msg": "Running in the system tray. Click the tray icon to reopen or use Quit to exit.",
        "notify_threat_title": "Threat Detected!",
        "notify_scan_done_threats_title": "Scan Complete — Threats Found!",
        "notify_scan_done_threats_msg": "{label} finished with {count} threat(s) detected.",
        "notify_scan_done_clean_title": "ClamAV Scan Completed",
        "notify_scan_done_clean_msg": "{label} finished cleanly (0 threats found).",
        "dlg_drop_title": "Scan Dropped Items",
        "dlg_drop_msg": "Start a ClamAV scan on:\n\n{preview}",
        "dlg_drop_more": "...and {count} more",
        "dlg_sudo_title": "Unlock Root Control",
        "dlg_sudo_prompt": "Enter your password to unlock root ClamAV control\n(this also enables automatic passwordless unlock for future launches):",
        "dlg_auth_failed": "Authentication Failed",
        "dlg_polkit_failed": "Polkit Authentication Failed",
        "dlg_root_req_title": "Root Permission Required",
        "dlg_root_req_text": "This action requires administrator privileges.",
        "dlg_root_req_info": "Unlock root access once (it can be remembered automatically for future launches).",
        "dlg_unlock_pw_btn": "Unlock with Password...",
        "dlg_restart_title": "Restart Scan With Full Output",
        "dlg_restart_msg": "Stop the current quiet (-i) scan (PID {pid}) and restart it with full output so every scanned file is logged?",
        "dlg_restart_err": "Restart Scan Failed",
        "dlg_sig_err": "Signal Error",
        "dlg_stop_title": "Stop ClamAV Scan",
        "dlg_stop_msg": "Stop the active scan (PID {pid})?",
        "dlg_stop_err": "Stop Error",
        "dlg_prio_err": "Priority Error",
        "dlg_no_sel_title": "No Selection",
        "dlg_no_sel_threat": "Please select a threat row first.",
        "dlg_no_sel_quar": "Please select a quarantined file first.",
        "dlg_quar_title": "Quarantine File",
        "dlg_quar_msg": "Move '{path}' to {qdir}?",
        "dlg_quar_err": "Quarantine Failed",
        "dlg_del_title": "Delete Infected File",
        "dlg_del_msg": "Permanently delete '{path}'?\nThis cannot be undone.",
        "dlg_del_err": "Delete Failed",
        "dlg_restore_dir": "Choose Folder to Restore File Into",
        "dlg_restore_title": "Restore Quarantined File",
        "dlg_restore_msg": "Restore '{name}' to:\n{dest}\n\nOnly restore files you trust.",
        "dlg_restore_ok_title": "File Restored",
        "dlg_restore_ok_msg": "Restored to:\n{dest}",
        "dlg_restore_err": "Restore Failed",
        "dlg_del_q_title": "Delete Quarantined File",
        "dlg_del_q_msg": "Permanently delete '{name}' from quarantine?",
        "dlg_clear_hist_title": "Clear History",
        "dlg_clear_hist_msg": "Clear saved GUI scan history?",
        "dlg_browse_dir": "Select Directory to Scan",
        "dlg_scan_running_title": "Scan Already Running",
        "dlg_scan_running_msg": "A scan is already running. Start another scan anyway?",
        "dlg_start_err": "Failed to Start Scan",
        "dlg_pick_title": "Select Item to Scan",
        "dlg_pick_msg": "Would you like to scan a Folder or a single File?",
        "dlg_pick_folder": "Choose Folder...",
        "dlg_pick_file": "Choose File...",
        "dlg_pick_folder_title": "Select Folder to Scan",
        "dlg_pick_file_title": "Select File to Scan",
        "label_quick_scan": "Quick Scan (Home & Downloads)",
        "label_full_scan": "Full System Scan (/)",
        "label_custom_scan": "Custom Scan ({target})",
        "label_dropped_one": "Dropped ({name})",
        "label_dropped_many": "Dropped ({count} items)",
        "status_found": "FOUND",
        "status_deleted": "Deleted",
        "status_quarantined": "Quarantined -> {dest}",
        "history_entries": "{count:,} entries",
        "history_see_log": "See log summary",
        "hero_missing_clamscan_title": "ClamAV Scanner Not Installed",
        "hero_missing_clamscan_sub": "The 'clamscan' binary was not found. Install clamav (e.g. zypper/dnf/apt install clamav clamav-freshclam){extra}.",
        "hero_missing_db_title": "Virus Database Missing — Update Needed",
        "hero_missing_db_sub": "No signature files (.cvd/.cld) were found in {db_dir}. Run Virus Database Update before scanning.",
        "hero_update_db_btn": "Update Virus Database",
        "db_state_ready": "DB Ready ({count} files)",
        "db_state_missing": "Missing (0 signature files in {db_dir})",
        "db_deps_ok": "All supporting tools available",
        "db_deps_missing": "Missing optional tools: {tools}",
        "db_status_full": "Installed ClamAV Version: {version}   |   freshclam binary: {freshclam_bin}\nVirus Database ({db_dir}): {db_state}\nAuto-Updater Service: {service}   |   {deps_note}",
        "meta_line_full": "{db_state}  •  Engine {version}  •  Auto-Updates: {service}{warn}",
        "idle_col_status": "Status",
        "idle_col_last_scan": "Last Scan",
        "idle_col_sigs": "Virus Signatures",
        "idle_col_sched": "Scheduled Scan",
        "idle_val_protected": "Protected",
        "idle_val_attention": "Action needed",
        "idle_val_missing_clam": "Not installed",
        "idle_val_no_scans": "No scans yet",
        "idle_val_today": "Today",
        "idle_val_threats_n": "{n} threats",
        "idle_val_up_to_date": "Up to date",
        "idle_val_sigs_missing": "Missing",
        "idle_val_not_sched": "Not scheduled",
        "idle_val_daily_at": "Daily {time}",
        "clamscan_missing_tip": "Disabled because 'clamscan' is not installed on this system.",
        "freshclam_missing_tip": "Disabled because 'freshclam' is not installed on this system.",
        "installed_word": "Installed",
        "missing_word": "Missing",
        "tile_quick_title": "Quick Scan",
        "tile_quick_sub": "Downloads & Home • ~2 min",
        "tile_full_title": "Full System Scan",
        "tile_full_sub": "Entire PC",
        "tile_pick_title": "Check File or Folder",
        "tile_pick_sub": "Drag & drop items here",
        "also_missing_suffix": " (also missing: {items})",
        "history_system_log": "System / Log Scan",
        "svc_active": "Active",
        "svc_inactive": "Inactive",
        "log_path_tip": "Scan logs managed by the root helper must reside under /var/log/ (e.g. /var/log/clamav-scan.log).",
        "log_inspect_err": "Log read notice: {err}",
        "polkit_source_hint": "Note: Passwordless Polkit auto-unlock activates automatically once installed as a system package.",
        "unknown_word": "Unknown",
    },
    "de": {
        "window_title": "ClamAV Sicherheitszentrum",
        "app_title": "ClamAV Sicherheitszentrum",
        "detecting_clamav": "ClamAV wird erkannt...",
        "root_active_badge": "●  Geschützter Zugriff aktiv",
        "user_mode_badge": "●  Benutzermodus aktiv",
        "user_mode_btn": "Benutzermodus",
        "continue_user_mode_btn": "Im Benutzermodus fortfahren",
        "quit_btn": "Beenden",
        "about_btn": "Über",
        "dlg_about_title": "Über ClamAV Sicherheitszentrum",
        "about_desc": "Open-Source-Desktop-Kontrollzentrum für Linux zur Verwaltung von ClamAV-Scans, Quarantäne und geplantem Hintergrundschutz.",
        "about_version_lbl": "Version:",
        "about_creator_lbl": "Ersteller:",
        "about_license_lbl": "Lizenz:",
        "about_github_lbl": "GitHub:",
        "auth_banner_text": "Admin-Zugriff einmalig freischalten für passwortlose Scans, Quarantäne & Zeitpläne.",
        "unlock_sudo_btn": "Passwort freischalten...",
        "unlock_polkit_btn": "Per Polkit freischalten",
        "waiting_polkit": "Warte auf Polkit...",
        "hero_threats_title": "Handlung erforderlich — {count} Bedrohung(en) erkannt",
        "hero_threats_sub": "Öffnen Sie den Tab ‚Erkannte Bedrohungen‘, um infizierte Dateien in Quarantäne zu verschieben oder zu löschen.",
        "hero_review_btn": "Bedrohungen prüfen",
        "hero_protected_title": "Ihr Computer ist geschützt",
        "hero_protected_sub": "Keine Bedrohungen erkannt. Jederzeit scanbereit.",
        "hero_paused_title": "Scan pausiert{pct}",
        "hero_paused_sub": "Klicken Sie auf ‚Scan fortsetzen‘, um weiterzumachen.",
        "hero_scanning_title": "System wird gescannt — {pct:.1f}% abgeschlossen",
        "hero_scanning_sub": "Geschätzte Restzeit: {eta}  •  Prüfe: {file}",
        "hero_bg_title": "Scan läuft im Hintergrund",
        "hero_bg_sub": "Schalten Sie oben den Root-Zugriff frei, um Prozentwert, Restzeit und Live-Dateien zu sehen.",
        "drop_hint": "Tipp: Dateien oder Ordner zum Scannen hierher ziehen",
        "card_status_title": "Scan-Status",
        "card_cpu_title": "Laufzeit / Aktivität",
        "card_io_title": "RAM / Festplatte gelesen",
        "card_threats_title": "Gefundene Bedrohungen",
        "state_running": "LÄUFT",
        "state_paused": "PAUSIERT",
        "idle_word": "Inaktiv",
        "clean_so_far": "Bisher sauber",
        "action_recommended": "Aktion empfohlen",
        "pid_owner": "PID {pid} | Besitzer: {user}",
        "bg_mode_label": "Hintergrundmodus",
        "normal_speed_label": "Normale Geschwindigkeit",
        "unlock_live_io": "Root freischalten für Live-Leserate (MB/s)",
        "ram_value": "RAM {rss}",
        "read_value": "{amount} gelesen",
        "io_sub": "{speed} | Datenträger {disk} | RAM {rss}",
        "ctrl_box_title": "Aktiver Scan-Fortschritt && Steuerung",
        "progress_label": "Fortschritt:",
        "eta_prefix": "Restzeit: {eta}",
        "eta_paused": "Pausiert",
        "eta_unlock_root": "Root nötig",
        "eta_finishing": "Wird abgeschlossen...",
        "eta_calculating": "Wird berechnet...",
        "no_active_scan": "Kein aktiver Scan",
        "no_active_scan_running": "Derzeit läuft kein Scan.",
        "currently_checking": "Aktuell geprüft:",
        "pause_scan": "Scan pausieren",
        "resume_scan": "Scan fortsetzen",
        "stop_scan": "Scan stoppen",
        "bg_mode_chk": "Hintergrundmodus (PC bleibt flüssig)",
        "bg_mode_tip": "Führt den Scan mit niedriger CPU- und Leerlauf-Festplattenpriorität aus, damit Desktop-Apps flüssig bleiben.",
        "progress_paused_unlock": "Pausiert (Root für % freischalten)",
        "progress_pct_paused": "{pct:.1f}% (Pausiert)",
        "progress_sub_unlock_ready": "Ziel: {elig_files:,} scanbare Dateien ({elig_bytes} <= {max_sz}; {all_files:,} gesamt / {all_bytes}) — Root-Zugriff für Live-% & Restzeit freischalten",
        "progress_sub_unlock_counting": "Erste Schätzung: {statvfs} (Dateien werden im Hintergrund gezählt: {all_files:,}...) — Root-Zugriff für Live-% & Restzeit freischalten",
        "progress_sub_unlock_est": "Erste Schätzung: {statvfs} — Root-Zugriff für Live-% & Restzeit freischalten",
        "progress_sub_accurate": "Genaue Vorabzählung: ~{eff} / {total} scanbar ({elig_files:,} Dateien <= {max_sz}; {all_files:,} gesamt / {all_bytes} belegt)",
        "progress_sub_refining": "Erste Schätzung: ~{eff} / {total} (wird im Hintergrund verfeinert: {all_files:,} Dateien...)",
        "progress_sub_est": "Erste Schätzung: ~{eff} / {total}",
        "scan_running_locked_file": "Scan läuft als {user} (PID {pid}). Root-Zugriff oben freischalten, um die aktuell geprüfte Datei anzuzeigen.",
        "scanning_metadata": "(Prüfe Verzeichnis-Metadaten / Dateiwechsel)",
        "archive_temp_suffix": "  (+{count} temporäre Archivdatei)",
        "show_tabs_btn": "Protokolle, Quarantäne && Einstellungen anzeigen ▾",
        "hide_tabs_btn": "Protokolle, Quarantäne && Einstellungen ausblenden ▴",
        "tab_log": "Live-Protokoll",
        "tab_threats": "Bedrohungen ({count})",
        "tab_quarantine": "Quarantäne ({count})",
        "tab_history": "Verlauf",
        "tab_schedule": "Zeitplan",
        "tab_custom": "Erweiterter Scan",
        "tab_db": "Virendatenbank",
        "log_path_lbl": "Protokollpfad:",
        "reload_log_btn": "Neu laden",
        "filter_lbl": "Filter:",
        "log_filter_ph": "Zeilen filtern (z. B. FOUND, ERROR, OK)...",
        "autoscroll_chk": "Automatisch scrollen",
        "stream_fd_chk": "Live geprüfte Dateien (/proc/fd) anzeigen, wenn -i aktiv ist",
        "restart_verbose_btn": "Scan ohne -i neu starten (alle Dateien protokollieren)",
        "quiet_log_hint": "Der aktive Scan verwendet -i (--infected), sodass ClamAV nur Funde und die Zusammenfassung ins Protokoll schreibt. Live-Dateien werden unten angezeigt oder Sie können den Scan ohne -i neu starten.",
        "col_file_path": "Dateipfad",
        "col_threat_sig": "Bedrohungssignatur",
        "col_status": "Status",
        "reveal_dolphin_btn": "Im Dateimanager anzeigen",
        "copy_path_btn": "Pfad kopieren",
        "move_quarantine_btn": "In Quarantäne verschieben",
        "delete_file_btn": "Datei löschen",
        "quarantine_note": "Dateien in Quarantäne sind sicher in /root/quarantine ohne Ausführungsrechte isoliert. Fehlalarme können wiederhergestellt oder dauerhaft gelöscht werden.",
        "col_q_name": "Dateiname",
        "col_q_orig": "Ursprungsort",
        "col_q_threat": "Bedrohung",
        "col_q_date": "Quarantäne-Datum",
        "col_q_size": "Größe",
        "refresh_btn": "Aktualisieren",
        "restore_orig_btn": "Am Ursprungsort wiederherstellen",
        "restore_to_btn": "In Ordner wiederherstellen...",
        "delete_perm_btn": "Endgültig löschen",
        "col_h_date": "Abgeschlossen am",
        "col_h_target": "Scan-Ziel",
        "col_h_duration": "Dauer",
        "col_h_scanned": "Dateien / Daten geprüft",
        "col_h_threats": "Funde",
        "col_h_result": "Ergebnis",
        "refresh_history_btn": "Verlauf aktualisieren",
        "clear_history_btn": "GUI-Verlauf leeren",
        "status_clean": "Sauber",
        "status_threats_found": "Bedrohungen gefunden",
        "sched_desc": "Planen Sie automatische Hintergrund-Scans über systemd-Timer. Geplante Scans laufen immer im Hintergrundmodus, damit Ihr PC flüssig bleibt.",
        "sched_enable_chk": "Automatische geplante Scans aktivieren",
        "sched_status_lbl": "Status:",
        "sched_type_lbl": "Scan-Typ:",
        "sched_freq_lbl": "Häufigkeit:",
        "sched_day_lbl": "Wochentag:",
        "sched_time_lbl": "Uhrzeit:",
        "sched_info_lbl": "Timer-Info:",
        "sched_type_quick": "Schnellscan (Home, Downloads & Temp)",
        "sched_type_full": "Vollständiger Systemscan (Gesamte Festplatte /)",
        "sched_freq_daily": "Täglich",
        "sched_freq_weekly": "Wöchentlich",
        "day_mon": "Montag",
        "day_tue": "Dienstag",
        "day_wed": "Mittwoch",
        "day_thu": "Donnerstag",
        "day_fri": "Freitag",
        "day_sat": "Samstag",
        "day_sun": "Sonntag",
        "sched_unlock_hint": "Root-Zugriff freischalten, um den Scan-Zeitplan anzuzeigen oder zu ändern.",
        "save_sched_btn": "Zeitplan speichern",
        "sched_enabled": "Aktiviert",
        "sched_disabled": "Deaktiviert",
        "sched_timer_status": "Timer-Status: {state}   |   Nächster Lauf: {next_run}",
        "sched_saved_status": "Gespeichert! Timer-Status: {state}   |   {next_run}",
        "sched_saved_title": "Zeitplan gespeichert",
        "sched_saved_msg": "Automatische Scans: {state}.",
        "sched_read_err": "Zeitplan konnte nicht gelesen werden: {err}",
        "sched_save_err": "Zeitplan speichern fehlgeschlagen",
        "adv_target_lbl": "Zielpfad:",
        "browse_btn": "Durchsuchen...",
        "adv_options_lbl": "Optionen:",
        "opt_recursive": "Rekursiv (-r)",
        "opt_infected_only": "Ruhiger Modus: nur Infizierte (-i) [Deaktiviert = alle gescannten Dateien anzeigen]",
        "opt_exclude_virtual": "/sys, /proc, /dev, /run ausschließen",
        "opt_cross_fs": "Auf einem Dateisystem bleiben (--cross-fs=no)",
        "adv_maxsize_lbl": "Max. Datei-/Scangröße:",
        "adv_action_lbl": "Bei Fund:",
        "action_report": "Nur melden (empfohlen für /)",
        "action_move": "Infizierte Dateien nach /root/quarantine verschieben",
        "action_copy": "Infizierte Dateien nach /root/quarantine kopieren",
        "adv_log_lbl": "Protokolldatei:",
        "adv_cmd_lbl": "Befehlsvorschau:",
        "start_custom_btn": "Benutzerdefinierten Scan starten",
        "db_checking": "Prüfe Status der ClamAV-Datenbank...",
        "freshclam_btn": "Virensignaturen jetzt aktualisieren (freshclam)",
        "freshclam_updating": "Signatur-Update läuft...",
        "freshclam_ph": "Ausgabe von freshclam erscheint hier...",
        "freshclam_running_msg": "Führe freshclam als Root aus, bitte warten...\n",
        "freshclam_success": "ERFOLGREICH",
        "freshclam_errors": "MIT FEHLERN BEENDET",
        "tray_tip_idle": "ClamAV Sicherheitszentrum — Geschützt ({count} Bedrohungen)",
        "tray_tip_paused": "ClamAV — Scan pausiert ({pct:.1f}%)",
        "tray_tip_scanning": "ClamAV — Scannt {pct:.1f}% (Restzeit {eta})",
        "tray_tip_running": "ClamAV — Scan läuft",
        "tray_open": "ClamAV Sicherheitszentrum öffnen",
        "tray_quick": "Schnellscan starten",
        "tray_minimized_msg": "Läuft im Systemabschnitt weiter. Klicken Sie auf das Symbol zum Öffnen oder auf Beenden.",
        "notify_threat_title": "Bedrohung erkannt!",
        "notify_scan_done_threats_title": "Scan abgeschlossen — Bedrohungen gefunden!",
        "notify_scan_done_threats_msg": "{label} abgeschlossen: {count} Bedrohung(en) erkannt.",
        "notify_scan_done_clean_title": "ClamAV-Scan abgeschlossen",
        "notify_scan_done_clean_msg": "{label} sauber abgeschlossen (0 Bedrohungen gefunden).",
        "dlg_drop_title": "Abgelegte Elemente scannen",
        "dlg_drop_msg": "ClamAV-Scan starten für:\n\n{preview}",
        "dlg_drop_more": "...und {count} weitere",
        "dlg_sudo_title": "Root-Zugriff freischalten",
        "dlg_sudo_prompt": "Passwort eingeben, um den Root-Zugriff für ClamAV freizuschalten\n(aktiviert automatisch passwortloses Freischalten für zukünftige Starts):",
        "dlg_auth_failed": "Authentifizierung fehlgeschlagen",
        "dlg_polkit_failed": "Polkit-Authentifizierung fehlgeschlagen",
        "dlg_root_req_title": "Root-Berechtigung erforderlich",
        "dlg_root_req_text": "Diese Aktion erfordert Administratorrechte.",
        "dlg_root_req_info": "Schalten Sie den Root-Zugriff einmal frei (kann für zukünftige Starts automatisch gemerkt werden).",
        "dlg_unlock_pw_btn": "Mit Passwort freischalten...",
        "dlg_restart_title": "Scan mit vollständiger Ausgabe neu starten",
        "dlg_restart_msg": "Aktuellen ruhigen (-i) Scan (PID {pid}) stoppen und mit vollständiger Ausgabe neu starten, sodass jede Datei protokolliert wird?",
        "dlg_restart_err": "Scan-Neustart fehlgeschlagen",
        "dlg_sig_err": "Signalfehler",
        "dlg_stop_title": "ClamAV-Scan stoppen",
        "dlg_stop_msg": "Aktiven Scan (PID {pid}) wirklich stoppen?",
        "dlg_stop_err": "Fehler beim Stoppen",
        "dlg_prio_err": "Prioritätsfehler",
        "dlg_no_sel_title": "Keine Auswahl",
        "dlg_no_sel_threat": "Bitte wählen Sie zuerst eine erkannte Bedrohung aus.",
        "dlg_no_sel_quar": "Bitte wählen Sie zuerst eine Datei in Quarantäne aus.",
        "dlg_quar_title": "Datei unter Quarantäne stellen",
        "dlg_quar_msg": "‚{path}‘ nach {qdir} verschieben?",
        "dlg_quar_err": "Quarantäne fehlgeschlagen",
        "dlg_del_title": "Infizierte Datei löschen",
        "dlg_del_msg": "‚{path}‘ endgültig löschen?\nDies kann nicht rückgängig gemacht werden.",
        "dlg_del_err": "Löschen fehlgeschlagen",
        "dlg_restore_dir": "Zielordner für Wiederherstellung wählen",
        "dlg_restore_title": "Datei aus Quarantäne wiederherstellen",
        "dlg_restore_msg": "‚{name}‘ wiederherstellen nach:\n{dest}\n\nStellen Sie nur vertrauenswürdige Dateien wieder her.",
        "dlg_restore_ok_title": "Datei wiederhergestellt",
        "dlg_restore_ok_msg": "Wiederhergestellt nach:\n{dest}",
        "dlg_restore_err": "Wiederherstellung fehlgeschlagen",
        "dlg_del_q_title": "Datei aus Quarantäne löschen",
        "dlg_del_q_msg": "‚{name}‘ endgültig aus der Quarantäne löschen?",
        "dlg_clear_hist_title": "Verlauf leeren",
        "dlg_clear_hist_msg": "Gespeicherten GUI-Scanverlauf löschen?",
        "dlg_browse_dir": "Zu scannenden Ordner auswählen",
        "dlg_scan_running_title": "Scan läuft bereits",
        "dlg_scan_running_msg": "Es läuft bereits ein Scan. Trotzdem einen weiteren Scan starten?",
        "dlg_start_err": "Scan konnte nicht gestartet werden",
        "dlg_pick_title": "Element zum Scannen wählen",
        "dlg_pick_msg": "Möchten Sie einen Ordner oder eine einzelne Datei scannen?",
        "dlg_pick_folder": "Ordner wählen...",
        "dlg_pick_file": "Datei wählen...",
        "dlg_pick_folder_title": "Ordner zum Scannen wählen",
        "dlg_pick_file_title": "Datei zum Scannen wählen",
        "label_quick_scan": "Schnellscan (Home & Downloads)",
        "label_full_scan": "Vollständiger Systemscan (/)",
        "label_custom_scan": "Benutzerdefinierter Scan ({target})",
        "label_dropped_one": "Abgelegt ({name})",
        "label_dropped_many": "Abgelegt ({count} Elemente)",
        "status_found": "GEFUNDEN",
        "status_deleted": "Gelöscht",
        "status_quarantined": "Quarantäne -> {dest}",
        "history_entries": "{count:,} Einträge",
        "history_see_log": "Siehe Protokoll",
        "hero_missing_clamscan_title": "ClamAV-Scanner nicht installiert",
        "hero_missing_clamscan_sub": "Das Programm ‚clamscan‘ wurde nicht gefunden. Bitte installieren Sie ClamAV (z. B. zypper/dnf/apt install clamav clamav-freshclam){extra}.",
        "hero_missing_db_title": "Virendatenbank fehlt — Update erforderlich",
        "hero_missing_db_sub": "Keine Signaturdateien (.cvd/.cld) in {db_dir} gefunden. Bitte vor dem Scannen aktualisieren.",
        "hero_update_db_btn": "Virendatenbank aktualisieren",
        "db_state_ready": "DB bereit ({count} Dateien)",
        "db_state_missing": "Fehlt (0 Signaturdateien in {db_dir})",
        "db_deps_ok": "Alle Hilfsprogramme verfügbar",
        "db_deps_missing": "Fehlende optionale Tools: {tools}",
        "db_status_full": "Installierte ClamAV-Version: {version}   |   freshclam-Programm: {freshclam_bin}\nVirendatenbank ({db_dir}): {db_state}\nAuto-Updater-Dienst: {service}   |   {deps_note}",
        "meta_line_full": "{db_state}  •  Engine {version}  •  Auto-Updates: {service}{warn}",
        "idle_col_status": "Status",
        "idle_col_last_scan": "Letzter Scan",
        "idle_col_sigs": "Virensignaturen",
        "idle_col_sched": "Geplanter Scan",
        "idle_val_protected": "Geschützt",
        "idle_val_attention": "Prüfung nötig",
        "idle_val_missing_clam": "Nicht installiert",
        "idle_val_no_scans": "Noch kein Scan",
        "idle_val_today": "Heute",
        "idle_val_threats_n": "{n} Bedrohungen",
        "idle_val_up_to_date": "Aktuell",
        "idle_val_sigs_missing": "Fehlt",
        "idle_val_not_sched": "Nicht geplant",
        "idle_val_daily_at": "Täglich {time}",
        "clamscan_missing_tip": "Deaktiviert, da ‚clamscan‘ auf diesem System nicht installiert ist.",
        "freshclam_missing_tip": "Deaktiviert, da ‚freshclam‘ auf diesem System nicht installiert ist.",
        "installed_word": "Installiert",
        "missing_word": "Fehlt",
        "tile_quick_title": "Schnellscan",
        "tile_quick_sub": "Downloads & Home • ~2 Min.",
        "tile_full_title": "Vollständiger Systemscan",
        "tile_full_sub": "Gesamter PC",
        "tile_pick_title": "Ordner oder Datei scannen",
        "tile_pick_sub": "Hierher ziehen oder wählen",
        "also_missing_suffix": " (außerdem fehlt: {items})",
        "history_system_log": "System- / Protokollscan",
        "svc_active": "Aktiv",
        "svc_inactive": "Inaktiv",
        "log_path_tip": "Scan-Protokolle des Root-Helpers müssen unter /var/log/ liegen (z. B. /var/log/clamav-scan.log).",
        "log_inspect_err": "Protokoll-Hinweis: {err}",
        "polkit_source_hint": "Hinweis: Passwortloses Polkit-Freischalten wird nach Installation als Systempaket automatisch aktiv.",
        "unknown_word": "Unbekannt",
    },
    "es": {
        "window_title": "Centro de Seguridad ClamAV",
        "app_title": "Centro de Seguridad ClamAV",
        "detecting_clamav": "Detectando ClamAV...",
        "root_active_badge": "●  Acceso protegido activo",
        "user_mode_badge": "●  Modo usuario activo",
        "user_mode_btn": "Modo usuario",
        "continue_user_mode_btn": "Continuar en modo usuario",
        "quit_btn": "Salir",
        "about_btn": "Acerca de",
        "dlg_about_title": "Acerca de Centro de Seguridad ClamAV",
        "about_desc": "Centro de control de código abierto para Linux con análisis ClamAV, cuarentena y protección programada en segundo plano.",
        "about_version_lbl": "Versión:",
        "about_creator_lbl": "Creador:",
        "about_license_lbl": "Licencia:",
        "about_github_lbl": "GitHub:",
        "auth_banner_text": "Desbloquee el acceso root una vez para análisis, cuarentena y programación.",
        "unlock_sudo_btn": "Contraseña...",
        "unlock_polkit_btn": "Desbloquear con Polkit",
        "waiting_polkit": "Esperando a Polkit...",
        "hero_threats_title": "Acción requerida: {count} amenaza(s) detectada(s)",
        "hero_threats_sub": "Abra la pestaña Amenazas detectadas para poner en cuarentena o eliminar archivos.",
        "hero_review_btn": "Revisar amenazas",
        "hero_protected_title": "Su equipo está protegido",
        "hero_protected_sub": "No se detectaron amenazas. Listo para analizar en cualquier momento.",
        "hero_paused_title": "Análisis en pausa{pct}",
        "hero_paused_sub": "Haga clic en Reanudar cuando desee continuar.",
        "hero_scanning_title": "Analizando equipo: {pct:.1f}% completado",
        "hero_scanning_sub": "Tiempo restante: {eta}  •  Archivo: {file}",
        "hero_bg_title": "Análisis en segundo plano",
        "hero_bg_sub": "Desbloquee el acceso root arriba para ver porcentaje, tiempo restante y archivo actual.",
        "drop_hint": "Consejo: arrastre archivos o carpetas aquí",
        "card_status_title": "Estado del análisis",
        "card_cpu_title": "Tiempo / Actividad",
        "card_io_title": "RAM / Lectura disco",
        "card_threats_title": "Amenazas",
        "state_running": "EN CURSO",
        "state_paused": "PAUSADO",
        "idle_word": "Inactivo",
        "clean_so_far": "Sin amenazas",
        "action_recommended": "Acción recomendada",
        "pid_owner": "PID {pid} | Usuario: {user}",
        "bg_mode_label": "Segundo plano",
        "normal_speed_label": "Velocidad normal",
        "unlock_live_io": "Desbloquee root para tasa MB/s",
        "ram_value": "RAM {rss}",
        "read_value": "{amount} leídos",
        "io_sub": "{speed} | Disco {disk} | RAM {rss}",
        "ctrl_box_title": "Progreso y control del análisis activo",
        "progress_label": "Progreso:",
        "eta_prefix": "Restante: {eta}",
        "eta_paused": "En pausa",
        "eta_unlock_root": "Requiere root",
        "eta_finishing": "Finalizando...",
        "eta_calculating": "Calculando...",
        "no_active_scan": "Sin análisis activo",
        "no_active_scan_running": "No hay ningún análisis en curso.",
        "currently_checking": "Analizando:",
        "pause_scan": "Pausar",
        "resume_scan": "Reanudar",
        "stop_scan": "Detener",
        "bg_mode_chk": "Modo segundo plano (PC fluido)",
        "bg_mode_tip": "Ejecuta el análisis con baja prioridad de CPU y disco.",
        "progress_paused_unlock": "Pausado (desbloquee root para %)",
        "progress_pct_paused": "{pct:.1f}% (En pausa)",
        "progress_sub_unlock_ready": "Objetivo: {elig_files:,} archivos ({elig_bytes} <= {max_sz}; {all_files:,} total / {all_bytes})",
        "progress_sub_unlock_counting": "Estimación inicial: {statvfs} (contando archivos: {all_files:,}...)",
        "progress_sub_unlock_est": "Estimación inicial: {statvfs}",
        "progress_sub_accurate": "Conteo exacto: ~{eff} / {total} ({elig_files:,} <= {max_sz}; {all_files:,} / {all_bytes})",
        "progress_sub_refining": "Estimación inicial: ~{eff} / {total} (contando: {all_files:,} archivos...)",
        "progress_sub_est": "Estimación inicial: ~{eff} / {total}",
        "scan_running_locked_file": "Ejecutándose como {user} (PID {pid}). Desbloquee root arriba para ver archivos.",
        "scanning_metadata": "(Verificando metadatos de directorio)",
        "archive_temp_suffix": "  (+{count} temporal de archivo)",
        "show_tabs_btn": "Mostrar registros, cuarentena y ajustes ▾",
        "hide_tabs_btn": "Ocultar registros, cuarentena y ajustes ▴",
        "tab_log": "Registro en vivo",
        "tab_threats": "Amenazas ({count})",
        "tab_quarantine": "Cuarentena ({count})",
        "tab_history": "Historial",
        "tab_schedule": "Programación",
        "tab_custom": "Análisis avanzado",
        "tab_db": "Base de virus",
        "log_path_lbl": "Registro:",
        "reload_log_btn": "Recargar",
        "filter_lbl": "Filtro:",
        "log_filter_ph": "Filtrar líneas (FOUND, ERROR, OK)...",
        "autoscroll_chk": "Autodesplazar",
        "stream_fd_chk": "Mostrar archivos /proc/fd cuando -i está activo",
        "restart_verbose_btn": "Reiniciar sin -i (registrar todo)",
        "quiet_log_hint": "El análisis usa -i (--infected): solo escribe amenazas y resumen. La actividad /proc/fd aparece abajo.",
        "col_file_path": "Ruta del archivo",
        "col_threat_sig": "Firma de amenaza",
        "col_status": "Estado",
        "reveal_dolphin_btn": "Mostrar en carpeta",
        "copy_path_btn": "Copiar ruta",
        "move_quarantine_btn": "Mover a cuarentena",
        "delete_file_btn": "Eliminar archivo",
        "quarantine_note": "Los archivos en cuarentena se aíslan en /root/quarantine sin permisos de ejecución.",
        "col_q_name": "Archivo",
        "col_q_orig": "Ubicación original",
        "col_q_threat": "Amenaza",
        "col_q_date": "Fecha",
        "col_q_size": "Tamaño",
        "refresh_btn": "Actualizar",
        "restore_orig_btn": "Restaurar origen",
        "restore_to_btn": "Restaurar en...",
        "delete_perm_btn": "Eliminar definitivamente",
        "col_h_date": "Fecha",
        "col_h_target": "Objetivo",
        "col_h_duration": "Duración",
        "col_h_scanned": "Archivos / Datos",
        "col_h_threats": "Amenazas",
        "col_h_result": "Resultado",
        "refresh_history_btn": "Actualizar historial",
        "clear_history_btn": "Limpiar historial",
        "status_clean": "Limpio",
        "status_threats_found": "Amenazas",
        "sched_desc": "Programe análisis automáticos en segundo plano mediante temporizadores systemd.",
        "sched_enable_chk": "Activar análisis automáticos",
        "sched_status_lbl": "Estado:",
        "sched_type_lbl": "Tipo:",
        "sched_freq_lbl": "Frecuencia:",
        "sched_day_lbl": "Día:",
        "sched_time_lbl": "Hora:",
        "sched_info_lbl": "Temporizador:",
        "sched_type_quick": "Análisis rápido (Inicio y Descargas)",
        "sched_type_full": "Análisis completo (/)",
        "sched_freq_daily": "Diario",
        "sched_freq_weekly": "Semanal",
        "day_mon": "Lunes",
        "day_tue": "Martes",
        "day_wed": "Miércoles",
        "day_thu": "Jueves",
        "day_fri": "Viernes",
        "day_sat": "Sábado",
        "day_sun": "Domingo",
        "sched_unlock_hint": "Desbloquee root para leer o cambiar la programación.",
        "save_sched_btn": "Guardar programación",
        "sched_enabled": "Activado",
        "sched_disabled": "Desactivado",
        "sched_timer_status": "Estado: {state}   |   Programación: {next_run}",
        "sched_saved_status": "¡Guardado! Estado: {state}   |   {next_run}",
        "sched_saved_title": "Programación guardada",
        "sched_saved_msg": "Análisis automáticos: {state}.",
        "sched_read_err": "No se pudo leer la programación: {err}",
        "sched_save_err": "Error al guardar",
        "adv_target_lbl": "Ruta:",
        "browse_btn": "Examinar...",
        "adv_options_lbl": "Opciones:",
        "opt_recursive": "Recursivo (-r)",
        "opt_infected_only": "Solo infectados (-i) [Desmarcado = registrar todos]",
        "opt_exclude_virtual": "Excluir /sys, /proc, /dev, /run",
        "opt_cross_fs": "Un solo sistema de archivos (--cross-fs=no)",
        "adv_maxsize_lbl": "Tamaño máx.:",
        "adv_action_lbl": "Al detectar amenaza:",
        "action_report": "Solo informar (recomendado para /)",
        "action_move": "Mover a /root/quarantine",
        "action_copy": "Copiar a /root/quarantine",
        "adv_log_lbl": "Archivo de registro:",
        "adv_cmd_lbl": "Vista del comando:",
        "start_custom_btn": "Iniciar análisis personalizado",
        "db_checking": "Comprobando base de datos ClamAV...",
        "freshclam_btn": "Actualizar firmas ahora (freshclam)",
        "freshclam_updating": "Actualizando firmas...",
        "freshclam_ph": "La salida de freshclam aparecerá aquí...",
        "freshclam_running_msg": "Ejecutando freshclam como root, espere...\n",
        "freshclam_success": "ÉXITO",
        "freshclam_errors": "FINALIZADO CON ERRORES",
        "tray_tip_idle": "Centro de Seguridad ClamAV — Protegido ({count} amenazas)",
        "tray_tip_paused": "ClamAV — En pausa ({pct:.1f}%)",
        "tray_tip_scanning": "ClamAV — Analizando {pct:.1f}% (Restante {eta})",
        "tray_tip_running": "ClamAV — Análisis en curso",
        "tray_open": "Abrir Centro de Seguridad ClamAV",
        "tray_quick": "Iniciar análisis rápido",
        "tray_minimized_msg": "En ejecución en la bandeja. Haga clic para abrir o Salir para cerrar.",
        "notify_threat_title": "¡Amenaza detectada!",
        "notify_scan_done_threats_title": "Análisis completado — ¡Amenazas!",
        "notify_scan_done_threats_msg": "{label} finalizó con {count} amenaza(s).",
        "notify_scan_done_clean_title": "Análisis ClamAV completado",
        "notify_scan_done_clean_msg": "{label} finalizó limpio (0 amenazas).",
        "dlg_drop_title": "Analizar elementos soltados",
        "dlg_drop_msg": "Iniciar análisis en:\n\n{preview}",
        "dlg_drop_more": "...y {count} más",
        "dlg_sudo_title": "Desbloquear acceso root",
        "dlg_sudo_prompt": "Introduzca su contraseña para desbloquear ClamAV\n(permite desbloqueo automático en futuros inicios):",
        "dlg_auth_failed": "Error de autenticación",
        "dlg_polkit_failed": "Error de Polkit",
        "dlg_root_req_title": "Permiso root necesario",
        "dlg_root_req_text": "Esta acción requiere privilegios de administrador.",
        "dlg_root_req_info": "Desbloquee el acceso root una vez.",
        "dlg_unlock_pw_btn": "Contraseña...",
        "dlg_restart_title": "Reiniciar con registro completo",
        "dlg_restart_msg": "¿Detener el análisis (-i) (PID {pid}) y reiniciarlo registrando cada archivo?",
        "dlg_restart_err": "Error al reiniciar",
        "dlg_sig_err": "Error de señal",
        "dlg_stop_title": "Detener análisis ClamAV",
        "dlg_stop_msg": "¿Detener el análisis activo (PID {pid})?",
        "dlg_stop_err": "Error al detener",
        "dlg_prio_err": "Error de prioridad",
        "dlg_no_sel_title": "Sin selección",
        "dlg_no_sel_threat": "Seleccione primero una fila de amenaza.",
        "dlg_no_sel_quar": "Seleccione primero un archivo en cuarentena.",
        "dlg_quar_title": "Mover a cuarentena",
        "dlg_quar_msg": "¿Mover '{path}' a {qdir}?",
        "dlg_quar_err": "Error en cuarentena",
        "dlg_del_title": "Eliminar archivo infectado",
        "dlg_del_msg": "¿Eliminar permanentemente '{path}'?\nNo se puede deshacer.",
        "dlg_del_err": "Error al eliminar",
        "dlg_restore_dir": "Seleccionar carpeta de destino",
        "dlg_restore_title": "Restaurar archivo",
        "dlg_restore_msg": "¿Restaurar '{name}' en:\n{dest}\n\nSolo restaure archivos de confianza.",
        "dlg_restore_ok_title": "Archivo restaurado",
        "dlg_restore_ok_msg": "Restaurado en:\n{dest}",
        "dlg_restore_err": "Error al restaurar",
        "dlg_del_q_title": "Eliminar de cuarentena",
        "dlg_del_q_msg": "¿Eliminar permanentemente '{name}'?",
        "dlg_clear_hist_title": "Limpiar historial",
        "dlg_clear_hist_msg": "¿Borrar el historial guardado?",
        "dlg_browse_dir": "Seleccionar directorio",
        "dlg_scan_running_title": "Análisis ya activo",
        "dlg_scan_running_msg": "Ya hay un análisis en curso. ¿Iniciar otro?",
        "dlg_start_err": "Error al iniciar",
        "dlg_pick_title": "Seleccionar elemento",
        "dlg_pick_msg": "¿Desea analizar una carpeta o un archivo?",
        "dlg_pick_folder": "Elegir carpeta...",
        "dlg_pick_file": "Elegir archivo...",
        "dlg_pick_folder_title": "Seleccionar carpeta",
        "dlg_pick_file_title": "Seleccionar archivo",
        "label_quick_scan": "Análisis rápido (Inicio y Descargas)",
        "label_full_scan": "Análisis completo (/)",
        "label_custom_scan": "Análisis personalizado ({target})",
        "label_dropped_one": "Soltado ({name})",
        "label_dropped_many": "Soltados ({count} elementos)",
        "status_found": "ENCONTRADO",
        "status_deleted": "Eliminado",
        "status_quarantined": "En cuarentena -> {dest}",
        "history_entries": "{count:,} entradas",
        "history_see_log": "Ver resumen",
        "hero_missing_clamscan_title": "ClamAV no está instalado",
        "hero_missing_clamscan_sub": "No se encontró 'clamscan'. Instale clamav (p. ej., clamav clamav-freshclam){extra}.",
        "hero_missing_db_title": "Falta la base de virus — Actualice",
        "hero_missing_db_sub": "Sin firmas (.cvd/.cld) en {db_dir}. Ejecute actualización antes de analizar.",
        "hero_update_db_btn": "Actualizar base de virus",
        "db_state_ready": "BD lista ({count} archivos)",
        "db_state_missing": "Falta (0 firmas en {db_dir})",
        "db_deps_ok": "Herramientas auxiliares disponibles",
        "db_deps_missing": "Faltan herramientas opcionales: {tools}",
        "db_status_full": "Versión ClamAV: {version}   |   freshclam: {freshclam_bin}\nBase de virus ({db_dir}): {db_state}\nActualizador automático: {service}   |   {deps_note}",
        "meta_line_full": "{db_state}  •  Motor {version}  •  Actualizaciones: {service}{warn}",
        "idle_col_status": "Estado",
        "idle_col_last_scan": "Último análisis",
        "idle_col_sigs": "Firmas de virus",
        "idle_col_sched": "Programado",
        "idle_val_protected": "Protegido",
        "idle_val_attention": "Requiere acción",
        "idle_val_missing_clam": "No instalado",
        "idle_val_no_scans": "Sin análisis",
        "idle_val_today": "Hoy",
        "idle_val_threats_n": "{n} amenazas",
        "idle_val_up_to_date": "Al día",
        "idle_val_sigs_missing": "Faltan",
        "idle_val_not_sched": "Sin programar",
        "idle_val_daily_at": "Diario {time}",
        "clamscan_missing_tip": "Desactivado porque 'clamscan' no está instalado.",
        "freshclam_missing_tip": "Desactivado porque 'freshclam' no está instalado.",
        "installed_word": "Instalado",
        "missing_word": "Falta",
        "tile_quick_title": "Análisis rápido",
        "tile_quick_sub": "Descargas e Inicio • ~2 min",
        "tile_full_title": "Análisis completo",
        "tile_full_sub": "Todo el equipo",
        "tile_pick_title": "Archivo o carpeta",
        "tile_pick_sub": "Arrastre elementos aquí",
        "also_missing_suffix": " (también falta: {items})",
        "history_system_log": "Sistema / Registro",
        "svc_active": "Activo",
        "svc_inactive": "Inactivo",
        "log_path_tip": "Los registros administrados por root deben estar bajo /var/log/.",
        "log_inspect_err": "Aviso de registro: {err}",
        "polkit_source_hint": "Nota: Polkit sin contraseña se activa al instalar el paquete del sistema.",
        "unknown_word": "Desconocido",
    },
    "fr": {
        "window_title": "Centre de sécurité ClamAV",
        "app_title": "Centre de sécurité ClamAV",
        "detecting_clamav": "Détection de ClamAV...",
        "root_active_badge": "●  Accès protégé actif",
        "user_mode_badge": "●  Mode utilisateur actif",
        "user_mode_btn": "Mode utilisateur",
        "continue_user_mode_btn": "Continuer en mode utilisateur",
        "quit_btn": "Quitter",
        "about_btn": "À propos",
        "dlg_about_title": "À propos du Centre de sécurité ClamAV",
        "about_desc": "Centre de contrôle open source pour Linux dédié aux analyses ClamAV, à la quarantaine et à la protection planifiée.",
        "about_version_lbl": "Version :",
        "about_creator_lbl": "Créateur :",
        "about_license_lbl": "Licence :",
        "about_github_lbl": "GitHub :",
        "auth_banner_text": "Déverrouillez l'accès root une fois pour analyses, quarantaine et planifications.",
        "unlock_sudo_btn": "Mot de passe...",
        "unlock_polkit_btn": "Via Polkit",
        "waiting_polkit": "Attente de Polkit...",
        "hero_threats_title": "Action requise — {count} menace(s) détectée(s)",
        "hero_threats_sub": "Ouvrez l'onglet Menaces détectées pour mettre en quarantaine ou supprimer.",
        "hero_review_btn": "Voir les menaces",
        "hero_protected_title": "Votre ordinateur est protégé",
        "hero_protected_sub": "Aucune menace détectée. Prêt à analyser à tout moment.",
        "hero_paused_title": "Analyse en pause{pct}",
        "hero_paused_sub": "Cliquez sur Reprendre lorsque vous êtes prêt.",
        "hero_scanning_title": "Analyse en cours — {pct:.1f}%",
        "hero_scanning_sub": "Temps restant : {eta}  •  Fichier : {file}",
        "hero_bg_title": "Analyse en arrière-plan",
        "hero_bg_sub": "Déverrouillez l'accès root ci-dessus pour voir le pourcentage et le fichier en direct.",
        "drop_hint": "Astuce : glissez des fichiers ou dossiers ici",
        "card_status_title": "État",
        "card_cpu_title": "Durée / Activité",
        "card_io_title": "RAM / Lecture disque",
        "card_threats_title": "Menaces",
        "state_running": "EN COURS",
        "state_paused": "EN PAUSE",
        "idle_word": "Inactif",
        "clean_so_far": "Aucune menace",
        "action_recommended": "Action requise",
        "pid_owner": "PID {pid} | Utilisateur : {user}",
        "bg_mode_label": "Arrière-plan",
        "normal_speed_label": "Vitesse normale",
        "unlock_live_io": "Root requis pour le débit Mo/s",
        "ram_value": "RAM {rss}",
        "read_value": "{amount} lus",
        "io_sub": "{speed} | Disque {disk} | RAM {rss}",
        "ctrl_box_title": "Progression et contrôle de l'analyse",
        "progress_label": "Progression :",
        "eta_prefix": "Restant : {eta}",
        "eta_paused": "En pause",
        "eta_unlock_root": "Root requis",
        "eta_finishing": "Finalisation...",
        "eta_calculating": "Calcul...",
        "no_active_scan": "Aucune analyse active",
        "no_active_scan_running": "Aucune analyse en cours.",
        "currently_checking": "Vérification :",
        "pause_scan": "Pause",
        "resume_scan": "Reprendre",
        "stop_scan": "Arrêter",
        "bg_mode_chk": "Mode arrière-plan (PC fluide)",
        "bg_mode_tip": "Exécute l'analyse avec faible priorité CPU et disque.",
        "progress_paused_unlock": "En pause (root requis pour %)",
        "progress_pct_paused": "{pct:.1f}% (En pause)",
        "progress_sub_unlock_ready": "Cible : {elig_files:,} fichiers ({elig_bytes} <= {max_sz} ; {all_files:,} total / {all_bytes})",
        "progress_sub_unlock_counting": "Estimation initiale : {statvfs} (comptage : {all_files:,}...)",
        "progress_sub_unlock_est": "Estimation initiale : {statvfs}",
        "progress_sub_accurate": "Comptage exact : ~{eff} / {total} ({elig_files:,} <= {max_sz} ; {all_files:,} / {all_bytes})",
        "progress_sub_refining": "Estimation : ~{eff} / {total} ({all_files:,} fichiers vus...)",
        "progress_sub_est": "Estimation initiale : ~{eff} / {total}",
        "scan_running_locked_file": "Analyse lancée par {user} (PID {pid}). Déverrouillez root pour voir les fichiers.",
        "scanning_metadata": "(Lecture des métadonnées du répertoire)",
        "archive_temp_suffix": "  (+{count} fichier temporaire)",
        "show_tabs_btn": "Afficher journaux, quarantaine et paramètres ▾",
        "hide_tabs_btn": "Masquer journaux, quarantaine et paramètres ▴",
        "tab_log": "Journal en direct",
        "tab_threats": "Menaces ({count})",
        "tab_quarantine": "Quarantaine ({count})",
        "tab_history": "Historique",
        "tab_schedule": "Planification",
        "tab_custom": "Analyse avancée",
        "tab_db": "Base virale",
        "log_path_lbl": "Journal :",
        "reload_log_btn": "Recharger",
        "filter_lbl": "Filtre :",
        "log_filter_ph": "Filtrer (FOUND, ERROR, OK)...",
        "autoscroll_chk": "Défilement auto",
        "stream_fd_chk": "Afficher /proc/fd en direct avec -i",
        "restart_verbose_btn": "Relancer sans -i (tout journaliser)",
        "quiet_log_hint": "Mode -i actif : seules les menaces et le résumé sont écrits dans le journal.",
        "col_file_path": "Chemin du fichier",
        "col_threat_sig": "Signature",
        "col_status": "État",
        "reveal_dolphin_btn": "Afficher dans le dossier",
        "copy_path_btn": "Copier le chemin",
        "move_quarantine_btn": "Mettre en quarantaine",
        "delete_file_btn": "Supprimer",
        "quarantine_note": "Les fichiers en quarantaine sont isolés dans /root/quarantine sans droits d'exécution.",
        "col_q_name": "Fichier",
        "col_q_orig": "Emplacement d'origine",
        "col_q_threat": "Menace",
        "col_q_date": "Date",
        "col_q_size": "Taille",
        "refresh_btn": "Actualiser",
        "restore_orig_btn": "Restaurer à l'origine",
        "restore_to_btn": "Restaurer vers...",
        "delete_perm_btn": "Supprimer définitivement",
        "col_h_date": "Date",
        "col_h_target": "Cible",
        "col_h_duration": "Durée",
        "col_h_scanned": "Fichiers / Données",
        "col_h_threats": "Menaces",
        "col_h_result": "Résultat",
        "refresh_history_btn": "Actualiser",
        "clear_history_btn": "Effacer l'historique",
        "status_clean": "Sain",
        "status_threats_found": "Menaces",
        "sched_desc": "Planifiez des analyses automatiques en arrière-plan via systemd.",
        "sched_enable_chk": "Activer les analyses automatiques",
        "sched_status_lbl": "État :",
        "sched_type_lbl": "Type :",
        "sched_freq_lbl": "Fréquence :",
        "sched_day_lbl": "Jour :",
        "sched_time_lbl": "Heure :",
        "sched_info_lbl": "Minuteur :",
        "sched_type_quick": "Analyse rapide (Accueil et Téléchargements)",
        "sched_type_full": "Analyse complète (/)",
        "sched_freq_daily": "Quotidien",
        "sched_freq_weekly": "Hebdomadaire",
        "day_mon": "Lundi",
        "day_tue": "Mardi",
        "day_wed": "Mercredi",
        "day_thu": "Jeudi",
        "day_fri": "Vendredi",
        "day_sat": "Samedi",
        "day_sun": "Dimanche",
        "sched_unlock_hint": "Déverrouillez root pour lire ou modifier la planification.",
        "save_sched_btn": "Enregistrer",
        "sched_enabled": "Activé",
        "sched_disabled": "Désactivé",
        "sched_timer_status": "État : {state}   |   Planification : {next_run}",
        "sched_saved_status": "Enregistré ! État : {state}   |   {next_run}",
        "sched_saved_title": "Planification enregistrée",
        "sched_saved_msg": "Analyses automatiques : {state}.",
        "sched_read_err": "Erreur de lecture : {err}",
        "sched_save_err": "Échec d'enregistrement",
        "adv_target_lbl": "Chemin cible :",
        "browse_btn": "Parcourir...",
        "adv_options_lbl": "Options :",
        "opt_recursive": "Récursif (-r)",
        "opt_infected_only": "Mode silencieux : infectés uniquement (-i)",
        "opt_exclude_virtual": "Exclure /sys, /proc, /dev, /run",
        "opt_cross_fs": "Rester sur un système de fichiers (--cross-fs=no)",
        "adv_maxsize_lbl": "Taille max. :",
        "adv_action_lbl": "En cas de menace :",
        "action_report": "Signaler uniquement (recommandé pour /)",
        "action_move": "Déplacer vers /root/quarantine",
        "action_copy": "Copier vers /root/quarantine",
        "adv_log_lbl": "Fichier journal :",
        "adv_cmd_lbl": "Aperçu commande :",
        "start_custom_btn": "Lancer l'analyse avancée",
        "db_checking": "Vérification de la base ClamAV...",
        "freshclam_btn": "Mettre à jour les signatures (freshclam)",
        "freshclam_updating": "Mise à jour...",
        "freshclam_ph": "La sortie de freshclam apparaîtra ici...",
        "freshclam_running_msg": "Exécution de freshclam en tant que root...\n",
        "freshclam_success": "SUCCÈS",
        "freshclam_errors": "TERMINÉ AVEC ERREURS",
        "tray_tip_idle": "Centre de sécurité ClamAV — Protégé ({count} menaces)",
        "tray_tip_paused": "ClamAV — En pause ({pct:.1f}%)",
        "tray_tip_scanning": "ClamAV — Analyse {pct:.1f}% (Restant {eta})",
        "tray_tip_running": "ClamAV — Analyse en cours",
        "tray_open": "Ouvrir ClamAV",
        "tray_quick": "Lancer une analyse rapide",
        "tray_minimized_msg": "Réduit dans la zone de notification.",
        "notify_threat_title": "Menace détectée !",
        "notify_scan_done_threats_title": "Analyse terminée — Menaces !",
        "notify_scan_done_threats_msg": "{label} terminé avec {count} menace(s).",
        "notify_scan_done_clean_title": "Analyse ClamAV terminée",
        "notify_scan_done_clean_msg": "{label} terminé sans menace.",
        "dlg_drop_title": "Analyser les éléments déposés",
        "dlg_drop_msg": "Lancer une analyse sur :\n\n{preview}",
        "dlg_drop_more": "...et {count} de plus",
        "dlg_sudo_title": "Déverrouiller l'accès root",
        "dlg_sudo_prompt": "Entrez votre mot de passe pour déverrouiller ClamAV :",
        "dlg_auth_failed": "Échec d'authentification",
        "dlg_polkit_failed": "Échec Polkit",
        "dlg_root_req_title": "Droits root requis",
        "dlg_root_req_text": "Cette action nécessite les privilèges administrateur.",
        "dlg_root_req_info": "Déverrouillez l'accès root une fois.",
        "dlg_unlock_pw_btn": "Mot de passe...",
        "dlg_restart_title": "Relancer avec journal complet",
        "dlg_restart_msg": "Arrêter l'analyse (-i) (PID {pid}) et relancer avec journal complet ?",
        "dlg_restart_err": "Échec du redémarrage",
        "dlg_sig_err": "Erreur de signal",
        "dlg_stop_title": "Arrêter l'analyse ClamAV",
        "dlg_stop_msg": "Arrêter l'analyse active (PID {pid}) ?",
        "dlg_stop_err": "Erreur d'arrêt",
        "dlg_prio_err": "Erreur de priorité",
        "dlg_no_sel_title": "Aucune sélection",
        "dlg_no_sel_threat": "Sélectionnez d'abord une menace.",
        "dlg_no_sel_quar": "Sélectionnez d'abord un fichier.",
        "dlg_quar_title": "Mettre en quarantaine",
        "dlg_quar_msg": "Déplacer « {path} » vers {qdir} ?",
        "dlg_quar_err": "Échec quarantaine",
        "dlg_del_title": "Supprimer le fichier infecté",
        "dlg_del_msg": "Supprimer définitivement « {path} » ?",
        "dlg_del_err": "Échec suppression",
        "dlg_restore_dir": "Choisir le dossier cible",
        "dlg_restore_title": "Restaurer le fichier",
        "dlg_restore_msg": "Restaurer « {name} » vers :\n{dest}",
        "dlg_restore_ok_title": "Fichier restauré",
        "dlg_restore_ok_msg": "Restauré vers :\n{dest}",
        "dlg_restore_err": "Échec restauration",
        "dlg_del_q_title": "Supprimer de la quarantaine",
        "dlg_del_q_msg": "Supprimer définitivement « {name} » ?",
        "dlg_clear_hist_title": "Effacer l'historique",
        "dlg_clear_hist_msg": "Effacer l'historique enregistré ?",
        "dlg_browse_dir": "Sélectionner un dossier",
        "dlg_scan_running_title": "Analyse déjà active",
        "dlg_scan_running_msg": "Une analyse est en cours. En lancer une autre ?",
        "dlg_start_err": "Échec du démarrage",
        "dlg_pick_title": "Choisir un élément",
        "dlg_pick_msg": "Voulez-vous analyser un dossier ou un fichier ?",
        "dlg_pick_folder": "Choisir un dossier...",
        "dlg_pick_file": "Choisir un fichier...",
        "dlg_pick_folder_title": "Sélectionner un dossier",
        "dlg_pick_file_title": "Sélectionner un fichier",
        "label_quick_scan": "Analyse rapide (Accueil & Téléchargements)",
        "label_full_scan": "Analyse complète (/)",
        "label_custom_scan": "Analyse personnalisée ({target})",
        "label_dropped_one": "Déposé ({name})",
        "label_dropped_many": "Déposés ({count} éléments)",
        "status_found": "TROUVÉ",
        "status_deleted": "Supprimé",
        "status_quarantined": "Quarantaine -> {dest}",
        "history_entries": "{count:,} entrées",
        "history_see_log": "Voir le journal",
        "hero_missing_clamscan_title": "ClamAV non installé",
        "hero_missing_clamscan_sub": "Le binaire 'clamscan' est introuvable. Installez clamav{extra}.",
        "hero_missing_db_title": "Base virale manquante",
        "hero_missing_db_sub": "Aucune signature (.cvd/.cld) dans {db_dir}. Lancez une mise à jour.",
        "hero_update_db_btn": "Mettre à jour la base",
        "db_state_ready": "BD prête ({count} fichiers)",
        "db_state_missing": "Manquante (0 signatures dans {db_dir})",
        "db_deps_ok": "Tous les outils sont disponibles",
        "db_deps_missing": "Outils optionnels manquants : {tools}",
        "db_status_full": "Version ClamAV : {version}   |   freshclam : {freshclam_bin}\nBase virale ({db_dir}) : {db_state}\nMises à jour auto : {service}   |   {deps_note}",
        "meta_line_full": "{db_state}  •  Moteur {version}  •  Mises à jour : {service}{warn}",
        "idle_col_status": "Statut",
        "idle_col_last_scan": "Dernier scan",
        "idle_col_sigs": "Signatures virales",
        "idle_col_sched": "Planifié",
        "idle_val_protected": "Protégé",
        "idle_val_attention": "Action requise",
        "idle_val_missing_clam": "Non installé",
        "idle_val_no_scans": "Aucun scan",
        "idle_val_today": "Aujourd'hui",
        "idle_val_threats_n": "{n} menaces",
        "idle_val_up_to_date": "À jour",
        "idle_val_sigs_missing": "Manquante",
        "idle_val_not_sched": "Non planifié",
        "idle_val_daily_at": "Quotidien {time}",
        "clamscan_missing_tip": "Désactivé : 'clamscan' introuvable.",
        "freshclam_missing_tip": "Désactivé : 'freshclam' introuvable.",
        "installed_word": "Installé",
        "missing_word": "Manquant",
        "tile_quick_title": "Analyse rapide",
        "tile_quick_sub": "Téléchargements & Accueil • ~2 min",
        "tile_full_title": "Analyse complète",
        "tile_full_sub": "Tout le PC",
        "tile_pick_title": "Fichier ou dossier",
        "tile_pick_sub": "Glisser-déposer ici",
        "also_missing_suffix": " (manquant aussi : {items})",
        "history_system_log": "Système / Journal",
        "svc_active": "Actif",
        "svc_inactive": "Inactif",
        "log_path_tip": "Les journaux root doivent résider dans /var/log/.",
        "log_inspect_err": "Note journal : {err}",
        "polkit_source_hint": "Note : Polkit sans mot de passe s'active via le paquet système.",
        "unknown_word": "Inconnu",
    },
    "pt": {
        "window_title": "Central de Segurança ClamAV",
        "app_title": "Central de Segurança ClamAV",
        "detecting_clamav": "Detectando ClamAV...",
        "root_active_badge": "●  Acesso protegido ativo",
        "user_mode_badge": "●  Modo usuário ativo",
        "user_mode_btn": "Modo usuário",
        "continue_user_mode_btn": "Continuar no modo usuário",
        "quit_btn": "Sair",
        "about_btn": "Sobre",
        "dlg_about_title": "Sobre a Central de Segurança ClamAV",
        "about_desc": "Central de controle de código aberto para Linux com verificações ClamAV, quarentena e proteção agendada em segundo plano.",
        "about_version_lbl": "Versão:",
        "about_creator_lbl": "Criador:",
        "about_license_lbl": "Licença:",
        "about_github_lbl": "GitHub:",
        "auth_banner_text": "Desbloqueie o acesso root uma vez para verificações, quarentena e agendamentos.",
        "unlock_sudo_btn": "Senha...",
        "unlock_polkit_btn": "Via Polkit",
        "waiting_polkit": "Aguardando Polkit...",
        "hero_threats_title": "Ação necessária — {count} ameaça(s) detectada(s)",
        "hero_threats_sub": "Abra a aba Ameaças detectadas para mover à quarentena ou remover.",
        "hero_review_btn": "Ver ameaças",
        "hero_protected_title": "Seu computador está protegido",
        "hero_protected_sub": "Nenhuma ameaça detectada. Pronto para verificar a qualquer momento.",
        "hero_paused_title": "Verificação pausada{pct}",
        "hero_paused_sub": "Clique em Retomar quando quiser continuar.",
        "hero_scanning_title": "Verificando sistema — {pct:.1f}%",
        "hero_scanning_sub": "Tempo restante: {eta}  •  Arquivo: {file}",
        "hero_bg_title": "Verificação em segundo plano",
        "hero_bg_sub": "Desbloqueie o acesso root acima para ver o progresso ao vivo.",
        "drop_hint": "Dica: arraste arquivos ou pastas aqui",
        "card_status_title": "Status",
        "card_cpu_title": "Tempo / Atividade",
        "card_io_title": "RAM / Leitura disco",
        "card_threats_title": "Ameaças",
        "state_running": "EM EXECUÇÃO",
        "state_paused": "PAUSADO",
        "idle_word": "Ocioso",
        "clean_so_far": "Nenhuma ameaça",
        "action_recommended": "Ação recomendada",
        "pid_owner": "PID {pid} | Usuário: {user}",
        "bg_mode_label": "Segundo plano",
        "normal_speed_label": "Velocidade normal",
        "unlock_live_io": "Desbloqueie root para taxa MB/s",
        "ram_value": "RAM {rss}",
        "read_value": "{amount} lidos",
        "io_sub": "{speed} | Disco {disk} | RAM {rss}",
        "ctrl_box_title": "Progresso e controle da verificação",
        "progress_label": "Progresso:",
        "eta_prefix": "Restante: {eta}",
        "eta_paused": "Pausado",
        "eta_unlock_root": "Root necessário",
        "eta_finishing": "Finalizando...",
        "eta_calculating": "Calculando...",
        "no_active_scan": "Sem verificação ativa",
        "no_active_scan_running": "Nenhuma verificação em execução.",
        "currently_checking": "Verificando:",
        "pause_scan": "Pausar",
        "resume_scan": "Retomar",
        "stop_scan": "Parar",
        "bg_mode_chk": "Modo segundo plano (PC fluido)",
        "bg_mode_tip": "Executa com prioridade baixa de CPU e disco.",
        "progress_paused_unlock": "Pausado (root necessário para %)",
        "progress_pct_paused": "{pct:.1f}% (Pausado)",
        "progress_sub_unlock_ready": "Alvo: {elig_files:,} arquivos ({elig_bytes} <= {max_sz}; {all_files:,} total / {all_bytes})",
        "progress_sub_unlock_counting": "Estimativa inicial: {statvfs} (contando: {all_files:,}...)",
        "progress_sub_unlock_est": "Estimativa inicial: {statvfs}",
        "progress_sub_accurate": "Contagem exata: ~{eff} / {total} ({elig_files:,} <= {max_sz}; {all_files:,} / {all_bytes})",
        "progress_sub_refining": "Estimativa: ~{eff} / {total} ({all_files:,} arquivos...)",
        "progress_sub_est": "Estimativa inicial: ~{eff} / {total}",
        "scan_running_locked_file": "Executando como {user} (PID {pid}). Desbloqueie root para ver arquivos.",
        "scanning_metadata": "(Verificando metadados do diretório)",
        "archive_temp_suffix": "  (+{count} arquivo temporário)",
        "show_tabs_btn": "Mostrar registros, quarentena e ajustes ▾",
        "hide_tabs_btn": "Ocultar registros, quarentena e ajustes ▴",
        "tab_log": "Log ao vivo",
        "tab_threats": "Ameaças ({count})",
        "tab_quarantine": "Quarentena ({count})",
        "tab_history": "Histórico",
        "tab_schedule": "Agendamento",
        "tab_custom": "Avançado",
        "tab_db": "Base viral",
        "log_path_lbl": "Log:",
        "reload_log_btn": "Recarregar",
        "filter_lbl": "Filtro:",
        "log_filter_ph": "Filtrar linhas (FOUND, ERROR, OK)...",
        "autoscroll_chk": "Auto-rolagem",
        "stream_fd_chk": "Transmitir /proc/fd com -i ativo",
        "restart_verbose_btn": "Reiniciar sem -i (registrar tudo)",
        "quiet_log_hint": "Modo -i ativo: apenas ameaças e resumo vão para o log.",
        "col_file_path": "Caminho do arquivo",
        "col_threat_sig": "Assinatura",
        "col_status": "Status",
        "reveal_dolphin_btn": "Mostrar na pasta",
        "copy_path_btn": "Copiar caminho",
        "move_quarantine_btn": "Mover para quarentena",
        "delete_file_btn": "Excluir arquivo",
        "quarantine_note": "Arquivos em quarentena ficam isolados em /root/quarantine sem permissão de execução.",
        "col_q_name": "Arquivo",
        "col_q_orig": "Local original",
        "col_q_threat": "Ameaça",
        "col_q_date": "Data",
        "col_q_size": "Tamanho",
        "refresh_btn": "Atualizar",
        "restore_orig_btn": "Restaurar origem",
        "restore_to_btn": "Restaurar para...",
        "delete_perm_btn": "Excluir permanentemente",
        "col_h_date": "Data",
        "col_h_target": "Alvo",
        "col_h_duration": "Duração",
        "col_h_scanned": "Arquivos / Dados",
        "col_h_threats": "Ameaças",
        "col_h_result": "Resultado",
        "refresh_history_btn": "Atualizar histórico",
        "clear_history_btn": "Limpar histórico",
        "status_clean": "Limpo",
        "status_threats_found": "Ameaças",
        "sched_desc": "Agende verificações automáticas em segundo plano via systemd.",
        "sched_enable_chk": "Ativar verificações automáticas",
        "sched_status_lbl": "Status:",
        "sched_type_lbl": "Tipo:",
        "sched_freq_lbl": "Frequência:",
        "sched_day_lbl": "Dia:",
        "sched_time_lbl": "Horário:",
        "sched_info_lbl": "Temporizador:",
        "sched_type_quick": "Verificação rápida (Início e Downloads)",
        "sched_type_full": "Verificação completa (/)",
        "sched_freq_daily": "Diário",
        "sched_freq_weekly": "Semanal",
        "day_mon": "Segunda",
        "day_tue": "Terça",
        "day_wed": "Quarta",
        "day_thu": "Quinta",
        "day_fri": "Sexta",
        "day_sat": "Sábado",
        "day_sun": "Domingo",
        "sched_unlock_hint": "Desbloqueie root para ler ou alterar agendamentos.",
        "save_sched_btn": "Salvar agendamento",
        "sched_enabled": "Ativado",
        "sched_disabled": "Desativado",
        "sched_timer_status": "Status: {state}   |   Agendamento: {next_run}",
        "sched_saved_status": "Salvo! Status: {state}   |   {next_run}",
        "sched_saved_title": "Agendamento salvo",
        "sched_saved_msg": "Verificações automáticas: {state}.",
        "sched_read_err": "Erro ao ler agendamento: {err}",
        "sched_save_err": "Erro ao salvar",
        "adv_target_lbl": "Caminho:",
        "browse_btn": "Procurar...",
        "adv_options_lbl": "Opções:",
        "opt_recursive": "Recursivo (-r)",
        "opt_infected_only": "Modo silencioso (-i) [Desmarcado = log completo]",
        "opt_exclude_virtual": "Excluir /sys, /proc, /dev, /run",
        "opt_cross_fs": "Não cruzar sistemas de arquivos (--cross-fs=no)",
        "adv_maxsize_lbl": "Tamanho máx.:",
        "adv_action_lbl": "Ao detectar ameaça:",
        "action_report": "Apenas relatar (recomendado para /)",
        "action_move": "Mover para /root/quarantine",
        "action_copy": "Copiar para /root/quarantine",
        "adv_log_lbl": "Arquivo de log:",
        "adv_cmd_lbl": "Prévia do comando:",
        "start_custom_btn": "Iniciar verificação personalizada",
        "db_checking": "Verificando base ClamAV...",
        "freshclam_btn": "Atualizar assinaturas agora (freshclam)",
        "freshclam_updating": "Atualizando assinaturas...",
        "freshclam_ph": "A saída do freshclam aparecerá aqui...",
        "freshclam_running_msg": "Executando freshclam como root...\n",
        "freshclam_success": "SUCESSO",
        "freshclam_errors": "CONCLUÍDO COM ERROS",
        "tray_tip_idle": "Central ClamAV — Protegido ({count} ameaças)",
        "tray_tip_paused": "ClamAV — Pausado ({pct:.1f}%)",
        "tray_tip_scanning": "ClamAV — Verificando {pct:.1f}% (Restante {eta})",
        "tray_tip_running": "ClamAV — Em execução",
        "tray_open": "Abrir Central ClamAV",
        "tray_quick": "Iniciar verificação rápida",
        "tray_minimized_msg": "Em execução na bandeja do sistema.",
        "notify_threat_title": "Ameaça detectada!",
        "notify_scan_done_threats_title": "Verificação concluída — Ameaças!",
        "notify_scan_done_threats_msg": "{label} terminou com {count} ameaça(s).",
        "notify_scan_done_clean_title": "Verificação ClamAV concluída",
        "notify_scan_done_clean_msg": "{label} concluída sem ameaças.",
        "dlg_drop_title": "Verificar itens soltos",
        "dlg_drop_msg": "Iniciar verificação em:\n\n{preview}",
        "dlg_drop_more": "...e mais {count}",
        "dlg_sudo_title": "Desbloquear acesso root",
        "dlg_sudo_prompt": "Digite sua senha para desbloquear o acesso root:",
        "dlg_auth_failed": "Falha na autenticação",
        "dlg_polkit_failed": "Falha no Polkit",
        "dlg_root_req_title": "Permissão root necessária",
        "dlg_root_req_text": "Esta ação requer privilégios de administrador.",
        "dlg_root_req_info": "Desbloqueie o acesso root uma vez.",
        "dlg_unlock_pw_btn": "Senha...",
        "dlg_restart_title": "Reiniciar com log completo",
        "dlg_restart_msg": "Parar a verificação atual (-i) (PID {pid}) e reiniciar com log completo?",
        "dlg_restart_err": "Falha ao reiniciar",
        "dlg_sig_err": "Erro de sinal",
        "dlg_stop_title": "Parar verificação ClamAV",
        "dlg_stop_msg": "Parar a verificação ativa (PID {pid})?",
        "dlg_stop_err": "Erro ao parar",
        "dlg_prio_err": "Erro de prioridade",
        "dlg_no_sel_title": "Sem seleção",
        "dlg_no_sel_threat": "Selecione uma linha primeiro.",
        "dlg_no_sel_quar": "Selecione um arquivo em quarentena.",
        "dlg_quar_title": "Mover para quarentena",
        "dlg_quar_msg": "Mover '{path}' para {qdir}?",
        "dlg_quar_err": "Falha na quarentena",
        "dlg_del_title": "Excluir arquivo infectado",
        "dlg_del_msg": "Excluir permanentemente '{path}'?",
        "dlg_del_err": "Erro ao excluir",
        "dlg_restore_dir": "Escolher pasta de destino",
        "dlg_restore_title": "Restaurar arquivo",
        "dlg_restore_msg": "Restaurar '{name}' para:\n{dest}",
        "dlg_restore_ok_title": "Arquivo restaurado",
        "dlg_restore_ok_msg": "Restaurado para:\n{dest}",
        "dlg_restore_err": "Falha ao restaurar",
        "dlg_del_q_title": "Excluir da quarentena",
        "dlg_del_q_msg": "Excluir permanentemente '{name}'?",
        "dlg_clear_hist_title": "Limpar histórico",
        "dlg_clear_hist_msg": "Limpar o histórico salvo?",
        "dlg_browse_dir": "Selecionar pasta",
        "dlg_scan_running_title": "Verificação já ativa",
        "dlg_scan_running_msg": "Já existe uma verificação ativa. Iniciar outra?",
        "dlg_start_err": "Falha ao iniciar",
        "dlg_pick_title": "Selecionar item",
        "dlg_pick_msg": "Deseja verificar uma pasta ou um arquivo?",
        "dlg_pick_folder": "Escolher pasta...",
        "dlg_pick_file": "Escolher arquivo...",
        "dlg_pick_folder_title": "Selecionar pasta",
        "dlg_pick_file_title": "Selecionar arquivo",
        "label_quick_scan": "Verificação rápida (Início e Downloads)",
        "label_full_scan": "Verificação completa (/)",
        "label_custom_scan": "Personalizada ({target})",
        "label_dropped_one": "Solto ({name})",
        "label_dropped_many": "Soltos ({count} itens)",
        "status_found": "ENCONTRADO",
        "status_deleted": "Excluído",
        "status_quarantined": "Quarentena -> {dest}",
        "history_entries": "{count:,} registros",
        "history_see_log": "Ver resumo",
        "hero_missing_clamscan_title": "ClamAV não instalado",
        "hero_missing_clamscan_sub": "Binário 'clamscan' não encontrado. Instale clamav{extra}.",
        "hero_missing_db_title": "Base de vírus ausente",
        "hero_missing_db_sub": "Nenhuma assinatura (.cvd/.cld) em {db_dir}. Atualize antes de verificar.",
        "hero_update_db_btn": "Atualizar base",
        "db_state_ready": "BD pronto ({count} arquivos)",
        "db_state_missing": "Ausente (0 assinaturas em {db_dir})",
        "db_deps_ok": "Ferramentas auxiliares disponíveis",
        "db_deps_missing": "Ferramentas opcionais ausentes: {tools}",
        "db_status_full": "Versão ClamAV: {version}   |   freshclam: {freshclam_bin}\nBase de vírus ({db_dir}): {db_state}\nAtualizador automático: {service}   |   {deps_note}",
        "meta_line_full": "{db_state}  •  Motor {version}  •  Atualizações: {service}{warn}",
        "idle_col_status": "Status",
        "idle_col_last_scan": "Última verificação",
        "idle_col_sigs": "Assinaturas",
        "idle_col_sched": "Agendado",
        "idle_val_protected": "Protegido",
        "idle_val_attention": "Ação necessária",
        "idle_val_missing_clam": "Não instalado",
        "idle_val_no_scans": "Sem histórico",
        "idle_val_today": "Hoje",
        "idle_val_threats_n": "{n} ameaças",
        "idle_val_up_to_date": "Atualizadas",
        "idle_val_sigs_missing": "Ausentes",
        "idle_val_not_sched": "Não agendado",
        "idle_val_daily_at": "Diário {time}",
        "clamscan_missing_tip": "Desativado: 'clamscan' não instalado.",
        "freshclam_missing_tip": "Desativado: 'freshclam' não instalado.",
        "installed_word": "Instalado",
        "missing_word": "Ausente",
        "tile_quick_title": "Verificação rápida",
        "tile_quick_sub": "Downloads e Início • ~2 min",
        "tile_full_title": "Verificação completa",
        "tile_full_sub": "PC inteiro",
        "tile_pick_title": "Arquivo ou pasta",
        "tile_pick_sub": "Arraste itens aqui",
        "also_missing_suffix": " (também ausente: {items})",
        "history_system_log": "Sistema / Log",
        "svc_active": "Ativo",
        "svc_inactive": "Inativo",
        "log_path_tip": "Logs gerenciados pelo root devem ficar sob /var/log/.",
        "log_inspect_err": "Aviso do log: {err}",
        "polkit_source_hint": "Nota: Polkit sem senha ativa após instalação do pacote do sistema.",
        "unknown_word": "Desconhecido",
    },
    "zh": {
        "window_title": "ClamAV 安全中心",
        "app_title": "ClamAV 安全中心",
        "detecting_clamav": "正在检测 ClamAV...",
        "root_active_badge": "●  受保护访问已启用",
        "user_mode_badge": "●  用户模式已启用",
        "user_mode_btn": "用户模式",
        "continue_user_mode_btn": "以用户模式继续",
        "quit_btn": "退出",
        "about_btn": "关于",
        "dlg_about_title": "关于 ClamAV 安全中心",
        "about_desc": "面向 Linux 的开源桌面安全控制中心，提供 ClamAV 病毒扫描、隔离管理与后台定时防护。",
        "about_version_lbl": "版本：",
        "about_creator_lbl": "作者：",
        "about_license_lbl": "许可证：",
        "about_github_lbl": "GitHub：",
        "auth_banner_text": "解锁一次管理员权限，即可启用免密扫描、隔离与定时任务。",
        "unlock_sudo_btn": "密码解锁...",
        "unlock_polkit_btn": "Polkit 解锁",
        "waiting_polkit": "正在等待 Polkit...",
        "hero_threats_title": "需要处理 — 检测到 {count} 个威胁",
        "hero_threats_sub": "请打开“检测到的威胁”标签页进行隔离或删除。",
        "hero_review_btn": "查看威胁",
        "hero_protected_title": "您的计算机已受保护",
        "hero_protected_sub": "未检测到威胁，随时可进行扫描。",
        "hero_paused_title": "扫描已暂停{pct}",
        "hero_paused_sub": "准备好后点击“继续”以恢复扫描。",
        "hero_scanning_title": "正在扫描计算机 — {pct:.1f}%",
        "hero_scanning_sub": "预计剩余: {eta}  •  当前文件: {file}",
        "hero_bg_title": "扫描正在后台运行",
        "hero_bg_sub": "解锁上方管理员权限即可查看实时百分比和当前文件。",
        "drop_hint": "提示：将文件或文件夹拖放到此处即可扫描",
        "card_status_title": "扫描状态",
        "card_cpu_title": "已用时间",
        "card_io_title": "内存 / 读取",
        "card_threats_title": "发现威胁",
        "state_running": "运行中",
        "state_paused": "已暂停",
        "idle_word": "空闲",
        "clean_so_far": "安全",
        "action_recommended": "建议处理",
        "pid_owner": "PID {pid} | 用户: {user}",
        "bg_mode_label": "后台模式",
        "normal_speed_label": "正常速度",
        "unlock_live_io": "解锁权限查看读取速度",
        "ram_value": "内存 {rss}",
        "read_value": "已读 {amount}",
        "io_sub": "{speed} | 磁盘 {disk} | 内存 {rss}",
        "ctrl_box_title": "活动扫描进度与控制",
        "progress_label": "进度:",
        "eta_prefix": "剩余时间: {eta}",
        "eta_paused": "已暂停",
        "eta_unlock_root": "需管理员",
        "eta_finishing": "即将完成...",
        "eta_calculating": "计算中...",
        "no_active_scan": "无活动扫描",
        "no_active_scan_running": "当前没有正在运行的扫描。",
        "currently_checking": "正在检查:",
        "pause_scan": "暂停",
        "resume_scan": "继续",
        "stop_scan": "停止",
        "bg_mode_chk": "后台模式 (保持系统流畅)",
        "bg_mode_tip": "以低 CPU 和磁盘优先级运行扫描。",
        "progress_paused_unlock": "已暂停 (需管理员权限显示 %)",
        "progress_pct_paused": "{pct:.1f}% (已暂停)",
        "progress_sub_unlock_ready": "目标: {elig_files:,} 个可扫描文件 ({elig_bytes} <= {max_sz}; 共 {all_files:,} / {all_bytes})",
        "progress_sub_unlock_counting": "初始估算: {statvfs} (正在统计文件: {all_files:,}...)",
        "progress_sub_unlock_est": "初始估算: {statvfs}",
        "progress_sub_accurate": "精确统计: ~{eff} / {total} ({elig_files:,} <= {max_sz}; 共 {all_files:,} / {all_bytes})",
        "progress_sub_refining": "初步估算: ~{eff} / {total} (统计中: {all_files:,}...)",
        "progress_sub_est": "初步估算: ~{eff} / {total}",
        "scan_running_locked_file": "正在以 {user} 身份运行 (PID {pid})。解锁权限以查看文件。",
        "scanning_metadata": "(正在检查目录元数据)",
        "archive_temp_suffix": "  (+{count} 压缩包临时文件)",
        "show_tabs_btn": "显示日志、隔离区和设置 ▾",
        "hide_tabs_btn": "隐藏日志、隔离区和设置 ▴",
        "tab_log": "实时日志",
        "tab_threats": "威胁 ({count})",
        "tab_quarantine": "隔离区 ({count})",
        "tab_history": "历史记录",
        "tab_schedule": "自动扫描",
        "tab_custom": "高级扫描",
        "tab_db": "病毒库",
        "log_path_lbl": "日志路径:",
        "reload_log_btn": "刷新日志",
        "filter_lbl": "筛选:",
        "log_filter_ph": "筛选行 (FOUND, ERROR, OK)...",
        "autoscroll_chk": "自动滚动",
        "stream_fd_chk": "-i 模式下显示 /proc/fd 实时文件",
        "restart_verbose_btn": "不使用 -i 重启扫描",
        "quiet_log_hint": "当前扫描使用 -i，仅记录威胁和摘要。实时文件活动见下方。",
        "col_file_path": "文件路径",
        "col_threat_sig": "威胁特征",
        "col_status": "状态",
        "reveal_dolphin_btn": "在文件夹中显示",
        "copy_path_btn": "复制路径",
        "move_quarantine_btn": "移入隔离区",
        "delete_file_btn": "删除文件",
        "quarantine_note": "隔离文件保存在 /root/quarantine 且无执行权限，可恢复或永久删除。",
        "col_q_name": "文件名",
        "col_q_orig": "原位置",
        "col_q_threat": "威胁",
        "col_q_date": "日期",
        "col_q_size": "大小",
        "refresh_btn": "刷新",
        "restore_orig_btn": "恢复到原位置",
        "restore_to_btn": "恢复到...",
        "delete_perm_btn": "永久删除",
        "col_h_date": "完成日期",
        "col_h_target": "目标",
        "col_h_duration": "耗时",
        "col_h_scanned": "扫描数 / 大小",
        "col_h_threats": "威胁",
        "col_h_result": "结果",
        "refresh_history_btn": "刷新历史",
        "clear_history_btn": "清空历史",
        "status_clean": "安全",
        "status_threats_found": "发现威胁",
        "sched_desc": "使用 systemd 定时器安排自动后台防病毒扫描。",
        "sched_enable_chk": "启用定时自动扫描",
        "sched_status_lbl": "状态:",
        "sched_type_lbl": "扫描类型:",
        "sched_freq_lbl": "频率:",
        "sched_day_lbl": "星期:",
        "sched_time_lbl": "时间:",
        "sched_info_lbl": "定时器信息:",
        "sched_type_quick": "快速扫描 (主目录与下载)",
        "sched_type_full": "全盘扫描 (/)",
        "sched_freq_daily": "每天",
        "sched_freq_weekly": "每周",
        "day_mon": "周一",
        "day_tue": "周二",
        "day_wed": "周三",
        "day_thu": "周四",
        "day_fri": "周五",
        "day_sat": "周六",
        "day_sun": "周日",
        "sched_unlock_hint": "解锁管理员权限以查看或修改定时任务。",
        "save_sched_btn": "保存设置",
        "sched_enabled": "已启用",
        "sched_disabled": "已禁用",
        "sched_timer_status": "状态: {state}   |   计划: {next_run}",
        "sched_saved_status": "已保存! 状态: {state}   |   {next_run}",
        "sched_saved_title": "计划已保存",
        "sched_saved_msg": "自动扫描: {state}。",
        "sched_read_err": "无法读取定时任务: {err}",
        "sched_save_err": "保存失败",
        "adv_target_lbl": "目标路径:",
        "browse_btn": "浏览...",
        "adv_options_lbl": "选项:",
        "opt_recursive": "递归扫描 (-r)",
        "opt_infected_only": "静默模式：仅记录感染文件 (-i)",
        "opt_exclude_virtual": "排除 /sys, /proc, /dev, /run",
        "opt_cross_fs": "不跨文件系统 (--cross-fs=no)",
        "adv_maxsize_lbl": "最大文件大小:",
        "adv_action_lbl": "发现威胁时:",
        "action_report": "仅报告 (推荐用于 /)",
        "action_move": "移动到 /root/quarantine",
        "action_copy": "复制到 /root/quarantine",
        "adv_log_lbl": "日志文件:",
        "adv_cmd_lbl": "命令预览:",
        "start_custom_btn": "开始自定义扫描",
        "db_checking": "正在检查 ClamAV 病毒库状态...",
        "freshclam_btn": "立即更新病毒库 (freshclam)",
        "freshclam_updating": "正在更新病毒库...",
        "freshclam_ph": "freshclam 更新输出将显示在此处...",
        "freshclam_running_msg": "正在以 root 身份运行 freshclam，请稍候...\n",
        "freshclam_success": "成功",
        "freshclam_errors": "完成但有错误",
        "tray_tip_idle": "ClamAV 安全中心 — 已受保护 ({count} 威胁)",
        "tray_tip_paused": "ClamAV — 已暂停 ({pct:.1f}%)",
        "tray_tip_scanning": "ClamAV — 扫描中 {pct:.1f}% (剩余 {eta})",
        "tray_tip_running": "ClamAV — 正在扫描",
        "tray_open": "打开 ClamAV 安全中心",
        "tray_quick": "开始快速扫描",
        "tray_minimized_msg": "已在系统托盘运行。",
        "notify_threat_title": "检测到威胁!",
        "notify_scan_done_threats_title": "扫描完成 — 发现威胁!",
        "notify_scan_done_threats_msg": "{label} 完成，发现 {count} 个威胁。",
        "notify_scan_done_clean_title": "ClamAV 扫描完成",
        "notify_scan_done_clean_msg": "{label} 完成，未发现威胁。",
        "dlg_drop_title": "扫描拖放的项目",
        "dlg_drop_msg": "开始扫描以下路径:\n\n{preview}",
        "dlg_drop_more": "...以及另外 {count} 项",
        "dlg_sudo_title": "解锁管理员权限",
        "dlg_sudo_prompt": "输入密码以解锁 ClamAV 管理员权限:",
        "dlg_auth_failed": "验证失败",
        "dlg_polkit_failed": "Polkit 验证失败",
        "dlg_root_req_title": "需要管理员权限",
        "dlg_root_req_text": "此操作需要管理员权限。",
        "dlg_root_req_info": "请先解锁一次管理员权限。",
        "dlg_unlock_pw_btn": "密码解锁...",
        "dlg_restart_title": "使用完整输出重启扫描",
        "dlg_restart_msg": "停止当前 (-i) 扫描 (PID {pid}) 并以完整日志重启？",
        "dlg_restart_err": "重启失败",
        "dlg_sig_err": "信号错误",
        "dlg_stop_title": "停止 ClamAV 扫描",
        "dlg_stop_msg": "确定停止当前扫描 (PID {pid})？",
        "dlg_stop_err": "停止失败",
        "dlg_prio_err": "优先级设置失败",
        "dlg_no_sel_title": "未选择",
        "dlg_no_sel_threat": "请先选择一行威胁记录。",
        "dlg_no_sel_quar": "请先选择隔离区中的文件。",
        "dlg_quar_title": "移入隔离区",
        "dlg_quar_msg": "将 '{path}' 移动到 {qdir}？",
        "dlg_quar_err": "隔离失败",
        "dlg_del_title": "删除受感染文件",
        "dlg_del_msg": "永久删除 '{path}'？\n此操作不可撤销。",
        "dlg_del_err": "删除失败",
        "dlg_restore_dir": "选择恢复目标文件夹",
        "dlg_restore_title": "恢复隔离文件",
        "dlg_restore_msg": "将 '{name}' 恢复到:\n{dest}",
        "dlg_restore_ok_title": "文件已恢复",
        "dlg_restore_ok_msg": "已恢复到:\n{dest}",
        "dlg_restore_err": "恢复失败",
        "dlg_del_q_title": "删除隔离文件",
        "dlg_del_q_msg": "从隔离区永久删除 '{name}'？",
        "dlg_clear_hist_title": "清空历史",
        "dlg_clear_hist_msg": "确定清空已保存的历史记录？",
        "dlg_browse_dir": "选择目录",
        "dlg_scan_running_title": "已有扫描在运行",
        "dlg_scan_running_msg": "已有扫描在进行中，是否仍要启动新扫描？",
        "dlg_start_err": "启动扫描失败",
        "dlg_pick_title": "选择扫描对象",
        "dlg_pick_msg": "您要扫描文件夹还是单个文件？",
        "dlg_pick_folder": "选择文件夹...",
        "dlg_pick_file": "选择文件...",
        "dlg_pick_folder_title": "选择文件夹",
        "dlg_pick_file_title": "选择文件",
        "label_quick_scan": "快速扫描 (主目录与下载)",
        "label_full_scan": "全盘系统扫描 (/)",
        "label_custom_scan": "自定义扫描 ({target})",
        "label_dropped_one": "已拖放 ({name})",
        "label_dropped_many": "已拖放 ({count} 项)",
        "status_found": "已发现",
        "status_deleted": "已删除",
        "status_quarantined": "已隔离 -> {dest}",
        "history_entries": "{count:,} 条",
        "history_see_log": "查看日志摘要",
        "hero_missing_clamscan_title": "未安装 ClamAV 扫描器",
        "hero_missing_clamscan_sub": "未找到 'clamscan'。请安装 clamav{extra}。",
        "hero_missing_db_title": "缺少病毒库 — 需要更新",
        "hero_missing_db_sub": "在 {db_dir} 中未找到特征库 (.cvd/.cld)，请先更新。",
        "hero_update_db_btn": "更新病毒库",
        "db_state_ready": "病毒库就绪 ({count} 个文件)",
        "db_state_missing": "缺失 ({db_dir} 中无特征库)",
        "db_deps_ok": "所有辅助工具均可用",
        "db_deps_missing": "缺少可选工具: {tools}",
        "db_status_full": "ClamAV 版本: {version}   |   freshclam: {freshclam_bin}\n病毒库 ({db_dir}): {db_state}\n自动更新服务: {service}   |   {deps_note}",
        "meta_line_full": "{db_state}  •  引擎 {version}  •  自动更新: {service}{warn}",
        "idle_col_status": "状态",
        "idle_col_last_scan": "上次扫描",
        "idle_col_sigs": "病毒特征库",
        "idle_col_sched": "定时扫描",
        "idle_val_protected": "已受保护",
        "idle_val_attention": "需要注意",
        "idle_val_missing_clam": "未安装",
        "idle_val_no_scans": "暂无记录",
        "idle_val_today": "今天",
        "idle_val_threats_n": "{n} 威胁",
        "idle_val_up_to_date": "已是最新",
        "idle_val_sigs_missing": "缺失",
        "idle_val_not_sched": "未计划",
        "idle_val_daily_at": "每天 {time}",
        "clamscan_missing_tip": "已禁用：未安装 'clamscan'。",
        "freshclam_missing_tip": "已禁用：未安装 'freshclam'。",
        "installed_word": "已安装",
        "missing_word": "缺失",
        "tile_quick_title": "快速扫描",
        "tile_quick_sub": "下载与主目录 • ~2 分钟",
        "tile_full_title": "全盘扫描",
        "tile_full_sub": "整个系统",
        "tile_pick_title": "检查文件或文件夹",
        "tile_pick_sub": "拖放项目到此处",
        "also_missing_suffix": " (同时缺少: {items})",
        "history_system_log": "系统 / 日志扫描",
        "svc_active": "运行中",
        "svc_inactive": "未启用",
        "log_path_tip": "Root 管理的日志必须位于 /var/log/ 下。",
        "log_inspect_err": "日志提示: {err}",
        "polkit_source_hint": "提示：安装为系统软件包后将自动启用免密 Polkit 解锁。",
        "unknown_word": "未知",
    },
    "ja": {
        "window_title": "ClamAV セキュリティセンター",
        "app_title": "ClamAV セキュリティセンター",
        "detecting_clamav": "ClamAV を検出中...",
        "root_active_badge": "●  保護アクセス有効",
        "user_mode_badge": "●  ユーザーモード有効",
        "user_mode_btn": "ユーザーモード",
        "continue_user_mode_btn": "ユーザーモードで続行",
        "quit_btn": "終了",
        "about_btn": "概要",
        "dlg_about_title": "ClamAV セキュリティセンターについて",
        "about_desc": "ClamAV スキャン、隔離、定期バックグラウンド保護を行うオープンソースの Linux デスクトップ管理ツールです。",
        "about_version_lbl": "バージョン:",
        "about_creator_lbl": "作成者:",
        "about_license_lbl": "ライセンス:",
        "about_github_lbl": "GitHub:",
        "auth_banner_text": "管理者アクセスを解除すると、隔離やスケジュール管理が有効になります。",
        "unlock_sudo_btn": "パスワード解除...",
        "unlock_polkit_btn": "Polkit で解除",
        "waiting_polkit": "Polkit を待機中...",
        "hero_threats_title": "対応が必要 — {count} 件の脅威を検出",
        "hero_threats_sub": "「検出された脅威」タブから隔離または削除を行ってください。",
        "hero_review_btn": "脅威を確認",
        "hero_protected_title": "PC は保護されています",
        "hero_protected_sub": "脅威は検出されていません。いつでもスキャンできます。",
        "hero_paused_title": "スキャン一時停止中{pct}",
        "hero_paused_sub": "続行する準備ができたら「再開」をクリックしてください。",
        "hero_scanning_title": "システムをスキャン中 — {pct:.1f}%",
        "hero_scanning_sub": "残り時間: {eta}  •  確認中: {file}",
        "hero_bg_title": "バックグラウンドでスキャン中",
        "hero_bg_sub": "上の管理者権限を解除すると進捗率と現在のファイルを確認できます。",
        "drop_hint": "ヒント: ファイルやフォルダをここにドロップしてスキャン",
        "card_status_title": "ステータス",
        "card_cpu_title": "経過 / 状態",
        "card_io_title": "メモリ / 読込",
        "card_threats_title": "検出数",
        "state_running": "実行中",
        "state_paused": "一時停止",
        "idle_word": "待機",
        "clean_so_far": "安全",
        "action_recommended": "対処推奨",
        "pid_owner": "PID {pid} | ユーザー: {user}",
        "bg_mode_label": "バックグラウンド",
        "normal_speed_label": "通常速度",
        "unlock_live_io": "読込速度表示には権限が必要",
        "ram_value": "RAM {rss}",
        "read_value": "{amount} 読込",
        "io_sub": "{speed} | ディスク {disk} | RAM {rss}",
        "ctrl_box_title": "アクティブスキャンの進捗と制御",
        "progress_label": "進捗:",
        "eta_prefix": "残り: {eta}",
        "eta_paused": "一時停止",
        "eta_unlock_root": "要権限",
        "eta_finishing": "完了処理中...",
        "eta_calculating": "計算中...",
        "no_active_scan": "アクティブなスキャンなし",
        "no_active_scan_running": "現在実行中のスキャンはありません。",
        "currently_checking": "確認中:",
        "pause_scan": "一時停止",
        "resume_scan": "再開",
        "stop_scan": "停止",
        "bg_mode_chk": "バックグラウンドモード (PC を快適に保つ)",
        "bg_mode_tip": "低い CPU とディスク優先度でスキャンを実行します。",
        "progress_paused_unlock": "一時停止 (要 root で % 表示)",
        "progress_pct_paused": "{pct:.1f}% (一時停止)",
        "progress_sub_unlock_ready": "対象: {elig_files:,} ファイル ({elig_bytes} <= {max_sz}; 計 {all_files:,} / {all_bytes})",
        "progress_sub_unlock_counting": "初期見積: {statvfs} (集計中: {all_files:,}...)",
        "progress_sub_unlock_est": "初期見積: {statvfs}",
        "progress_sub_accurate": "正確集計: ~{eff} / {total} ({elig_files:,} <= {max_sz}; 計 {all_files:,} / {all_bytes})",
        "progress_sub_refining": "初期見積: ~{eff} / {total} (集計中: {all_files:,}...)",
        "progress_sub_est": "初期見積: ~{eff} / {total}",
        "scan_running_locked_file": "{user} として実行中 (PID {pid})。ファイル表示には管理者解除が必要です。",
        "scanning_metadata": "(ディレクトリ情報を確認中)",
        "archive_temp_suffix": "  (+{count} 一時ファイル)",
        "show_tabs_btn": "ログ・隔離・設定を表示 ▾",
        "hide_tabs_btn": "ログ・隔離・設定を非表示 ▴",
        "tab_log": "ライブログ",
        "tab_threats": "脅威 ({count})",
        "tab_quarantine": "隔離 ({count})",
        "tab_history": "履歴",
        "tab_schedule": "スケジュール",
        "tab_custom": "詳細スキャン",
        "tab_db": "定義ファイル",
        "log_path_lbl": "ログ:",
        "reload_log_btn": "再読込",
        "filter_lbl": "フィルタ:",
        "log_filter_ph": "行を絞り込み (FOUND, ERROR, OK)...",
        "autoscroll_chk": "自動スクロール",
        "stream_fd_chk": "-i 有効時に /proc/fd を表示",
        "restart_verbose_btn": "-i なしで再起動",
        "quiet_log_hint": "-i モードでは脅威と概要のみログに出力されます。",
        "col_file_path": "ファイルパス",
        "col_threat_sig": "脅威名",
        "col_status": "状態",
        "reveal_dolphin_btn": "フォルダを開く",
        "copy_path_btn": "パスをコピー",
        "move_quarantine_btn": "隔離へ移動",
        "delete_file_btn": "削除",
        "quarantine_note": "隔離されたファイルは /root/quarantine に実行権限なしで保存されます。",
        "col_q_name": "ファイル名",
        "col_q_orig": "元の場所",
        "col_q_threat": "脅威",
        "col_q_date": "日付",
        "col_q_size": "サイズ",
        "refresh_btn": "更新",
        "restore_orig_btn": "元の場所に戻す",
        "restore_to_btn": "指定フォルダに戻す...",
        "delete_perm_btn": "完全削除",
        "col_h_date": "完了日時",
        "col_h_target": "対象",
        "col_h_duration": "時間",
        "col_h_scanned": "スキャン数 / 容量",
        "col_h_threats": "脅威",
        "col_h_result": "結果",
        "refresh_history_btn": "履歴を更新",
        "clear_history_btn": "履歴を消去",
        "status_clean": "安全",
        "status_threats_found": "脅威あり",
        "sched_desc": "systemd タイマーによる定期自動スキャンを設定します。",
        "sched_enable_chk": "自動スケジュールを有効にする",
        "sched_status_lbl": "状態:",
        "sched_type_lbl": "種類:",
        "sched_freq_lbl": "頻度:",
        "sched_day_lbl": "曜日:",
        "sched_time_lbl": "時刻:",
        "sched_info_lbl": "タイマー:",
        "sched_type_quick": "クイックスキャン (ホームとダウンロード)",
        "sched_type_full": "フルスキャン (/)",
        "sched_freq_daily": "毎日",
        "sched_freq_weekly": "毎週",
        "day_mon": "月曜日",
        "day_tue": "火曜日",
        "day_wed": "水曜日",
        "day_thu": "木曜日",
        "day_fri": "金曜日",
        "day_sat": "土曜日",
        "day_sun": "日曜日",
        "sched_unlock_hint": "スケジュール変更には管理者権限が必要です。",
        "save_sched_btn": "保存",
        "sched_enabled": "有効",
        "sched_disabled": "無効",
        "sched_timer_status": "状態: {state}   |   予定: {next_run}",
        "sched_saved_status": "保存しました! 状態: {state}   |   {next_run}",
        "sched_saved_title": "設定を保存",
        "sched_saved_msg": "自動スキャン: {state}",
        "sched_read_err": "読込エラー: {err}",
        "sched_save_err": "保存失敗",
        "adv_target_lbl": "対象パス:",
        "browse_btn": "参照...",
        "adv_options_lbl": "オプション:",
        "opt_recursive": "再帰的 (-r)",
        "opt_infected_only": "感染のみログ記録 (-i)",
        "opt_exclude_virtual": "/sys, /proc, /dev, /run を除外",
        "opt_cross_fs": "単一ファイルシステム (--cross-fs=no)",
        "adv_maxsize_lbl": "最大サイズ:",
        "adv_action_lbl": "検出時の動作:",
        "action_report": "報告のみ (/ 推奨)",
        "action_move": "/root/quarantine へ移動",
        "action_copy": "/root/quarantine へコピー",
        "adv_log_lbl": "ログファイル:",
        "adv_cmd_lbl": "コマンドプレビュー:",
        "start_custom_btn": "詳細スキャンを開始",
        "db_checking": "ClamAV データベースを確認中...",
        "freshclam_btn": "定義ファイルを今すぐ更新 (freshclam)",
        "freshclam_updating": "更新中...",
        "freshclam_ph": "freshclam の出力がここに表示されます...",
        "freshclam_running_msg": "root として freshclam を実行しています...\n",
        "freshclam_success": "成功",
        "freshclam_errors": "エラーありで完了",
        "tray_tip_idle": "ClamAV セキュリティセンター — 保護中 ({count} 件の脅威)",
        "tray_tip_paused": "ClamAV — 一時停止 ({pct:.1f}%)",
        "tray_tip_scanning": "ClamAV — スキャン中 {pct:.1f}% (残り {eta})",
        "tray_tip_running": "ClamAV — 実行中",
        "tray_open": "ClamAV を開く",
        "tray_quick": "クイックスキャンを開始",
        "tray_minimized_msg": "システムトレイで動作しています。",
        "notify_threat_title": "脅威を検出!",
        "notify_scan_done_threats_title": "スキャン完了 — 脅威検出!",
        "notify_scan_done_threats_msg": "{label} 完了: {count} 件の脅威。",
        "notify_scan_done_clean_title": "ClamAV スキャン完了",
        "notify_scan_done_clean_msg": "{label} は問題なく完了しました。",
        "dlg_drop_title": "ドロップ項目のスキャン",
        "dlg_drop_msg": "次をスキャンしますか?\n\n{preview}",
        "dlg_drop_more": "...他 {count} 件",
        "dlg_sudo_title": "管理者権限の解除",
        "dlg_sudo_prompt": "ClamAV の管理者アクセスを解除するパスワードを入力:",
        "dlg_auth_failed": "認証に失敗しました",
        "dlg_polkit_failed": "Polkit 認証に失敗しました",
        "dlg_root_req_title": "管理者権限が必要",
        "dlg_root_req_text": "この操作には管理者権限が必要です。",
        "dlg_root_req_info": "一度管理者権限を解除してください。",
        "dlg_unlock_pw_btn": "パスワード...",
        "dlg_restart_title": "詳細ログで再起動",
        "dlg_restart_msg": "現在の -i スキャン (PID {pid}) を停止して全記録で再起動しますか？",
        "dlg_restart_err": "再起動に失敗しました",
        "dlg_sig_err": "シグナルエラー",
        "dlg_stop_title": "スキャンを停止",
        "dlg_stop_msg": "実行中のスキャン (PID {pid}) を停止しますか？",
        "dlg_stop_err": "停止に失敗しました",
        "dlg_prio_err": "優先度エラー",
        "dlg_no_sel_title": "未選択",
        "dlg_no_sel_threat": "行を選択してください。",
        "dlg_no_sel_quar": "隔離ファイルを選択してください。",
        "dlg_quar_title": "隔離へ移動",
        "dlg_quar_msg": "'{path}' を {qdir} へ移動しますか？",
        "dlg_quar_err": "隔離に失敗しました",
        "dlg_del_title": "感染ファイルを削除",
        "dlg_del_msg": "'{path}' を完全に削除しますか？",
        "dlg_del_err": "削除に失敗しました",
        "dlg_restore_dir": "復元先フォルダを選択",
        "dlg_restore_title": "隔離ファイルを復元",
        "dlg_restore_msg": "'{name}' を次へ復元:\n{dest}",
        "dlg_restore_ok_title": "復元完了",
        "dlg_restore_ok_msg": "復元先:\n{dest}",
        "dlg_restore_err": "復元に失敗しました",
        "dlg_del_q_title": "隔離から削除",
        "dlg_del_q_msg": "'{name}' を完全に削除しますか？",
        "dlg_clear_hist_title": "履歴を消去",
        "dlg_clear_hist_msg": "保存済みの履歴を消去しますか？",
        "dlg_browse_dir": "フォルダを選択",
        "dlg_scan_running_title": "スキャン実行中",
        "dlg_scan_running_msg": "既にスキャンが実行中です。新しく開始しますか？",
        "dlg_start_err": "開始に失敗しました",
        "dlg_pick_title": "対象を選択",
        "dlg_pick_msg": "フォルダとファイルのどちらをスキャンしますか？",
        "dlg_pick_folder": "フォルダを選択...",
        "dlg_pick_file": "ファイルを選択...",
        "dlg_pick_folder_title": "フォルダを選択",
        "dlg_pick_file_title": "ファイルを選択",
        "label_quick_scan": "クイックスキャン (ホーム & ダウンロード)",
        "label_full_scan": "フルスキャン (/)",
        "label_custom_scan": "カスタムスキャン ({target})",
        "label_dropped_one": "ドロップ ({name})",
        "label_dropped_many": "ドロップ ({count} 件)",
        "status_found": "検出",
        "status_deleted": "削除済み",
        "status_quarantined": "隔離済み -> {dest}",
        "history_entries": "{count:,} 件",
        "history_see_log": "ログ概要を参照",
        "hero_missing_clamscan_title": "ClamAV が未インストールです",
        "hero_missing_clamscan_sub": "'clamscan' が見つかりません。clamav をインストールしてください{extra}。",
        "hero_missing_db_title": "ウイルス定義ファイルがありません",
        "hero_missing_db_sub": "{db_dir} に署名ファイル (.cvd/.cld) がありません。更新してください。",
        "hero_update_db_btn": "定義を更新",
        "db_state_ready": "DB 準備完了 ({count} ファイル)",
        "db_state_missing": "未検出 ({db_dir} に 0 件)",
        "db_deps_ok": "補助ツール利用可能",
        "db_deps_missing": "不足ツール: {tools}",
        "db_status_full": "ClamAV: {version}   |   freshclam: {freshclam_bin}\nウイルス DB ({db_dir}): {db_state}\n自動更新: {service}   |   {deps_note}",
        "meta_line_full": "{db_state}  •  エンジン {version}  •  自動更新: {service}{warn}",
        "idle_col_status": "状態",
        "idle_col_last_scan": "前回のスキャン",
        "idle_col_sigs": "定義ファイル",
        "idle_col_sched": "定期スキャン",
        "idle_val_protected": "保護済み",
        "idle_val_attention": "要確認",
        "idle_val_missing_clam": "未導入",
        "idle_val_no_scans": "履歴なし",
        "idle_val_today": "今日",
        "idle_val_threats_n": "脅威 {n} 件",
        "idle_val_up_to_date": "最新",
        "idle_val_sigs_missing": "不足",
        "idle_val_not_sched": "未設定",
        "idle_val_daily_at": "毎日 {time}",
        "clamscan_missing_tip": "'clamscan' がインストールされていないため無効です。",
        "freshclam_missing_tip": "'freshclam' がインストールされていないため無効です。",
        "installed_word": "導入済み",
        "missing_word": "不足",
        "tile_quick_title": "クイックスキャン",
        "tile_quick_sub": "ダウンロード & ホーム • ~2分",
        "tile_full_title": "フルシステムスキャン",
        "tile_full_sub": "PC 全体",
        "tile_pick_title": "ファイル・フォルダ",
        "tile_pick_sub": "ここにドラッグ & ドロップ",
        "also_missing_suffix": " (その他不足: {items})",
        "history_system_log": "システム / ログ",
        "svc_active": "有効",
        "svc_inactive": "無効",
        "log_path_tip": "root 管理ログは /var/log/ 配下に置く必要があります。",
        "log_inspect_err": "ログ通知: {err}",
        "polkit_source_hint": "注: パッケージ導入後は Polkit によるパスワードなし解除が有効になります。",
        "unknown_word": "不明",
    },
    "ru": {
        "window_title": "Центр безопасности ClamAV",
        "app_title": "Центр безопасности ClamAV",
        "detecting_clamav": "Поиск ClamAV...",
        "root_active_badge": "●  Защищённый доступ активен",
        "user_mode_badge": "●  Режим пользователя",
        "user_mode_btn": "Без root",
        "continue_user_mode_btn": "Продолжить без root",
        "quit_btn": "Выход",
        "about_btn": "О программе",
        "dlg_about_title": "О программе Центр безопасности ClamAV",
        "about_desc": "Центр управления с открытым исходным кодом для Linux: проверка ClamAV, карантин и фоновая защита по расписанию.",
        "about_version_lbl": "Версия:",
        "about_creator_lbl": "Автор:",
        "about_license_lbl": "Лицензия:",
        "about_github_lbl": "GitHub:",
        "auth_banner_text": "Откройте root-доступ один раз для проверок, карантина и расписания.",
        "unlock_sudo_btn": "Пароль...",
        "unlock_polkit_btn": "Через Polkit",
        "waiting_polkit": "Ожидание Polkit...",
        "hero_threats_title": "Требуется действие — угроз: {count}",
        "hero_threats_sub": "Откройте вкладку «Угрозы» для помещения в карантин или удаления.",
        "hero_review_btn": "Проверить",
        "hero_protected_title": "Ваш компьютер защищён",
        "hero_protected_sub": "Угроз не обнаружено. Готов к проверке в любое время.",
        "hero_paused_title": "Проверка на паузе{pct}",
        "hero_paused_sub": "Нажмите «Продолжить», когда будете готовы.",
        "hero_scanning_title": "Идёт проверка — {pct:.1f}%",
        "hero_scanning_sub": "Осталось: {eta}  •  Файл: {file}",
        "hero_bg_title": "Проверка в фоне",
        "hero_bg_sub": "Разблокируйте root выше, чтобы видеть процент и текущий файл.",
        "drop_hint": "Перетащите файлы или папки сюда",
        "card_status_title": "Статус",
        "card_cpu_title": "Время / Режим",
        "card_io_title": "ОЗУ / Чтение",
        "card_threats_title": "Угрозы",
        "state_running": "ПРОВЕРКА",
        "state_paused": "ПАУЗА",
        "idle_word": "Простой",
        "clean_so_far": "Угроз нет",
        "action_recommended": "Нужно действие",
        "pid_owner": "PID {pid} | Владелец: {user}",
        "bg_mode_label": "Фоновый режим",
        "normal_speed_label": "Обычная",
        "unlock_live_io": "Нужен root для МБ/с",
        "ram_value": "ОЗУ {rss}",
        "read_value": "Прочитано {amount}",
        "io_sub": "{speed} | Диск {disk} | ОЗУ {rss}",
        "ctrl_box_title": "Прогресс и управление проверкой",
        "progress_label": "Прогресс:",
        "eta_prefix": "Осталось: {eta}",
        "eta_paused": "Пауза",
        "eta_unlock_root": "Нужен root",
        "eta_finishing": "Завершение...",
        "eta_calculating": "Расчёт...",
        "no_active_scan": "Нет активной проверки",
        "no_active_scan_running": "Активная проверка не запущена.",
        "currently_checking": "Файл:",
        "pause_scan": "Пауза",
        "resume_scan": "Продолжить",
        "stop_scan": "Стоп",
        "bg_mode_chk": "Фоновый режим (не тормозить ПК)",
        "bg_mode_tip": "Низкий приоритет ЦП и диска во время сканирования.",
        "progress_paused_unlock": "Пауза (нужен root для %)",
        "progress_pct_paused": "{pct:.1f}% (Пауза)",
        "progress_sub_unlock_ready": "Цель: {elig_files:,} файлов ({elig_bytes} <= {max_sz}; всего {all_files:,} / {all_bytes})",
        "progress_sub_unlock_counting": "Оценка диска: {statvfs} (подсчёт: {all_files:,}...)",
        "progress_sub_unlock_est": "Оценка диска: {statvfs}",
        "progress_sub_accurate": "Точно: ~{eff} / {total} ({elig_files:,} <= {max_sz}; {all_files:,} / {all_bytes})",
        "progress_sub_refining": "Оценка: ~{eff} / {total} (подсчёт: {all_files:,}...)",
        "progress_sub_est": "Начальная оценка: ~{eff} / {total}",
        "scan_running_locked_file": "Запущено от {user} (PID {pid}). Разблокируйте root выше.",
        "scanning_metadata": "(Чтение метаданных каталога)",
        "archive_temp_suffix": "  (+{count} врем. архив)",
        "show_tabs_btn": "Показать журналы, карантин и настройки ▾",
        "hide_tabs_btn": "Скрыть журналы, карантин и настройки ▴",
        "tab_log": "Журнал",
        "tab_threats": "Угрозы ({count})",
        "tab_quarantine": "Карантин ({count})",
        "tab_history": "История",
        "tab_schedule": "Расписание",
        "tab_custom": "Доп. проверка",
        "tab_db": "База вирусов",
        "log_path_lbl": "Журнал:",
        "reload_log_btn": "Обновить",
        "filter_lbl": "Фильтр:",
        "log_filter_ph": "Фильтр строк (FOUND, ERROR, OK)...",
        "autoscroll_chk": "Автопрокрутка",
        "stream_fd_chk": "Показывать файлы /proc/fd при -i",
        "restart_verbose_btn": "Перезапустить без -i",
        "quiet_log_hint": "Включён -i: в файл пишутся только угрозы и итог.",
        "col_file_path": "Путь к файлу",
        "col_threat_sig": "Сигнатура",
        "col_status": "Статус",
        "reveal_dolphin_btn": "Показать в папке",
        "copy_path_btn": "Копировать путь",
        "move_quarantine_btn": "В карантин",
        "delete_file_btn": "Удалить файл",
        "quarantine_note": "Файлы в /root/quarantine изолированы без прав выполнения.",
        "col_q_name": "Файл",
        "col_q_orig": "Исходный путь",
        "col_q_threat": "Угроза",
        "col_q_date": "Дата",
        "col_q_size": "Размер",
        "refresh_btn": "Обновить",
        "restore_orig_btn": "Восстановить",
        "restore_to_btn": "Восстановить в...",
        "delete_perm_btn": "Удалить навсегда",
        "col_h_date": "Дата",
        "col_h_target": "Цель",
        "col_h_duration": "Длительность",
        "col_h_scanned": "Файлы / Объём",
        "col_h_threats": "Угрозы",
        "col_h_result": "Итог",
        "refresh_history_btn": "Обновить",
        "clear_history_btn": "Очистить",
        "status_clean": "Чисто",
        "status_threats_found": "Есть угрозы",
        "sched_desc": "Настройте автоматическую фоновую проверку через таймеры systemd.",
        "sched_enable_chk": "Включить автопроверку",
        "sched_status_lbl": "Статус:",
        "sched_type_lbl": "Тип:",
        "sched_freq_lbl": "Частота:",
        "sched_day_lbl": "День недели:",
        "sched_time_lbl": "Время:",
        "sched_info_lbl": "Таймер:",
        "sched_type_quick": "Быстрая (Дом и Загрузки)",
        "sched_type_full": "Полная (/)",
        "sched_freq_daily": "Ежедневно",
        "sched_freq_weekly": "Еженедельно",
        "day_mon": "Пн",
        "day_tue": "Вт",
        "day_wed": "Ср",
        "day_thu": "Чт",
        "day_fri": "Пт",
        "day_sat": "Сб",
        "day_sun": "Вс",
        "sched_unlock_hint": "Нужен root-доступ для изменения расписания.",
        "save_sched_btn": "Сохранить",
        "sched_enabled": "Вкл.",
        "sched_disabled": "Выкл.",
        "sched_timer_status": "Статус: {state}   |   Запуск: {next_run}",
        "sched_saved_status": "Сохранено! {state}   |   {next_run}",
        "sched_saved_title": "Сохранено",
        "sched_saved_msg": "Автопроверка: {state}.",
        "sched_read_err": "Ошибка чтения: {err}",
        "sched_save_err": "Ошибка сохранения",
        "adv_target_lbl": "Цель:",
        "browse_btn": "Обзор...",
        "adv_options_lbl": "Параметры:",
        "opt_recursive": "Рекурсивно (-r)",
        "opt_infected_only": "Только заражённые (-i)",
        "opt_exclude_virtual": "Исключить /sys, /proc, /dev, /run",
        "opt_cross_fs": "Одна файловая система (--cross-fs=no)",
        "adv_maxsize_lbl": "Макс. размер:",
        "adv_action_lbl": "При угрозе:",
        "action_report": "Только отчёт (для /)",
        "action_move": "Переместить в /root/quarantine",
        "action_copy": "Копировать в /root/quarantine",
        "adv_log_lbl": "Файл журнала:",
        "adv_cmd_lbl": "Команда:",
        "start_custom_btn": "Запустить проверку",
        "db_checking": "Проверка базы ClamAV...",
        "freshclam_btn": "Обновить базы сейчас (freshclam)",
        "freshclam_updating": "Обновление баз...",
        "freshclam_ph": "Вывод freshclam появится здесь...",
        "freshclam_running_msg": "Запуск freshclam от root...\n",
        "freshclam_success": "УСПЕШНО",
        "freshclam_errors": "С ОШИБКАМИ",
        "tray_tip_idle": "ClamAV — Защищён ({count} угроз)",
        "tray_tip_paused": "ClamAV — Пауза ({pct:.1f}%)",
        "tray_tip_scanning": "ClamAV — Проверка {pct:.1f}% ({eta})",
        "tray_tip_running": "ClamAV — Идёт проверка",
        "tray_open": "Открыть ClamAV",
        "tray_quick": "Быстрая проверка",
        "tray_minimized_msg": "Свёрнуто в трей.",
        "notify_threat_title": "Обнаружена угроза!",
        "notify_scan_done_threats_title": "Проверка завершена — угрозы!",
        "notify_scan_done_threats_msg": "{label}: найдено угроз {count}.",
        "notify_scan_done_clean_title": "Проверка завершена",
        "notify_scan_done_clean_msg": "{label}: угроз не найдено.",
        "dlg_drop_title": "Проверка файлов",
        "dlg_drop_msg": "Проверить:\n\n{preview}",
        "dlg_drop_more": "...и ещё {count}",
        "dlg_sudo_title": "Доступ root",
        "dlg_sudo_prompt": "Введите пароль для root-доступа ClamAV:",
        "dlg_auth_failed": "Ошибка входа",
        "dlg_polkit_failed": "Ошибка Polkit",
        "dlg_root_req_title": "Требуется root",
        "dlg_root_req_text": "Для этого действия нужны права администратора.",
        "dlg_root_req_info": "Разблокируйте root-доступ.",
        "dlg_unlock_pw_btn": "Пароль...",
        "dlg_restart_title": "Перезапуск с полным журналом",
        "dlg_restart_msg": "Остановить проверку -i (PID {pid}) и запустить с полным выводом?",
        "dlg_restart_err": "Ошибка перезапуска",
        "dlg_sig_err": "Ошибка сигнала",
        "dlg_stop_title": "Остановить проверку",
        "dlg_stop_msg": "Остановить активную проверку (PID {pid})?",
        "dlg_stop_err": "Ошибка остановки",
        "dlg_prio_err": "Ошибка приоритета",
        "dlg_no_sel_title": "Нет выбора",
        "dlg_no_sel_threat": "Сначала выберите строку.",
        "dlg_no_sel_quar": "Выберите файл в карантине.",
        "dlg_quar_title": "В карантин",
        "dlg_quar_msg": "Переместить «{path}» в {qdir}?",
        "dlg_quar_err": "Ошибка карантина",
        "dlg_del_title": "Удалить файл",
        "dlg_del_msg": "Удалить «{path}» навсегда?",
        "dlg_del_err": "Ошибка удаления",
        "dlg_restore_dir": "Папка назначения",
        "dlg_restore_title": "Восстановить файл",
        "dlg_restore_msg": "Восстановить «{name}» в:\n{dest}",
        "dlg_restore_ok_title": "Восстановлено",
        "dlg_restore_ok_msg": "Восстановлено в:\n{dest}",
        "dlg_restore_err": "Ошибка восстановления",
        "dlg_del_q_title": "Удалить из карантина",
        "dlg_del_q_msg": "Удалить «{name}» навсегда?",
        "dlg_clear_hist_title": "Очистить историю",
        "dlg_clear_hist_msg": "Очистить сохранённую историю?",
        "dlg_browse_dir": "Выбор каталога",
        "dlg_scan_running_title": "Проверка уже идёт",
        "dlg_scan_running_msg": "Уже запущена проверка. Начать ещё одну?",
        "dlg_start_err": "Ошибка запуска",
        "dlg_pick_title": "Выбор объекта",
        "dlg_pick_msg": "Проверить папку или файл?",
        "dlg_pick_folder": "Папка...",
        "dlg_pick_file": "Файл...",
        "dlg_pick_folder_title": "Выбрать папку",
        "dlg_pick_file_title": "Выбрать файл",
        "label_quick_scan": "Быстрая (Дом и Загрузки)",
        "label_full_scan": "Полная (/)",
        "label_custom_scan": "Проверка ({target})",
        "label_dropped_one": "Файл ({name})",
        "label_dropped_many": "Файлы ({count})",
        "status_found": "НАЙДЕНО",
        "status_deleted": "Удалён",
        "status_quarantined": "В карантине -> {dest}",
        "history_entries": "{count:,} записей",
        "history_see_log": "См. журнал",
        "hero_missing_clamscan_title": "ClamAV не установлен",
        "hero_missing_clamscan_sub": "Не найден 'clamscan'. Установите пакет clamav{extra}.",
        "hero_missing_db_title": "Нет базы вирусов",
        "hero_missing_db_sub": "Нет сигнатур (.cvd/.cld) в {db_dir}. Обновите базу.",
        "hero_update_db_btn": "Обновить базы",
        "db_state_ready": "БД готова ({count} файлов)",
        "db_state_missing": "Нет баз (0 в {db_dir})",
        "db_deps_ok": "Инструменты доступны",
        "db_deps_missing": "Нет доп. утилит: {tools}",
        "db_status_full": "ClamAV: {version}   |   freshclam: {freshclam_bin}\nБаза ({db_dir}): {db_state}\nАвтообновление: {service}   |   {deps_note}",
        "meta_line_full": "{db_state}  •  Движок {version}  •  Обновление: {service}{warn}",
        "idle_col_status": "Статус",
        "idle_col_last_scan": "Последняя проверка",
        "idle_col_sigs": "База вирусов",
        "idle_col_sched": "Расписание",
        "idle_val_protected": "Защищён",
        "idle_val_attention": "Нужна проверка",
        "idle_val_missing_clam": "Не установлен",
        "idle_val_no_scans": "Нет проверок",
        "idle_val_today": "Сегодня",
        "idle_val_threats_n": "угроз: {n}",
        "idle_val_up_to_date": "Актуальна",
        "idle_val_sigs_missing": "Отсутствует",
        "idle_val_not_sched": "Не задано",
        "idle_val_daily_at": "Ежедн. {time}",
        "clamscan_missing_tip": "Отключено: нет 'clamscan'.",
        "freshclam_missing_tip": "Отключено: нет 'freshclam'.",
        "installed_word": "Установлен",
        "missing_word": "Отсутствует",
        "tile_quick_title": "Быстрая проверка",
        "tile_quick_sub": "Загрузки и Дом • ~2 мин",
        "tile_full_title": "Полная проверка",
        "tile_full_sub": "Весь ПК",
        "tile_pick_title": "Файл или папка",
        "tile_pick_sub": "Перетащите сюда",
        "also_missing_suffix": " (также нет: {items})",
        "history_system_log": "Система / Журнал",
        "svc_active": "Активно",
        "svc_inactive": "Отключено",
        "log_path_tip": "Журналы root должны находиться в /var/log/.",
        "log_inspect_err": "Заметка: {err}",
        "polkit_source_hint": "Примечание: Polkit без пароля включается при установке системного пакета.",
        "unknown_word": "Неизвестно",
    },
}


def _match_supported_lang(raw: str) -> str | None:
    """Map an OS locale string (e.g. 'es_ES.UTF-8', 'pt_BR', 'zh_CN') to a supported key."""
    token = raw.strip().lower().split(".", 1)[0].split("@", 1)[0]
    if not token:
        return None
    if token in ("c", "posix"):
        return "en"
    prefix = re.split(r"[-_]", token, maxsplit=1)[0]
    return prefix if prefix in TRANSLATIONS else None


def detect_default_language(_settings: dict[str, Any] | None = None) -> str:
    """Determine UI language automatically from the OS locale (LC_ALL, LC_MESSAGES, LANGUAGE, LANG)."""
    for env_key in ("LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"):
        val = os.environ.get(env_key, "").strip()
        if not val:
            continue
        for part in val.split(":"):
            matched = _match_supported_lang(part)
            if matched:
                return matched

    try:
        loc, _ = locale.getlocale()
        if loc:
            matched = _match_supported_lang(loc)
            if matched:
                return matched
    except Exception:  # noqa: BLE001
        pass
    return "en"


def tr(lang: str, key: str, **kwargs: Any) -> str:
    """Translate key across supported locales, formatting optional placeholders."""
    table = TRANSLATIONS.get(lang, TRANSLATIONS["en"])
    template = table.get(key) or TRANSLATIONS["en"].get(key) or key
    if kwargs:
        try:
            return template.format(**kwargs)
        except Exception:  # noqa: BLE001
            return template
    return template


def format_bytes(num_bytes: int | float) -> str:
    """Format a byte count into human-readable units."""
    value = float(max(0, num_bytes))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{value:.2f} TB"


def format_duration(seconds: float) -> str:
    """Format elapsed seconds as HH:MM:SS."""
    total = max(0, int(seconds))
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def extract_log_path_from_cmdline(args: list[str]) -> str:
    """Extract --log / -l target path from a clamscan command line."""
    for idx, arg in enumerate(args):
        if arg.startswith("--log="):
            return arg.split("=", 1)[1]
        if arg in ("--log", "-l") and idx + 1 < len(args):
            return args[idx + 1]
    return DEFAULT_LOG_PATH if os.path.exists(DEFAULT_LOG_PATH) else ""


def parse_proc_uptime() -> float:
    """Read system uptime in seconds from /proc/uptime."""
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as fh:
            return float(fh.read().split()[0])
    except OSError:
        return 0.0


def parse_proc_stat(pid: int) -> dict[str, Any] | None:
    """Parse world-readable fields from /proc/<pid>/stat."""
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read().strip()
    except OSError:
        return None

    lparen = raw.find("(")
    rparen = raw.rfind(")")
    if lparen == -1 or rparen == -1 or rparen + 2 >= len(raw):
        return None

    comm = raw[lparen + 1 : rparen]
    rest = raw[rparen + 2 :].split()
    if len(rest) < 20:
        return None

    return {
        "comm": comm,
        "state": rest[0],
        "ppid": int(rest[1]),
        "utime": int(rest[11]),
        "stime": int(rest[12]),
        "priority": int(rest[15]),
        "nice": int(rest[16]),
        "threads": int(rest[17]),
        "starttime": int(rest[19]),
    }


def parse_proc_status(pid: int) -> dict[str, Any]:
    """Parse world-readable fields from /proc/<pid>/status."""
    info: dict[str, Any] = {
        "uid": None,
        "user": "unknown",
        "rss_kb": 0,
        "voluntary_ctxt_switches": 0,
        "nonvoluntary_ctxt_switches": 0,
    }
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("Uid:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        uid = int(parts[1])
                        info["uid"] = uid
                        try:
                            info["user"] = pwd.getpwuid(uid).pw_name if pwd is not None else str(uid)
                        except KeyError:
                            info["user"] = str(uid)
                elif line.startswith("VmRSS:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        info["rss_kb"] = int(parts[1])
                elif line.startswith("voluntary_ctxt_switches:"):
                    info["voluntary_ctxt_switches"] = int(line.split(":", 1)[1].strip())
                elif line.startswith("nonvoluntary_ctxt_switches:"):
                    info["nonvoluntary_ctxt_switches"] = int(line.split(":", 1)[1].strip())
    except OSError:
        pass
    return info


def read_proc_cmdline(pid: int) -> list[str]:
    """Read NUL-delimited /proc/<pid>/cmdline."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            raw = fh.read()
        return [part.decode("utf-8", errors="replace") for part in raw.split(b"\x00") if part]
    except OSError:
        return []


_SPAWNED_PROCS_LOCK = threading.Lock()
_SPAWNED_PROCS: dict[int, subprocess.Popen[Any]] = {}
_SPAWNED_PROCS_META: dict[int, dict[str, Any]] = {}
_WINDOWS_PAUSED_PIDS: set[int] = set()


def _win32_suspend_resume(pid: int, suspend: bool) -> None:
    """Suspend or resume a Windows process via NtSuspendProcess / NtResumeProcess."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    ntdll = ctypes.windll.ntdll  # type: ignore[attr-defined]
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(0x0800, False, int(pid))
    if not handle:
        raise ProcessLookupError(f"Process {pid} no longer exists")
    try:
        fn = ntdll.NtSuspendProcess if suspend else ntdll.NtResumeProcess
        fn.argtypes = [wintypes.HANDLE]
        fn.restype = ctypes.c_long
        status = fn(handle)
        if status < 0:
            raise OSError(f"Failed changing Windows process state for PID {pid}: {status:#x}")
    finally:
        kernel32.CloseHandle(handle)


def _win32_set_priority(pid: int, mode: str) -> None:
    """Adjust Windows process priority class ('normal', 'low', or 'idle')."""
    import ctypes
    from ctypes import wintypes

    prio_map = {"normal": 0x00000020, "low": 0x00004000, "idle": 0x00000040}
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.SetPriorityClass.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.SetPriorityClass.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(0x0200, False, int(pid))
    if not handle:
        raise ProcessLookupError(f"Process {pid} no longer exists")
    try:
        if not kernel32.SetPriorityClass(handle, prio_map[mode]):
            raise OSError(f"SetPriorityClass failed for PID {pid}")
    finally:
        kernel32.CloseHandle(handle)


def _win32_get_io_counters(pid: int) -> dict[str, int]:
    """Read cumulative Windows process I/O transfer counters via GetProcessIoCounters."""
    import ctypes
    from ctypes import wintypes

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_uint64),
            ("WriteOperationCount", ctypes.c_uint64),
            ("OtherOperationCount", ctypes.c_uint64),
            ("ReadTransferCount", ctypes.c_uint64),
            ("WriteTransferCount", ctypes.c_uint64),
            ("OtherTransferCount", ctypes.c_uint64),
        ]

    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetProcessIoCounters.argtypes = [wintypes.HANDLE, ctypes.POINTER(_IoCounters)]
    kernel32.GetProcessIoCounters.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(0x1000, False, int(pid))
    if not handle:
        return {}
    try:
        counters = _IoCounters()
        if not kernel32.GetProcessIoCounters(handle, ctypes.byref(counters)):
            return {}
        read_b = int(counters.ReadTransferCount)
        write_b = int(counters.WriteTransferCount)
        return {"rchar": read_b, "wchar": write_b, "read_bytes": read_b, "write_bytes": write_b}
    finally:
        kernel32.CloseHandle(handle)


def _win32_get_proc_times_and_priority(pid: int) -> tuple[int, int, float]:
    """Return (cpu_ticks_10ms, nice_equiv, elapsed_sec) for a Windows PID."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetPriorityClass.argtypes = [wintypes.HANDLE]
    kernel32.GetPriorityClass.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(0x1000, False, int(pid))
    if not handle:
        return 0, 0, 0.0
    try:
        prio = int(kernel32.GetPriorityClass(handle))
        nice_eq = 19 if prio == 0x00000040 else (10 if prio == 0x00004000 else 0)
        c_ft, e_ft, k_ft, u_ft = (
            wintypes.FILETIME(),
            wintypes.FILETIME(),
            wintypes.FILETIME(),
            wintypes.FILETIME(),
        )
        cpu_ticks = 0
        elapsed = 0.0
        if kernel32.GetProcessTimes(handle, ctypes.byref(c_ft), ctypes.byref(e_ft), ctypes.byref(k_ft), ctypes.byref(u_ft)):
            k_100ns = (k_ft.dwHighDateTime << 32) | k_ft.dwLowDateTime
            u_100ns = (u_ft.dwHighDateTime << 32) | u_ft.dwLowDateTime
            c_100ns = (c_ft.dwHighDateTime << 32) | c_ft.dwLowDateTime
            cpu_ticks = int((k_100ns + u_100ns) // 100_000)
            created_unix = (c_100ns - 116444736000000000) / 10_000_000.0
            elapsed = max(0.0, time.time() - created_unix) if created_unix > 0 else 0.0
        return cpu_ticks, nice_eq, elapsed
    finally:
        kernel32.CloseHandle(handle)


def _win32_is_pid_running(pid: int) -> bool:
    """Return True if a Windows PID currently exists and has exit code STILL_ACTIVE."""
    if pid <= 0:
        return False
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(0x1000, False, int(pid))
    if not handle:
        return False
    try:
        code = wintypes.DWORD(0)
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return False
        return int(code.value) == 259
    finally:
        kernel32.CloseHandle(handle)


def _is_pid_running(pid: int) -> bool:
    if IS_WINDOWS:
        return _win32_is_pid_running(pid)
    if IS_MACOS or not os.path.exists("/proc"):
        with _SPAWNED_PROCS_LOCK:
            spawned = _SPAWNED_PROCS.get(pid)
        if spawned is not None and spawned.poll() is not None:
            return False
        try:
            os.kill(pid, 0)
            return True
        except PermissionError:
            return True
        except OSError:
            return False
    return os.path.exists(f"/proc/{pid}")


def _parse_ps_etime(raw: str) -> float:
    """Parse ps elapsed time format [[dd-]hh:]mm:ss into seconds."""
    text = raw.strip()
    if not text:
        return 0.0
    days = 0
    if "-" in text:
        d_part, text = text.split("-", 1)
        try:
            days = max(0, int(d_part))
        except ValueError:
            days = 0
    parts = text.split(":")
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return 0.0
    if len(nums) == 3:
        return float(days * 86400 + nums[0] * 3600 + nums[1] * 60 + nums[2])
    if len(nums) == 2:
        return float(days * 86400 + nums[0] * 60 + nums[1])
    if len(nums) == 1:
        return float(days * 86400 + nums[0])
    return 0.0


def _discover_macos_clamscan_processes() -> list[dict[str, Any]]:
    """Discover running clamscan processes on macOS via ps and local helper metadata."""
    meta_by_pid: dict[int, dict[str, Any]] = {}
    with _SPAWNED_PROCS_LOCK:
        for pid, proc in list(_SPAWNED_PROCS.items()):
            if proc.poll() is None:
                meta_by_pid[pid] = dict(_SPAWNED_PROCS_META.get(pid) or {})

    found: dict[int, dict[str, Any]] = {}
    try:
        res = subprocess.run(
            ["ps", "-axo", "pid=,uid=,user=,state=,nice=,rss=,etime=,comm=,args="],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            for line in res.stdout.splitlines():
                parts = line.split(None, 8)
                if len(parts) < 8 or not parts[0].isdigit():
                    continue
                pid_val = int(parts[0])
                uid_val = int(parts[1]) if parts[1].isdigit() else _uid()
                user_val = parts[2]
                state_raw = parts[3]
                if state_raw.startswith("Z"):
                    continue
                try:
                    nice_val = int(parts[4])
                except ValueError:
                    nice_val = 0
                try:
                    rss_val = int(parts[5])
                except ValueError:
                    rss_val = 0
                etime_sec = _parse_ps_etime(parts[6])
                comm_raw = parts[7]
                args_str = parts[8] if len(parts) > 8 else comm_raw
                cmdline = args_str.split() if args_str else [comm_raw]
                exe_base = os.path.basename(comm_raw).lower()
                arg0_base = os.path.basename(cmdline[0]).lower() if cmdline else ""
                if exe_base != "clamscan" and arg0_base != "clamscan":
                    continue
                meta = meta_by_pid.get(pid_val) or {}
                if meta.get("cmdline"):
                    cmdline = list(meta["cmdline"])
                state_char = "T" if state_raw.startswith("T") else "R"
                found[pid_val] = {
                    "pid": pid_val,
                    "comm": "clamscan",
                    "state": state_char,
                    "nice": nice_val,
                    "cpu_ticks": 0,
                    "elapsed_sec": etime_sec,
                    "uid": uid_val,
                    "user": user_val,
                    "rss_kb": rss_val,
                    "voluntary_ctxt_switches": 0,
                    "nonvoluntary_ctxt_switches": 0,
                    "cmdline": cmdline,
                    "cmdline_str": " ".join(cmdline) if cmdline else "clamscan",
                    "log_path": str(meta.get("log_path") or extract_log_path_from_cmdline(cmdline)),
                    "quiet_infected_only": ("-i" in cmdline or "--infected" in cmdline),
                }
    except (OSError, subprocess.TimeoutExpired):
        pass

    current_user = getpass.getuser()
    for pid_val, meta in meta_by_pid.items():
        if pid_val not in found and _is_pid_running(pid_val):
            cmdline = list(meta.get("cmdline") or ["clamscan"])
            elapsed = max(0.0, time.monotonic() - float(meta["start_time"])) if "start_time" in meta else 0.0
            found[pid_val] = {
                "pid": pid_val,
                "comm": "clamscan",
                "state": "R",
                "nice": 0,
                "cpu_ticks": 0,
                "elapsed_sec": elapsed,
                "uid": _uid(),
                "user": current_user,
                "rss_kb": 0,
                "voluntary_ctxt_switches": 0,
                "nonvoluntary_ctxt_switches": 0,
                "cmdline": cmdline,
                "cmdline_str": " ".join(cmdline) if cmdline else "clamscan",
                "log_path": str(meta.get("log_path") or extract_log_path_from_cmdline(cmdline)),
                "quiet_infected_only": ("-i" in cmdline or "--infected" in cmdline),
            }

    return sorted(found.values(), key=lambda item: item["pid"])


def _discover_windows_clamscan_processes() -> list[dict[str, Any]]:
    """Discover running clamscan.exe processes on Windows using spawned metadata + tasklist."""
    meta_by_pid: dict[int, dict[str, Any]] = {}
    with _SPAWNED_PROCS_LOCK:
        for pid, proc in list(_SPAWNED_PROCS.items()):
            if proc.poll() is None:
                meta_by_pid[pid] = dict(_SPAWNED_PROCS_META.get(pid) or {})

    tasklist_mem: dict[int, int] = {}
    try:
        res = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH", "/FI", "IMAGENAME eq clamscan.exe"],
            capture_output=True,
            encoding="oem",
            errors="replace",
            timeout=3,
            check=False,
            creationflags=_SUBPROCESS_NO_WINDOW,
        )
        if res.returncode == 0 and res.stdout.strip():
            for row in csv.reader(res.stdout.splitlines()):
                if len(row) >= 5 and row[0].strip().lower() == "clamscan.exe" and row[1].strip().isdigit():
                    pid_val = int(row[1].strip())
                    mem_digits = "".join(ch for ch in row[4] if ch.isdigit())
                    tasklist_mem[pid_val] = int(mem_digits) if mem_digits else 0
                    meta_by_pid.setdefault(pid_val, {})
    except (OSError, subprocess.TimeoutExpired):
        pass

    current_user = getpass.getuser()
    found: list[dict[str, Any]] = []
    for pid, meta in meta_by_pid.items():
        if not _win32_is_pid_running(pid):
            continue
        cmdline = list(meta.get("cmdline") or ["clamscan.exe"])
        cpu_ticks, nice_eq, win_elapsed = _win32_get_proc_times_and_priority(pid)
        elapsed = (
            max(0.0, time.monotonic() - float(meta["start_time"]))
            if "start_time" in meta
            else win_elapsed
        )
        with _SPAWNED_PROCS_LOCK:
            paused = pid in _WINDOWS_PAUSED_PIDS
        found.append(
            {
                "pid": pid,
                "comm": "clamscan.exe",
                "state": "T" if paused else "R",
                "nice": nice_eq,
                "cpu_ticks": cpu_ticks,
                "elapsed_sec": elapsed,
                "uid": _uid(),
                "user": current_user,
                "rss_kb": tasklist_mem.get(pid, 0),
                "voluntary_ctxt_switches": 0,
                "nonvoluntary_ctxt_switches": 0,
                "cmdline": cmdline,
                "cmdline_str": " ".join(cmdline) if cmdline else "clamscan.exe",
                "log_path": str(meta.get("log_path") or extract_log_path_from_cmdline(cmdline)),
                "quiet_infected_only": ("-i" in cmdline or "--infected" in cmdline),
            }
        )
    found.sort(key=lambda item: item["pid"])
    return found


def discover_clamscan_processes() -> list[dict[str, Any]]:
    """Discover all active clamscan processes across Linux (/proc), macOS (ps), and Windows."""
    if IS_WINDOWS:
        return _discover_windows_clamscan_processes()
    if IS_MACOS:
        return _discover_macos_clamscan_processes()
    uptime = parse_proc_uptime()
    clk_tck = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    found: list[dict[str, Any]] = []

    try:
        entries = os.listdir("/proc")
    except OSError:
        return found

    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            with open(f"/proc/{pid}/comm", "r", encoding="utf-8", errors="replace") as fh:
                comm = fh.read().strip()
        except OSError:
            continue

        if comm != "clamscan":
            continue

        stat_info = parse_proc_stat(pid)
        if not stat_info or stat_info["state"] in ("Z", "X", "x"):
            continue
        status_info = parse_proc_status(pid)
        cmdline = read_proc_cmdline(pid)
        elapsed = max(0.0, uptime - (stat_info["starttime"] / clk_tck)) if uptime > 0 else 0.0

        found.append(
            {
                "pid": pid,
                "comm": comm,
                "state": stat_info["state"],
                "nice": stat_info["nice"],
                "cpu_ticks": stat_info["utime"] + stat_info["stime"],
                "elapsed_sec": elapsed,
                "uid": status_info["uid"],
                "user": status_info["user"],
                "rss_kb": status_info["rss_kb"],
                "voluntary_ctxt_switches": status_info["voluntary_ctxt_switches"],
                "nonvoluntary_ctxt_switches": status_info["nonvoluntary_ctxt_switches"],
                "cmdline": cmdline,
                "cmdline_str": " ".join(cmdline) if cmdline else "clamscan",
                "log_path": extract_log_path_from_cmdline(cmdline),
                "quiet_infected_only": ("-i" in cmdline or "--infected" in cmdline),
            }
        )

    found.sort(key=lambda item: item["pid"])
    return found


def parse_threats_from_text(text: str) -> list[tuple[str, str]]:
    """Extract (file_path, threat_name) tuples from ClamAV log lines."""
    threats: list[tuple[str, str]] = []
    for line in text.splitlines():
        match = THREAT_LINE_RE.match(line.strip())
        if match:
            threats.append((match.group(1), match.group(2)))
    return threats


def parse_size_to_bytes(val: str, default: int = 25 * 1024 * 1024) -> int:
    """Parse ClamAV size strings (e.g. 25M, 100M, 1G) into bytes."""
    text = val.strip().upper()
    if not text:
        return default
    multipliers = (
        ("TB", 1024**4),
        ("T", 1024**4),
        ("GB", 1024**3),
        ("G", 1024**3),
        ("MB", 1024**2),
        ("M", 1024**2),
        ("KB", 1024),
        ("K", 1024),
        ("B", 1),
    )
    for suffix, mult in multipliers:
        if text.endswith(suffix):
            num_part = text[: -len(suffix)].strip()
            try:
                return max(1, int(float(num_part) * mult))
            except ValueError:
                return default
    try:
        return max(1, int(text))
    except ValueError:
        return default


def _normalize_exclude_path(raw: str) -> str | None:
    """Convert a clamscan --exclude-dir regex/path into a find-compatible path."""
    cleaned = raw.strip().lstrip("^").rstrip("$").rstrip("/\\")
    if not cleaned:
        return None
    if not (cleaned.startswith("/") or (len(cleaned) >= 2 and cleaned[1] == ":")):
        return None
    if any(ch in cleaned for ch in ("*", "?", "[", "(", "|", "+")):
        return None
    return cleaned


def parse_scan_targets_and_limits(cmdline: list[str]) -> dict[str, Any]:
    """Extract scan targets, --max-filesize, --exclude-dir, and --cross-fs from cmdline."""
    value_flags = {
        "-l",
        "--log",
        "-d",
        "--database",
        "--move",
        "--copy",
        "--exclude",
        "--exclude-dir",
        "--include",
        "--include-dir",
        "--max-filesize",
        "--max-scansize",
        "--tempdir",
        "-f",
        "--file-list",
    }
    targets: list[str] = []
    exclude_dirs: list[str] = [] if IS_WINDOWS else ["/proc", "/sys", "/dev", "/run"]
    max_filesize = 25 * 1024 * 1024
    cross_fs = True

    args = cmdline[1:] if cmdline else []
    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "--":
            targets.extend(args[idx + 1 :])
            break
        if arg.startswith("--exclude-dir="):
            norm = _normalize_exclude_path(arg.split("=", 1)[1])
            if norm and norm not in exclude_dirs:
                exclude_dirs.append(norm)
        elif arg == "--exclude-dir" and idx + 1 < len(args):
            idx += 1
            norm = _normalize_exclude_path(args[idx])
            if norm and norm not in exclude_dirs:
                exclude_dirs.append(norm)
        elif arg.startswith("--max-filesize="):
            max_filesize = parse_size_to_bytes(arg.split("=", 1)[1], max_filesize)
        elif arg == "--max-filesize" and idx + 1 < len(args):
            idx += 1
            max_filesize = parse_size_to_bytes(args[idx], max_filesize)
        elif arg.startswith("--cross-fs="):
            val = arg.split("=", 1)[1].strip().lower()
            cross_fs = val not in ("no", "false", "0")
        elif arg in value_flags:
            idx += 1
        elif arg.startswith("-"):
            pass
        else:
            targets.append(arg)
        idx += 1

    if not targets:
        targets = [_system_root_target()]

    return {
        "targets": targets,
        "max_filesize": max_filesize,
        "exclude_dirs": exclude_dirs,
        "cross_fs": cross_fs,
    }


def estimate_statvfs_used_bytes(targets: list[str], cross_fs: bool = True) -> int:
    """Stage 1 instant disk-space estimator summing unique mounted local filesystems."""
    local_fs_types = {"ext4", "ext3", "ext2", "xfs", "btrfs", "vfat", "ntfs", "ntfs3", "f2fs", "zfs", "exfat"}
    mounts: list[str] = []
    if cross_fs and not IS_WINDOWS:
        try:
            with open("/proc/mounts", "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 3 and parts[2] in local_fs_types:
                        mounts.append(parts[1].replace("\\040", " "))
        except OSError:
            pass

    seen_devs: set[int] = set()
    total_used = 0
    for target in targets:
        resolved_target = _system_root_target() if IS_WINDOWS and target == "/" else target
        if not os.path.exists(resolved_target):
            continue
        if os.path.isfile(resolved_target):
            try:
                total_used += os.path.getsize(resolved_target)
            except OSError:
                pass
            continue

        norm_target = os.path.realpath(resolved_target)
        candidate_paths = [norm_target]
        if cross_fs and not IS_WINDOWS:
            prefix = "/" if norm_target == "/" else norm_target.rstrip("/") + "/"
            for mp in mounts:
                if mp == norm_target or (norm_target == "/" and mp.startswith("/")) or mp.startswith(prefix):
                    candidate_paths.append(mp)

        for path in candidate_paths:
            try:
                dev = os.stat(path).st_dev
                if dev in seen_devs:
                    continue
                seen_devs.add(dev)
                if hasattr(os, "statvfs") and not IS_WINDOWS:
                    st = os.statvfs(path)
                    total_used += max(0, (st.f_blocks - st.f_bfree) * st.f_frsize)
                else:
                    total_used += max(0, int(shutil.disk_usage(path).used))
            except OSError:
                continue

    return total_used


_PRECOUNT_LOCK = threading.Lock()
_PRECOUNT_GEN = 0
_PRECOUNT_PROC: subprocess.Popen[str] | None = None
_PRECOUNT_STATE: dict[str, Any] = {
    "key": None,
    "gen": 0,
    "running": False,
    "done": False,
    "all_files": 0,
    "all_bytes": 0,
    "eligible_files": 0,
    "eligible_bytes": 0,
    "max_filesize": 25 * 1024 * 1024,
    "uid": _euid(),
    "elapsed_sec": 0.0,
}


def get_precount_snapshot() -> dict[str, Any]:
    """Return a shallow copy of the current background pre-count state."""
    with _PRECOUNT_LOCK:
        snap = dict(_PRECOUNT_STATE)
        snap.pop("key", None)
        return snap


def cancel_background_precount() -> None:
    """Terminate any running background pre-count worker and clear cached pre-count state."""
    global _PRECOUNT_GEN, _PRECOUNT_PROC
    with _PRECOUNT_LOCK:
        _PRECOUNT_GEN += 1
        proc = _PRECOUNT_PROC
        _PRECOUNT_PROC = None
        _PRECOUNT_STATE.update(
            {
                "key": None,
                "gen": _PRECOUNT_GEN,
                "running": False,
                "done": False,
                "all_files": 0,
                "all_bytes": 0,
                "eligible_files": 0,
                "eligible_bytes": 0,
                "elapsed_sec": 0.0,
            }
        )
    if proc is not None and proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=0.5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                proc.kill()
                proc.wait(timeout=0.5)
            except (OSError, subprocess.TimeoutExpired):
                pass


def _walk_precount(
    valid_targets: list[str],
    exclude_dirs: list[str],
    max_filesize: int,
    cross_fs: bool,
    gen: int,
    t0: float,
) -> None:
    """Pure-Python directory walker fallback for Windows or environments without GNU find."""
    excl_norm = {os.path.normcase(os.path.abspath(ex)) for ex in exclude_dirs if ex}
    all_files = 0
    all_bytes = 0
    eligible_files = 0
    eligible_bytes = 0

    for target in valid_targets:
        with _PRECOUNT_LOCK:
            if _PRECOUNT_STATE.get("gen") != gen:
                return
        if os.path.isfile(target):
            try:
                sz = os.path.getsize(target)
            except OSError:
                sz = 0
            all_files += 1
            all_bytes += sz
            if sz <= max_filesize:
                eligible_files += 1
                eligible_bytes += sz
            continue

        try:
            root_dev = os.stat(target).st_dev if not cross_fs else None
        except OSError:
            continue

        for root, dirs, files in os.walk(target, followlinks=False):
            with _PRECOUNT_LOCK:
                if _PRECOUNT_STATE.get("gen") != gen:
                    return
            kept_dirs: list[str] = []
            for dname in dirs:
                dpath = os.path.join(root, dname)
                if os.path.normcase(os.path.abspath(dpath)) in excl_norm:
                    continue
                if root_dev is not None:
                    try:
                        if os.stat(dpath).st_dev != root_dev:
                            continue
                    except OSError:
                        continue
                kept_dirs.append(dname)
            dirs[:] = kept_dirs

            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    sz = os.lstat(fpath).st_size
                except OSError:
                    continue
                all_files += 1
                all_bytes += sz
                if sz <= max_filesize:
                    eligible_files += 1
                    eligible_bytes += sz
                if all_files % 5000 == 0:
                    with _PRECOUNT_LOCK:
                        if _PRECOUNT_STATE.get("gen") != gen:
                            return
                        _PRECOUNT_STATE.update(
                            {
                                "all_files": all_files,
                                "all_bytes": all_bytes,
                                "eligible_files": eligible_files,
                                "eligible_bytes": eligible_bytes,
                                "elapsed_sec": time.monotonic() - t0,
                            }
                        )

    with _PRECOUNT_LOCK:
        if _PRECOUNT_STATE.get("gen") == gen:
            _PRECOUNT_STATE.update(
                {
                    "running": False,
                    "done": True,
                    "all_files": all_files,
                    "all_bytes": all_bytes,
                    "eligible_files": eligible_files,
                    "eligible_bytes": eligible_bytes,
                    "elapsed_sec": time.monotonic() - t0,
                }
            )


def start_background_precount(
    targets: list[str],
    exclude_dirs: list[str],
    max_filesize: int,
    cross_fs: bool,
) -> dict[str, Any]:
    """Start Stage 2 background file/byte pre-count if configuration changed."""
    global _PRECOUNT_GEN, _PRECOUNT_PROC

    valid_targets = [t for t in targets if os.path.exists(t)]
    key = (tuple(valid_targets), tuple(exclude_dirs), int(max_filesize), bool(cross_fs), _euid())

    with _PRECOUNT_LOCK:
        if _PRECOUNT_STATE.get("key") == key and (_PRECOUNT_STATE.get("running") or _PRECOUNT_STATE.get("done")):
            snap = dict(_PRECOUNT_STATE)
            snap.pop("key", None)
            return snap

        _PRECOUNT_GEN += 1
        gen = _PRECOUNT_GEN
        old_proc = _PRECOUNT_PROC
        _PRECOUNT_PROC = None

        _PRECOUNT_STATE.update(
            {
                "key": key,
                "gen": gen,
                "running": bool(valid_targets),
                "done": not bool(valid_targets),
                "all_files": 0,
                "all_bytes": 0,
                "eligible_files": 0,
                "eligible_bytes": 0,
                "max_filesize": max_filesize,
                "uid": _euid(),
                "elapsed_sec": 0.0,
            }
        )
        snap = dict(_PRECOUNT_STATE)
        snap.pop("key", None)

    if old_proc is not None and old_proc.poll() is None:
        try:
            old_proc.terminate()
        except OSError:
            pass

    if not valid_targets:
        return snap

    def _worker() -> None:
        global _PRECOUNT_PROC
        t0 = time.monotonic()
        with _PRECOUNT_LOCK:
            if _PRECOUNT_STATE.get("gen") != gen:
                return
        if IS_WINDOWS or IS_MACOS or shutil.which("find") is None:
            _walk_precount(valid_targets, exclude_dirs, max_filesize, cross_fs, gen, t0)
            return
        cmd: list[str] = []
        if shutil.which("ionice"):
            cmd.extend(["ionice", "-c", "3"])
        if shutil.which("nice"):
            cmd.extend(["nice", "-n", "19"])
        cmd.append("find")
        cmd.extend(valid_targets)
        if not cross_fs:
            cmd.append("-xdev")
        if exclude_dirs:
            prune_expr: list[str] = []
            for idx, ex in enumerate(exclude_dirs):
                if idx > 0:
                    prune_expr.append("-o")
                prune_expr.extend(["-path", ex])
            cmd.extend(["(", *prune_expr, ")", "-prune", "-o"])
        cmd.extend(["-type", "f", "-printf", "%s\n"])

        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except OSError:
            with _PRECOUNT_LOCK:
                if _PRECOUNT_STATE.get("gen") == gen:
                    _PRECOUNT_STATE["running"] = False
                    _PRECOUNT_STATE["done"] = True
            return

        cancelled_early = False
        with _PRECOUNT_LOCK:
            if _PRECOUNT_STATE.get("gen") != gen:
                cancelled_early = True
            else:
                _PRECOUNT_PROC = proc
        if cancelled_early:
            try:
                proc.terminate()
            except OSError:
                pass
            if proc.stdout is not None:
                try:
                    proc.stdout.close()
                except OSError:
                    pass
            try:
                proc.wait(timeout=0.5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    proc.kill()
                    proc.wait(timeout=0.5)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            return

        all_files = 0
        all_bytes = 0
        eligible_files = 0
        eligible_bytes = 0

        assert proc.stdout is not None
        try:
            for line in proc.stdout:
                try:
                    sz = int(line)
                except ValueError:
                    continue
                all_files += 1
                all_bytes += sz
                if sz <= max_filesize:
                    eligible_files += 1
                    eligible_bytes += sz
                if all_files % 25000 == 0:
                    with _PRECOUNT_LOCK:
                        if _PRECOUNT_STATE.get("gen") != gen:
                            proc.terminate()
                            return
                        _PRECOUNT_STATE.update(
                            {
                                "all_files": all_files,
                                "all_bytes": all_bytes,
                                "eligible_files": eligible_files,
                                "eligible_bytes": eligible_bytes,
                                "elapsed_sec": time.monotonic() - t0,
                            }
                        )
            proc.wait()
        finally:
            if proc.poll() is None:
                try:
                    proc.terminate()
                except OSError:
                    pass
            try:
                if proc.stdout is not None:
                    proc.stdout.close()
            except OSError:
                pass
            try:
                proc.wait(timeout=0.5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    proc.kill()
                    proc.wait(timeout=0.5)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        with _PRECOUNT_LOCK:
            if _PRECOUNT_PROC is proc:
                _PRECOUNT_PROC = None
            if _PRECOUNT_STATE.get("gen") == gen:
                _PRECOUNT_STATE.update(
                    {
                        "running": False,
                        "done": True,
                        "all_files": all_files,
                        "all_bytes": all_bytes,
                        "eligible_files": eligible_files,
                        "eligible_bytes": eligible_bytes,
                        "elapsed_sec": time.monotonic() - t0,
                    }
                )

    threading.Thread(target=_worker, daemon=True).start()
    return snap


_PROTECTED_SYSTEM_PREFIXES = (
    "/bin",
    "/sbin",
    "/usr",
    "/lib",
    "/lib64",
    "/boot",
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/var/lib/rpm",
    "/var/lib/dpkg",
)


def _is_secure_root_owned_path(path: str) -> bool:
    """Verify path and all ancestor directories up to '/' are root-owned and not group/world-writable."""
    if not path or not os.path.isabs(path):
        return False
    cur = os.path.abspath(path)
    while True:
        try:
            lst = os.lstat(cur)
        except OSError:
            return False
        if lst.st_uid != 0:
            return False
        if not stat.S_ISLNK(lst.st_mode) and (lst.st_mode & (stat.S_IWGRP | stat.S_IWOTH)) != 0:
            return False
        if stat.S_ISLNK(lst.st_mode):
            target = os.path.realpath(cur)
            try:
                tst = os.lstat(target)
                if tst.st_uid != 0 or (tst.st_mode & (stat.S_IWGRP | stat.S_IWOTH)) != 0:
                    return False
            except OSError:
                return False
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return True


def _resolve_invoking_username() -> str | None:
    """Return username of the non-root caller under pkexec or sudo if present."""
    if pwd is None:
        return None
    for env_key in ("PKEXEC_UID", "SUDO_UID"):
        raw = os.environ.get(env_key, "").strip()
        if raw.isdigit():
            try:
                return pwd.getpwuid(int(raw)).pw_name
            except KeyError:
                continue
    sudo_user = os.environ.get("SUDO_USER", "").strip()
    if sudo_user and sudo_user != "root":
        try:
            pwd.getpwnam(sudo_user)
            return sudo_user
        except KeyError:
            pass
    return None


def _is_protected_system_path(target: str) -> bool:
    """Return True if target points to critical OS paths, polkit/systemd config, or this script."""
    if not target:
        return True
    real = os.path.realpath(target)
    protected_exact = {
        os.path.realpath(SCRIPT_PATH),
        os.path.realpath(POLKIT_RULE_PATH),
        os.path.realpath(SYSTEMD_SERVICE_PATH),
        os.path.realpath(SYSTEMD_TIMER_PATH),
        os.path.realpath(DEFAULT_QUARANTINE_DIR),
    }
    if target in protected_exact or real in protected_exact:
        return True
    if IS_WINDOWS:
        win_prefixes = [
            p
            for p in (
                os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows",
                os.environ.get("ProgramFiles") or r"C:\Program Files",
                os.environ.get("ProgramFiles(x86)") or r"C:\Program Files (x86)",
            )
            if p
        ]
        for candidate in (target, real):
            norm_c = os.path.normcase(os.path.abspath(candidate))
            for pref in win_prefixes:
                norm_p = os.path.normcase(os.path.abspath(pref)).rstrip("\\")
                if norm_c == norm_p or norm_c.startswith(norm_p + "\\"):
                    return True
    elif IS_MACOS:
        for candidate in (target, real):
            for mac_pref in ("/System/", "/Library/", "/usr/", "/bin/", "/sbin/", "/private/etc/"):
                if candidate == mac_pref.rstrip("/") or candidate.startswith(mac_pref):
                    return True
    for candidate in (target, real):
        for prefix in _PROTECTED_SYSTEM_PREFIXES:
            if candidate == prefix or candidate.startswith(prefix + "/"):
                return True
    return False


def _validate_helper_log_path(log_path: str) -> str:
    """Validate log_path used by root helper (restricts root file read/chmod/truncate to /var/log/clamav*)."""
    cleaned = str(log_path or "").strip()
    if not cleaned:
        return ""
    if "\x00" in cleaned or not os.path.isabs(cleaned):
        raise PermissionError(f"Invalid log path: {cleaned}")
    if os.path.islink(cleaned):
        raise PermissionError(f"Refusing symlink log path: {cleaned}")
    if IS_WINDOWS:
        return cleaned
    if _euid() != 0:
        if cleaned.startswith("/var/log/") and not os.access(os.path.dirname(cleaned) or "/var/log", os.W_OK):
            return str(APP_DATA_DIR / os.path.basename(cleaned))
        return cleaned

    parent = os.path.realpath(os.path.dirname(cleaned))
    if not (parent == "/var/log" or parent.startswith("/var/log/clamav")):
        raise PermissionError(f"Root helper restricts scan logs to /var/log/: {cleaned}")
    base = os.path.basename(cleaned)
    real_full = os.path.join(parent, base)
    if real_full != DEFAULT_LOG_PATH and not (base.startswith("clam") and base.endswith(".log")):
        raise PermissionError(f"Log filename must match ClamAV log policy: {cleaned}")
    return real_full


def _resolve_quarantine_dir(raw_qdir: Any) -> str:
    """Confine root quarantine operations strictly to DEFAULT_QUARANTINE_DIR."""
    requested = str(raw_qdir or DEFAULT_QUARANTINE_DIR).strip() or DEFAULT_QUARANTINE_DIR
    if "\x00" in requested or not os.path.isabs(requested):
        raise ValueError(f"Invalid quarantine directory: {requested}")
    if (not IS_WINDOWS) and _euid() == 0:
        if os.path.realpath(requested) != os.path.realpath(DEFAULT_QUARANTINE_DIR) or os.path.islink(
            DEFAULT_QUARANTINE_DIR
        ):
            raise PermissionError("Root quarantine is restricted to DEFAULT_QUARANTINE_DIR")
        return DEFAULT_QUARANTINE_DIR
    if (not IS_WINDOWS) and _euid() != 0:
        if requested == "/root/quarantine" or requested.startswith("/root/"):
            requested = str(APP_DATA_DIR / "quarantine")
    if os.path.islink(requested):
        raise PermissionError(f"Refusing symlink quarantine directory: {requested}")
    return requested


def _validate_clamscan_pid(pid: int) -> None:
    """Verify pid exists and belongs to a legitimate clamscan process."""
    if not isinstance(pid, int) or pid <= 1:
        raise ValueError(f"Invalid PID: {pid}")
    if IS_WINDOWS:
        with _SPAWNED_PROCS_LOCK:
            spawned = _SPAWNED_PROCS.get(pid)
        if (spawned is not None and spawned.poll() is None) or any(
            p["pid"] == pid for p in _discover_windows_clamscan_processes()
        ):
            return
        raise ProcessLookupError(f"Process {pid} no longer exists")
    if IS_MACOS:
        if pid == os.getpid():
            raise PermissionError("Refusing to target GUI/helper process")
        with _SPAWNED_PROCS_LOCK:
            spawned = _SPAWNED_PROCS.get(pid)
        if (spawned is not None and spawned.poll() is None) or any(
            p["pid"] == pid for p in _discover_macos_clamscan_processes()
        ):
            return
        if _is_pid_running(pid):
            raise PermissionError(f"PID {pid} is not 'clamscan'")
        raise ProcessLookupError(f"Process {pid} no longer exists")
    comm_path = f"/proc/{pid}/comm"
    if not os.path.exists(comm_path):
        raise ProcessLookupError(f"Process {pid} no longer exists")
    with open(comm_path, "r", encoding="utf-8", errors="replace") as fh:
        comm = fh.read().strip()
    if comm != "clamscan":
        raise PermissionError(f"PID {pid} is '{comm}', not 'clamscan'")
    try:
        exe_target = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe_target = ""
    if exe_target:
        if os.path.basename(exe_target) != "clamscan":
            raise PermissionError(f"PID {pid} executable is '{exe_target}', not 'clamscan'")
        if _euid() == 0 and not _is_secure_root_owned_path(exe_target):
            raise PermissionError(f"PID {pid} executable is not root-owned/secure: {exe_target}")


def _inspect_proc_fds(pid: int) -> dict[str, Any]:
    """Read /proc/<pid>/fd targets to determine the file currently being scanned."""
    fd_dir = f"/proc/{pid}/fd"
    real_files: list[str] = []
    tmp_files: list[str] = []

    try:
        fd_names = sorted(os.listdir(fd_dir), key=lambda name: int(name) if name.isdigit() else 999999)
    except OSError as exc:
        return {"current_file": None, "open_files": [], "tmp_count": 0, "fd_error": str(exc)}

    for fd_name in fd_names:
        if fd_name in ("0", "1", "2"):
            continue
        try:
            target = os.readlink(os.path.join(fd_dir, fd_name))
        except OSError:
            continue

        if any(target.startswith(prefix) for prefix in EXCLUDED_FD_PREFIXES):
            continue
        if target.startswith("/tmp/clamav-"):
            tmp_files.append(target)
        else:
            real_files.append(target)

    current_file = real_files[-1] if real_files else (tmp_files[-1] if tmp_files else None)
    return {
        "current_file": current_file,
        "open_files": (real_files + tmp_files)[:10],
        "tmp_count": len(tmp_files),
        "fd_error": None,
    }


def _inspect_proc_io(pid: int) -> dict[str, int]:
    """Read byte counters from /proc/<pid>/io."""
    io_stats: dict[str, int] = {}
    try:
        with open(f"/proc/{pid}/io", "r", encoding="utf-8") as fh:
            for line in fh:
                if ":" in line:
                    key, val = line.split(":", 1)
                    io_stats[key.strip()] = int(val.strip())
    except OSError:
        pass
    return io_stats


def _read_log_chunk(log_path: str, log_offset: int, max_bytes: int = 1048576) -> dict[str, Any]:
    """Read incremental log updates starting at log_offset."""
    if not log_path:
        return {"exists": False, "new_text": "", "new_offset": 0, "file_size": 0, "reset": False}
    if not os.path.exists(log_path):
        return {"exists": False, "new_text": "", "new_offset": 0, "file_size": 0, "reset": False}

    file_size = os.path.getsize(log_path)
    reset = False
    offset = max(0, int(log_offset))
    if offset > file_size:
        offset = 0
        reset = True

    with open(log_path, "rb") as fh:
        fh.seek(offset)
        chunk = fh.read(max_bytes)
        new_offset = fh.tell()

    return {
        "exists": True,
        "new_text": chunk.decode("utf-8", errors="replace"),
        "new_offset": new_offset,
        "file_size": file_size,
        "reset": reset,
    }


def _helper_ping(_params: dict[str, Any]) -> dict[str, Any]:
    return {"uid": _euid(), "pid": os.getpid()}


def _ensure_log_readable(log_path: str) -> None:
    """Make validated log_path readable (0644) by unprivileged users when running as root."""
    if IS_WINDOWS or not log_path or _euid() != 0:
        return
    try:
        safe_path = _validate_helper_log_path(log_path)
        if safe_path and not os.path.islink(safe_path) and os.path.isfile(safe_path):
            if (os.stat(safe_path).st_mode & 0o004) == 0:
                os.chmod(safe_path, 0o644)
    except (OSError, PermissionError):
        pass


def get_quick_scan_targets(home_dir: str | None = None) -> list[str]:
    """Return existing user download/desktop/temp folders for Quick Scan."""
    home = home_dir or os.path.expanduser("~")
    candidates = [
        os.path.join(home, "Downloads"),
        os.path.join(home, "Desktop"),
        os.path.join(home, "Schreibtisch"),
        os.path.join(home, "Documents"),
        os.path.join(home, "Dokumente"),
        "/tmp",
    ]
    existing = [p for p in candidates if os.path.exists(p)]
    return existing or [home]


def load_json_file(path: Path, default: Any) -> Any:
    """Safely load JSON from disk or return default."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return default


def save_json_file(path: Path, data: Any) -> None:
    """Atomically save JSON to disk using an unpredictable temp file, creating parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def parse_scan_summaries_from_log(text: str) -> list[dict[str, Any]]:
    """Extract completed ClamAV SCAN SUMMARY blocks from log text."""
    entries: list[dict[str, Any]] = []
    blocks = text.split("----------- SCAN SUMMARY -----------")
    for block in blocks[1:]:
        fields: dict[str, str] = {}
        for line in block.splitlines():
            stripped = line.strip()
            if not stripped:
                if fields:
                    break
                continue
            if ":" in stripped:
                key, val = stripped.split(":", 1)
                fields[key.strip()] = val.strip()

        if "Scanned files" not in fields:
            continue

        start_raw = fields.get("Start Date", "")
        end_raw = fields.get("End Date", "")
        date_str = (end_raw or start_raw).replace(":", "-", 2)
        try:
            scanned_files = int(fields.get("Scanned files", "0"))
        except ValueError:
            scanned_files = 0
        try:
            infected_files = int(fields.get("Infected files", "0"))
        except ValueError:
            infected_files = 0

        data_scanned = fields.get("Data scanned", "-")
        duration_raw = fields.get("Time", "-")
        status = "Threats Found" if infected_files > 0 else "Clean"

        entries.append(
            {
                "date": date_str or "Unknown",
                "target": "System / Log Scan",
                "duration": duration_raw,
                "scanned": f"{scanned_files:,} files ({data_scanned})",
                "threats": infected_files,
                "status": status,
                "source": "log",
            }
        )
    return entries


def _is_safe_systemd_path(path: str) -> bool:
    """Return True if path is safe to embed inside a quoted systemd ExecStart argument."""
    if not path or not os.path.isabs(path) or not os.path.exists(path):
        return False
    forbidden = ("\n", "\r", "\x00", "\t", '"', "'", "\\", "$", "`", "%", ";")
    return not any(ch in path for ch in forbidden)


def build_systemd_schedule_units(
    frequency: str,
    day_of_week: str,
    time_of_day: str,
    scan_type: str,
    quick_targets: list[str],
    enabled: bool = True,
    user_mode: bool = False,
) -> tuple[str, str, dict[str, Any]]:
    """Generate systemd service and timer unit contents for scheduled ClamAV scans."""
    day_map = {
        "monday": "Mon",
        "mon": "Mon",
        "tuesday": "Tue",
        "tue": "Tue",
        "wednesday": "Wed",
        "wed": "Wed",
        "thursday": "Thu",
        "thu": "Thu",
        "friday": "Fri",
        "fri": "Fri",
        "saturday": "Sat",
        "sat": "Sat",
        "sunday": "Sun",
        "sun": "Sun",
    }
    freq = "weekly" if str(frequency).lower() == "weekly" else "daily"
    day3 = day_map.get(str(day_of_week).strip().lower(), "Sun")
    parts = str(time_of_day).strip().split(":")
    try:
        hh = max(0, min(23, int(parts[0])))
        mm = max(0, min(59, int(parts[1]))) if len(parts) > 1 else 0
    except ValueError:
        hh, mm = 3, 0
    time_norm = f"{hh:02d}:{mm:02d}"
    stype = "full" if str(scan_type).lower() == "full" else "quick"

    on_calendar = f"*-*-* {time_norm}:00" if freq == "daily" else f"{day3} *-*-* {time_norm}:00"
    clamscan_bin = shutil.which("clamscan") or "/usr/bin/clamscan"
    nice_bin = shutil.which("nice") or "/usr/bin/nice"
    ionice_bin = shutil.which("ionice") or "/usr/bin/ionice"
    chmod_bin = shutil.which("chmod") or "/usr/bin/chmod"
    log_path = (
        str(APP_DATA_DIR / "clamav-scan.log")
        if user_mode and DEFAULT_LOG_PATH.startswith("/var/log/")
        else DEFAULT_LOG_PATH
    )
    db_flag = ""
    if user_mode:
        db_dir = _default_db_dir()
        if db_dir != "/var/lib/clamav" and _has_clamav_db_files(db_dir) and _is_safe_systemd_path(db_dir):
            db_flag = f'--database="{db_dir}" '

    if stype == "full":
        if user_mode:
            home_str = str(Path.home())
            full_target = home_str if _is_safe_systemd_path(home_str) else "/home"
            scan_args = (
                f"{clamscan_bin} -r {db_flag}--max-filesize=100M --max-scansize=100M "
                f'--log="{log_path}" "{full_target}"'
            )
        else:
            scan_args = (
                f"{clamscan_bin} -r --exclude-dir=^/sys --exclude-dir=^/proc "
                f"--exclude-dir=^/dev --exclude-dir=^/run --max-filesize=100M --max-scansize=100M "
                f"--log={log_path} /"
            )
    else:
        valid_q = [t for t in quick_targets if _is_safe_systemd_path(t)] or ["/home", "/tmp"]
        quoted_targets = " ".join(f'"{t}"' for t in valid_q)
        log_arg = f'--log="{log_path}"' if user_mode else f"--log={log_path}"
        scan_args = (
            f"{clamscan_bin} -r {db_flag}--max-filesize=100M --max-scansize=100M "
            f"{log_arg} {quoted_targets}"
        )

    cfg = {
        "enabled": bool(enabled),
        "frequency": freq,
        "day_of_week": day3,
        "time_of_day": time_norm,
        "scan_type": stype,
    }
    service_unit = (
        "[Unit]\n"
        "Description=Scheduled ClamAV Antivirus Scan (ClamAV Control Center)\n"
        "After=network.target\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        "SuccessExitStatus=0 1\n"
        f"ExecStart={nice_bin} -n 19 {ionice_bin} -c 3 {scan_args}\n"
        f"ExecStartPost=-{chmod_bin} 0644 {log_path}\n"
    )
    timer_unit = (
        f"# CLAMAV_GUI_CONFIG={json.dumps(cfg)}\n"
        "[Unit]\n"
        "Description=Automatic Scheduled ClamAV Scan Timer\n\n"
        "[Timer]\n"
        f"OnCalendar={on_calendar}\n"
        "Persistent=true\n\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )
    return service_unit, timer_unit, cfg


def _inspect_macos_proc_fds(pid: int) -> dict[str, Any]:
    """Read open files for clamscan on macOS via lsof when available."""
    lsof_bin = shutil.which("lsof")
    if not lsof_bin:
        return {"current_file": None, "open_files": [], "tmp_count": 0, "fd_error": None}
    real_files: list[str] = []
    tmp_files: list[str] = []
    mac_excluded = (*EXCLUDED_FD_PREFIXES, "/System/Library/", "/usr/lib/", "/private/var/db/", "/dev/")
    try:
        res = subprocess.run(
            [lsof_bin, "-n", "-P", "-p", str(pid), "-Fn"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        for line in res.stdout.splitlines():
            if not line.startswith("n/"):
                continue
            target = line[1:].strip()
            if any(target.startswith(pref) for pref in mac_excluded):
                continue
            if target.startswith("/tmp/clamav-") or target.startswith("/private/tmp/clamav-"):
                tmp_files.append(target)
            else:
                real_files.append(target)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"current_file": None, "open_files": [], "tmp_count": 0, "fd_error": str(exc)}
    return {
        "current_file": real_files[-1] if real_files else None,
        "open_files": real_files[-10:],
        "tmp_count": len(tmp_files),
        "fd_error": None,
    }


def _helper_inspect_proc(params: dict[str, Any]) -> dict[str, Any]:
    pid = params.get("pid")
    raw_log = str(params.get("log_path") or "").strip()
    log_path = _validate_helper_log_path(raw_log) if raw_log else ""
    log_offset = int(params.get("log_offset") or 0)
    cmdline = params.get("cmdline")

    if log_path:
        _ensure_log_readable(log_path)

    precount_snap: dict[str, Any] = {}
    if isinstance(cmdline, list) and cmdline:
        parsed = parse_scan_targets_and_limits([str(a) for a in cmdline])
        precount_snap = start_background_precount(
            parsed["targets"],
            parsed["exclude_dirs"],
            parsed["max_filesize"],
            parsed["cross_fs"],
        )

    proc_info: dict[str, Any] = {"alive": False}
    if isinstance(pid, int) and pid > 1 and _is_pid_running(pid):
        if IS_WINDOWS:
            proc_info = {
                "alive": True,
                "io": _win32_get_io_counters(pid),
                "current_file": None,
                "open_files": [],
                "tmp_count": 0,
                "fd_error": None,
            }
        elif IS_MACOS:
            proc_info = {
                "alive": True,
                "io": {},
                **_inspect_macos_proc_fds(pid),
            }
        else:
            proc_info = {
                "alive": True,
                "io": _inspect_proc_io(pid),
                **_inspect_proc_fds(pid),
            }

    log_info = _read_log_chunk(log_path, log_offset)
    return {"proc": proc_info, "log": log_info, "precount": precount_snap}


def _terminate_pid_gracefully(pid: int, force_cont: bool = False) -> None:
    """Terminate pid even if paused, escalating to force kill and waiting for exit."""
    if IS_WINDOWS:
        with _SPAWNED_PROCS_LOCK:
            was_paused = force_cont or (pid in _WINDOWS_PAUSED_PIDS)
            _WINDOWS_PAUSED_PIDS.discard(pid)
            spawned = _SPAWNED_PROCS.get(pid)
        if was_paused:
            try:
                _win32_suspend_resume(pid, suspend=False)
            except (ProcessLookupError, OSError):
                pass
        if spawned is not None:
            try:
                spawned.terminate()
                spawned.wait(timeout=1.0)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    spawned.kill()
                    spawned.wait(timeout=1.0)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        if _win32_is_pid_running(pid):
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                text=True,
                check=False,
                creationflags=_SUBPROCESS_NO_WINDOW,
            )
        return

    if IS_MACOS:
        try:
            os.kill(pid, signal.SIGTERM)
            if force_cont:
                os.kill(pid, signal.SIGCONT)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 0.6
        while time.monotonic() < deadline and _is_pid_running(pid):
            time.sleep(0.05)
        if _is_pid_running(pid):
            try:
                os.kill(pid, signal.SIGKILL)
                os.kill(pid, signal.SIGCONT)
            except ProcessLookupError:
                return
            kill_deadline = time.monotonic() + 1.0
            while time.monotonic() < kill_deadline and _is_pid_running(pid):
                time.sleep(0.05)
        return

    stat_before = parse_proc_stat(pid)
    was_paused = force_cont or bool(stat_before and stat_before.get("state") == "T")
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    if was_paused:
        try:
            os.kill(pid, signal.SIGCONT)
        except ProcessLookupError:
            return

    proc_dir = f"/proc/{pid}"
    if not os.path.exists(proc_dir):
        return
    deadline = time.monotonic() + 0.6
    while time.monotonic() < deadline:
        st = parse_proc_stat(pid)
        if not st or st["state"] in ("Z", "X", "x"):
            return
        time.sleep(0.05)

    st_now = parse_proc_stat(pid)
    still_paused = was_paused or bool(st_now and st_now.get("state") == "T")
    try:
        os.kill(pid, signal.SIGKILL)
        if still_paused:
            os.kill(pid, signal.SIGCONT)
    except ProcessLookupError:
        return

    kill_deadline = time.monotonic() + 1.5
    while time.monotonic() < kill_deadline:
        st = parse_proc_stat(pid)
        if not st or st["state"] in ("Z", "X", "x"):
            return
        time.sleep(0.05)


def _reap_spawned_proc(pid: int) -> None:
    """Wait synchronously for a helper-spawned process to exit so PID disappears."""
    with _SPAWNED_PROCS_LOCK:
        proc = _SPAWNED_PROCS.get(pid)
        _WINDOWS_PAUSED_PIDS.discard(pid)
    if proc is not None:
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            pass
        with _SPAWNED_PROCS_LOCK:
            _SPAWNED_PROCS.pop(pid, None)
            _SPAWNED_PROCS_META.pop(pid, None)


def _helper_signal_proc(params: dict[str, Any]) -> dict[str, Any]:
    pid = int(params["pid"])
    sig_name = str(params["sig"])
    allowed = {"SIGSTOP", "SIGCONT", "SIGTERM", "SIGKILL"}
    if sig_name not in allowed:
        raise ValueError(f"Unsupported signal: {sig_name}")
    _validate_clamscan_pid(pid)
    if IS_WINDOWS:
        if sig_name == "SIGSTOP":
            _win32_suspend_resume(pid, suspend=True)
            with _SPAWNED_PROCS_LOCK:
                _WINDOWS_PAUSED_PIDS.add(pid)
        elif sig_name == "SIGCONT":
            _win32_suspend_resume(pid, suspend=False)
            with _SPAWNED_PROCS_LOCK:
                _WINDOWS_PAUSED_PIDS.discard(pid)
        else:
            cancel_background_precount()
            _terminate_pid_gracefully(pid, force_cont=True)
            _reap_spawned_proc(pid)
        return {"pid": pid, "sig": sig_name}

    if sig_name == "SIGTERM":
        cancel_background_precount()
        _terminate_pid_gracefully(pid)
        _reap_spawned_proc(pid)
    elif sig_name == "SIGKILL":
        cancel_background_precount()
        stat_before = None if IS_MACOS else parse_proc_stat(pid)
        try:
            os.kill(pid, signal.SIGKILL)
            if IS_MACOS or (stat_before and stat_before.get("state") == "T"):
                os.kill(pid, signal.SIGCONT)
        except ProcessLookupError:
            pass
        _reap_spawned_proc(pid)
    else:
        os.kill(pid, getattr(signal, sig_name))
        if sig_name == "SIGSTOP":
            deadline = time.monotonic() + 0.2
            while time.monotonic() < deadline:
                st = parse_proc_stat(pid)
                if st is None or st.get("state") == "T":
                    break
                time.sleep(0.01)
    return {"pid": pid, "sig": sig_name}


def _helper_set_priority(params: dict[str, Any]) -> dict[str, Any]:
    pid = int(params["pid"])
    mode = str(params["mode"])
    profiles = {
        "normal": ("0", "2", "4"),
        "low": ("10", "2", "7"),
        "idle": ("19", "3", None),
    }
    if mode not in profiles:
        raise ValueError(f"Unsupported priority mode: {mode}")
    _validate_clamscan_pid(pid)

    if IS_WINDOWS:
        _win32_set_priority(pid, mode)
        return {"pid": pid, "mode": mode, "renice": f"win32:{mode}"}

    nice_val, io_class, io_level = profiles[mode]
    renice_res = subprocess.run(
        ["renice", "-n", nice_val, "-p", str(pid)],
        capture_output=True,
        text=True,
        check=False,
    )
    if IS_MACOS or shutil.which("ionice") is None:
        if renice_res.returncode != 0 and _euid() == 0:
            raise RuntimeError(renice_res.stderr.strip() or renice_res.stdout.strip() or "renice failed")
        return {
            "pid": pid,
            "mode": mode,
            "renice": renice_res.stdout.strip() or renice_res.stderr.strip(),
        }
    ionice_cmd = ["ionice", "-c", io_class]
    if io_level is not None:
        ionice_cmd.extend(["-n", io_level])
    ionice_cmd.extend(["-p", str(pid)])
    ionice_res = subprocess.run(ionice_cmd, capture_output=True, text=True, check=False)

    if renice_res.returncode != 0 and _euid() == 0:
        raise RuntimeError(renice_res.stderr.strip() or renice_res.stdout.strip() or "renice failed")
    if ionice_res.returncode != 0 and _euid() == 0:
        raise RuntimeError(ionice_res.stderr.strip() or ionice_res.stdout.strip() or "ionice failed")

    return {
        "pid": pid,
        "mode": mode,
        "renice": renice_res.stdout.strip() or renice_res.stderr.strip(),
    }


def _validate_clamscan_args(cmd_args: list[str]) -> list[str]:
    """Validate and resolve trusted clamscan executable and allowlisted arguments."""
    if not cmd_args:
        raise ValueError("cmd_args cannot be empty")
    raw_exe = str(cmd_args[0])
    allowed_exe_names = ("clamscan", "clamscan.exe")
    if "\x00" in raw_exe or os.path.basename(raw_exe).lower() not in allowed_exe_names:
        raise PermissionError("Only clamscan may be launched")

    if os.path.isabs(raw_exe):
        resolved_exe = os.path.realpath(raw_exe)
        if os.path.basename(resolved_exe).lower() not in allowed_exe_names:
            raise PermissionError("Only clamscan may be launched")
    else:
        fallbacks: tuple[str, ...] = ("/usr/bin/clamscan",)
        if IS_WINDOWS:
            fallbacks = tuple(os.path.join(d, "clamscan.exe") for d in _win_clamav_dirs())
        elif IS_MACOS:
            fallbacks = tuple(os.path.join(d, "clamscan") for d in _mac_clamav_dirs())
        resolved_exe = _find_binary_path("clamscan", fallbacks) or (
            "clamscan.exe" if IS_WINDOWS else "clamscan" if IS_MACOS else "/usr/bin/clamscan"
        )
        if os.path.exists(resolved_exe):
            resolved_exe = os.path.realpath(resolved_exe)

    if (not IS_WINDOWS) and _euid() == 0:
        trusted_dirs = (
            ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/opt/homebrew/bin/", "/usr/local/bin/", "/opt/local/bin/")
            if IS_MACOS
            else ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/")
        )
        if not resolved_exe.startswith(trusted_dirs) or not _is_secure_root_owned_path(resolved_exe):
            raise PermissionError(f"Refusing untrusted clamscan binary: {resolved_exe}")

    validated: list[str] = [resolved_exe]
    simple_flags = {"-r", "--recursive", "-i", "--infected", "--no-summary"}
    size_re = re.compile(r"^\d+[KMG]?$", re.IGNORECASE)
    args_list = list(cmd_args[1:])
    idx = 0
    while idx < len(args_list):
        s = str(args_list[idx])
        idx += 1
        if not s or "\x00" in s:
            raise ValueError("Invalid clamscan argument")
        if s in simple_flags:
            validated.append(s)
        elif s.startswith("--exclude-dir="):
            validated.append(s)
        elif s in ("--cross-fs=no", "--cross-fs=yes"):
            validated.append(s)
        elif s.startswith("--max-filesize=") and size_re.match(s.split("=", 1)[1]):
            validated.append(s)
        elif s.startswith("--max-scansize=") and size_re.match(s.split("=", 1)[1]):
            validated.append(s)
        elif s.startswith("--database="):
            if (not IS_WINDOWS) and (not IS_MACOS) and _euid() == 0:
                raise PermissionError(f"Unsupported or disallowed clamscan flag: {s}")
            db_arg = s.split("=", 1)[1].strip()
            if not db_arg or "\x00" in db_arg or not os.path.isabs(db_arg):
                raise ValueError(f"Database path must be absolute: {db_arg}")
            validated.append(f"--database={db_arg}")
        elif s == "-d" and idx < len(args_list):
            if (not IS_WINDOWS) and (not IS_MACOS) and _euid() == 0:
                raise PermissionError(f"Unsupported or disallowed clamscan flag: {s}")
            db_arg = str(args_list[idx]).strip()
            idx += 1
            if not db_arg or "\x00" in db_arg or not os.path.isabs(db_arg):
                raise ValueError(f"Database path must be absolute: {db_arg}")
            validated.append(f"--database={db_arg}")
        elif s.startswith("--log="):
            safe_log = _validate_helper_log_path(s.split("=", 1)[1])
            validated.append(f"--log={safe_log}")
        elif s.startswith("--move=") or s.startswith("--copy="):
            flag_name, target_q = s.split("=", 1)
            safe_q = _resolve_quarantine_dir(target_q)
            validated.append(f"{flag_name}={safe_q}")
        elif s.startswith("-"):
            raise PermissionError(f"Unsupported or disallowed clamscan flag: {s}")
        else:
            if not os.path.isabs(s):
                raise ValueError(f"Scan target path must be absolute: {s}")
            validated.append(s)
    return validated


def _helper_start_scan(params: dict[str, Any]) -> dict[str, Any]:
    raw_args = [str(arg) for arg in params.get("cmd_args", [])]
    cmd_args = _validate_clamscan_args(raw_args)
    raw_log = str(params.get("log_path") or "").strip()
    log_path = _validate_helper_log_path(raw_log) if raw_log else ""
    truncate_log = bool(params.get("truncate_log", False))

    has_log_flag = any(
        arg == "-l" or arg == "--log" or arg.startswith("--log=") for arg in cmd_args
    )

    if log_path:
        parent_dir = os.path.dirname(log_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        if os.path.islink(log_path):
            raise PermissionError(f"Refusing symlink log path: {log_path}")
        nofol = getattr(os, "O_NOFOLLOW", 0)
        if truncate_log and os.path.exists(log_path):
            fd = os.open(log_path, os.O_WRONLY | os.O_TRUNC | nofol, 0o644)
            os.close(fd)
        elif not os.path.exists(log_path):
            fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | nofol, 0o644)
            os.close(fd)
        _ensure_log_readable(log_path)

    log_fh = None
    try:
        if log_path and not has_log_flag:
            log_fh = open(log_path, "ab")
            stdout_target: Any = log_fh
            stderr_target: Any = subprocess.STDOUT
        else:
            stdout_target = subprocess.DEVNULL
            stderr_target = subprocess.DEVNULL

        popen_kwargs: dict[str, Any] = {
            "stdin": subprocess.DEVNULL,
            "stdout": stdout_target,
            "stderr": stderr_target,
            "close_fds": not IS_WINDOWS,
        }
        if IS_WINDOWS:
            popen_kwargs["creationflags"] = _SUBPROCESS_NO_WINDOW
        else:
            popen_kwargs["start_new_session"] = True

        proc = subprocess.Popen(cmd_args, **popen_kwargs)
        with _SPAWNED_PROCS_LOCK:
            _SPAWNED_PROCS[proc.pid] = proc
            _SPAWNED_PROCS_META[proc.pid] = {
                "cmdline": cmd_args,
                "start_time": time.monotonic(),
                "log_path": log_path,
            }

        def _wait_and_cleanup(p: subprocess.Popen[Any] = proc) -> None:
            try:
                p.wait()
            finally:
                with _SPAWNED_PROCS_LOCK:
                    _SPAWNED_PROCS.pop(p.pid, None)
                    _SPAWNED_PROCS_META.pop(p.pid, None)
                    _WINDOWS_PAUSED_PIDS.discard(p.pid)

        # Reap exited child clamscan asynchronously so helper never leaves Z-state zombies.
        threading.Thread(target=_wait_and_cleanup, daemon=True).start()
    finally:
        if log_fh is not None:
            log_fh.close()

    return {"pid": proc.pid, "cmd": cmd_args, "log_path": log_path}


_CLAMAV_DB_EXTS = (".cvd", ".cld", ".ndb", ".hdb", ".ldb")


def _has_clamav_db_files(db_dir: str) -> bool:
    """Return True if db_dir contains at least one non-empty signature database file."""
    if not db_dir or not os.path.isdir(db_dir):
        return False
    try:
        for name in os.listdir(db_dir):
            if name.endswith(_CLAMAV_DB_EXTS):
                full = os.path.join(db_dir, name)
                if os.path.isfile(full) and os.path.getsize(full) > 0:
                    return True
    except OSError:
        pass
    return False


def _mac_clamav_db_dirs() -> list[str]:
    return [
        "/opt/homebrew/var/lib/clamav",
        "/usr/local/var/lib/clamav",
        "/opt/local/var/db/clamav",
        "/var/lib/clamav",
        str(APP_DATA_DIR / "database"),
    ]


def _default_db_dir() -> str:
    """Return platform-appropriate ClamAV virus signature directory."""
    if IS_WINDOWS:
        prog_data = os.environ.get("ProgramData") or r"C:\ProgramData"
        candidates = [os.path.join(prog_data, "ClamAV", "db")]
        for d in _win_clamav_dirs():
            candidates.append(os.path.join(d, "database"))
            candidates.append(os.path.join(d, "db"))
        candidates.append(str(APP_DATA_DIR / "database"))
        for c in candidates:
            if _has_clamav_db_files(c):
                return c
        return str(APP_DATA_DIR / "database")
    if IS_MACOS:
        for c in _mac_clamav_db_dirs():
            if _has_clamav_db_files(c):
                return c
        return str(APP_DATA_DIR / "database")
    if _has_clamav_db_files("/var/lib/clamav"):
        return "/var/lib/clamav"
    user_db = str(APP_DATA_DIR / "database")
    if _has_clamav_db_files(user_db):
        return user_db
    return "/var/lib/clamav"


def _is_dir_writable(path: str) -> bool:
    try:
        os.makedirs(path, exist_ok=True)
        fd, probe = tempfile.mkstemp(prefix=".write_test_", dir=path)
        os.close(fd)
        os.unlink(probe)
        return True
    except OSError:
        return False


def _ensure_windows_freshclam_config(
    freshclam_bin: str | None = None,
    force_user_dir: bool = False,
) -> tuple[str, str]:
    """Ensure a valid, writable freshclam.conf and database dir exist."""
    app_db = str(APP_DATA_DIR / "database")
    db_candidates: list[str] = []
    if not force_user_dir:
        if freshclam_bin:
            db_candidates.append(os.path.join(os.path.dirname(freshclam_bin), "database"))
        for d in _win_clamav_dirs():
            db_candidates.append(os.path.join(d, "database"))
    db_dir = app_db
    for cand in db_candidates:
        if _has_clamav_db_files(cand) and _is_dir_writable(cand):
            db_dir = cand
            break
    else:
        if (not force_user_dir) and freshclam_bin:
            install_db = os.path.join(os.path.dirname(freshclam_bin), "database")
            if _is_dir_writable(install_db):
                db_dir = install_db
    os.makedirs(db_dir, exist_ok=True)

    conf_path = str(APP_DATA_DIR / "freshclam.conf")
    if (not force_user_dir) and freshclam_bin:
        install_dir = os.path.dirname(freshclam_bin)
        install_conf = os.path.join(install_dir, "freshclam.conf")
        if _is_dir_writable(install_dir) and (
            not os.path.exists(install_conf) or os.access(install_conf, os.W_OK)
        ):
            conf_path = install_conf

    os.makedirs(os.path.dirname(conf_path), exist_ok=True)
    lines: list[str] = []
    has_mirror = False
    has_dbdir = False
    if os.path.isfile(conf_path):
        try:
            with open(conf_path, "r", encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    stripped = raw.strip()
                    if stripped.lower() == "example":
                        lines.append("# Example (disabled automatically by ClamAV Security Center)\n")
                        continue
                    if stripped.startswith("DatabaseMirror "):
                        has_mirror = True
                    elif stripped.startswith("DatabaseDirectory "):
                        has_dbdir = True
                    lines.append(raw)
        except OSError:
            lines = []
    if not lines:
        lines = [
            "# Generated automatically by ClamAV Security Center\n",
            "DatabaseMirror database.clamav.net\n",
            f'DatabaseDirectory "{db_dir}"\n',
            "Checks 24\n",
        ]
    else:
        if not has_mirror:
            lines.append("DatabaseMirror database.clamav.net\n")
        if not has_dbdir:
            lines.append(f'DatabaseDirectory "{db_dir}"\n')

    with open(conf_path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)
    return conf_path, db_dir


def _detect_freshclam_services() -> tuple[list[str], str]:
    """Detect active/installed freshclam systemd unit across RHEL and openSUSE."""
    if IS_WINDOWS or IS_MACOS:
        return [], "manual"
    candidates = ("clamav-freshclam.service", "freshclam.service", "freshclam.timer")
    active_units: list[str] = []
    any_known_status = "inactive"
    for unit in candidates:
        try:
            res = subprocess.run(
                ["systemctl", "is-active", unit],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            status = res.stdout.strip() or res.stderr.strip() or "inactive"
            if res.returncode == 0:
                active_units.append(unit)
                any_known_status = "active"
            elif status in ("inactive", "activating", "deactivating", "failed"):
                any_known_status = status
        except OSError:
            pass
    return active_units, ("active" if active_units else any_known_status)


def _helper_run_freshclam(params: dict[str, Any]) -> dict[str, Any]:
    win_candidates = tuple(os.path.join(d, "freshclam.exe") for d in _win_clamav_dirs()) if IS_WINDOWS else ()
    mac_candidates = tuple(os.path.join(d, "freshclam") for d in _mac_clamav_dirs()) if IS_MACOS else ()
    freshclam_bin = _find_binary_path(
        "freshclam",
        win_candidates
        if IS_WINDOWS
        else (*mac_candidates, "/usr/sbin/freshclam", "/usr/local/bin/freshclam")
        if IS_MACOS
        else ("/usr/sbin/freshclam", "/usr/local/bin/freshclam"),
    )
    if not freshclam_bin or not os.path.exists(freshclam_bin):
        raise FileNotFoundError("freshclam binary not found")

    if IS_WINDOWS or IS_MACOS or bool(params.get("user_mode")):
        conf_path, db_dir = _ensure_windows_freshclam_config(
            freshclam_bin,
            force_user_dir=(not IS_WINDOWS) and (IS_MACOS or bool(params.get("user_mode"))),
        )
        update_res = subprocess.run(
            [freshclam_bin, f"--config-file={conf_path}", f"--datadir={db_dir}"],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
            creationflags=_SUBPROCESS_NO_WINDOW if IS_WINDOWS else 0,
        )
        notes = [f"Config: {conf_path}", f"Database: {db_dir}"]
        combined = "\n".join(
            part for part in [*notes, update_res.stdout.strip(), update_res.stderr.strip()] if part
        )
        return {
            "success": update_res.returncode == 0,
            "returncode": update_res.returncode,
            "output": combined,
        }

    active_units, _ = _detect_freshclam_services()
    service_units = [u for u in active_units if u.endswith(".service")]
    notes = []
    stopped_units: list[str] = []

    for unit in service_units:
        stop_res = subprocess.run(
            ["systemctl", "stop", unit],
            capture_output=True,
            text=True,
            check=False,
        )
        if stop_res.returncode == 0:
            stopped_units.append(unit)
            notes.append(f"Temporarily stopped {unit}.")
        else:
            notes.append(f"Warning stopping {unit}: {stop_res.stderr.strip()}")

    try:
        update_res = subprocess.run(
            [freshclam_bin],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    finally:
        for unit in stopped_units:
            start_res = subprocess.run(
                ["systemctl", "start", unit],
                capture_output=True,
                text=True,
                check=False,
            )
            if start_res.returncode == 0:
                notes.append(f"Restarted {unit}.")
            else:
                notes.append(f"Warning restarting {unit}: {start_res.stderr.strip()}")

    combined = "\n".join(
        part for part in [*notes, update_res.stdout.strip(), update_res.stderr.strip()] if part
    )
    return {
        "success": update_res.returncode == 0,
        "returncode": update_res.returncode,
        "output": combined,
    }


def _quarantine_manifest_path(qdir: str) -> Path:
    return Path(qdir) / QUARANTINE_MANIFEST


def _load_quarantine_manifest(qdir: str) -> dict[str, dict[str, Any]]:
    data = load_json_file(_quarantine_manifest_path(qdir), {})
    return data if isinstance(data, dict) else {}


def _save_quarantine_manifest(qdir: str, manifest: dict[str, dict[str, Any]]) -> None:
    save_json_file(_quarantine_manifest_path(qdir), manifest)


def _validate_quarantine_item_name(qdir: str, name: str) -> str:
    if not name or os.path.basename(name) != name or name in (".", "..", QUARANTINE_MANIFEST):
        raise ValueError(f"Invalid quarantine item name: {name}")
    full = os.path.join(qdir, name)
    if not (os.path.isfile(full) or os.path.islink(full)):
        raise FileNotFoundError(f"Quarantined file not found: {full}")
    return full


def _helper_quarantine_file(params: dict[str, Any]) -> dict[str, Any]:
    src = str(params["path"])
    qdir = _resolve_quarantine_dir(params.get("quarantine_dir"))
    threat_name = str(params.get("threat_name") or "Detected Threat")
    if "\x00" in src or not os.path.isabs(src):
        raise ValueError("Source path must be absolute")
    if _is_protected_system_path(src):
        raise PermissionError(f"Refusing to quarantine protected system path: {src}")
    if not (os.path.isfile(src) or os.path.islink(src)):
        raise FileNotFoundError(f"File not found: {src}")

    os.makedirs(qdir, mode=0o700, exist_ok=True)
    if os.path.islink(qdir):
        raise PermissionError(f"Refusing symlink quarantine directory: {qdir}")
    if (not IS_WINDOWS) and _euid() == 0 and os.lstat(qdir).st_uid != 0:
        raise PermissionError(f"Quarantine directory must be owned by root: {qdir}")
    if not IS_WINDOWS:
        os.chmod(qdir, 0o700)

    try:
        file_size = os.path.getsize(src) if os.path.isfile(src) and not os.path.islink(src) else 0
    except OSError:
        file_size = 0

    base = os.path.basename(src)
    dest = os.path.join(qdir, base)
    if os.path.lexists(dest):
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        candidate = os.path.join(qdir, f"{base}.{stamp}")
        suffix = 1
        while os.path.lexists(candidate):
            candidate = os.path.join(qdir, f"{base}.{stamp}.{suffix}")
            suffix += 1
        dest = candidate

    shutil.move(src, dest)
    if not os.path.islink(dest):
        os.chmod(dest, 0o600)
    qname = os.path.basename(dest)
    manifest = _load_quarantine_manifest(qdir)
    manifest[qname] = {
        "original_path": src,
        "threat_name": threat_name,
        "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "size": file_size,
    }
    _save_quarantine_manifest(qdir, manifest)
    return {"src": src, "dest": dest, "name": qname}


def _helper_list_quarantine(params: dict[str, Any]) -> dict[str, Any]:
    qdir = _resolve_quarantine_dir(params.get("quarantine_dir"))
    if not os.path.isdir(qdir):
        return {"items": []}

    manifest = _load_quarantine_manifest(qdir)
    items: list[dict[str, Any]] = []
    for name in sorted(os.listdir(qdir)):
        if name == QUARANTINE_MANIFEST:
            continue
        full = os.path.join(qdir, name)
        if not (os.path.isfile(full) or os.path.islink(full)):
            continue
        meta = manifest.get(name) or {}
        try:
            st = os.lstat(full)
            size = int(meta.get("size") or st.st_size)
            date_str = str(
                meta.get("date")
                or datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            )
        except OSError:
            size = int(meta.get("size") or 0)
            date_str = str(meta.get("date") or "Unknown")

        items.append(
            {
                "name": name,
                "original_path": str(meta.get("original_path") or "Unknown"),
                "threat_name": str(meta.get("threat_name") or "Unknown"),
                "date": date_str,
                "size": size,
            }
        )

    items.sort(key=lambda item: item["date"], reverse=True)
    return {"items": items}


def _ensure_no_symlink_ancestors_and_mkdir(directory: str) -> None:
    """Create missing directories along an absolute path while rejecting any symlink ancestor."""
    parts = Path(os.path.abspath(directory)).parts
    if not parts:
        return
    cur = Path(parts[0])
    for part in parts[1:]:
        cur = cur / part
        if cur.is_symlink():
            raise PermissionError(f"Refusing to restore across symlink directory: {cur}")
        if not cur.exists():
            cur.mkdir(mode=0o755, exist_ok=True)
        elif not cur.is_dir():
            raise NotADirectoryError(f"Non-directory ancestor in restore path: {cur}")


def _helper_restore_quarantine(params: dict[str, Any]) -> dict[str, Any]:
    qdir = _resolve_quarantine_dir(params.get("quarantine_dir"))
    name = str(params["name"])
    src = _validate_quarantine_item_name(qdir, name)

    manifest = _load_quarantine_manifest(qdir)
    meta = manifest.get(name) or {}
    orig_path = str(meta.get("original_path") or "").strip()
    requested_dest = str(params.get("dest_path") or "").strip()
    dest = requested_dest or orig_path
    if not dest or dest == "Unknown" or "\x00" in dest or not os.path.isabs(dest):
        raise ValueError("Valid absolute destination path required to restore file.")
    if _is_protected_system_path(dest):
        raise PermissionError(f"Refusing to restore into protected system path: {dest}")

    invoker = _resolve_invoking_username()
    if (not IS_WINDOWS) and _euid() == 0 and requested_dest and requested_dest != orig_path:
        # Custom destination overrides may only restore into the invoking user's home or recorded path
        if not invoker or not os.path.realpath(requested_dest).startswith(f"/home/{invoker}/"):
            raise PermissionError("Custom restore destination must stay inside caller's home directory.")

    if os.path.lexists(dest):
        raise FileExistsError(f"Destination already exists: {dest}")

    parent = os.path.dirname(dest)
    if parent:
        _ensure_no_symlink_ancestors_and_mkdir(parent)

    shutil.move(src, dest)
    if (not IS_WINDOWS) and dest.startswith("/home/") and pwd is not None:
        parts = Path(dest).parts
        if len(parts) >= 3:
            target_user = parts[2]
            # Only restore user ownership if original location also belonged to that user's home
            if orig_path.startswith(f"/home/{target_user}/"):
                try:
                    pw = pwd.getpwnam(target_user)
                    os.chown(dest, pw.pw_uid, pw.pw_gid)
                    if not os.path.islink(dest):
                        os.chmod(dest, 0o644)
                except (KeyError, OSError):
                    pass

    manifest.pop(name, None)
    _save_quarantine_manifest(qdir, manifest)
    return {"name": name, "restored_to": dest}


def _helper_delete_quarantine(params: dict[str, Any]) -> dict[str, Any]:
    qdir = _resolve_quarantine_dir(params.get("quarantine_dir"))
    name = str(params["name"])
    src = _validate_quarantine_item_name(qdir, name)
    os.unlink(src)
    manifest = _load_quarantine_manifest(qdir)
    manifest.pop(name, None)
    _save_quarantine_manifest(qdir, manifest)
    return {"deleted": name}


def _helper_delete_file(params: dict[str, Any]) -> dict[str, Any]:
    target = str(params["path"])
    if "\x00" in target or not os.path.isabs(target):
        raise ValueError("Target path must be absolute")
    if _is_protected_system_path(target):
        raise PermissionError(f"Refusing to delete protected system path: {target}")
    if not (os.path.isfile(target) or os.path.islink(target)):
        raise FileNotFoundError(f"File not found: {target}")
    os.unlink(target)
    return {"deleted": target}


def _helper_install_polkit_rule(params: dict[str, Any]) -> dict[str, Any]:
    if IS_WINDOWS or pwd is None:
        return {"rule_path": "", "username": ""}
    invoker = _resolve_invoking_username()
    username = invoker or str(params.get("username") or "").strip()
    if not username:
        raise ValueError("username is required")
    if invoker and params.get("username") and str(params.get("username")).strip() != invoker:
        raise PermissionError("Polkit rule can only be installed for the invoking user")
    pwd.getpwnam(username)

    if _euid() == 0:
        if not _is_secure_root_owned_path(SCRIPT_PATH):
            raise PermissionError(
                f"Refusing to install passwordless Polkit rule for user-writable script: {SCRIPT_PATH}"
            )
        if not _is_secure_root_owned_path(os.path.realpath(sys.executable)):
            raise PermissionError("Refusing to install passwordless Polkit rule for untrusted python binary")

    progs = sorted({sys.executable, os.path.realpath(sys.executable)})
    prog_checks = " || ".join(f'action.lookup("program") == {json.dumps(p)}' for p in progs)
    cmd_checks = " || ".join(
        f'action.lookup("command_line") == {json.dumps(f"{p} {SCRIPT_PATH} --helper")}' for p in progs
    )
    rule_js = (
        "polkit.addRule(function(action, subject) {\n"
        '    if (action.id == "org.freedesktop.policykit.exec" &&\n'
        "        subject.active && subject.local &&\n"
        f"        subject.user == {json.dumps(username)} &&\n"
        f"        ({prog_checks}) &&\n"
        f"        ({cmd_checks})) {{\n"
        "        return polkit.Result.YES;\n"
        "    }\n"
        "});\n"
    )
    os.makedirs(os.path.dirname(POLKIT_RULE_PATH), exist_ok=True)
    with open(POLKIT_RULE_PATH, "w", encoding="utf-8") as fh:
        fh.write(rule_js)
    os.chmod(POLKIT_RULE_PATH, 0o644)
    return {"rule_path": POLKIT_RULE_PATH, "username": username}


def _helper_windows_get_schedule() -> dict[str, Any]:
    """Read scheduled ClamAV scan settings and Task Scheduler next-run info on Windows."""
    cfg: dict[str, Any] = {
        "frequency": "weekly",
        "day_of_week": "Sun",
        "time_of_day": "03:00",
        "scan_type": "quick",
        "enabled": False,
    }
    saved = load_json_file(WINDOWS_SCHEDULE_CONFIG_PATH, {})
    if isinstance(saved, dict):
        cfg.update(saved)

    enabled = bool(cfg.get("enabled"))
    next_run = "-"
    try:
        res = subprocess.run(
            ["schtasks", "/Query", "/TN", WINDOWS_TASK_NAME, "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            check=False,
            creationflags=_SUBPROCESS_NO_WINDOW,
        )
        if res.returncode == 0 and res.stdout.strip():
            rows = list(csv.reader(res.stdout.splitlines()))
            if rows and len(rows[0]) >= 3:
                enabled = True
                next_run = rows[0][1].strip() or "-"
        else:
            enabled = False
    except OSError:
        pass
    cfg["enabled"] = enabled
    return {"enabled": enabled, "next_run": next_run, **cfg}


def _helper_windows_set_schedule(params: dict[str, Any]) -> dict[str, Any]:
    """Create, update, or remove the Windows Task Scheduler ClamAV scan task."""
    enabled = bool(params.get("enabled", False))
    day_map = {
        "monday": ("Mon", "MON"),
        "mon": ("Mon", "MON"),
        "tuesday": ("Tue", "TUE"),
        "tue": ("Tue", "TUE"),
        "wednesday": ("Wed", "WED"),
        "wed": ("Wed", "WED"),
        "thursday": ("Thu", "THU"),
        "thu": ("Thu", "THU"),
        "friday": ("Fri", "FRI"),
        "fri": ("Fri", "FRI"),
        "saturday": ("Sat", "SAT"),
        "sat": ("Sat", "SAT"),
        "sunday": ("Sun", "SUN"),
        "sun": ("Sun", "SUN"),
    }
    freq = "weekly" if str(params.get("frequency") or "weekly").lower() == "weekly" else "daily"
    day3, win_day = day_map.get(str(params.get("day_of_week") or "Sun").strip().lower(), ("Sun", "SUN"))
    parts = str(params.get("time_of_day") or "03:00").strip().split(":")
    try:
        hh = max(0, min(23, int(parts[0])))
        mm = max(0, min(59, int(parts[1]))) if len(parts) > 1 else 0
    except ValueError:
        hh, mm = 3, 0
    time_norm = f"{hh:02d}:{mm:02d}"
    stype = "full" if str(params.get("scan_type") or "quick").lower() == "full" else "quick"

    cfg = {
        "enabled": enabled,
        "frequency": freq,
        "day_of_week": day3,
        "time_of_day": time_norm,
        "scan_type": stype,
    }
    save_json_file(WINDOWS_SCHEDULE_CONFIG_PATH, cfg)

    if not enabled:
        subprocess.run(
            ["schtasks", "/Delete", "/TN", WINDOWS_TASK_NAME, "/F"],
            capture_output=True,
            text=True,
            check=False,
            creationflags=_SUBPROCESS_NO_WINDOW,
        )
        return _helper_windows_get_schedule()

    clamscan_bin = _find_binary_path(
        "clamscan", tuple(os.path.join(d, "clamscan.exe") for d in _win_clamav_dirs())
    ) or "clamscan.exe"
    quick_targets = [str(p) for p in (params.get("quick_targets") or []) if os.path.exists(str(p))]
    targets = [_system_root_target()] if stype == "full" else (quick_targets or get_quick_scan_targets())
    db_flag = f'--database="{_default_db_dir()}" ' if _has_clamav_db_files(_default_db_dir()) else ""
    quoted_targets = " ".join(f'"{t}"' for t in targets)
    cmd_script = APP_DATA_DIR / "scheduled-scan.cmd"
    cmd_script.parent.mkdir(parents=True, exist_ok=True)
    cmd_script.write_text(
        f'@echo off\r\n"{clamscan_bin}" -r {db_flag}--max-filesize=100M --max-scansize=100M '
        f'--log="{DEFAULT_LOG_PATH}" {quoted_targets}\r\n',
        encoding="utf-8",
    )

    sch_cmd = [
        "schtasks",
        "/Create",
        "/TN",
        WINDOWS_TASK_NAME,
        "/F",
        "/SC",
        "WEEKLY" if freq == "weekly" else "DAILY",
    ]
    if freq == "weekly":
        sch_cmd.extend(["/D", win_day])
    sch_cmd.extend(["/ST", time_norm, "/TR", f'"{cmd_script}"'])
    res = subprocess.run(
        sch_cmd,
        capture_output=True,
        text=True,
        check=False,
        creationflags=_SUBPROCESS_NO_WINDOW,
    )
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip() or res.stdout.strip() or "Failed creating scheduled Windows task")
    return _helper_windows_get_schedule()


def _helper_macos_get_schedule() -> dict[str, Any]:
    """Read scheduled ClamAV scan settings and launchd LaunchAgent status on macOS."""
    cfg: dict[str, Any] = {
        "frequency": "weekly",
        "day_of_week": "Sun",
        "time_of_day": "03:00",
        "scan_type": "quick",
        "enabled": False,
    }
    saved = load_json_file(MACOS_SCHEDULE_CONFIG_PATH, {})
    if isinstance(saved, dict):
        cfg.update(saved)

    enabled = bool(cfg.get("enabled")) and os.path.isfile(MACOS_LAUNCH_AGENT_PLIST)
    if enabled:
        if cfg.get("frequency") == "daily":
            next_run = f"Daily {cfg.get('time_of_day', '03:00')} (launchd)"
        else:
            next_run = f"{cfg.get('day_of_week', 'Sun')} {cfg.get('time_of_day', '03:00')} (launchd)"
    else:
        next_run = "-"
    cfg["enabled"] = enabled
    return {"enabled": enabled, "next_run": next_run, **cfg}


def _helper_macos_set_schedule(params: dict[str, Any]) -> dict[str, Any]:
    """Create, update, or remove the macOS launchd LaunchAgent ClamAV scan timer."""
    enabled = bool(params.get("enabled", False))
    day_map = {
        "monday": ("Mon", 1),
        "mon": ("Mon", 1),
        "tuesday": ("Tue", 2),
        "tue": ("Tue", 2),
        "wednesday": ("Wed", 3),
        "wed": ("Wed", 3),
        "thursday": ("Thu", 4),
        "thu": ("Thu", 4),
        "friday": ("Fri", 5),
        "fri": ("Fri", 5),
        "saturday": ("Sat", 6),
        "sat": ("Sat", 6),
        "sunday": ("Sun", 0),
        "sun": ("Sun", 0),
    }
    freq = "weekly" if str(params.get("frequency") or "weekly").lower() == "weekly" else "daily"
    day3, weekday_num = day_map.get(str(params.get("day_of_week") or "Sun").strip().lower(), ("Sun", 0))
    parts = str(params.get("time_of_day") or "03:00").strip().split(":")
    try:
        hh = max(0, min(23, int(parts[0])))
        mm = max(0, min(59, int(parts[1]))) if len(parts) > 1 else 0
    except ValueError:
        hh, mm = 3, 0
    time_norm = f"{hh:02d}:{mm:02d}"
    stype = "full" if str(params.get("scan_type") or "quick").lower() == "full" else "quick"

    cfg = {
        "enabled": enabled,
        "frequency": freq,
        "day_of_week": day3,
        "time_of_day": time_norm,
        "scan_type": stype,
    }
    save_json_file(MACOS_SCHEDULE_CONFIG_PATH, cfg)

    if not enabled:
        if os.path.exists(MACOS_LAUNCH_AGENT_PLIST):
            try:
                subprocess.run(
                    ["launchctl", "unload", MACOS_LAUNCH_AGENT_PLIST],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            except OSError:
                pass
            try:
                os.unlink(MACOS_LAUNCH_AGENT_PLIST)
            except OSError:
                pass
        return _helper_macos_get_schedule()

    clamscan_bin = _find_binary_path(
        "clamscan", tuple(os.path.join(d, "clamscan") for d in _mac_clamav_dirs())
    ) or "clamscan"
    quick_targets = [str(p) for p in (params.get("quick_targets") or []) if os.path.exists(str(p))]
    targets = [_system_root_target()] if stype == "full" else (quick_targets or get_quick_scan_targets())
    db_dir = _default_db_dir()
    prog_args = [clamscan_bin, "-r"]
    if _has_clamav_db_files(db_dir):
        prog_args.append(f"--database={db_dir}")
    prog_args.extend(["--max-filesize=100M", "--max-scansize=100M", f"--log={DEFAULT_LOG_PATH}", *targets])

    cal_interval: dict[str, int] = {"Hour": hh, "Minute": mm}
    if freq == "weekly":
        cal_interval["Weekday"] = weekday_num

    plist_data = {
        "Label": MACOS_LAUNCH_AGENT_LABEL,
        "ProgramArguments": prog_args,
        "StartCalendarInterval": cal_interval,
        "Nice": 19,
        "LowPriorityIO": True,
        "StandardOutPath": DEFAULT_LOG_PATH,
        "StandardErrorPath": DEFAULT_LOG_PATH,
    }
    os.makedirs(os.path.dirname(MACOS_LAUNCH_AGENT_PLIST), exist_ok=True)
    with open(MACOS_LAUNCH_AGENT_PLIST, "wb") as fh:
        fh.write(plistlib.dumps(plist_data))
    subprocess.run(
        ["launchctl", "unload", MACOS_LAUNCH_AGENT_PLIST],
        capture_output=True,
        text=True,
        check=False,
    )
    res = subprocess.run(
        ["launchctl", "load", "-w", MACOS_LAUNCH_AGENT_PLIST],
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        err = res.stderr.strip() or res.stdout.strip()
        if err:
            raise RuntimeError(err)
    return _helper_macos_get_schedule()


def _is_user_schedule_mode(params: dict[str, Any] | None = None) -> bool:
    if IS_WINDOWS or IS_MACOS:
        return False
    if params and "user_mode" in params:
        return bool(params["user_mode"])
    if not SYSTEMD_TIMER_PATH.startswith("/etc/"):
        return False
    return _euid() != 0


def _helper_get_schedule(params: dict[str, Any]) -> dict[str, Any]:
    if IS_WINDOWS:
        return _helper_windows_get_schedule()
    if IS_MACOS:
        return _helper_macos_get_schedule()
    user_mode = _is_user_schedule_mode(params)
    tmr_path = USER_SYSTEMD_TIMER_PATH if user_mode else SYSTEMD_TIMER_PATH
    systemctl_cmd = ["systemctl", "--user"] if user_mode else ["systemctl"]
    cfg: dict[str, Any] = {
        "frequency": "weekly",
        "day_of_week": "Sun",
        "time_of_day": "03:00",
        "scan_type": "quick",
    }
    if os.path.exists(tmr_path):
        try:
            with open(tmr_path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.startswith("# CLAMAV_GUI_CONFIG="):
                        parsed = json.loads(line.split("=", 1)[1].strip())
                        if isinstance(parsed, dict):
                            cfg.update(parsed)
                        break
        except (OSError, json.JSONDecodeError):
            pass

    enabled_res = subprocess.run(
        [*systemctl_cmd, "is-enabled", "clamav-gui-scan.timer"],
        capture_output=True,
        text=True,
        check=False,
    )
    enabled = enabled_res.returncode == 0 and enabled_res.stdout.strip() == "enabled"
    if (
        user_mode
        and not enabled
        and os.path.exists(tmr_path)
        and ("connect to bus" in (enabled_res.stderr or "").lower() or "failed to connect" in (enabled_res.stderr or "").lower())
    ):
        enabled = bool(cfg.get("enabled", False))

    next_run = "-"
    if enabled:
        list_res = subprocess.run(
            [*systemctl_cmd, "list-timers", "clamav-gui-scan.timer", "--no-pager", "--no-legend"],
            capture_output=True,
            text=True,
            check=False,
        )
        out = list_res.stdout.strip()
        if out:
            first_line = out.splitlines()[0].strip()
            m_next = re.match(
                r"^([A-Za-z]{3}\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\s+[A-Za-z0-9+-]+)?)",
                first_line,
            )
            next_run = m_next.group(1) if m_next else first_line

    return {"enabled": enabled, "next_run": next_run, **cfg}


def _helper_set_schedule(params: dict[str, Any]) -> dict[str, Any]:
    if IS_WINDOWS:
        return _helper_windows_set_schedule(params)
    if IS_MACOS:
        return _helper_macos_set_schedule(params)
    user_mode = _is_user_schedule_mode(params)
    svc_path = USER_SYSTEMD_SERVICE_PATH if user_mode else SYSTEMD_SERVICE_PATH
    tmr_path = USER_SYSTEMD_TIMER_PATH if user_mode else SYSTEMD_TIMER_PATH
    systemctl_cmd = ["systemctl", "--user"] if user_mode else ["systemctl"]
    enabled = bool(params.get("enabled", False))
    frequency = str(params.get("frequency") or "weekly")
    day_of_week = str(params.get("day_of_week") or "Sun")
    time_of_day = str(params.get("time_of_day") or "03:00")
    scan_type = str(params.get("scan_type") or "quick")
    quick_targets = [str(p) for p in (params.get("quick_targets") or [])]

    service_txt, timer_txt, cfg = build_systemd_schedule_units(
        frequency,
        day_of_week,
        time_of_day,
        scan_type,
        quick_targets,
        enabled=enabled,
        user_mode=user_mode,
    )
    os.makedirs(os.path.dirname(svc_path), exist_ok=True)
    os.makedirs(os.path.dirname(tmr_path), exist_ok=True)
    with open(svc_path, "w", encoding="utf-8") as fh:
        fh.write(service_txt)
    with open(tmr_path, "w", encoding="utf-8") as fh:
        fh.write(timer_txt)
    os.chmod(svc_path, 0o644)
    os.chmod(tmr_path, 0o644)

    subprocess.run([*systemctl_cmd, "daemon-reload"], capture_output=True, text=True, check=not user_mode)
    action = ["enable", "--now"] if enabled else ["disable", "--now"]
    res = subprocess.run(
        [*systemctl_cmd, *action, "clamav-gui-scan.timer"],
        capture_output=True,
        text=True,
        check=False,
    )
    if enabled and res.returncode != 0:
        err_low = (res.stderr or "").lower()
        if not (user_mode and ("connect to bus" in err_low or "failed to connect" in err_low)):
            raise RuntimeError(res.stderr.strip() or res.stdout.strip() or "Failed enabling timer")

    return _helper_get_schedule({"user_mode": True} if user_mode else {})


HELPER_HANDLERS = {
    "ping": _helper_ping,
    "inspect_proc": _helper_inspect_proc,
    "signal_proc": _helper_signal_proc,
    "set_priority": _helper_set_priority,
    "start_scan": _helper_start_scan,
    "run_freshclam": _helper_run_freshclam,
    "quarantine_file": _helper_quarantine_file,
    "list_quarantine": _helper_list_quarantine,
    "restore_quarantine": _helper_restore_quarantine,
    "delete_quarantine": _helper_delete_quarantine,
    "delete_file": _helper_delete_file,
    "install_polkit_rule": _helper_install_polkit_rule,
    "get_schedule": _helper_get_schedule,
    "set_schedule": _helper_set_schedule,
}


def run_helper() -> int:
    """Run headless JSON-over-stdin/stdout privileged helper."""
    print(json.dumps({"type": "ready", "uid": _euid()}), flush=True)
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line or not line.startswith("{"):
            continue
        req_id = None
        try:
            req = json.loads(line)
            req_id = req.get("id")
            action = req.get("action")
            handler = HELPER_HANDLERS.get(action)
            if handler is None:
                raise ValueError(f"Unknown action: {action}")
            result = handler(req.get("params") or {})
            resp = {"id": req_id, "ok": True, "result": result}
        except Exception as exc:  # noqa: BLE001
            resp = {"id": req_id, "ok": False, "error": str(exc)}
        print(json.dumps(resp), flush=True)
    return 0


def run_self_test() -> int:
    """Verify /proc discovery, log parsing, and helper JSON protocol."""
    print("[self-test] Discovering clamscan processes...")
    procs = discover_clamscan_processes()
    print(f"[self-test] Found {len(procs)} clamscan process(es).")
    for proc in procs:
        print(
            f"  PID={proc['pid']} user={proc['user']} state={proc['state']} "
            f"nice={proc['nice']} rss={proc['rss_kb']}KB elapsed={format_duration(proc['elapsed_sec'])} "
            f"log={proc['log_path']}"
        )

    sample_log = "/tmp/eicar.com: Win.Test.EICAR_HDB-1 FOUND\n/home/user/doc.pdf: OK\n"
    threats = parse_threats_from_text(sample_log)
    assert threats == [("/tmp/eicar.com", "Win.Test.EICAR_HDB-1")], f"Unexpected threats: {threats}"
    print("[self-test] Threat parser passed.")

    parsed_cmd = parse_scan_targets_and_limits(
        [
            "clamscan",
            "-r",
            "-i",
            "--exclude-dir=^/sys",
            "--exclude-dir=^/proc",
            "--max-filesize=100M",
            "--log=/var/log/clamav-scan.log",
            "/",
        ]
    )
    assert parsed_cmd["targets"] == ["/"], f"Unexpected targets: {parsed_cmd}"
    assert parsed_cmd["max_filesize"] == 100 * 1024 * 1024
    assert "/sys" in parsed_cmd["exclude_dirs"] and "/proc" in parsed_cmd["exclude_dirs"]
    used_bytes = estimate_statvfs_used_bytes(parsed_cmd["targets"], parsed_cmd["cross_fs"])
    assert used_bytes > 0, f"Unexpected used_bytes: {used_bytes}"
    print(f"[self-test] Target parser & Stage 1 statvfs estimator passed ({format_bytes(used_bytes)}).")

    sample_summary = (
        "----------- SCAN SUMMARY -----------\n"
        "Scanned files: 42\n"
        "Infected files: 1\n"
        "Data scanned: 12.50 MB\n"
        "Time: 3.210 sec (0 m 3 s)\n"
        "Start Date: 2026:11:21 16:00:00\n"
        "End Date:   2026:11:21 16:00:03\n"
    )
    summaries = parse_scan_summaries_from_log(sample_summary)
    assert len(summaries) == 1 and summaries[0]["threats"] == 1
    assert summaries[0]["date"] == "2026-11-21 16:00:03"
    svc_txt, tmr_txt, cfg = build_systemd_schedule_units("weekly", "Sunday", "03:15", "quick", ["/tmp"])
    assert "OnCalendar=Sun *-*-* 03:15:00" in tmr_txt and "SuccessExitStatus=0 1" in svc_txt
    assert cfg["frequency"] == "weekly"
    print("[self-test] Summary history parser & systemd schedule generator passed.")

    print("[self-test] Testing --helper JSON protocol...")
    helper_proc = subprocess.Popen(
        _self_helper_cmd(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        creationflags=_SUBPROCESS_NO_WINDOW,
    )
    try:
        assert helper_proc.stdout is not None and helper_proc.stdin is not None
        ready_line = helper_proc.stdout.readline().strip()
        ready_msg = json.loads(ready_line)
        assert ready_msg.get("type") == "ready", f"Unexpected ready: {ready_msg}"

        helper_proc.stdin.write("non-json-password-noise\n")
        helper_proc.stdin.write(json.dumps({"id": 1, "action": "ping", "params": {}}) + "\n")
        helper_proc.stdin.flush()
        ping_msg = json.loads(helper_proc.stdout.readline().strip())
        assert ping_msg["id"] == 1 and ping_msg["ok"] is True, f"Unexpected ping: {ping_msg}"

        test_log_path = SCRIPT_PATH
        cleanup_test_log = False
        if _is_posix_root():
            # Root helper confines log reads to /var/log/clam*.log; stage an ephemeral log there.
            if os.path.isdir("/var/log") and os.access("/var/log", os.W_OK):
                test_log_path = os.path.join("/var/log", f"clamav-selftest-{os.getpid()}.log")
                with open(test_log_path, "w", encoding="utf-8") as fh:
                    fh.write("# clamav-security-center self-test\n")
                cleanup_test_log = True
            else:
                test_log_path = ""
        elif not os.path.isfile(test_log_path):
            fd, test_log_path = tempfile.mkstemp(prefix="clamav-selftest-", suffix=".log")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write("# clamav-security-center self-test\n")
            cleanup_test_log = True

        try:
            helper_proc.stdin.write(
                json.dumps(
                    {
                        "id": 2,
                        "action": "inspect_proc",
                        "params": {"pid": os.getpid(), "log_path": test_log_path, "log_offset": 0},
                    }
                )
                + "\n"
            )
            helper_proc.stdin.flush()
            insp_msg = json.loads(helper_proc.stdout.readline().strip())
            assert insp_msg["id"] == 2 and insp_msg["ok"] is True, f"Unexpected inspect_proc: {insp_msg}"
            if test_log_path:
                assert insp_msg["result"]["log"]["exists"] is True
                assert insp_msg["result"]["log"]["file_size"] > 0
            print("[self-test] Helper JSON protocol passed.")
        finally:
            if cleanup_test_log:
                try:
                    os.unlink(test_log_path)
                except OSError:
                    pass
    finally:
        helper_proc.terminate()
        helper_proc.wait(timeout=3)
        for pipe in (helper_proc.stdin, helper_proc.stdout, helper_proc.stderr):
            if pipe is not None:
                pipe.close()

    print("[self-test] ALL CHECKS PASSED.")
    return 0


class HelperClient:
    """Thread-safe JSON RPC client communicating with the privileged helper."""

    def __init__(self) -> None:
        self._proc: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()
        self._pending: dict[int, queue.Queue[dict[str, Any]]] = {}
        self._next_id = 1
        self._reader_thread: threading.Thread | None = None
        self.uid: int | None = None
        self.on_disconnect = None

    @property
    def is_connected(self) -> bool:
        return self._proc is not None and self._proc.poll() is None and self.uid is not None

    @property
    def is_root(self) -> bool:
        return self._proc is not None and self._proc.poll() is None and (self.uid == 0 or IS_WINDOWS or IS_MACOS)

    @property
    def is_user_mode(self) -> bool:
        return (
            self._proc is not None
            and self._proc.poll() is None
            and self.uid is not None
            and self.uid != 0
            and not IS_WINDOWS
            and not IS_MACOS
        )

    def close(self) -> None:
        with self._lock:
            proc = self._proc
            self._proc = None
            self.uid = None
        if proc is not None:
            try:
                if proc.stdin:
                    proc.stdin.close()
            except OSError:
                pass
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=1)
            for pipe in (proc.stdout, proc.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except OSError:
                        pass

    def _spawn_auth_process(self, cmd: list[str]) -> tuple[subprocess.Popen[str] | None, str]:
        """Spawn a helper or auth wrapper process cleanly, handling missing binaries."""
        try:
            popen_kwargs: dict[str, Any] = {
                "stdin": subprocess.PIPE,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "text": True,
                "bufsize": 1,
            }
            if IS_WINDOWS:
                popen_kwargs["creationflags"] = _SUBPROCESS_NO_WINDOW
            proc = subprocess.Popen(cmd, **popen_kwargs)
            return proc, ""
        except OSError as exc:
            return None, f"Failed to launch {cmd[0]}: {exc}"

    def start_local(self) -> tuple[bool, str]:
        """Spawn the local JSON-RPC helper directly without sudo or pkexec."""
        self.close()
        proc, spawn_err = self._spawn_auth_process(_self_helper_cmd())
        if proc is None:
            return False, spawn_err
        assert proc.stdout is not None
        line = proc.stdout.readline()
        if line.strip().startswith("{"):
            try:
                msg = json.loads(line.strip())
                if msg.get("type") == "ready":
                    self._attach(proc, int(msg.get("uid", 0)))
                    return True, "Local helper active."
            except (json.JSONDecodeError, ValueError):
                pass
        if proc.poll() is None:
            proc.terminate()
        return False, "Local helper did not report ready."

    def start_with_sudo(self, password: str) -> tuple[bool, str]:
        """Spawn helper using sudo -k -S and validate root readiness."""
        self.close()
        cmd = ["sudo", "-k", "-S", "-p", "", *_self_helper_cmd()]
        proc, spawn_err = self._spawn_auth_process(cmd)
        if proc is None:
            return False, spawn_err
        assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None

        stderr_lines: list[str] = []
        ready_q: queue.Queue[tuple[str, Any]] = queue.Queue()

        def _watch_stdout() -> None:
            while True:
                line = proc.stdout.readline()  # type: ignore[union-attr]
                if not line:
                    ready_q.put(("stdout_eof", None))
                    return
                stripped = line.strip()
                if stripped.startswith("{"):
                    try:
                        msg = json.loads(stripped)
                        if msg.get("type") == "ready":
                            ready_q.put(("ready", msg))
                            return
                    except json.JSONDecodeError:
                        pass

        def _watch_stderr() -> None:
            while True:
                line = proc.stderr.readline()  # type: ignore[union-attr]
                if not line:
                    return
                text = line.strip()
                if text:
                    stderr_lines.append(text)
                    ready_q.put(("stderr", text))

        threading.Thread(target=_watch_stdout, daemon=True).start()
        threading.Thread(target=_watch_stderr, daemon=True).start()

        try:
            proc.stdin.write(password + "\n")
            proc.stdin.flush()
        except OSError as exc:
            proc.terminate()
            return False, f"Failed writing password to sudo: {exc}"

        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline:
            remaining = max(0.05, deadline - time.monotonic())
            try:
                kind, payload = ready_q.get(timeout=min(0.4, remaining))
            except queue.Empty:
                if proc.poll() is not None:
                    break
                continue

            if kind == "ready":
                uid = int(payload.get("uid", -1))
                if uid == 0:
                    self._attach(proc, uid)
                    return True, "Root helper active (sudo)."
                proc.terminate()
                return False, f"Helper started with unexpected UID {uid}."

            if kind == "stderr":
                # Give stdout a brief grace window in case sudo printed a notice and still succeeded
                time.sleep(0.25)
                try:
                    kind2, payload2 = ready_q.get_nowait()
                    if kind2 == "ready" and int(payload2.get("uid", -1)) == 0:
                        self._attach(proc, 0)
                        return True, "Root helper active (sudo)."
                except queue.Empty:
                    pass
                proc.terminate()
                return False, " ".join(stderr_lines) or "Authentication failed."

            if kind == "stdout_eof":
                break

        proc.terminate()
        err = " ".join(stderr_lines).strip()
        return False, err or "Timed out waiting for sudo authentication."

    def start_with_sudo_nopass(self) -> tuple[bool, str]:
        """Attempt non-interactive sudo -n helper launch if credentials are cached or NOPASSWD."""
        self.close()
        cmd = ["sudo", "-n", *_self_helper_cmd()]
        proc, spawn_err = self._spawn_auth_process(cmd)
        if proc is None:
            return False, spawn_err
        assert proc.stdout is not None and proc.stderr is not None
        line = proc.stdout.readline()
        if line.strip().startswith("{"):
            try:
                msg = json.loads(line.strip())
                if msg.get("type") == "ready" and int(msg.get("uid", -1)) == 0:
                    self._attach(proc, 0)
                    return True, "Root helper active (sudo cached)."
            except json.JSONDecodeError:
                pass
        if proc.poll() is None:
            proc.terminate()
        return False, "Non-interactive sudo unavailable."

    def start_with_pkexec(self) -> tuple[bool, str]:
        """Spawn helper via pkexec (triggers KDE Polkit prompt)."""
        self.close()
        cmd = ["pkexec", *_self_helper_cmd()]
        proc, spawn_err = self._spawn_auth_process(cmd)
        if proc is None:
            return False, spawn_err
        assert proc.stdout is not None and proc.stderr is not None

        while True:
            line = proc.stdout.readline()
            if not line:
                err = proc.stderr.read().strip()
                rc = proc.wait()
                if rc in (126, 127) and not err:
                    err = "Polkit authentication was cancelled or unavailable."
                return False, err or f"pkexec exited with code {rc}."
            stripped = line.strip()
            if stripped.startswith("{"):
                try:
                    msg = json.loads(stripped)
                    if msg.get("type") == "ready":
                        uid = int(msg.get("uid", -1))
                        if uid == 0:
                            self._attach(proc, uid)
                            return True, "Root helper active (pkexec)."
                        proc.terminate()
                        return False, f"Helper started with unexpected UID {uid}."
                except json.JSONDecodeError:
                    continue

    def _attach(self, proc: subprocess.Popen[str], uid: int) -> None:
        with self._lock:
            self._proc = proc
            self.uid = uid
        self._reader_thread = threading.Thread(target=self._read_loop, args=(proc,), daemon=True)
        self._reader_thread.start()

    def _read_loop(self, proc: subprocess.Popen[str]) -> None:
        assert proc.stdout is not None
        for raw_line in proc.stdout:
            line = raw_line.strip()
            if not line.startswith("{"):
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            req_id = msg.get("id")
            with self._lock:
                waiter = self._pending.pop(req_id, None)
            if waiter is not None:
                waiter.put(msg)

        with self._lock:
            if self._proc is proc:
                self._proc = None
                self.uid = None
            pending_items = list(self._pending.values())
            self._pending.clear()
        for waiter in pending_items:
            waiter.put({"ok": False, "error": "Root helper disconnected."})
        if self.on_disconnect is not None:
            self.on_disconnect()

    def call(self, action: str, params: dict[str, Any] | None = None, timeout: float = 10.0) -> dict[str, Any]:
        """Execute a synchronous RPC request against the running helper."""
        waiter: queue.Queue[dict[str, Any]] = queue.Queue()
        with self._lock:
            if self._proc is None or self._proc.poll() is not None or self._proc.stdin is None:
                raise RuntimeError("Root access is not unlocked.")
            req_id = self._next_id
            self._next_id += 1
            self._pending[req_id] = waiter
            payload = json.dumps({"id": req_id, "action": action, "params": params or {}}) + "\n"
            try:
                self._proc.stdin.write(payload)
                self._proc.stdin.flush()
            except OSError as exc:
                self._pending.pop(req_id, None)
                raise RuntimeError(f"Failed sending request to helper: {exc}") from exc

        try:
            resp = waiter.get(timeout=timeout)
        except queue.Empty as exc:
            with self._lock:
                self._pending.pop(req_id, None)
            raise TimeoutError(f"Helper request '{action}' timed out.") from exc

        if not resp.get("ok"):
            raise RuntimeError(str(resp.get("error") or f"Action '{action}' failed"))
        return dict(resp.get("result") or {})


def _find_binary_path(name: str, fallbacks: tuple[str, ...] = ()) -> str | None:
    """Resolve binary path using PATH plus common distro fallback locations."""
    found = shutil.which(name)
    if found:
        return found
    for candidate in fallbacks:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def check_system_dependencies(db_dir: str | None = None) -> dict[str, Any]:
    """Check installed ClamAV binaries, virus database files, and supporting system tools."""
    resolved_db_dir = db_dir if db_dir is not None else _default_db_dir()
    clamscan_fallbacks = (
        tuple(os.path.join(d, "clamscan.exe") for d in _win_clamav_dirs())
        if IS_WINDOWS
        else tuple(os.path.join(d, "clamscan") for d in _mac_clamav_dirs())
        if IS_MACOS
        else ("/usr/bin/clamscan", "/usr/sbin/clamscan")
    )
    freshclam_fallbacks = (
        tuple(os.path.join(d, "freshclam.exe") for d in _win_clamav_dirs())
        if IS_WINDOWS
        else tuple(os.path.join(d, "freshclam") for d in _mac_clamav_dirs())
        if IS_MACOS
        else ("/usr/bin/freshclam", "/usr/sbin/freshclam", "/usr/local/bin/freshclam")
    )
    clamscan_path = _find_binary_path("clamscan", clamscan_fallbacks)
    freshclam_path = _find_binary_path("freshclam", freshclam_fallbacks)

    tools: dict[str, bool] = {
        "clamscan": clamscan_path is not None,
        "freshclam": freshclam_path is not None,
        "pkexec": False if (IS_WINDOWS or IS_MACOS) else (_find_binary_path("pkexec") is not None),
        "sudo": False if IS_WINDOWS else (_find_binary_path("sudo") is not None),
        "find": True if IS_WINDOWS else (_find_binary_path("find") is not None),
        "renice": True if IS_WINDOWS else (_find_binary_path("renice") is not None),
        "ionice": True if (IS_WINDOWS or IS_MACOS) else (_find_binary_path("ionice") is not None),
        "systemctl": (
            _find_binary_path("schtasks") is not None
            if IS_WINDOWS
            else (_find_binary_path("launchctl") is not None)
            if IS_MACOS
            else (_find_binary_path("systemctl") is not None)
        ),
        "notify-send": True if (IS_WINDOWS or IS_MACOS) else (_find_binary_path("notify-send") is not None),
    }

    db_files: list[str] = []
    if os.path.isdir(resolved_db_dir):
        try:
            for name in os.listdir(resolved_db_dir):
                if name.endswith(_CLAMAV_DB_EXTS):
                    full = os.path.join(resolved_db_dir, name)
                    if os.path.isfile(full) and os.path.getsize(full) > 0:
                        db_files.append(name)
        except OSError:
            pass

    missing_required = [pkg for pkg in ("clamscan", "freshclam") if not tools[pkg]]
    if (not IS_WINDOWS) and (not IS_MACOS) and not tools["pkexec"] and not tools["sudo"]:
        missing_required.append("pkexec/sudo")
    missing_optional = (
        []
        if (IS_WINDOWS or IS_MACOS)
        else [
            tool
            for tool in ("pkexec", "sudo", "find", "renice", "ionice", "systemctl", "notify-send")
            if not tools[tool]
        ]
    )

    return {
        "clamscan_path": clamscan_path,
        "freshclam_path": freshclam_path,
        "has_clamscan": tools["clamscan"],
        "has_freshclam": tools["freshclam"],
        "has_virus_db": len(db_files) > 0,
        "db_files_count": len(db_files),
        "db_dir": resolved_db_dir,
        "tools": tools,
        "missing_required": missing_required,
        "missing_optional": missing_optional,
    }


def get_clamav_metadata(db_dir: str | None = None) -> dict[str, Any]:
    """Read ClamAV version, freshclam service state, dependency health, and virus DB presence."""
    deps = check_system_dependencies(db_dir=db_dir)
    version = "Unavailable"
    if deps["clamscan_path"]:
        try:
            res = subprocess.run(
                [deps["clamscan_path"], "--version"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
                creationflags=_SUBPROCESS_NO_WINDOW,
            )
            if res.returncode == 0 and res.stdout.strip():
                version = res.stdout.strip()
        except OSError:
            pass

    _, svc_status = _detect_freshclam_services()
    return {
        "version": version,
        "freshclam_service": svc_status,
        **deps,
    }


@dataclass
class ScanTelemetry:
    """State tracked across 1-second GUI poll intervals."""

    selected_pid: int | None = None
    last_cpu_ticks: int | None = None
    last_cpu_time: float | None = None
    last_io_bytes: int | None = None
    last_io_time: float | None = None
    last_eta_speed_bps: float | None = None
    last_proc_data: dict[str, Any] = field(default_factory=dict)
    last_precount: dict[str, Any] = field(default_factory=dict)
    statvfs_cache_key: tuple[Any, ...] | None = None
    statvfs_bytes: int = 0
    log_path: str = DEFAULT_LOG_PATH
    log_offset: int = 0
    log_lines: deque[str] = field(default_factory=lambda: deque(maxlen=5000))
    partial_line: str = ""
    total_lines_logged: int = 0
    last_sampled_fd_file: str | None = None
    seen_threats: set[tuple[str, str]] = field(default_factory=set)


def detect_desktop_environment() -> str:
    """Detect active desktop environment ('kde', 'gnome', or 'other')."""
    combined = " ".join(
        [
            os.environ.get("XDG_CURRENT_DESKTOP", ""),
            os.environ.get("XDG_SESSION_DESKTOP", ""),
            os.environ.get("DESKTOP_SESSION", ""),
        ]
    ).lower()
    if "gnome" in combined:
        return "gnome"
    if "kde" in combined or "plasma" in combined:
        return "kde"
    return "other"


def _gdbus_show_items_command(path: str) -> list[str]:
    """Build safe gdbus org.freedesktop.FileManager1.ShowItems invocation for a file path."""
    uri = Path(path).resolve().as_uri() if os.path.isabs(path) else "file://" + urllib.parse.quote(path)
    return [
        "gdbus",
        "call",
        "--session",
        "--dest",
        "org.freedesktop.FileManager1",
        "--object-path",
        "/org/freedesktop/FileManager1",
        "--method",
        "org.freedesktop.FileManager1.ShowItems",
        f"['{uri}']",
        "",
    ]


def build_reveal_file_command(path: str, desktop: str | None = None) -> list[str]:
    """Build command to reveal and highlight a file in Finder, Explorer, KDE Dolphin, GNOME Files, or fallback."""
    if IS_WINDOWS:
        return ["explorer.exe", f"/select,{os.path.normpath(path)}"]
    if IS_MACOS:
        return ["open", "-R", path]
    de = desktop or detect_desktop_environment()
    if de == "kde" and shutil.which("dolphin"):
        return ["dolphin", "--select", path]
    if de == "gnome":
        if shutil.which("nautilus"):
            return ["nautilus", "--select", path]
        if shutil.which("gdbus") and os.environ.get("DBUS_SESSION_BUS_ADDRESS"):
            return _gdbus_show_items_command(path)
    if shutil.which("dolphin"):
        return ["dolphin", "--select", path]
    if shutil.which("nautilus"):
        return ["nautilus", "--select", path]
    if shutil.which("gdbus") and os.environ.get("DBUS_SESSION_BUS_ADDRESS"):
        return _gdbus_show_items_command(path)
    return ["xdg-open", os.path.dirname(path) or "/"]


def create_main_window(auto_poll: bool = False, lang: str | None = None) -> Any:
    """Create and return the Qt6 ClamAVMainWindow (PySide6 with PyQt6 fallback)."""
    try:
        from PySide6.QtCore import Qt, QTime, QTimer, Signal, QObject, QPointF, QRectF
        from PySide6.QtGui import (
            QAction,
            QBrush,
            QColor,
            QFont,
            QIcon,
            QLinearGradient,
            QPainter,
            QPainterPath,
            QPalette,
            QPen,
            QPixmap,
            QTextCursor,
        )
        from PySide6.QtWidgets import (
            QApplication,
            QCheckBox,
            QComboBox,
            QDialog,
            QDialogButtonBox,
            QFileDialog,
            QFormLayout,
            QFrame,
            QGraphicsDropShadowEffect,
            QGridLayout,
            QGroupBox,
            QHBoxLayout,
            QHeaderView,
            QInputDialog,
            QLabel,
            QLineEdit,
            QListView,
            QMainWindow,
            QMenu,
            QMessageBox,
            QPlainTextEdit,
            QProgressBar,
            QPushButton,
            QScrollArea,
            QSizePolicy,
            QSpinBox,
            QSystemTrayIcon,
            QTableWidget,
            QTableWidgetItem,
            QTabWidget,
            QTimeEdit,
            QTreeView,
            QVBoxLayout,
            QWidget,
        )
    except ImportError:
        from PyQt6.QtCore import Qt, QTime, QTimer, pyqtSignal as Signal, QObject, QPointF, QRectF
        from PyQt6.QtGui import (
            QAction,
            QBrush,
            QColor,
            QFont,
            QIcon,
            QLinearGradient,
            QPainter,
            QPainterPath,
            QPalette,
            QPen,
            QPixmap,
            QTextCursor,
        )
        from PyQt6.QtWidgets import (
            QApplication,
            QCheckBox,
            QComboBox,
            QDialog,
            QDialogButtonBox,
            QFileDialog,
            QFormLayout,
            QFrame,
            QGraphicsDropShadowEffect,
            QGridLayout,
            QGroupBox,
            QHBoxLayout,
            QHeaderView,
            QInputDialog,
            QLabel,
            QLineEdit,
            QListView,
            QMainWindow,
            QMenu,
            QMessageBox,
            QPlainTextEdit,
            QProgressBar,
            QPushButton,
            QScrollArea,
            QSizePolicy,
            QSpinBox,
            QSystemTrayIcon,
            QTableWidget,
            QTableWidgetItem,
            QTabWidget,
            QTimeEdit,
            QTreeView,
            QVBoxLayout,
            QWidget,
        )

    def _theme_icon(*names: str) -> QIcon:
        """Return first non-null themed icon across KDE Breeze and GNOME Adwaita themes."""
        for name in names:
            icon = QIcon.fromTheme(name)
            if not icon.isNull():
                return icon
        return QIcon.fromTheme(names[0]) if names else QIcon()

    class AsyncSignals(QObject):
        pkexec_done = Signal(bool, str, bool)
        auto_sudo_done = Signal(bool)
        helper_disconnected = Signal()
        inspect_done = Signal(object, str)
        freshclam_done = Signal(bool, str)

    def _is_dark_theme() -> bool:
        app = QApplication.instance()
        if app is None:
            return False
        return app.palette().color(QPalette.ColorRole.Window).lightness() < 128

    def _apply_card_shadow(widget: Any, dark: bool) -> None:
        if dark:
            return
        eff = QGraphicsDropShadowEffect(widget)
        eff.setBlurRadius(22)
        eff.setXOffset(0)
        eff.setYOffset(3)
        eff.setColor(QColor(15, 23, 42, 20))
        widget.setGraphicsEffect(eff)

    def _draw_shield_pixmap(size: int, bg_hex: str, symbol: str = "check") -> QPixmap:
        """Render a crisp 3x HiDPI faceted vector shield badge."""
        dpr = 3.0
        px = int(round(size * dpr))
        pm = QPixmap(px, px)
        pm.fill(Qt.GlobalColor.transparent)
        pm.setDevicePixelRatio(dpr)

        painter = QPainter(pm)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        w = float(size)

        path = QPainterPath()
        path.moveTo(w * 0.50, w * 0.08)
        path.lineTo(w * 0.85, w * 0.21)
        path.quadTo(w * 0.87, w * 0.64, w * 0.50, w * 0.92)
        path.quadTo(w * 0.13, w * 0.64, w * 0.15, w * 0.21)
        path.closeSubpath()

        base_c = QColor(bg_hex)
        grad = QLinearGradient(QPointF(w * 0.2, w * 0.1), QPointF(w * 0.85, w * 0.9))
        grad.setColorAt(0.0, base_c.lighter(118))
        grad.setColorAt(1.0, base_c.darker(108))
        outline = QPen(base_c.darker(125), max(1.3, w * 0.038))
        outline.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(outline)
        painter.setBrush(QBrush(grad))
        painter.drawPath(path)

        # Subtle right-half facet & crisp inner white rim (matches mockup_1 shield)
        facet = QPainterPath()
        facet.moveTo(w * 0.50, w * 0.11)
        facet.lineTo(w * 0.82, w * 0.23)
        facet.quadTo(w * 0.84, w * 0.62, w * 0.50, w * 0.89)
        facet.closeSubpath()
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(QColor(0, 0, 0, 22)))
        painter.drawPath(facet)

        inner = QPainterPath()
        inner.moveTo(w * 0.50, w * 0.13)
        inner.lineTo(w * 0.80, w * 0.24)
        inner.quadTo(w * 0.82, w * 0.61, w * 0.50, w * 0.86)
        inner.quadTo(w * 0.18, w * 0.61, w * 0.20, w * 0.24)
        inner.closeSubpath()
        painter.setPen(QPen(QColor(255, 255, 255, 115), max(1.0, w * 0.025)))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(inner)

        pen = QPen(QColor("#ffffff"))
        pen.setWidthF(max(2.0, w * 0.088))
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        if symbol == "check":
            chk = QPainterPath()
            chk.moveTo(w * 0.34, w * 0.50)
            chk.lineTo(w * 0.45, w * 0.62)
            chk.lineTo(w * 0.67, w * 0.39)
            painter.drawPath(chk)
        elif symbol == "alert":
            painter.drawLine(QPointF(w * 0.50, w * 0.32), QPointF(w * 0.50, w * 0.55))
            painter.drawPoint(QPointF(w * 0.50, w * 0.68))
        elif symbol == "scan":
            painter.drawEllipse(QRectF(w * 0.34, w * 0.34, w * 0.32, w * 0.32))
            painter.drawPoint(QPointF(w * 0.50, w * 0.50))
        else:
            painter.drawLine(QPointF(w * 0.50, w * 0.33), QPointF(w * 0.50, w * 0.63))
            painter.drawLine(QPointF(w * 0.38, w * 0.52), QPointF(w * 0.50, w * 0.64))
            painter.drawLine(QPointF(w * 0.62, w * 0.52), QPointF(w * 0.50, w * 0.64))
        painter.end()
        return pm

    def _build_app_icon(bg_hex: str = "#1f9d68", symbol: str = "check") -> QIcon:
        """Build a multi-size QIcon using the app's faceted vector shield artwork."""
        icon = QIcon()
        for px in (16, 22, 24, 32, 48, 64, 128):
            icon.addPixmap(_draw_shield_pixmap(px, bg_hex, symbol))
        return icon

    def _draw_tile_pixmap(kind: str, size: int = 56) -> QPixmap:
        """Render 3x HiDPI vector illustrations matching mockup_1 tiles."""
        dpr = 3.0
        px = int(round(size * dpr))
        pm = QPixmap(px, px)
        pm.fill(Qt.GlobalColor.transparent)
        pm.setDevicePixelRatio(dpr)

        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        w = float(size)

        if kind == "quick":
            # Dynamic speed fins/leaves on bottom-left + lightning shield (mockup_1 Tile 1)
            fin1 = QPainterPath()
            fin1.moveTo(w * 0.14, w * 0.64)
            fin1.quadTo(w * 0.18, w * 0.46, w * 0.36, w * 0.48)
            fin1.quadTo(w * 0.28, w * 0.64, w * 0.14, w * 0.64)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(QColor("#5fd09d")))
            p.drawPath(fin1)

            fin2 = QPainterPath()
            fin2.moveTo(w * 0.23, w * 0.84)
            fin2.quadTo(w * 0.30, w * 0.68, w * 0.45, w * 0.72)
            fin2.quadTo(w * 0.36, w * 0.86, w * 0.23, w * 0.84)
            p.setBrush(QBrush(QColor("#1ea870")))
            p.drawPath(fin2)

            fin3 = QPainterPath()
            fin3.moveTo(w * 0.58, w * 0.86)
            fin3.quadTo(w * 0.68, w * 0.72, w * 0.76, w * 0.78)
            fin3.quadTo(w * 0.68, w * 0.88, w * 0.58, w * 0.86)
            p.setBrush(QBrush(QColor("#8ce0ba")))
            p.drawPath(fin3)

            sh = QPainterPath()
            sh.moveTo(w * 0.55, w * 0.10)
            sh.lineTo(w * 0.84, w * 0.22)
            sh.quadTo(w * 0.84, w * 0.60, w * 0.53, w * 0.82)
            sh.quadTo(w * 0.24, w * 0.60, w * 0.26, w * 0.22)
            sh.closeSubpath()

            s_grad = QLinearGradient(QPointF(w * 0.28, w * 0.12), QPointF(w * 0.82, w * 0.80))
            s_grad.setColorAt(0.0, QColor("#29b87e"))
            s_grad.setColorAt(1.0, QColor("#147b52"))
            p.setPen(QPen(QColor("#116443"), 1.8, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
            p.setBrush(QBrush(s_grad))
            p.drawPath(sh)

            sh_in = QPainterPath()
            sh_in.moveTo(w * 0.55, w * 0.16)
            sh_in.lineTo(w * 0.78, w * 0.26)
            sh_in.quadTo(w * 0.78, w * 0.57, w * 0.53, w * 0.75)
            sh_in.quadTo(w * 0.30, w * 0.57, w * 0.32, w * 0.26)
            sh_in.closeSubpath()
            p.setPen(QPen(QColor(255, 255, 255, 110), 1.2))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawPath(sh_in)

            bolt = QPainterPath()
            bolt.moveTo(w * 0.58, w * 0.28)
            bolt.lineTo(w * 0.43, w * 0.49)
            bolt.lineTo(w * 0.54, w * 0.49)
            bolt.lineTo(w * 0.49, w * 0.67)
            bolt.lineTo(w * 0.66, w * 0.44)
            bolt.lineTo(w * 0.55, w * 0.44)
            bolt.closeSubpath()
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(QColor("#e9fcf2")))
            p.drawPath(bolt)

        elif kind == "full":
            # Slate-blue monitor + foreground drive/device panel (mockup_1 Tile 2)
            stroke = QColor("#4d6986")
            p.setPen(QPen(stroke, 2.0, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
            p.setBrush(QBrush(QColor("#dce6f2")))
            p.drawRoundedRect(QRectF(w * 0.12, w * 0.16, w * 0.66, w * 0.48), 5.0, 5.0)

            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(QColor("#8aa5c1")))
            p.drawRoundedRect(QRectF(w * 0.17, w * 0.21, w * 0.56, w * 0.35), 2.5, 2.5)
            p.setBrush(QBrush(QColor("#b8cae0")))
            p.drawRoundedRect(QRectF(w * 0.20, w * 0.24, w * 0.30, w * 0.10), 2.0, 2.0)

            # Stand neck & base
            p.setBrush(QBrush(QColor("#8aa5c1")))
            p.setPen(QPen(stroke, 1.8))
            p.drawRect(QRectF(w * 0.38, w * 0.64, w * 0.14, w * 0.11))
            p.drawLine(QPointF(w * 0.24, w * 0.77), QPointF(w * 0.58, w * 0.77))

            # White halo behind overlapping drive card
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(QColor("#ffffff")))
            p.drawRoundedRect(QRectF(w * 0.54, w * 0.35, w * 0.34, w * 0.49), 6.0, 6.0)

            # Foreground vertical drive/device panel
            p.setPen(QPen(stroke, 2.0))
            p.setBrush(QBrush(QColor("#d4e1ef")))
            p.drawRoundedRect(QRectF(w * 0.56, w * 0.37, w * 0.30, w * 0.45), 5.0, 5.0)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(QColor("#6985a4")))
            p.drawRoundedRect(QRectF(w * 0.62, w * 0.44, w * 0.18, w * 0.045), 1.5, 1.5)
            p.setBrush(QBrush(QColor("#92abc7")))
            p.drawRoundedRect(QRectF(w * 0.62, w * 0.52, w * 0.12, w * 0.035), 1.5, 1.5)
            p.setBrush(QBrush(stroke))
            p.drawRoundedRect(QRectF(w * 0.64, w * 0.71, w * 0.14, w * 0.05), 2.0, 2.0)

        else:
            # Lavender-indigo dashed drop frame + folder with '+' + circular check badge (mockup_1 Tile 3)
            dash_pen = QPen(QColor("#9fa3d8"), 1.8, Qt.PenStyle.DashLine)
            dash_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            p.setPen(dash_pen)
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawRoundedRect(QRectF(w * 0.30, w * 0.14, w * 0.56, w * 0.46), 6.0, 6.0)

            indigo = QColor("#6769b3")
            folder_path = QPainterPath()
            folder_path.moveTo(w * 0.16, w * 0.25)
            folder_path.lineTo(w * 0.37, w * 0.25)
            folder_path.lineTo(w * 0.44, w * 0.33)
            folder_path.lineTo(w * 0.72, w * 0.33)
            folder_path.quadTo(w * 0.76, w * 0.33, w * 0.76, w * 0.38)
            folder_path.lineTo(w * 0.76, w * 0.71)
            folder_path.quadTo(w * 0.76, w * 0.76, w * 0.71, w * 0.76)
            folder_path.lineTo(w * 0.21, w * 0.76)
            folder_path.quadTo(w * 0.16, w * 0.76, w * 0.16, w * 0.71)
            folder_path.closeSubpath()

            p.setPen(QPen(indigo, 2.0, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
            p.setBrush(QBrush(QColor("#dcdff8")))
            p.drawPath(folder_path)

            # '+' icon inside folder
            plus_pen = QPen(indigo, 2.3)
            plus_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            p.setPen(plus_pen)
            p.drawLine(QPointF(w * 0.44, w * 0.46), QPointF(w * 0.44, w * 0.62))
            p.drawLine(QPointF(w * 0.36, w * 0.54), QPointF(w * 0.52, w * 0.54))

            # Halo + circular check badge at bottom-right
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(QColor("#ffffff")))
            p.drawEllipse(QRectF(w * 0.55, w * 0.52, w * 0.34, w * 0.34))
            p.setBrush(QBrush(QColor("#5b5ea6")))
            p.drawEllipse(QRectF(w * 0.58, w * 0.55, w * 0.28, w * 0.28))

            chk_pen = QPen(QColor("#ffffff"), 2.2)
            chk_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            chk_pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
            p.setPen(chk_pen)
            chk = QPainterPath()
            chk.moveTo(w * 0.66, w * 0.69)
            chk.lineTo(w * 0.71, w * 0.74)
            chk.lineTo(w * 0.80, w * 0.64)
            p.drawPath(chk)

        p.end()
        return pm

    class ScanTileButton(QPushButton):
        """Card-style scan tile with HiDPI vector artwork, bold title, and muted subtitle."""

        def __init__(self, kind: str, title: str, subtitle: str, dark: bool = False) -> None:
            super().__init__()
            self._title = title
            self.setObjectName("ScanTile")
            self.setCursor(Qt.CursorShape.PointingHandCursor)
            self.setMinimumHeight(138)
            if dark:
                self.setStyleSheet(
                    "#ScanTile { background-color: palette(base); border: 1px solid palette(mid); "
                    "border-radius: 14px; padding: 14px 16px; text-align: center; } "
                    "#ScanTile:hover { border: 1px solid palette(highlight); background-color: palette(alternateBase); } "
                    "#ScanTile:disabled { opacity: 0.55; }"
                )
            else:
                self.setStyleSheet(
                    "#ScanTile { background-color: #ffffff; border: 1px solid #dde3ec; "
                    "border-radius: 14px; padding: 14px 16px; text-align: center; } "
                    "#ScanTile:hover { border: 1px solid #96b8cf; background-color: #fbfdff; } "
                    "#ScanTile:pressed { background-color: #f3f7fc; } "
                    "#ScanTile:disabled { background-color: #f8fafc; color: #94a3b8; }"
                )
                _apply_card_shadow(self, dark)

            lay = QVBoxLayout(self)
            lay.setContentsMargins(12, 14, 12, 14)
            lay.setSpacing(5)
            lay.setAlignment(Qt.AlignmentFlag.AlignVCenter)

            self.icon_lbl = QLabel()
            self.icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.icon_lbl.setPixmap(_draw_tile_pixmap(kind, 60))
            self.icon_lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

            self.title_lbl = QLabel(title)
            tf = QFont()
            tf.setPointSize(11)
            tf.setBold(True)
            self.title_lbl.setFont(tf)
            self.title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            if not dark:
                self.title_lbl.setStyleSheet("color: #111827;")
            self.title_lbl.setWordWrap(True)
            self.title_lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

            self.sub_lbl = QLabel(subtitle)
            sf = QFont()
            sf.setPointSize(9)
            self.sub_lbl.setFont(sf)
            self.sub_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.sub_lbl.setWordWrap(True)
            self.sub_lbl.setStyleSheet("color: palette(placeholderText);" if dark else "color: #5b6778;")
            self.sub_lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

            lay.addWidget(self.icon_lbl)
            lay.addSpacing(2)
            lay.addWidget(self.title_lbl)
            lay.addWidget(self.sub_lbl)

        def text(self) -> str:
            return self._title

        def setText(self, text: str) -> None:
            self._title = text
            self.title_lbl.setText(text)

        def setSubtitle(self, subtitle: str) -> None:
            self.sub_lbl.setText(subtitle)

    class StatCard(QFrame):
        """Compact metric column inside the unified 4-column status strip."""

        def __init__(self, title: str, initial_value: str = "-", subtitle: str = "", dark: bool = False) -> None:
            super().__init__()
            self._dark = dark
            self.setObjectName("StatCard")
            layout = QVBoxLayout(self)
            layout.setContentsMargins(10, 12, 10, 12)
            layout.setSpacing(3)
            layout.setAlignment(Qt.AlignmentFlag.AlignVCenter)

            self.title_lbl = QLabel(title)
            title_font = QFont()
            title_font.setPointSize(9)
            self.title_lbl.setFont(title_font)
            self.title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.title_lbl.setWordWrap(True)
            self.title_lbl.setStyleSheet("color: palette(placeholderText);" if dark else "color: #5b6778;")

            self.value_lbl = QLabel(initial_value)
            val_font = QFont()
            val_font.setPointSize(11)
            val_font.setBold(True)
            self.value_lbl.setFont(val_font)
            self.value_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.value_lbl.setWordWrap(True)
            if not dark:
                self.value_lbl.setStyleSheet("color: #111827;")

            self.sub_lbl = QLabel(subtitle)
            sub_font = QFont()
            sub_font.setPointSize(8)
            self.sub_lbl.setFont(sub_font)
            self.sub_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.sub_lbl.setWordWrap(True)
            self.sub_lbl.setStyleSheet("color: palette(placeholderText);" if dark else "color: #64748b;")
            self.sub_lbl.setVisible(bool(subtitle))

            layout.addWidget(self.title_lbl)
            layout.addWidget(self.value_lbl)
            layout.addWidget(self.sub_lbl)

        def set_data(self, value: str, subtitle: str = "", color: str | None = None) -> None:
            self.value_lbl.setText(value)
            self.sub_lbl.setText(subtitle)
            self.sub_lbl.setVisible(bool(subtitle))
            if color:
                self.value_lbl.setStyleSheet(f"color: {color};")
            else:
                self.value_lbl.setStyleSheet("" if self._dark else "color: #111827;")
            self.value_lbl.setMinimumHeight(self.value_lbl.heightForWidth(max(1, self.value_lbl.width())))

    class FileOrFolderPickerDialog(QFileDialog):
        """File browser allowing immediate selection of either files or folders."""

        def __init__(self, parent: QWidget | None = None, caption: str = "", directory: str = "") -> None:
            super().__init__(parent, caption, directory)
            self.setOption(QFileDialog.Option.DontUseNativeDialog, True)
            self.setFileMode(QFileDialog.FileMode.ExistingFiles)
            self.chosen_paths: list[str] = []

            self._lv = self.findChild(QListView, "listView")
            self._tv = self.findChild(QTreeView, "treeView")
            self._edit = self.findChild(QLineEdit, "fileNameEdit")
            self._bbox = self.findChild(QDialogButtonBox)
            self._open_btn = self._bbox.button(QDialogButtonBox.StandardButton.Open) if self._bbox else None

            for view in (self._lv, self._tv):
                if view is not None and view.selectionModel() is not None:
                    view.selectionModel().selectionChanged.connect(self._sync_selection)
            self.directoryEntered.connect(self._on_directory_entered)
            if self._open_btn is not None:
                try:
                    self._open_btn.clicked.disconnect()
                except (RuntimeError, TypeError):
                    pass
                self._open_btn.clicked.connect(self._accept_current_selection)
                self._open_btn.setEnabled(True)

        def _on_directory_entered(self, _directory: str) -> None:
            if self._edit is not None:
                self._edit.clear()
            self._sync_selection()

        def _current_view_paths(self) -> list[str]:
            base = self.directory().absolutePath()
            for view in (self._lv, self._tv):
                if view is not None and view.isVisible() and view.selectionModel() is not None:
                    rows = view.selectionModel().selectedRows(0)
                    if not rows:
                        rows = [idx for idx in view.selectionModel().selectedIndexes() if idx.column() == 0]
                    if rows:
                        model = view.model()
                        out: list[str] = []
                        for idx in rows:
                            path = ""
                            if model is not None and hasattr(model, "filePath"):
                                path = str(model.filePath(idx) or "").strip()
                            if not path and model is not None:
                                name = str(model.data(idx) or "").strip()
                                if name:
                                    path = os.path.join(base, name)
                            if path:
                                out.append(path)
                        if out:
                            return out
            return []

        def _sync_selection(self, *_args: Any) -> None:
            paths = self._current_view_paths()
            if self._edit is not None and len(paths) == 1:
                self._edit.setText(os.path.basename(paths[0]) or paths[0])
            if self._open_btn is not None:
                self._open_btn.setEnabled(True)

        def _accept_current_selection(self) -> None:
            paths = self._current_view_paths()
            if not paths and self._edit is not None:
                typed = self._edit.text().strip()
                if typed and not typed.startswith('"'):
                    candidate = typed if os.path.isabs(typed) else os.path.join(self.directory().absolutePath(), typed)
                    if os.path.exists(candidate):
                        paths = [os.path.abspath(candidate)]
            if not paths:
                files = [p for p in self.selectedFiles() if p and os.path.exists(p)]
                paths = files if files else [self.directory().absolutePath()]
            self.chosen_paths = paths
            QDialog.accept(self)

        def accept(self) -> None:
            paths = self._current_view_paths()
            if len(paths) == 1 and os.path.isdir(paths[0]):
                self.setDirectory(paths[0])
                return
            self._accept_current_selection()

    class ClamAVMainWindow(QMainWindow):
        def __init__(self, auto_poll: bool = True, initial_lang: str | None = None) -> None:
            super().__init__()
            if initial_lang in TRANSLATIONS:
                self.lang = initial_lang
            else:
                self.lang = detect_default_language()

            self._tr_text: list[tuple[Any, str]] = []
            self._tr_title: list[tuple[Any, str]] = []
            self._tr_tip: list[tuple[Any, str]] = []
            self._tr_ph: list[tuple[Any, str]] = []
            self._quarantine_count = 0
            self._polkit_waiting = False
            self._freshclam_running = False

            self.setWindowTitle(self._tr("window_title"))
            self.setWindowIcon(_build_app_icon())
            self._dark = _is_dark_theme()
            self.resize(980, 560)
            self.setAcceptDrops(True)

            self._qt_app = QApplication.instance()
            self.helper = HelperClient()
            self.telemetry = ScanTelemetry()
            self.signals = AsyncSignals()
            self._inspect_inflight = False
            self._current_proc: dict[str, Any] | None = None
            self._known_procs: list[dict[str, Any]] = []
            self._force_quit = False
            self._tray_hint_shown = False
            self._tray_icon: QSystemTrayIcon | None = None
            self._last_active_scan: dict[str, Any] | None = None
            self._latest_scan_entry: dict[str, Any] | None = None
            self._last_pct: float = 0.0
            self._last_eta_str: str = "--:--:--"
            self._pending_scan_labels: dict[int, str] = {}
            self._last_meta: dict[str, Any] = {}
            self._log_reload_error: str = ""
            self._last_about_dialog: QDialog | None = None

            self.helper.on_disconnect = self.signals.helper_disconnected.emit
            self.signals.pkexec_done.connect(self._on_pkexec_done)
            self.signals.auto_sudo_done.connect(self._on_auto_sudo_done)
            self.signals.helper_disconnected.connect(self._on_helper_disconnected)
            self.signals.inspect_done.connect(self._on_inspect_done)
            self.signals.freshclam_done.connect(self._on_freshclam_done)

            self._build_ui()
            if auto_poll:
                self._setup_tray()
            self._apply_translations()
            self._update_command_preview()
            self._refresh_history()
            self.resize(980, max(460, self.minimumSizeHint().height()))

            self.poll_timer = QTimer(self)
            self.poll_timer.setInterval(1000)
            self.poll_timer.timeout.connect(self._poll_tick)
            if auto_poll:
                self.poll_timer.start()
                self._poll_tick()
                QTimer.singleShot(200, self._try_auto_connect)

        def _tr(self, key: str, **kwargs: Any) -> str:
            return tr(self.lang, key, **kwargs)

        def _reg_text(self, widget: Any, key: str) -> Any:
            self._tr_text.append((widget, key))
            widget.setText(self._tr(key))
            return widget

        def _reg_title(self, widget: Any, key: str) -> Any:
            self._tr_title.append((widget, key))
            widget.setTitle(self._tr(key))
            return widget

        def _reg_tip(self, widget: Any, key: str) -> Any:
            self._tr_tip.append((widget, key))
            widget.setToolTip(self._tr(key))
            return widget

        def _reg_ph(self, widget: Any, key: str) -> Any:
            self._tr_ph.append((widget, key))
            widget.setPlaceholderText(self._tr(key))
            return widget

        def dragEnterEvent(self, event: Any) -> None:
            if event.mimeData().hasUrls():
                local_paths = [u.toLocalFile() for u in event.mimeData().urls() if u.isLocalFile()]
                if any(os.path.exists(p) for p in local_paths):
                    event.acceptProposedAction()
                    return
            event.ignore()

        def dropEvent(self, event: Any) -> None:
            if not event.mimeData().hasUrls():
                return
            paths = [
                u.toLocalFile()
                for u in event.mimeData().urls()
                if u.isLocalFile() and os.path.exists(u.toLocalFile())
            ]
            if not paths:
                return
            preview = "\n".join(paths[:5])
            if len(paths) > 5:
                preview += "\n" + self._tr("dlg_drop_more", count=len(paths) - 5)
            ans = QMessageBox.question(
                self,
                self._tr("dlg_drop_title"),
                self._tr("dlg_drop_msg", preview=preview),
            )
            if ans == QMessageBox.StandardButton.Yes:
                label = (
                    self._tr("label_dropped_one", name=os.path.basename(paths[0]))
                    if len(paths) == 1
                    else self._tr("label_dropped_many", count=len(paths))
                )
                self._launch_scan_args(paths, label=label, exclude_virtual=False)

        def closeEvent(self, event: Any) -> None:
            if not self._force_quit and self._tray_icon is not None and self._tray_icon.isVisible():
                event.ignore()
                self.hide()
                if not self._tray_hint_shown:
                    self._tray_hint_shown = True
                    self._notify(
                        self._tr("app_title"),
                        self._tr("tray_minimized_msg"),
                    )
                return
            if self._tray_icon is not None:
                self._tray_icon.hide()
            cancel_background_precount()
            self.helper.close()
            super().closeEvent(event)

        def _quit_app(self) -> None:
            self._force_quit = True
            self.close()
            QApplication.quit()

        def _setup_tray(self) -> None:
            if not QSystemTrayIcon.isSystemTrayAvailable():
                return
            tray = QSystemTrayIcon(_build_app_icon(), self)
            tray.setToolTip(self._tr("tray_tip_idle", count=0))

            menu = QMenu(self)
            self.tray_open_act = QAction(self._tr("tray_open"), self)
            self.tray_open_act.triggered.connect(self._restore_from_tray)
            menu.addAction(self.tray_open_act)

            self.tray_quick_act = QAction(self._tr("tray_quick"), self)
            self.tray_quick_act.triggered.connect(self._start_quick_scan)
            menu.addAction(self.tray_quick_act)

            self.tray_pause_act = QAction(self._tr("pause_scan"), self)
            self.tray_pause_act.triggered.connect(self._toggle_pause_scan)
            self.tray_pause_act.setEnabled(False)
            menu.addAction(self.tray_pause_act)

            self.tray_stop_act = QAction(self._tr("stop_scan"), self)
            self.tray_stop_act.triggered.connect(self._stop_scan)
            self.tray_stop_act.setEnabled(False)
            menu.addAction(self.tray_stop_act)

            menu.addSeparator()
            self.tray_about_act = QAction(self._tr("about_btn"), self)
            self.tray_about_act.triggered.connect(self._show_about_dialog)
            menu.addAction(self.tray_about_act)
            self.tray_quit_act = QAction(self._tr("quit_btn"), self)
            self.tray_quit_act.triggered.connect(self._quit_app)
            menu.addAction(self.tray_quit_act)

            tray.setContextMenu(menu)
            tray.activated.connect(self._on_tray_activated)
            tray.show()
            self._tray_icon = tray

        def _restore_from_tray(self) -> None:
            self.showNormal()
            self.raise_()
            self.activateWindow()

        def _on_tray_activated(self, reason: Any) -> None:
            if reason in (
                QSystemTrayIcon.ActivationReason.Trigger,
                QSystemTrayIcon.ActivationReason.DoubleClick,
            ):
                if self.isVisible() and not self.isMinimized():
                    self.hide()
                else:
                    self._restore_from_tray()

        def _notify(self, title: str, message: str, critical: bool = False) -> None:
            if self._tray_icon is not None and self._tray_icon.isVisible():
                icon = (
                    QSystemTrayIcon.MessageIcon.Critical
                    if critical
                    else QSystemTrayIcon.MessageIcon.Information
                )
                self._tray_icon.showMessage(title, message, icon, 6000)
                return
            if shutil.which("notify-send"):
                urgency = "critical" if critical else "normal"
                subprocess.Popen(
                    [
                        "notify-send",
                        "-u",
                        urgency,
                        "-i",
                        "clamav-security-center",
                        "-h",
                        "string:desktop-entry:clamav-security-center",
                        "-a",
                        self._tr("app_title"),
                        title,
                        message,
                    ],
                    start_new_session=True,
                )

        def _build_ui(self) -> None:
            central = QWidget()
            central.setObjectName("MainCanvas")
            if not self._dark:
                central.setStyleSheet("#MainCanvas { background-color: #eef2f6; }")
            self.setCentralWidget(central)
            root = QVBoxLayout(central)
            root.setContentsMargins(22, 18, 22, 16)
            root.setSpacing(14)

            # Header bar (mockup_1: shield icon + title/meta on left; badge + EN/DE pill + subtle quit on right)
            header_row = QHBoxLayout()
            header_row.setSpacing(12)

            self.header_shield_lbl = QLabel()
            self.header_shield_lbl.setFixedSize(34, 34)
            self.header_shield_lbl.setPixmap(_draw_shield_pixmap(34, "#1f9d68", "check"))
            header_row.addWidget(self.header_shield_lbl)

            title_box = QVBoxLayout()
            title_box.setSpacing(1)
            self.app_title_lbl = self._reg_text(QLabel(), "app_title")
            title_font = QFont()
            title_font.setPointSize(15)
            title_font.setBold(True)
            self.app_title_lbl.setFont(title_font)
            if not self._dark:
                self.app_title_lbl.setStyleSheet("color: #111827;")

            self.meta_lbl = QLabel(self._tr("detecting_clamav"))
            meta_font = QFont()
            meta_font.setPointSize(9)
            self.meta_lbl.setFont(meta_font)
            self.meta_lbl.setWordWrap(True)
            self.meta_lbl.setStyleSheet("color: palette(placeholderText);" if self._dark else "color: #5b6778;")
            title_box.addWidget(self.app_title_lbl)
            title_box.addWidget(self.meta_lbl)
            header_row.addLayout(title_box, 1)

            self.root_badge_lbl = self._reg_text(QLabel(), "root_active_badge")
            self.root_badge_lbl.setStyleSheet(
                "color: #147a4c; font-weight: 600; padding: 5px 13px; "
                "background-color: #d7f3e4; border: 1px solid #b5e7cd; border-radius: 14px;"
                if not self._dark
                else "color: #34d399; font-weight: bold; padding: 5px 13px; "
                "background-color: rgba(31, 138, 91, 0.22); border: 1px solid rgba(52, 211, 153, 0.35); border-radius: 14px;"
            )
            self.root_badge_lbl.setVisible(False)
            header_row.addWidget(self.root_badge_lbl)

            link_btn_css = (
                "QPushButton { border: none; background: transparent; color: palette(placeholderText); padding: 4px 6px; }"
                "QPushButton:hover { color: palette(text); }"
                if self._dark
                else "QPushButton { border: none; background: transparent; color: #64748b; padding: 4px 6px; font-weight: 500; }"
                "QPushButton:hover { color: #111827; }"
            )
            self.about_btn = self._reg_text(QPushButton(), "about_btn")
            self.about_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self.about_btn.setStyleSheet(link_btn_css)
            self.about_btn.clicked.connect(self._show_about_dialog)
            header_row.addWidget(self.about_btn)

            self.quit_btn = self._reg_text(QPushButton(), "quit_btn")
            self.quit_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self.quit_btn.setStyleSheet(link_btn_css)
            self.quit_btn.clicked.connect(self._quit_app)
            header_row.addWidget(self.quit_btn)
            root.addLayout(header_row)

            # Sleek Privilege Strip (hidden automatically once protected root access is active)
            self.auth_banner = QFrame()
            self.auth_banner.setObjectName("AuthBanner")
            self.auth_banner.setFrameShape(QFrame.Shape.NoFrame)
            auth_layout = QHBoxLayout(self.auth_banner)
            auth_layout.setContentsMargins(14, 8, 14, 8)
            auth_layout.setSpacing(10)

            self.auth_lbl = self._reg_text(QLabel(), "auth_banner_text")
            self._reg_tip(self.auth_lbl, "polkit_source_hint")
            self.auth_lbl.setWordWrap(True)
            if not self._dark:
                self.auth_lbl.setStyleSheet("color: #334155;")
            auth_layout.addWidget(self.auth_lbl, 1)

            pill_btn_css = (
                "QPushButton { background-color: #ffffff; color: #1e293b; border: 1px solid #cbd5e1; "
                "border-radius: 9px; padding: 5px 11px; font-weight: 500; }"
                "QPushButton:hover { background-color: #f8fafc; border-color: #94a3b8; }"
                if not self._dark
                else ""
            )
            self.sudo_btn = self._reg_text(QPushButton(), "unlock_sudo_btn")
            self.sudo_btn.setIcon(QIcon.fromTheme("dialog-password"))
            if pill_btn_css:
                self.sudo_btn.setStyleSheet(pill_btn_css)
            self.sudo_btn.clicked.connect(self._unlock_sudo)
            auth_layout.addWidget(self.sudo_btn)

            self.pkexec_btn = self._reg_text(QPushButton(), "unlock_polkit_btn")
            self.pkexec_btn.setIcon(
                _theme_icon("preferences-system-privacy", "changes-allow", "dialog-password", "security-high")
            )
            if pill_btn_css:
                self.pkexec_btn.setStyleSheet(pill_btn_css)
            self.pkexec_btn.clicked.connect(self._unlock_pkexec)
            auth_layout.addWidget(self.pkexec_btn)

            self.user_mode_btn = self._reg_text(QPushButton(), "user_mode_btn")
            self.user_mode_btn.setIcon(
                _theme_icon("user-identity", "system-users", "folder-home")
            )
            if pill_btn_css:
                self.user_mode_btn.setStyleSheet(pill_btn_css)
            self.user_mode_btn.clicked.connect(self._activate_user_mode)
            auth_layout.addWidget(self.user_mode_btn)
            root.addWidget(self.auth_banner)

            # Plain-English Hero Status Banner (mockup_1: 48x48 HiDPI vector shield + clean copy + CTA)
            self.hero_banner = QFrame()
            self.hero_banner.setObjectName("HeroBanner")
            self.hero_banner.setFrameShape(QFrame.Shape.NoFrame)
            hero_outer = QHBoxLayout(self.hero_banner)
            hero_outer.setContentsMargins(20, 16, 20, 16)
            hero_outer.setSpacing(16)

            self.hero_icon_lbl = QLabel()
            self.hero_icon_lbl.setFixedSize(48, 48)
            self.hero_icon_lbl.setPixmap(_draw_shield_pixmap(48, "#1f9d68", "check"))
            hero_outer.addWidget(self.hero_icon_lbl)

            hero_layout = QVBoxLayout()
            hero_layout.setSpacing(3)

            self.hero_title_lbl = QLabel(self._tr("hero_protected_title"))
            hero_font = QFont()
            hero_font.setPointSize(14)
            hero_font.setBold(True)
            self.hero_title_lbl.setFont(hero_font)
            self.hero_title_lbl.setWordWrap(True)
            if not self._dark:
                self.hero_title_lbl.setStyleSheet("color: #13251b;")

            self.hero_sub_lbl = QLabel(self._tr("hero_protected_sub"))
            self.hero_sub_lbl.setWordWrap(True)
            if not self._dark:
                self.hero_sub_lbl.setStyleSheet("color: #2f4a3b;")
            hero_layout.addWidget(self.hero_title_lbl)
            hero_layout.addWidget(self.hero_sub_lbl)
            hero_outer.addLayout(hero_layout, 1)

            self.hero_review_btn = self._reg_text(QPushButton(), "hero_review_btn")
            self.hero_review_btn.setIcon(_theme_icon("security-low", "dialog-warning"))
            self.hero_review_btn.setVisible(False)
            self.hero_review_btn.clicked.connect(lambda: self._open_tab(1))
            hero_outer.addWidget(self.hero_review_btn)

            self.hero_db_btn = self._reg_text(QPushButton(), "hero_update_db_btn")
            self.hero_db_btn.setIcon(_theme_icon("view-refresh"))
            self.hero_db_btn.setVisible(False)
            self.hero_db_btn.clicked.connect(lambda: self._open_tab(3))
            hero_outer.addWidget(self.hero_db_btn)
            root.addWidget(self.hero_banner)

            # One-Click Quick Action Tiles (mockup_1: 3 equal elevated white cards)
            quick_row = QHBoxLayout()
            quick_row.setSpacing(16)

            self.btn_quick_scan = self._reg_text(
                ScanTileButton("quick", self._tr("tile_quick_title"), self._tr("tile_quick_sub"), dark=self._dark),
                "tile_quick_title",
            )
            self.btn_quick_scan.clicked.connect(self._start_quick_scan)
            quick_row.addWidget(self.btn_quick_scan, 1)

            self.btn_full_scan = self._reg_text(
                ScanTileButton("full", self._tr("tile_full_title"), self._tr("tile_full_sub"), dark=self._dark),
                "tile_full_title",
            )
            self.btn_full_scan.clicked.connect(self._start_full_scan)
            quick_row.addWidget(self.btn_full_scan, 1)

            self.btn_pick_scan = self._reg_text(
                ScanTileButton("pick", self._tr("tile_pick_title"), self._tr("tile_pick_sub"), dark=self._dark),
                "tile_pick_title",
            )
            self.btn_pick_scan.clicked.connect(self._start_custom_picker_scan)
            quick_row.addWidget(self.btn_pick_scan, 1)

            self.drop_hint_lbl = self._reg_text(QLabel(), "drop_hint")
            self.drop_hint_lbl.setVisible(False)
            root.addLayout(quick_row)

            # Unified 4-Column Status Summary Strip (mockup_1)
            self.stats_strip = QFrame()
            self.stats_strip.setObjectName("StatsStrip")
            self.stats_strip.setFrameShape(QFrame.Shape.NoFrame)
            self.stats_strip.setStyleSheet(
                "#StatsStrip { background-color: palette(base); border: 1px solid palette(mid); "
                "border-radius: 14px; }"
                if self._dark
                else "#StatsStrip { background-color: #ffffff; border: 1px solid #dde3ec; "
                "border-radius: 14px; }"
            )
            _apply_card_shadow(self.stats_strip, self._dark)
            cards_layout = QHBoxLayout(self.stats_strip)
            cards_layout.setContentsMargins(8, 6, 8, 6)
            cards_layout.setSpacing(0)
            self.card_status = StatCard(
                self._tr("idle_col_status"), self._tr("idle_val_protected"), "", dark=self._dark
            )
            self.card_cpu = StatCard(
                self._tr("idle_col_last_scan"), self._tr("idle_val_no_scans"), "", dark=self._dark
            )
            self.card_io = StatCard(
                self._tr("idle_col_sigs"), self._tr("idle_val_up_to_date"), "", dark=self._dark
            )
            self.card_threats = StatCard(
                self._tr("idle_col_sched"), self._tr("idle_val_not_sched"), "", dark=self._dark
            )
            stat_list = (self.card_status, self.card_cpu, self.card_io, self.card_threats)
            for idx_c, card in enumerate(stat_list):
                cards_layout.addWidget(card, 1)
                if idx_c < len(stat_list) - 1:
                    sep = QFrame()
                    sep.setFixedWidth(1)
                    sep.setStyleSheet(
                        "background-color: palette(mid); margin: 12px 0px; border: none;"
                        if self._dark
                        else "background-color: #e5eaf0; margin: 12px 0px; border: none;"
                    )
                    cards_layout.addWidget(sep)
            root.addWidget(self.stats_strip)

            # Currently Scanning Box + Control Bar (hidden when idle so Home matches mockup_1)
            self.ctrl_box = self._reg_title(QGroupBox(), "ctrl_box_title")
            self.ctrl_box.setStyleSheet(
                "QGroupBox { border: 1px solid palette(mid); border-radius: 12px; margin-top: 8px; padding-top: 10px; } "
                "QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 4px; }"
                if self._dark
                else "QGroupBox { background-color: #ffffff; border: 1px solid #dde3ec; border-radius: 14px; "
                "margin-top: 8px; padding-top: 12px; color: #111827; font-weight: 600; } "
                "QGroupBox::title { subcontrol-origin: margin; left: 14px; padding: 0 6px; color: #334155; }"
            )
            _apply_card_shadow(self.ctrl_box, self._dark)
            ctrl_layout = QVBoxLayout(self.ctrl_box)
            ctrl_layout.setSpacing(8)

            prog_row = QHBoxLayout()
            prog_row.addWidget(self._reg_text(QLabel(), "progress_label"))
            self.progress_bar = QProgressBar()
            self.progress_bar.setRange(0, 1000)
            self.progress_bar.setValue(0)
            self.progress_bar.setTextVisible(True)
            self.progress_bar.setFormat(self._tr("idle_word"))
            prog_row.addWidget(self.progress_bar, 1)

            self.eta_lbl = QLabel(self._tr("eta_prefix", eta="--:--:--"))
            eta_font = QFont()
            eta_font.setBold(True)
            self.eta_lbl.setFont(eta_font)
            self.eta_lbl.setMinimumWidth(160)
            prog_row.addWidget(self.eta_lbl)
            ctrl_layout.addLayout(prog_row)

            self.progress_sub_lbl = QLabel(self._tr("no_active_scan"))
            sub_font = QFont()
            sub_font.setPointSize(8)
            self.progress_sub_lbl.setFont(sub_font)
            self.progress_sub_lbl.setStyleSheet("color: palette(placeholderText);" if self._dark else "color: #5b6778;")
            ctrl_layout.addWidget(self.progress_sub_lbl)

            file_row = QHBoxLayout()
            file_row.addWidget(self._reg_text(QLabel(), "currently_checking"))
            self.current_file_edit = QLineEdit(self._tr("no_active_scan_running"))
            self.current_file_edit.setReadOnly(True)
            file_row.addWidget(self.current_file_edit, 1)
            ctrl_layout.addLayout(file_row)

            btn_row = QHBoxLayout()
            self.pause_btn = QPushButton(self._tr("pause_scan"))
            self.pause_btn.setIcon(QIcon.fromTheme("media-playback-pause"))
            self.pause_btn.clicked.connect(self._toggle_pause_scan)
            btn_row.addWidget(self.pause_btn)

            self.stop_btn = self._reg_text(QPushButton(), "stop_scan")
            self.stop_btn.setIcon(QIcon.fromTheme("process-stop"))
            self.stop_btn.clicked.connect(self._stop_scan)
            btn_row.addWidget(self.stop_btn)

            btn_row.addSpacing(16)
            self.bg_mode_chk = self._reg_text(QCheckBox(), "bg_mode_chk")
            self._reg_tip(self.bg_mode_chk, "bg_mode_tip")
            self.bg_mode_chk.clicked.connect(self._on_bg_mode_clicked)
            btn_row.addWidget(self.bg_mode_chk)
            btn_row.addStretch(1)
            ctrl_layout.addLayout(btn_row)
            self.ctrl_box.setVisible(False)
            root.addWidget(self.ctrl_box)

            # Toggle button for bottom detail tabs (centered subtle footer link, mockup_1)
            tabs_toggle_row = QHBoxLayout()
            self.toggle_tabs_btn = QPushButton(self._tr("show_tabs_btn"))
            self.toggle_tabs_btn.setCheckable(True)
            self.toggle_tabs_btn.setChecked(False)
            self.toggle_tabs_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self.toggle_tabs_btn.setStyleSheet(
                "QPushButton { border: none; background: transparent; color: palette(placeholderText); "
                "padding: 4px 10px; font-weight: 500; } "
                "QPushButton:hover { color: palette(text); }"
                if self._dark
                else "QPushButton { border: none; background: transparent; color: #556476; "
                "padding: 4px 10px; font-weight: 500; } "
                "QPushButton:hover { color: #111827; }"
            )
            self.toggle_tabs_btn.clicked.connect(self._on_toggle_tabs_panel)
            tabs_toggle_row.addStretch(1)
            tabs_toggle_row.addWidget(self.toggle_tabs_btn)
            tabs_toggle_row.addStretch(1)
            root.addLayout(tabs_toggle_row)

            # Main Tabs (hidden until requested; consolidated into 4 clear tabs)
            self.tabs = QTabWidget()
            self.tabs.setUsesScrollButtons(True)
            self.tabs.setElideMode(Qt.TextElideMode.ElideNone)
            log_hist_page = self._build_log_and_history_tab()
            threats_quar_page = self._build_threats_and_quarantine_tab()
            sched_custom_page = self._build_schedule_and_custom_tab()
            db_page = self._build_db_tab()
            tab_specs = (
                (log_hist_page, _theme_icon("text-x-log", "text-x-generic", "document-properties"), self._tab_label_log_history()),
                (threats_quar_page, _theme_icon("security-low", "security-medium", "dialog-warning"), self._tab_label_threats_quarantine()),
                (sched_custom_page, _theme_icon("appointment-new", "x-office-calendar"), self._tab_label_schedule_custom()),
                (db_page, _theme_icon("view-refresh"), self._tr("tab_db")),
            )
            for tab_page, tab_icon, tab_label in tab_specs:
                scroll = QScrollArea()
                scroll.setWidgetResizable(True)
                scroll.setFrameShape(QFrame.Shape.NoFrame)
                scroll.setWidget(tab_page)
                self.tabs.addTab(scroll, tab_icon, tab_label)
            self.tabs.setVisible(False)
            root.addWidget(self.tabs, 1)

            self._bottom_spacer = QWidget()
            root.addWidget(self._bottom_spacer, 1)

            self._update_auth_banner()
            self._update_controls_enabled()
            self._update_hero_banner(None)

        def _on_toggle_tabs_panel(self, checked: bool) -> None:
            prev_width = self.width()
            self.tabs.setVisible(checked)
            self._bottom_spacer.setVisible(not checked)
            if self.centralWidget() and self.centralWidget().layout():
                self.centralWidget().layout().activate()
            if self.layout():
                self.layout().activate()
            if checked:
                self.toggle_tabs_btn.setText(self._tr("hide_tabs_btn"))
                target_h = max(840, self.minimumSizeHint().height())
                self.resize(prev_width, target_h)
            else:
                self.toggle_tabs_btn.setText(self._tr("show_tabs_btn"))
                target_h = max(460, self.minimumSizeHint().height())
                self.resize(prev_width, target_h)

        def _open_tab(self, index: int) -> None:
            if not self.toggle_tabs_btn.isChecked():
                self.toggle_tabs_btn.setChecked(True)
                self._on_toggle_tabs_panel(True)
            self.tabs.setCurrentIndex(index)

        def _tab_label_log_history(self) -> str:
            return f"{self._tr('tab_log')} && {self._tr('tab_history')}"

        def _tab_label_threats_quarantine(self) -> str:
            t_cnt = self.threats_table.rowCount() if hasattr(self, "threats_table") else 0
            return f"{self._tr('tab_threats', count=t_cnt)} && {self._tr('tab_quarantine', count=self._quarantine_count)}"

        def _tab_label_schedule_custom(self) -> str:
            return f"{self._tr('tab_schedule')} && {self._tr('tab_custom')}"

        def _build_log_and_history_tab(self) -> QWidget:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setSpacing(12)

            self.log_group = self._reg_title(QGroupBox(), "tab_log")
            log_inner = QVBoxLayout(self.log_group)
            log_inner.setContentsMargins(8, 8, 8, 8)
            log_widget = self._build_log_tab()
            self.log_view.setMinimumHeight(180)
            log_inner.addWidget(log_widget)
            layout.addWidget(self.log_group, 3)

            self.history_group = self._reg_title(QGroupBox(), "tab_history")
            hist_inner = QVBoxLayout(self.history_group)
            hist_inner.setContentsMargins(8, 8, 8, 8)
            hist_widget = self._build_history_tab()
            self.history_table.setMinimumHeight(140)
            hist_inner.addWidget(hist_widget)
            layout.addWidget(self.history_group, 2)
            return page

        def _build_threats_and_quarantine_tab(self) -> QWidget:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setSpacing(12)

            self.threats_group = QGroupBox(self._tr("tab_threats", count=0))
            threats_inner = QVBoxLayout(self.threats_group)
            threats_inner.setContentsMargins(8, 8, 8, 8)
            threats_widget = self._build_threats_tab()
            self.threats_table.setMinimumHeight(140)
            threats_inner.addWidget(threats_widget)
            layout.addWidget(self.threats_group, 1)

            self.quarantine_group = QGroupBox(self._tr("tab_quarantine", count=0))
            quar_inner = QVBoxLayout(self.quarantine_group)
            quar_inner.setContentsMargins(8, 8, 8, 8)
            quar_widget = self._build_quarantine_tab()
            self.quarantine_table.setMinimumHeight(140)
            quar_inner.addWidget(quar_widget)
            layout.addWidget(self.quarantine_group, 1)
            return page

        def _build_schedule_and_custom_tab(self) -> QWidget:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setSpacing(12)

            self.schedule_group = self._reg_title(QGroupBox(), "tab_schedule")
            sched_inner = QVBoxLayout(self.schedule_group)
            sched_inner.setContentsMargins(8, 8, 8, 8)
            sched_inner.addWidget(self._build_schedule_tab())
            layout.addWidget(self.schedule_group)

            self.custom_group = self._reg_title(QGroupBox(), "tab_custom")
            custom_inner = QVBoxLayout(self.custom_group)
            custom_inner.setContentsMargins(8, 8, 8, 8)
            custom_inner.addWidget(self._build_new_scan_tab())
            layout.addWidget(self.custom_group)
            layout.addStretch(1)
            return page

        def _build_log_tab(self) -> QWidget:
            tab = QWidget()
            layout = QVBoxLayout(tab)

            top_bar = QHBoxLayout()
            top_bar.addWidget(self._reg_text(QLabel(), "log_path_lbl"))
            self.log_path_edit = self._reg_tip(QLineEdit(DEFAULT_LOG_PATH), "log_path_tip")
            top_bar.addWidget(self.log_path_edit, 1)

            reload_btn = self._reg_text(QPushButton(), "reload_log_btn")
            reload_btn.clicked.connect(self._reload_log)
            top_bar.addWidget(reload_btn)

            top_bar.addWidget(self._reg_text(QLabel(), "filter_lbl"))
            self.log_filter_edit = self._reg_ph(QLineEdit(), "log_filter_ph")
            self.log_filter_edit.textChanged.connect(self._render_log_view)
            top_bar.addWidget(self.log_filter_edit)

            self.autoscroll_chk = self._reg_text(QCheckBox(), "autoscroll_chk")
            self.autoscroll_chk.setChecked(True)
            top_bar.addWidget(self.autoscroll_chk)
            layout.addLayout(top_bar)

            opts_bar = QHBoxLayout()
            self.stream_fd_chk = self._reg_text(QCheckBox(), "stream_fd_chk")
            self.stream_fd_chk.setChecked(True)
            opts_bar.addWidget(self.stream_fd_chk)
            opts_bar.addStretch(1)
            layout.addLayout(opts_bar)

            hint_row = QHBoxLayout()
            self.log_hint_lbl = QLabel("")
            self.log_hint_lbl.setWordWrap(True)
            self.log_hint_lbl.setStyleSheet("color: palette(placeholderText);")
            hint_row.addWidget(self.log_hint_lbl, 1)

            self.restart_verbose_btn = self._reg_text(QPushButton(), "restart_verbose_btn")
            self.restart_verbose_btn.setIcon(QIcon.fromTheme("view-refresh"))
            self.restart_verbose_btn.setVisible(False)
            self.restart_verbose_btn.clicked.connect(self._restart_scan_without_i)
            hint_row.addWidget(self.restart_verbose_btn)
            layout.addLayout(hint_row)

            self.log_view = QPlainTextEdit()
            self.log_view.setReadOnly(True)
            self.log_view.setMaximumBlockCount(5000)
            mono = QFont("Monospace")
            mono.setStyleHint(QFont.StyleHint.TypeWriter)
            self.log_view.setFont(mono)
            self.log_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
            layout.addWidget(self.log_view, 1)
            return tab

        def _build_threats_tab(self) -> QWidget:
            tab = QWidget()
            layout = QVBoxLayout(tab)

            self.threats_table = QTableWidget(0, 3)
            self.threats_table.setHorizontalHeaderLabels(
                [self._tr("col_file_path"), self._tr("col_threat_sig"), self._tr("col_status")]
            )
            self.threats_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            self.threats_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
            self.threats_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            self.threats_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            self.threats_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            layout.addWidget(self.threats_table, 1)

            actions = QHBoxLayout()
            dolphin_btn = self._reg_text(QPushButton(), "reveal_dolphin_btn")
            dolphin_btn.setIcon(_theme_icon("system-file-manager", "folder-open"))
            dolphin_btn.clicked.connect(self._reveal_threat_in_dolphin)
            actions.addWidget(dolphin_btn)

            copy_btn = self._reg_text(QPushButton(), "copy_path_btn")
            copy_btn.setIcon(_theme_icon("edit-copy"))
            copy_btn.clicked.connect(self._copy_threat_path)
            actions.addWidget(copy_btn)

            quarantine_btn = self._reg_text(QPushButton(), "move_quarantine_btn")
            quarantine_btn.setIcon(_theme_icon("folder-locked", "changes-prevent", "system-lock-screen"))
            quarantine_btn.clicked.connect(self._quarantine_selected_threat)
            actions.addWidget(quarantine_btn)

            delete_btn = self._reg_text(QPushButton(), "delete_file_btn")
            delete_btn.setIcon(QIcon.fromTheme("edit-delete"))
            delete_btn.clicked.connect(self._delete_selected_threat)
            actions.addWidget(delete_btn)
            actions.addStretch(1)
            layout.addLayout(actions)
            return tab

        def _build_quarantine_tab(self) -> QWidget:
            tab = QWidget()
            layout = QVBoxLayout(tab)

            note = self._reg_text(QLabel(), "quarantine_note")
            note.setWordWrap(True)
            note.setStyleSheet("color: palette(placeholderText);")
            layout.addWidget(note)

            self.quarantine_table = QTableWidget(0, 5)
            self.quarantine_table.setHorizontalHeaderLabels(
                [
                    self._tr("col_q_name"),
                    self._tr("col_q_orig"),
                    self._tr("col_q_threat"),
                    self._tr("col_q_date"),
                    self._tr("col_q_size"),
                ]
            )
            self.quarantine_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            self.quarantine_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            self.quarantine_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            self.quarantine_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
            self.quarantine_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
            self.quarantine_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            self.quarantine_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            layout.addWidget(self.quarantine_table, 1)

            actions = QHBoxLayout()
            refresh_btn = self._reg_text(QPushButton(), "refresh_btn")
            refresh_btn.setIcon(QIcon.fromTheme("view-refresh"))
            refresh_btn.clicked.connect(self._refresh_quarantine)
            actions.addWidget(refresh_btn)

            restore_orig_btn = self._reg_text(QPushButton(), "restore_orig_btn")
            restore_orig_btn.setIcon(QIcon.fromTheme("edit-undo"))
            restore_orig_btn.clicked.connect(lambda: self._restore_quarantine(pick_dir=False))
            actions.addWidget(restore_orig_btn)

            restore_to_btn = self._reg_text(QPushButton(), "restore_to_btn")
            restore_to_btn.setIcon(QIcon.fromTheme("folder-open"))
            restore_to_btn.clicked.connect(lambda: self._restore_quarantine(pick_dir=True))
            actions.addWidget(restore_to_btn)

            del_q_btn = self._reg_text(QPushButton(), "delete_perm_btn")
            del_q_btn.setIcon(QIcon.fromTheme("edit-delete"))
            del_q_btn.clicked.connect(self._delete_quarantine_item)
            actions.addWidget(del_q_btn)
            actions.addStretch(1)
            layout.addLayout(actions)
            return tab

        def _build_history_tab(self) -> QWidget:
            tab = QWidget()
            layout = QVBoxLayout(tab)

            self.history_table = QTableWidget(0, 6)
            self.history_table.setHorizontalHeaderLabels(
                [
                    self._tr("col_h_date"),
                    self._tr("col_h_target"),
                    self._tr("col_h_duration"),
                    self._tr("col_h_scanned"),
                    self._tr("col_h_threats"),
                    self._tr("col_h_result"),
                ]
            )
            self.history_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            self.history_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            self.history_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            self.history_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
            self.history_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
            self.history_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
            self.history_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            self.history_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            layout.addWidget(self.history_table, 1)

            actions = QHBoxLayout()
            refresh_btn = self._reg_text(QPushButton(), "refresh_history_btn")
            refresh_btn.setIcon(QIcon.fromTheme("view-refresh"))
            refresh_btn.clicked.connect(self._refresh_history)
            actions.addWidget(refresh_btn)

            clear_btn = self._reg_text(QPushButton(), "clear_history_btn")
            clear_btn.setIcon(_theme_icon("edit-clear-history", "edit-clear-all", "edit-clear"))
            clear_btn.clicked.connect(self._clear_history)
            actions.addWidget(clear_btn)
            actions.addStretch(1)
            layout.addLayout(actions)
            return tab

        def _build_schedule_tab(self) -> QWidget:
            tab = QWidget()
            layout = QVBoxLayout(tab)

            desc = self._reg_text(QLabel(), "sched_desc")
            desc.setWordWrap(True)
            desc.setStyleSheet("color: palette(placeholderText);" if self._dark else "color: #475569;")
            layout.addWidget(desc)

            form = QFormLayout()
            form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
            form.setHorizontalSpacing(14)
            form.setVerticalSpacing(5)
            self.sched_enabled_chk = self._reg_text(QCheckBox(), "sched_enable_chk")
            form.addRow(self._reg_text(QLabel(), "sched_status_lbl"), self.sched_enabled_chk)

            self.sched_type_combo = QComboBox()
            self.sched_type_combo.addItem(self._tr("sched_type_quick"), "quick")
            self.sched_type_combo.addItem(self._tr("sched_type_full"), "full")
            form.addRow(self._reg_text(QLabel(), "sched_type_lbl"), self.sched_type_combo)

            self.sched_freq_combo = QComboBox()
            self.sched_freq_combo.addItem(self._tr("sched_freq_daily"), "daily")
            self.sched_freq_combo.addItem(self._tr("sched_freq_weekly"), "weekly")
            self.sched_freq_combo.currentIndexChanged.connect(self._update_sched_day_visibility)
            form.addRow(self._reg_text(QLabel(), "sched_freq_lbl"), self.sched_freq_combo)

            self.sched_day_combo = QComboBox()
            for day_key, day_code in (
                ("day_mon", "Mon"),
                ("day_tue", "Tue"),
                ("day_wed", "Wed"),
                ("day_thu", "Thu"),
                ("day_fri", "Fri"),
                ("day_sat", "Sat"),
                ("day_sun", "Sun"),
            ):
                self.sched_day_combo.addItem(self._tr(day_key), day_code)
            self.sched_day_combo.setCurrentIndex(6)
            form.addRow(self._reg_text(QLabel(), "sched_day_lbl"), self.sched_day_combo)

            self.sched_time_edit = QTimeEdit(QTime(3, 0))
            self.sched_time_edit.setDisplayFormat("HH:mm")
            form.addRow(self._reg_text(QLabel(), "sched_time_lbl"), self.sched_time_edit)

            self.sched_status_lbl = QLabel(self._tr("sched_unlock_hint"))
            self.sched_status_lbl.setWordWrap(True)
            self.sched_status_lbl.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.MinimumExpanding)
            self.sched_status_lbl.setMinimumHeight(24)
            self.sched_status_lbl.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            self.sched_status_lbl.setStyleSheet(
                "color: #cbd5e1; font-weight: 500;" if self._dark else "color: #334155; font-weight: 500;"
            )
            form.addRow(self._reg_text(QLabel(), "sched_info_lbl"), self.sched_status_lbl)
            layout.addLayout(form)

            btn_row = QHBoxLayout()
            self.sched_save_btn = self._reg_text(QPushButton(), "save_sched_btn")
            self.sched_save_btn.setIcon(QIcon.fromTheme("document-save"))
            self.sched_save_btn.clicked.connect(self._save_schedule)
            btn_row.addWidget(self.sched_save_btn)

            self.sched_refresh_btn = self._reg_text(QPushButton(), "refresh_btn")
            self.sched_refresh_btn.clicked.connect(self._refresh_schedule)
            btn_row.addWidget(self.sched_refresh_btn)
            btn_row.addStretch(1)
            layout.addLayout(btn_row)
            layout.addStretch(1)
            self._update_sched_day_visibility()
            return tab

        def _build_new_scan_tab(self) -> QWidget:
            tab = QWidget()
            layout = QVBoxLayout(tab)

            form = QFormLayout()

            target_row = QHBoxLayout()
            self.scan_target_combo = QComboBox()
            self.scan_target_combo.setEditable(True)
            default_targets = (
                [_system_root_target(), os.path.expanduser("~"), tempfile.gettempdir()]
                if IS_WINDOWS
                else ["/", os.path.expanduser("~"), "/tmp", "/var"]
            )
            self.scan_target_combo.addItems(default_targets)
            self.scan_target_combo.currentTextChanged.connect(self._update_command_preview)
            target_row.addWidget(self.scan_target_combo, 1)
            browse_btn = self._reg_text(QPushButton(), "browse_btn")
            browse_btn.clicked.connect(self._browse_scan_target)
            target_row.addWidget(browse_btn)
            form.addRow(self._reg_text(QLabel(), "adv_target_lbl"), target_row)

            opts_box = QVBoxLayout()
            opts_box.setSpacing(4)
            self.opt_recursive = self._reg_text(QCheckBox(), "opt_recursive")
            self.opt_recursive.setChecked(True)
            self.opt_infected_only = self._reg_text(QCheckBox(), "opt_infected_only")
            self.opt_infected_only.setChecked(False)
            self.opt_exclude_virtual = self._reg_text(QCheckBox(), "opt_exclude_virtual")
            self.opt_exclude_virtual.setChecked(not IS_WINDOWS)
            self.opt_cross_fs = self._reg_text(QCheckBox(), "opt_cross_fs")
            self.opt_cross_fs.setChecked(False)
            for chk in (self.opt_recursive, self.opt_infected_only, self.opt_exclude_virtual, self.opt_cross_fs):
                chk.toggled.connect(self._update_command_preview)
                opts_box.addWidget(chk)
            form.addRow(self._reg_text(QLabel(), "adv_options_lbl"), opts_box)

            size_row = QHBoxLayout()
            self.max_size_spin = QSpinBox()
            self.max_size_spin.setRange(10, 4000)
            self.max_size_spin.setValue(100)
            self.max_size_spin.setSuffix(" MB")
            self.max_size_spin.valueChanged.connect(self._update_command_preview)
            size_row.addWidget(self.max_size_spin)
            size_row.addStretch(1)
            form.addRow(self._reg_text(QLabel(), "adv_maxsize_lbl"), size_row)

            self.infected_action_combo = QComboBox()
            self.infected_action_combo.addItem(self._tr("action_report"), "report")
            self.infected_action_combo.addItem(self._tr("action_move"), "move")
            self.infected_action_combo.addItem(self._tr("action_copy"), "copy")
            self.infected_action_combo.currentIndexChanged.connect(self._update_command_preview)
            form.addRow(self._reg_text(QLabel(), "adv_action_lbl"), self.infected_action_combo)

            self.new_log_edit = self._reg_tip(QLineEdit(DEFAULT_LOG_PATH), "log_path_tip")
            self.new_log_edit.textChanged.connect(self._update_command_preview)
            form.addRow(self._reg_text(QLabel(), "adv_log_lbl"), self.new_log_edit)

            self.cmd_preview_edit = QLineEdit()
            self.cmd_preview_edit.setReadOnly(True)
            form.addRow(self._reg_text(QLabel(), "adv_cmd_lbl"), self.cmd_preview_edit)
            layout.addLayout(form)

            start_row = QHBoxLayout()
            self.start_scan_btn = self._reg_text(QPushButton(), "start_custom_btn")
            self.start_scan_btn.setIcon(QIcon.fromTheme("media-playback-start"))
            self.start_scan_btn.clicked.connect(self._start_new_scan)
            start_row.addWidget(self.start_scan_btn)
            start_row.addStretch(1)
            layout.addLayout(start_row)
            layout.addStretch(1)
            return tab

        def _build_db_tab(self) -> QWidget:
            tab = QWidget()
            layout = QVBoxLayout(tab)

            info_row = QHBoxLayout()
            self.db_status_lbl = QLabel(self._tr("db_checking"))
            self.db_status_lbl.setWordWrap(True)
            info_row.addWidget(self.db_status_lbl, 1)

            self.freshclam_btn = QPushButton(self._tr("freshclam_btn"))
            self.freshclam_btn.setIcon(QIcon.fromTheme("view-refresh"))
            self.freshclam_btn.clicked.connect(self._run_freshclam)
            info_row.addWidget(self.freshclam_btn)
            layout.addLayout(info_row)

            self.freshclam_output = self._reg_ph(QPlainTextEdit(), "freshclam_ph")
            self.freshclam_output.setReadOnly(True)
            mono = QFont("Monospace")
            mono.setStyleHint(QFont.StyleHint.TypeWriter)
            self.freshclam_output.setFont(mono)
            layout.addWidget(self.freshclam_output, 1)
            return tab

        def _apply_translations(self) -> None:
            self.setWindowTitle(self._tr("window_title"))
            for widget, key in self._tr_text:
                widget.setText(self._tr(key))
            for widget, key in self._tr_title:
                widget.setTitle(self._tr(key))
            for widget, key in self._tr_tip:
                widget.setToolTip(self._tr(key))
            for widget, key in self._tr_ph:
                widget.setPlaceholderText(self._tr(key))

            self._sync_stat_card_titles(self._current_proc)

            for i, k in enumerate(("sched_type_quick", "sched_type_full")):
                self.sched_type_combo.setItemText(i, self._tr(k))
            for i, k in enumerate(("sched_freq_daily", "sched_freq_weekly")):
                self.sched_freq_combo.setItemText(i, self._tr(k))
            for i, k in enumerate(("day_mon", "day_tue", "day_wed", "day_thu", "day_fri", "day_sat", "day_sun")):
                self.sched_day_combo.setItemText(i, self._tr(k))
            for i, k in enumerate(("action_report", "action_move", "action_copy")):
                self.infected_action_combo.setItemText(i, self._tr(k))

            self.threats_table.setHorizontalHeaderLabels(
                [self._tr("col_file_path"), self._tr("col_threat_sig"), self._tr("col_status")]
            )
            self.quarantine_table.setHorizontalHeaderLabels(
                [
                    self._tr("col_q_name"),
                    self._tr("col_q_orig"),
                    self._tr("col_q_threat"),
                    self._tr("col_q_date"),
                    self._tr("col_q_size"),
                ]
            )
            self.history_table.setHorizontalHeaderLabels(
                [
                    self._tr("col_h_date"),
                    self._tr("col_h_target"),
                    self._tr("col_h_duration"),
                    self._tr("col_h_scanned"),
                    self._tr("col_h_threats"),
                    self._tr("col_h_result"),
                ]
            )

            self.threats_group.setTitle(self._tr("tab_threats", count=self.threats_table.rowCount()))
            self.quarantine_group.setTitle(self._tr("tab_quarantine", count=self._quarantine_count))
            self.tabs.setTabText(0, self._tab_label_log_history())
            self.tabs.setTabText(1, self._tab_label_threats_quarantine())
            self.tabs.setTabText(2, self._tab_label_schedule_custom())
            self.tabs.setTabText(3, self._tr("tab_db"))

            self.toggle_tabs_btn.setText(
                self._tr("hide_tabs_btn" if self.toggle_tabs_btn.isChecked() else "show_tabs_btn")
            )
            self.pkexec_btn.setText(
                self._tr("waiting_polkit" if self._polkit_waiting else "unlock_polkit_btn")
            )
            self.freshclam_btn.setText(
                self._tr("freshclam_updating" if self._freshclam_running else "freshclam_btn")
            )

            if hasattr(self, "tray_open_act"):
                self.tray_open_act.setText(self._tr("tray_open"))
                self.tray_quick_act.setText(self._tr("tray_quick"))
                self.tray_stop_act.setText(self._tr("stop_scan"))
                self.tray_about_act.setText(self._tr("about_btn"))
                self.tray_quit_act.setText(self._tr("quit_btn"))

            if not self.helper.is_connected:
                self.sched_status_lbl.setText(self._tr("sched_unlock_hint"))
            else:
                self._refresh_schedule()

            self.btn_quick_scan.setSubtitle(self._tr("tile_quick_sub"))
            self.btn_full_scan.setSubtitle(self._tr("tile_full_sub"))
            self.btn_pick_scan.setSubtitle(self._tr("tile_pick_sub"))

            self._refresh_metadata()
            self._update_auth_banner()
            self._update_controls_enabled()
            self._update_threat_count()
            self._render_unprivileged_telemetry(self._current_proc)
            self._update_hero_banner(self._current_proc)
            self._update_tray_status(self._current_proc)
            self._refresh_history()

        def _refresh_metadata(self) -> None:
            meta = get_clamav_metadata()
            # Provide clean defaults if a test mocks get_clamav_metadata() with minimal keys
            has_clamscan = bool(meta.get("has_clamscan", meta.get("version") != "Unavailable"))
            has_freshclam = bool(meta.get("has_freshclam", True))
            has_db = bool(meta.get("has_virus_db", has_clamscan))
            db_count = int(meta.get("db_files_count", 1 if has_db else 0))
            db_dir = str(meta.get("db_dir", "/var/lib/clamav"))
            missing_opt = list(meta.get("missing_optional", []))
            normalized = {
                **meta,
                "has_clamscan": has_clamscan,
                "has_freshclam": has_freshclam,
                "has_virus_db": has_db,
                "db_files_count": db_count,
                "db_dir": db_dir,
                "missing_optional": missing_opt,
            }
            self._last_meta = normalized

            db_state = (
                self._tr("db_state_ready", count=db_count)
                if has_db
                else self._tr("db_state_missing", db_dir=db_dir)
            )
            fc_state = self._tr("installed_word" if has_freshclam else "missing_word")
            deps_note = (
                self._tr("db_deps_missing", tools=", ".join(missing_opt))
                if missing_opt
                else self._tr("db_deps_ok")
            )
            warn_parts = []
            if not has_freshclam:
                warn_parts.append("freshclam: " + self._tr("missing_word"))
            if missing_opt:
                warn_parts.append(", ".join(missing_opt) + " " + self._tr("missing_word"))
            warn_str = ("   |   " + "; ".join(warn_parts)) if warn_parts else ""

            raw_svc = str(meta.get("freshclam_service", "inactive"))
            svc_disp = (
                self._tr("svc_active")
                if raw_svc == "active"
                else (self._tr("svc_inactive") if raw_svc == "inactive" else raw_svc)
            )
            if not has_clamscan:
                self.header_shield_lbl.setPixmap(_draw_shield_pixmap(34, "#b91c1c", "alert"))
            elif not has_db:
                self.header_shield_lbl.setPixmap(_draw_shield_pixmap(34, "#b45309", "alert"))
            else:
                self.header_shield_lbl.setPixmap(_draw_shield_pixmap(34, "#1f9d68", "check"))

            raw_ver = str(meta.get("version", "Unavailable"))
            short_ver = raw_ver.split("/")[0].strip() or raw_ver
            self.meta_lbl.setText(
                self._tr(
                    "meta_line_full",
                    version=short_ver,
                    db_state=db_state,
                    service=svc_disp,
                    warn=warn_str,
                )
            )
            self.db_status_lbl.setText(
                self._tr(
                    "db_status_full",
                    version=raw_ver,
                    freshclam_bin=fc_state,
                    db_dir=db_dir,
                    db_state=db_state,
                    service=svc_disp,
                    deps_note=deps_note,
                )
            )

            for scan_btn in (self.btn_quick_scan, self.btn_full_scan, self.btn_pick_scan, self.start_scan_btn):
                scan_btn.setEnabled(has_clamscan)
                scan_btn.setToolTip("" if has_clamscan else self._tr("clamscan_missing_tip"))
            if not self._freshclam_running:
                self.freshclam_btn.setEnabled(has_freshclam)
                self.freshclam_btn.setToolTip("" if has_freshclam else self._tr("freshclam_missing_tip"))

            self._update_hero_banner(self._current_proc)
            if self._current_proc is None:
                self._render_idle_stats_strip()

        def _update_auth_banner(self) -> None:
            connected = self.helper.is_connected
            self.auth_banner.setVisible(not connected)
            self.root_badge_lbl.setVisible(connected)
            if connected:
                if self.helper.is_user_mode:
                    self.root_badge_lbl.setText(self._tr("user_mode_badge"))
                    self.root_badge_lbl.setStyleSheet(
                        "color: #1d4ed8; font-weight: 600; padding: 5px 13px; "
                        "background-color: #dbeafe; border: 1px solid #bfdbfe; border-radius: 14px;"
                        if not self._dark
                        else "color: #60a5fa; font-weight: bold; padding: 5px 13px; "
                        "background-color: rgba(37, 99, 235, 0.22); border: 1px solid rgba(96, 165, 250, 0.35); border-radius: 14px;"
                    )
                else:
                    self.root_badge_lbl.setText(self._tr("root_active_badge"))
                    self.root_badge_lbl.setStyleSheet(
                        "color: #147a4c; font-weight: 600; padding: 5px 13px; "
                        "background-color: #d7f3e4; border: 1px solid #b5e7cd; border-radius: 14px;"
                        if not self._dark
                        else "color: #34d399; font-weight: bold; padding: 5px 13px; "
                        "background-color: rgba(31, 138, 91, 0.22); border: 1px solid rgba(52, 211, 153, 0.35); border-radius: 14px;"
                    )
            if not connected:
                self.auth_banner.setStyleSheet(
                    "#AuthBanner { border: 1px solid #d9e2ec; border-radius: 12px; "
                    "background-color: #f8fafc; }"
                    if not self._dark
                    else "#AuthBanner { border: 1px solid #b45309; border-radius: 10px; "
                    "background-color: rgba(180, 83, 9, 0.14); }"
                )
            self._compact_window_if_idle()

        def _update_hero_banner(self, proc: dict[str, Any] | None) -> None:
            threats = self.threats_table.rowCount()
            self.hero_review_btn.setVisible(threats > 0)
            self.hero_db_btn.setVisible(False)
            if threats > 0:
                self.hero_banner.setStyleSheet(
                    "#HeroBanner { border: 1.5px solid #e5989b; border-radius: 14px; "
                    "background-color: #fdf0f0; }"
                    if not self._dark
                    else "#HeroBanner { border: 1px solid #b91c1c; border-radius: 12px; "
                    "background-color: rgba(185, 28, 28, 0.10); }"
                )
                self.hero_icon_lbl.setPixmap(_draw_shield_pixmap(48, "#c53030", "alert"))
                self.hero_title_lbl.setText(self._tr("hero_threats_title", count=threats))
                self.hero_sub_lbl.setText(self._tr("hero_threats_sub"))
                return

            if proc is None:
                meta = self._last_meta
                if meta and not meta.get("has_clamscan", True):
                    self.hero_banner.setStyleSheet(
                        "#HeroBanner { border: 1.5px solid #e5989b; border-radius: 14px; "
                        "background-color: #fdf0f0; }"
                        if not self._dark
                        else "#HeroBanner { border: 1px solid #b91c1c; border-radius: 12px; "
                        "background-color: rgba(185, 28, 28, 0.10); }"
                    )
                    self.hero_icon_lbl.setPixmap(_draw_shield_pixmap(48, "#c53030", "alert"))
                    missing_req = [p for p in meta.get("missing_required", []) if p != "clamscan"]
                    extra = (
                        self._tr("also_missing_suffix", items=", ".join(missing_req)) if missing_req else ""
                    )
                    self.hero_title_lbl.setText(self._tr("hero_missing_clamscan_title"))
                    self.hero_sub_lbl.setText(self._tr("hero_missing_clamscan_sub", extra=extra))
                    return
                if meta and not meta.get("has_virus_db", True):
                    self.hero_banner.setStyleSheet(
                        "#HeroBanner { border: 1.5px solid #ebd094; border-radius: 14px; "
                        "background-color: #fef9ec; }"
                        if not self._dark
                        else "#HeroBanner { border: 1px solid #b45309; border-radius: 12px; "
                        "background-color: rgba(180, 83, 9, 0.10); }"
                    )
                    self.hero_icon_lbl.setPixmap(_draw_shield_pixmap(48, "#b45309", "download"))
                    self.hero_title_lbl.setText(self._tr("hero_missing_db_title"))
                    self.hero_sub_lbl.setText(
                        self._tr("hero_missing_db_sub", db_dir=meta.get("db_dir", "/var/lib/clamav"))
                    )
                    self.hero_db_btn.setVisible(bool(meta.get("has_freshclam", True)))
                    return

                self.hero_banner.setStyleSheet(
                    "#HeroBanner { border: 1.5px solid #96d8b6; border-radius: 14px; "
                    "background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #dcf5e8, stop:1 #e7f9f0); }"
                    if not self._dark
                    else "#HeroBanner { border: 1px solid rgba(31, 138, 91, 0.45); border-radius: 12px; "
                    "background-color: rgba(31, 138, 91, 0.12); }"
                )
                self.hero_icon_lbl.setPixmap(_draw_shield_pixmap(48, "#1f9d68", "check"))
                self.hero_title_lbl.setText(self._tr("hero_protected_title"))
                self.hero_sub_lbl.setText(self._tr("hero_protected_sub"))
            elif proc.get("state") == "T":
                self.hero_banner.setStyleSheet(
                    "#HeroBanner { border: 1.5px solid #ebd094; border-radius: 14px; "
                    "background-color: #fef9ec; }"
                    if not self._dark
                    else "#HeroBanner { border: 1px solid #b45309; border-radius: 12px; "
                    "background-color: rgba(180, 83, 9, 0.10); }"
                )
                self.hero_icon_lbl.setPixmap(_draw_shield_pixmap(48, "#b45309", "alert"))
                pct_txt = f" ({self._last_pct:.1f}%)" if self.helper.is_connected else ""
                self.hero_title_lbl.setText(self._tr("hero_paused_title", pct=pct_txt))
                self.hero_sub_lbl.setText(self._tr("hero_paused_sub"))
            else:
                self.hero_banner.setStyleSheet(
                    "#HeroBanner { border: 1.5px solid #9dc9e8; border-radius: 14px; "
                    "background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #e3f2fc, stop:1 #eef7fe); }"
                    if not self._dark
                    else "#HeroBanner { border: 1px solid #0369a1; border-radius: 12px; "
                    "background-color: rgba(3, 105, 161, 0.12); }"
                )
                self.hero_icon_lbl.setPixmap(_draw_shield_pixmap(48, "#0284c7", "scan"))
                if self.helper.is_connected:
                    self.hero_title_lbl.setText(self._tr("hero_scanning_title", pct=self._last_pct))
                    cur_file = self.current_file_edit.text().strip()
                    short_file = os.path.basename(cur_file) if os.path.isabs(cur_file) else cur_file
                    self.hero_sub_lbl.setText(
                        self._tr("hero_scanning_sub", eta=self._last_eta_str, file=short_file)
                    )
                else:
                    self.hero_title_lbl.setText(self._tr("hero_bg_title"))
                    self.hero_sub_lbl.setText(self._tr("hero_bg_sub"))

        def _update_tray_status(self, proc: dict[str, Any] | None) -> None:
            if self._tray_icon is None:
                return
            threats = self.threats_table.rowCount()
            if proc is None:
                tip = self._tr("tray_tip_idle", count=threats)
                self.tray_pause_act.setEnabled(False)
                self.tray_stop_act.setEnabled(False)
            else:
                can_ctrl = self.helper.is_connected or proc.get("uid") == _uid()
                self.tray_pause_act.setEnabled(can_ctrl)
                self.tray_stop_act.setEnabled(can_ctrl)
                if proc.get("state") == "T":
                    self.tray_pause_act.setText(self._tr("resume_scan"))
                    tip = self._tr("tray_tip_paused", pct=self._last_pct)
                else:
                    self.tray_pause_act.setText(self._tr("pause_scan"))
                    if self.helper.is_connected:
                        tip = self._tr("tray_tip_scanning", pct=self._last_pct, eta=self._last_eta_str)
                    else:
                        tip = self._tr("tray_tip_running")
            self._tray_icon.setToolTip(tip)

        def _update_controls_enabled(self) -> None:
            proc = self._current_proc
            has_proc = proc is not None
            self.ctrl_box.setVisible(has_proc)
            can_control = has_proc and (self.helper.is_connected or proc.get("uid") == _uid())
            self.pause_btn.setEnabled(can_control)
            self.stop_btn.setEnabled(can_control)
            self.bg_mode_chk.setEnabled(can_control or not has_proc)

            if proc is not None:
                self.bg_mode_chk.blockSignals(True)
                self.bg_mode_chk.setChecked(int(proc.get("nice", 0)) >= 10)
                self.bg_mode_chk.blockSignals(False)

            if proc and proc.get("state") == "T":
                self.pause_btn.setText(self._tr("resume_scan"))
                self.pause_btn.setIcon(QIcon.fromTheme("media-playback-start"))
            else:
                self.pause_btn.setText(self._tr("pause_scan"))
                self.pause_btn.setIcon(QIcon.fromTheme("media-playback-pause"))

        def _reset_log_state(self, reset_offset: bool = True) -> None:
            if reset_offset:
                self.telemetry.log_offset = 0
            self.telemetry.log_lines.clear()
            self.telemetry.partial_line = ""
            self.telemetry.total_lines_logged = 0
            self.telemetry.last_sampled_fd_file = None
            self.telemetry.seen_threats.clear()
            self.threats_table.setRowCount(0)
            self.log_view.clear()
            self._update_threat_count()

        def _on_root_unlocked(self) -> None:
            self._log_reload_error = ""
            self._reset_log_state(reset_offset=True)
            self._update_auth_banner()
            self._update_controls_enabled()
            self._update_command_preview()
            self._poll_tick()
            self._refresh_quarantine()
            self._refresh_schedule()
            self._refresh_history()

        def _try_auto_connect(self) -> None:
            if self.helper.is_connected:
                return
            settings = load_json_file(SETTINGS_FILE_PATH, {})
            has_polkit_rule = (
                (not IS_WINDOWS)
                and (not IS_MACOS)
                and (os.path.exists(POLKIT_RULE_PATH) or bool(settings.get("polkit_rule_installed")))
            )

            def _auto_worker() -> None:
                if IS_WINDOWS or IS_MACOS or _euid() == 0:
                    ok_local, _ = self.helper.start_local()
                    if ok_local:
                        self.signals.auto_sudo_done.emit(True)
                    return
                ok_sudo, _ = self.helper.start_with_sudo_nopass()
                if ok_sudo:
                    self.signals.auto_sudo_done.emit(True)
                    return
                if has_polkit_rule:
                    ok_pk, msg_pk = self.helper.start_with_pkexec()
                    self.signals.pkexec_done.emit(ok_pk, msg_pk, True)

            threading.Thread(target=_auto_worker, daemon=True).start()

        def _on_auto_sudo_done(self, ok: bool) -> None:
            if ok:
                self._on_root_unlocked()

        def _install_polkit_rule_best_effort(self) -> None:
            try:
                username = getpass.getuser()
                self.helper.call("install_polkit_rule", {"username": username})
                settings = load_json_file(SETTINGS_FILE_PATH, {})
                if not isinstance(settings, dict):
                    settings = {}
                settings["polkit_rule_installed"] = True
                save_json_file(SETTINGS_FILE_PATH, settings)
            except Exception:  # noqa: BLE001
                pass

        def _unlock_sudo(self, silent_refresh: bool = False) -> bool:
            password, ok = QInputDialog.getText(
                self,
                self._tr("dlg_sudo_title"),
                self._tr("dlg_sudo_prompt"),
                QLineEdit.EchoMode.Password,
            )
            if not ok or not password:
                return False
            success, msg = self.helper.start_with_sudo(password)
            if not success:
                QMessageBox.warning(self, self._tr("dlg_auth_failed"), msg)
                return False
            self._install_polkit_rule_best_effort()
            self._on_root_unlocked()
            return True

        def _unlock_pkexec(self) -> None:
            self._polkit_waiting = True
            self.pkexec_btn.setEnabled(False)
            self.pkexec_btn.setText(self._tr("waiting_polkit"))

            def _worker() -> None:
                ok, msg = self.helper.start_with_pkexec()
                self.signals.pkexec_done.emit(ok, msg, False)

            threading.Thread(target=_worker, daemon=True).start()

        def _on_pkexec_done(self, ok: bool, msg: str, silent: bool) -> None:
            self._polkit_waiting = False
            self.pkexec_btn.setEnabled(True)
            self.pkexec_btn.setText(self._tr("unlock_polkit_btn"))
            if not ok:
                if not silent:
                    QMessageBox.warning(self, self._tr("dlg_polkit_failed"), msg)
            else:
                self._install_polkit_rule_best_effort()
                self._on_root_unlocked()

        def _on_helper_disconnected(self) -> None:
            self.telemetry.last_proc_data = {}
            self.telemetry.last_precount = {}
            self.telemetry.last_eta_speed_bps = None
            self._update_auth_banner()
            self._update_controls_enabled()
            self._update_progress_ui(self._current_proc)
            self._update_hero_banner(self._current_proc)
            self._update_tray_status(self._current_proc)

        def _apply_compact_idle_size(self) -> None:
            if self.toggle_tabs_btn.isChecked() or self._current_proc is not None:
                return
            for child in (
                self.card_status,
                self.card_cpu,
                self.card_io,
                self.card_threats,
                self.stats_strip,
                self.hero_banner,
            ):
                if child.layout():
                    child.layout().activate()
            if self.centralWidget() and self.centralWidget().layout():
                self.centralWidget().layout().activate()
            if self.layout():
                self.layout().activate()
            self.resize(self.width(), max(460, self.minimumSizeHint().height()))

        def _compact_window_if_idle(self) -> None:
            if self.toggle_tabs_btn.isChecked() or self._current_proc is not None:
                return
            self._apply_compact_idle_size()
            QTimer.singleShot(0, self._apply_compact_idle_size)

        def _clear_scan_telemetry(self) -> None:
            self.telemetry.selected_pid = None
            self.telemetry.last_proc_data = {}
            self.telemetry.last_precount = {}
            self.telemetry.last_eta_speed_bps = None
            self.telemetry.last_cpu_ticks = None
            self.telemetry.last_cpu_time = None
            self.telemetry.last_io_bytes = None
            self.telemetry.last_io_time = None

        def _poll_tick(self) -> None:
            procs = discover_clamscan_processes()
            self._known_procs = procs
            was_running = self._current_proc is not None

            selected = next((p for p in procs if p["pid"] == self.telemetry.selected_pid), None)
            if selected is None and procs:
                selected = procs[0]
                self.telemetry.selected_pid = selected["pid"]
                self.telemetry.last_cpu_ticks = None
                self.telemetry.last_io_bytes = None
                self.telemetry.last_eta_speed_bps = None
                self.telemetry.last_proc_data = {}
                self.telemetry.last_precount = {}
                self.telemetry.statvfs_cache_key = None
            elif selected is None:
                if self._last_active_scan is not None:
                    self._handle_scan_finished(self._last_active_scan)
                    self._last_active_scan = None
                self._clear_scan_telemetry()

            if selected is not None:
                label = self._pending_scan_labels.get(selected["pid"])
                if not label:
                    limits = parse_scan_targets_and_limits(selected["cmdline"])
                    t_str = ", ".join(limits["targets"])
                    label = self._tr("label_full_scan") if t_str == _system_root_target() else self._tr("label_custom_scan", target=t_str)
                self._last_active_scan = {
                    "pid": selected["pid"],
                    "label": label,
                    "elapsed_sec": selected["elapsed_sec"],
                    "cmdline": selected["cmdline"],
                    "log_path": selected["log_path"] or self.telemetry.log_path,
                }

            self._current_proc = selected
            self._render_unprivileged_telemetry(selected)
            self._update_controls_enabled()
            self._update_hero_banner(selected)
            self._update_tray_status(selected)
            if was_running and selected is None:
                self._compact_window_if_idle()

            log_path = self.log_path_edit.text().strip()
            if selected and selected["log_path"] and self.telemetry.log_path != selected["log_path"]:
                self.telemetry.log_path = selected["log_path"]
                self.log_path_edit.setText(selected["log_path"])
                self._reset_log_state(reset_offset=True)
            elif log_path and log_path != self.telemetry.log_path:
                self.telemetry.log_path = log_path
                self._reset_log_state(reset_offset=True)

            if self.helper.is_connected and not self._inspect_inflight:
                self._inspect_inflight = True
                req_pid = selected["pid"] if selected else None
                req_cmdline = selected["cmdline"] if selected else None
                req_log = self.telemetry.log_path
                req_offset = self.telemetry.log_offset

                def _worker() -> None:
                    try:
                        res = self.helper.call(
                            "inspect_proc",
                            {
                                "pid": req_pid,
                                "cmdline": req_cmdline,
                                "log_path": req_log,
                                "log_offset": req_offset,
                            },
                            timeout=4.0,
                        )
                        self.signals.inspect_done.emit(res, "")
                    except Exception as exc:  # noqa: BLE001
                        self.signals.inspect_done.emit(None, str(exc))

                threading.Thread(target=_worker, daemon=True).start()
            elif not self.helper.is_connected:
                if self.telemetry.log_path and os.access(self.telemetry.log_path, os.R_OK):
                    try:
                        log_res = _read_log_chunk(self.telemetry.log_path, self.telemetry.log_offset)
                        self._apply_log_result(log_res)
                    except OSError:
                        pass

        def _handle_scan_finished(self, finished: dict[str, Any]) -> None:
            threats = self.threats_table.rowCount()
            if self.helper.is_connected:
                try:
                    res = self.helper.call(
                        "inspect_proc",
                        {"pid": None, "log_path": finished.get("log_path") or self.telemetry.log_path, "log_offset": self.telemetry.log_offset},
                        timeout=3.0,
                    )
                    self._apply_log_result(res.get("log") or {})
                    threats = self.threats_table.rowCount()
                except Exception:  # noqa: BLE001
                    pass

            history = load_json_file(HISTORY_FILE_PATH, [])
            if not isinstance(history, list):
                history = []
            history.insert(
                0,
                {
                    "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "target": finished.get("label", "ClamAV Scan"),
                    "duration": format_duration(finished.get("elapsed_sec", 0)),
                    "scanned": self._tr("history_entries", count=self.telemetry.total_lines_logged)
                    if self.telemetry.total_lines_logged > 0
                    else "See log summary",
                    "threats": threats,
                    "status": "Threats Found" if threats > 0 else "Clean",
                    "source": "gui",
                },
            )
            save_json_file(HISTORY_FILE_PATH, history[:100])
            self._refresh_history()

            if threats > 0:
                self._notify(
                    self._tr("notify_scan_done_threats_title"),
                    self._tr("notify_scan_done_threats_msg", label=finished.get("label", "Scan"), count=threats),
                    critical=True,
                )
            else:
                self._notify(
                    self._tr("notify_scan_done_clean_title"),
                    self._tr("notify_scan_done_clean_msg", label=finished.get("label", "Scan")),
                )

        def _read_idle_schedule_display(self) -> str:
            """Summarize scheduled scan timer cleanly without spawning elevated commands."""
            if IS_WINDOWS or IS_MACOS:
                cfg_path = WINDOWS_SCHEDULE_CONFIG_PATH if IS_WINDOWS else MACOS_SCHEDULE_CONFIG_PATH
                cfg = load_json_file(cfg_path, {})
                if not isinstance(cfg, dict) or not cfg.get("enabled"):
                    return self._tr("idle_val_not_sched")
                time_val = str(cfg.get("time_of_day") or "03:00")
                if cfg.get("frequency") == "weekly":
                    day_raw = str(cfg.get("day_of_week") or "Sun")
                    day_key = f"day_{day_raw[:3].lower()}"
                    day_name = self._tr(day_key) if day_key in TRANSLATIONS.get(self.lang, {}) else day_raw
                    return f"{day_name[:3]} {time_val}"
                return self._tr("idle_val_daily_at", time=time_val)

            if not SYSTEMD_TIMER_PATH.startswith("/etc/") and not self.helper.is_user_mode:
                timer_paths = [SYSTEMD_TIMER_PATH]
            elif self.helper.is_user_mode:
                timer_paths = [USER_SYSTEMD_TIMER_PATH, SYSTEMD_TIMER_PATH]
            else:
                timer_paths = [SYSTEMD_TIMER_PATH, USER_SYSTEMD_TIMER_PATH]

            for tmr_path in timer_paths:
                if not os.path.exists(tmr_path) or not os.access(tmr_path, os.R_OK):
                    continue
                try:
                    with open(tmr_path, "r", encoding="utf-8", errors="replace") as fh:
                        text = fh.read()
                except OSError:
                    continue
                disabled_in_cfg = False
                for raw in text.splitlines():
                    if raw.startswith("# CLAMAV_GUI_CONFIG="):
                        try:
                            cfg = json.loads(raw.split("=", 1)[1].strip())
                            if isinstance(cfg, dict) and cfg.get("enabled") is False:
                                disabled_in_cfg = True
                        except json.JSONDecodeError:
                            pass
                if disabled_in_cfg:
                    return self._tr("idle_val_not_sched")
                for raw in text.splitlines():
                    if raw.strip().startswith("OnCalendar="):
                        val = raw.split("=", 1)[1].strip()
                        m_day = re.match(r"^([A-Za-z]+)\s+\*-\*-\*\s+(\d{2}:\d{2})", val)
                        if m_day:
                            day_key = f"day_{m_day.group(1)[:3].lower()}"
                            day_name = self._tr(day_key) if day_key in TRANSLATIONS.get(self.lang, {}) else m_day.group(1)
                            return f"{day_name[:3]} {m_day.group(2)}"
                        m_daily = re.match(r"^(?:daily|\*-\*-\*)\s+(\d{2}:\d{2})", val)
                        if m_daily:
                            return self._tr("idle_val_daily_at", time=m_daily.group(1))
                        return val[:20]
            return self._tr("idle_val_not_sched")

        def _sync_stat_card_titles(self, proc: dict[str, Any] | None) -> None:
            if proc is None:
                self.card_status.title_lbl.setText(self._tr("idle_col_status"))
                self.card_cpu.title_lbl.setText(self._tr("idle_col_last_scan"))
                self.card_io.title_lbl.setText(self._tr("idle_col_sigs"))
                self.card_threats.title_lbl.setText(self._tr("idle_col_sched"))
            else:
                self.card_status.title_lbl.setText(self._tr("card_status_title"))
                self.card_cpu.title_lbl.setText(self._tr("card_cpu_title"))
                self.card_io.title_lbl.setText(self._tr("card_io_title"))
                self.card_threats.title_lbl.setText(self._tr("card_threats_title"))

        def _render_idle_stats_strip(self) -> None:
            self._sync_stat_card_titles(None)
            threats = self.threats_table.rowCount()
            meta = self._last_meta
            if threats > 0:
                self.card_status.set_data(self._tr("idle_val_attention"), "", "#c53030")
            elif meta and not meta.get("has_clamscan", True):
                self.card_status.set_data(self._tr("idle_val_missing_clam"), "", "#c53030")
            elif meta and not meta.get("has_virus_db", True):
                self.card_status.set_data(self._tr("idle_val_attention"), "", "#b45309")
            else:
                self.card_status.set_data(self._tr("idle_val_protected"), "", "#178253")

            entry = self._latest_scan_entry
            if entry:
                raw_date = str(entry.get("date", ""))[:10]
                today_iso = datetime.date.today().isoformat()
                day_lbl = self._tr("idle_val_today") if raw_date == today_iso else (raw_date or self._tr("unknown_word"))
                t_cnt = int(entry.get("threats", 0))
                self.card_cpu.set_data(f"{day_lbl}, {self._tr('idle_val_threats_n', n=t_cnt)}", "")
            else:
                self.card_cpu.set_data(self._tr("idle_val_no_scans"), "")

            if meta and not meta.get("has_virus_db", True):
                self.card_io.set_data(self._tr("idle_val_sigs_missing"), "", "#b45309")
            else:
                self.card_io.set_data(self._tr("idle_val_up_to_date"), "")

            self.card_threats.set_data(self._read_idle_schedule_display(), "")

        def _render_unprivileged_telemetry(self, proc: dict[str, Any] | None) -> None:
            now = time.monotonic()
            self.ctrl_box.setVisible(proc is not None)
            if proc is None:
                self._render_idle_stats_strip()
                if not self.helper.is_connected:
                    self.current_file_edit.setText(self._tr("no_active_scan_running"))
                self.log_hint_lbl.setText(self._log_reload_error)
                self.restart_verbose_btn.setVisible(False)
                self._update_progress_ui(None)
                return

            self._sync_stat_card_titles(proc)
            self._update_threat_count()

            state_char = proc["state"]
            if state_char == "T":
                state_text, color = self._tr("state_paused"), "#b45309"
            elif state_char in ("R", "S", "D"):
                state_text, color = self._tr("state_running"), "#1f7a3f"
            else:
                state_text, color = state_char, None

            self.card_status.set_data(
                state_text,
                self._tr("pid_owner", pid=proc["pid"], user=proc["user"]),
                color,
            )

            cpu_pct_str = "..."
            clk_tck = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
            if self.telemetry.last_cpu_ticks is not None and self.telemetry.last_cpu_time is not None:
                dt = now - self.telemetry.last_cpu_time
                if dt > 0.2:
                    cpu_pct = ((proc["cpu_ticks"] - self.telemetry.last_cpu_ticks) / clk_tck / dt) * 100.0
                    cpu_pct_str = f"{max(0.0, cpu_pct):.1f}% CPU"
            self.telemetry.last_cpu_ticks = proc["cpu_ticks"]
            self.telemetry.last_cpu_time = now

            mode_label = self._tr("bg_mode_label") if proc["nice"] >= 10 else self._tr("normal_speed_label")
            self.card_cpu.set_data(
                format_duration(proc["elapsed_sec"]),
                f"{cpu_pct_str} | {mode_label}",
            )

            rss_str = format_bytes(proc["rss_kb"] * 1024)
            if not self.helper.is_connected:
                self.card_io.set_data(self._tr("ram_value", rss=rss_str), self._tr("unlock_live_io"))
                self.current_file_edit.setText(
                    self._tr("scan_running_locked_file", user=proc["user"], pid=proc["pid"])
                )

            if proc.get("quiet_infected_only"):
                self.log_hint_lbl.setText(self._tr("quiet_log_hint"))
                self.restart_verbose_btn.setVisible(True)
            else:
                self.log_hint_lbl.setText("")
                self.restart_verbose_btn.setVisible(False)

            self._update_progress_ui(proc)

        def _compute_effective_bytes(self, io_data: dict[str, int]) -> int:
            rchar = int(io_data.get("rchar", 0))
            read_bytes = int(io_data.get("read_bytes", rchar))
            db_overhead = 310 * 1024 * 1024
            net_rchar = max(0, rchar - db_overhead)
            if read_bytes >= net_rchar * 0.15:
                return min(net_rchar, int(read_bytes * 1.08))
            return net_rchar

        def _update_progress_ui(self, proc: dict[str, Any] | None) -> None:
            if proc is None:
                self._last_pct = 0.0
                self._last_eta_str = "--:--:--"
                self.progress_bar.setRange(0, 1000)
                self.progress_bar.setValue(0)
                self.progress_bar.setFormat(self._tr("idle_word"))
                self.eta_lbl.setText(self._tr("eta_prefix", eta="--:--:--"))
                self.progress_sub_lbl.setText(self._tr("no_active_scan"))
                return

            limits = parse_scan_targets_and_limits(proc["cmdline"])
            cache_key = (tuple(limits["targets"]), limits["cross_fs"])
            if self.telemetry.statvfs_cache_key != cache_key:
                self.telemetry.statvfs_cache_key = cache_key
                self.telemetry.statvfs_bytes = estimate_statvfs_used_bytes(
                    limits["targets"],
                    limits["cross_fs"],
                )

            if self.helper.is_connected and self.telemetry.last_precount:
                precount = self.telemetry.last_precount
            else:
                precount = start_background_precount(
                    limits["targets"],
                    limits["exclude_dirs"],
                    limits["max_filesize"],
                    limits["cross_fs"],
                )

            pre_done = bool(precount.get("done"))
            elig_bytes = int(precount.get("eligible_bytes") or 0)
            elig_files = int(precount.get("eligible_files") or 0)
            all_files = int(precount.get("all_files") or 0)
            all_bytes = int(precount.get("all_bytes") or 0)

            if pre_done and elig_bytes > 0:
                total_target_bytes = elig_bytes
                total_target_files = all_files
            else:
                total_target_bytes = self.telemetry.statvfs_bytes
                total_target_files = all_files

            proc_data = self.telemetry.last_proc_data
            if not self.helper.is_connected or not proc_data.get("alive"):
                if proc.get("state") == "T":
                    self.progress_bar.setRange(0, 1000)
                    self.progress_bar.setValue(0)
                    self.progress_bar.setFormat(self._tr("progress_paused_unlock"))
                    self._last_eta_str = self._tr("eta_paused")
                else:
                    self.progress_bar.setRange(0, 0)
                    self.progress_bar.setFormat("")
                    self._last_eta_str = self._tr("eta_unlock_root")
                self.eta_lbl.setText(self._tr("eta_prefix", eta=self._last_eta_str))

                if pre_done and elig_bytes > 0:
                    self.progress_sub_lbl.setText(
                        self._tr(
                            "progress_sub_unlock_ready",
                            elig_files=elig_files,
                            elig_bytes=format_bytes(elig_bytes),
                            max_sz=format_bytes(limits["max_filesize"]),
                            all_files=all_files,
                            all_bytes=format_bytes(all_bytes),
                        )
                    )
                elif precount.get("running"):
                    self.progress_sub_lbl.setText(
                        self._tr(
                            "progress_sub_unlock_counting",
                            statvfs=format_bytes(self.telemetry.statvfs_bytes),
                            all_files=all_files,
                        )
                    )
                else:
                    self.progress_sub_lbl.setText(
                        self._tr("progress_sub_unlock_est", statvfs=format_bytes(self.telemetry.statvfs_bytes))
                    )
                return

            io_data = proc_data.get("io") or {}
            effective_bytes = self._compute_effective_bytes(io_data)
            byte_pct = (effective_bytes / total_target_bytes * 100.0) if total_target_bytes > 0 else 0.0

            if (
                not proc.get("quiet_infected_only")
                and self.telemetry.total_lines_logged > 10
                and total_target_files > 0
            ):
                file_pct = (self.telemetry.total_lines_logged / total_target_files) * 100.0
                pct = max(file_pct, byte_pct) if effective_bytes < 512 * 1024 * 1024 else file_pct
            else:
                pct = byte_pct

            pct = max(0.0, min(99.5, pct))
            self._last_pct = pct
            self.progress_bar.setRange(0, 1000)
            self.progress_bar.setValue(int(round(pct * 10)))
            paused = proc.get("state") == "T"
            self.progress_bar.setFormat(
                self._tr("progress_pct_paused", pct=pct) if paused else f"{pct:.1f}%"
            )

            avg_bps = effective_bytes / max(1.0, proc["elapsed_sec"])
            inst_bps = (
                self.telemetry.last_eta_speed_bps
                if self.telemetry.last_eta_speed_bps is not None
                else avg_bps
            )
            blended_bps = (0.7 * avg_bps) + (0.3 * inst_bps)

            if paused:
                self._last_eta_str = self._tr("eta_paused")
            elif blended_bps > 1024 and total_target_bytes > effective_bytes:
                eta_sec = (total_target_bytes - effective_bytes) / blended_bps
                self._last_eta_str = format_duration(eta_sec)
            elif total_target_bytes > 0 and effective_bytes >= total_target_bytes:
                self._last_eta_str = self._tr("eta_finishing")
            else:
                self._last_eta_str = self._tr("eta_calculating")
            self.eta_lbl.setText(self._tr("eta_prefix", eta=self._last_eta_str))

            if pre_done and elig_bytes > 0:
                self.progress_sub_lbl.setText(
                    self._tr(
                        "progress_sub_accurate",
                        eff=format_bytes(effective_bytes),
                        total=format_bytes(total_target_bytes),
                        elig_files=elig_files,
                        max_sz=format_bytes(limits["max_filesize"]),
                        all_files=all_files,
                        all_bytes=format_bytes(all_bytes),
                    )
                )
            elif precount.get("running"):
                self.progress_sub_lbl.setText(
                    self._tr(
                        "progress_sub_refining",
                        eff=format_bytes(effective_bytes),
                        total=format_bytes(total_target_bytes),
                        all_files=all_files,
                    )
                )
            else:
                self.progress_sub_lbl.setText(
                    self._tr(
                        "progress_sub_est",
                        eff=format_bytes(effective_bytes),
                        total=format_bytes(total_target_bytes),
                    )
                )

        def _on_inspect_done(self, result: Any, error: str) -> None:
            self._inspect_inflight = False
            if error:
                self.log_hint_lbl.setText(self._tr("log_inspect_err", err=error))
                return
            if not isinstance(result, dict):
                return
            if not (self._current_proc and self._current_proc.get("quiet_infected_only")):
                self.log_hint_lbl.setText("")

            if self._current_proc is None:
                log_res = result.get("log") or {}
                self._apply_log_result(log_res)
                return

            if isinstance(result.get("precount"), dict) and result["precount"]:
                self.telemetry.last_precount = result["precount"]

            proc_data = result.get("proc") or {}
            self.telemetry.last_proc_data = proc_data
            if proc_data.get("alive"):
                current_file = proc_data.get("current_file")
                tmp_count = proc_data.get("tmp_count", 0)
                if current_file:
                    suffix = self._tr("archive_temp_suffix", count=tmp_count) if tmp_count else ""
                    self.current_file_edit.setText(f"{current_file}{suffix}")
                else:
                    self.current_file_edit.setText(self._tr("scanning_metadata"))

                io_data = proc_data.get("io") or {}
                read_bytes = io_data.get("read_bytes", io_data.get("rchar", 0))
                rchar = io_data.get("rchar", 0)
                effective_bytes = self._compute_effective_bytes(io_data)
                now = time.monotonic()
                speed_str = "0.0 MB/s"
                if self.telemetry.last_io_bytes is not None and self.telemetry.last_io_time is not None:
                    dt = now - self.telemetry.last_io_time
                    if dt > 0.2:
                        speed_bps = max(0, effective_bytes - self.telemetry.last_io_bytes) / dt
                        speed_str = f"{format_bytes(speed_bps)}/s"
                        if self._current_proc.get("state") != "T":
                            if self.telemetry.last_eta_speed_bps is None:
                                self.telemetry.last_eta_speed_bps = speed_bps
                            else:
                                self.telemetry.last_eta_speed_bps = (
                                    0.75 * self.telemetry.last_eta_speed_bps + 0.25 * speed_bps
                                )
                self.telemetry.last_io_bytes = effective_bytes
                self.telemetry.last_io_time = now

                rss_str = format_bytes(self._current_proc["rss_kb"] * 1024)
                self.card_io.set_data(
                    self._tr("read_value", amount=format_bytes(rchar)),
                    self._tr("io_sub", speed=speed_str, disk=format_bytes(read_bytes), rss=rss_str),
                )

                if (
                    self._current_proc.get("quiet_infected_only")
                    and self.stream_fd_chk.isChecked()
                    and current_file
                    and current_file != self.telemetry.last_sampled_fd_file
                ):
                    self.telemetry.last_sampled_fd_file = current_file
                    self._append_log_lines([f"[LIVE] {current_file}"], check_threats=False)

                self._update_progress_ui(self._current_proc)
                self._update_hero_banner(self._current_proc)
                self._update_tray_status(self._current_proc)

            log_res = result.get("log") or {}
            self._apply_log_result(log_res)

        def _append_log_lines(self, lines: list[str], check_threats: bool = True) -> None:
            if not lines:
                return

            if check_threats:
                added_threat = False
                new_threats: list[tuple[str, str]] = []
                for file_path, sig in parse_threats_from_text("\n".join(lines)):
                    key = (file_path, sig)
                    if key not in self.telemetry.seen_threats:
                        self.telemetry.seen_threats.add(key)
                        row = self.threats_table.rowCount()
                        self.threats_table.insertRow(row)
                        self.threats_table.setItem(row, 0, QTableWidgetItem(file_path))
                        self.threats_table.setItem(row, 1, QTableWidgetItem(sig))
                        self.threats_table.setItem(row, 2, QTableWidgetItem(self._tr("status_found")))
                        added_threat = True
                        new_threats.append((file_path, sig))
                if added_threat:
                    self._update_threat_count()
                    self._update_hero_banner(self._current_proc)
                    self._update_tray_status(self._current_proc)
                    for fp, sg in new_threats[:3]:
                        self._notify(self._tr("notify_threat_title"), f"{sg}\n{fp}", critical=True)

            self.telemetry.log_lines.extend(lines)
            self.telemetry.total_lines_logged += len(lines)

            needle = self.log_filter_edit.text().strip().lower()
            to_append = [ln for ln in lines if needle in ln.lower()] if needle else lines
            if not to_append:
                return

            vbar = self.log_view.verticalScrollBar()
            prev_scroll = vbar.value()
            self.log_view.appendPlainText("\n".join(to_append))
            if self.autoscroll_chk.isChecked():
                self.log_view.moveCursor(QTextCursor.MoveOperation.End)
            else:
                vbar.setValue(prev_scroll)

        def _apply_log_result(self, log_res: dict[str, Any]) -> None:
            if not log_res.get("exists"):
                return
            if log_res.get("reset"):
                self._reset_log_state(reset_offset=False)

            new_text = log_res.get("new_text", "")
            self.telemetry.log_offset = int(log_res.get("new_offset", self.telemetry.log_offset))
            if not new_text:
                return

            combined = self.telemetry.partial_line + new_text
            if combined.endswith("\n"):
                lines = combined.splitlines()
                self.telemetry.partial_line = ""
            else:
                head, sep, tail = combined.rpartition("\n")
                if sep:
                    lines = head.splitlines()
                    self.telemetry.partial_line = tail
                else:
                    lines = []
                    self.telemetry.partial_line = combined

            self._append_log_lines(lines, check_threats=True)

        def _update_threat_count(self) -> None:
            count = self.threats_table.rowCount()
            self.threats_group.setTitle(self._tr("tab_threats", count=count))
            self.tabs.setTabText(1, self._tab_label_threats_quarantine())
            if self._current_proc is None:
                self._render_idle_stats_strip()
                return
            if count > 0:
                self.card_threats.set_data(str(count), self._tr("action_recommended"), "#b91c1c")
            else:
                self.card_threats.set_data("0", self._tr("clean_so_far"), "#1f7a3f")

        def _render_log_view(self) -> None:
            needle = self.log_filter_edit.text().strip().lower()
            lines = self.telemetry.log_lines
            if needle:
                display = "\n".join(line for line in lines if needle in line.lower())
            else:
                display = "\n".join(lines)
            self.log_view.setPlainText(display)
            if self.autoscroll_chk.isChecked():
                self.log_view.moveCursor(QTextCursor.MoveOperation.End)

        def _reload_log(self) -> None:
            self.telemetry.log_path = self.log_path_edit.text().strip()
            self._reset_log_state(reset_offset=True)
            self._log_reload_error = ""
            if not self.helper.is_connected and self.telemetry.log_path:
                lp = self.telemetry.log_path
                if not os.path.exists(lp):
                    self._log_reload_error = self._tr("log_inspect_err", err=f"{lp}: {os.strerror(2)}")
                elif not os.access(lp, os.R_OK):
                    self._log_reload_error = self._tr("log_inspect_err", err=f"{lp}: {os.strerror(13)}")
            self.log_hint_lbl.setText(self._log_reload_error)
            self._poll_tick()

        def _restart_scan_without_i(self) -> None:
            proc = self._current_proc
            if not proc or not self._require_root_helper():
                return

            ans = QMessageBox.question(
                self,
                self._tr("dlg_restart_title"),
                self._tr("dlg_restart_msg", pid=proc["pid"]),
            )
            if ans != QMessageBox.StandardButton.Yes:
                return

            new_args: list[str] = []
            for arg in proc["cmdline"]:
                if arg in ("-i", "--infected"):
                    continue
                if arg.startswith("-") and not arg.startswith("--") and "i" in arg[1:]:
                    stripped = "-" + arg[1:].replace("i", "")
                    if stripped != "-":
                        new_args.append(stripped)
                    continue
                new_args.append(arg)

            if not new_args:
                new_args = ["clamscan", "-r", _system_root_target()]

            log_path = proc.get("log_path") or self.log_path_edit.text().strip() or DEFAULT_LOG_PATH
            prev_pid = proc["pid"]
            prev_label = self._pending_scan_labels.pop(prev_pid, None)
            want_bg = self.bg_mode_chk.isChecked()
            try:
                self.helper.call("signal_proc", {"pid": prev_pid, "sig": "SIGTERM"})
                cancel_background_precount()
                deadline = time.monotonic() + 2.0
                while time.monotonic() < deadline and _is_pid_running(prev_pid):
                    time.sleep(0.1)

                res = self.helper.call(
                    "start_scan",
                    {"cmd_args": new_args, "log_path": log_path, "truncate_log": True},
                )
                self._reset_log_state(reset_offset=True)
                new_pid = res.get("pid")
                if isinstance(new_pid, int):
                    if prev_label:
                        self._pending_scan_labels[new_pid] = prev_label
                    if want_bg:
                        try:
                            self.helper.call("set_priority", {"pid": new_pid, "mode": "idle"})
                        except Exception:  # noqa: BLE001
                            pass
                self.telemetry.selected_pid = new_pid
                self.telemetry.log_path = log_path
                self.log_path_edit.setText(log_path)
                self._poll_tick()
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(self, self._tr("dlg_restart_err"), str(exc))

        def _active_log_path(self) -> str:
            if self.helper.is_user_mode and DEFAULT_LOG_PATH.startswith("/var/log/"):
                return str(APP_DATA_DIR / os.path.basename(DEFAULT_LOG_PATH))
            return DEFAULT_LOG_PATH

        def _active_quarantine_dir(self) -> str:
            if self.helper.is_user_mode and DEFAULT_QUARANTINE_DIR.startswith("/root"):
                return str(APP_DATA_DIR / "quarantine")
            return DEFAULT_QUARANTINE_DIR

        def _activate_user_mode(self) -> bool:
            ok, msg = self.helper.start_local()
            if not ok:
                QMessageBox.warning(self, self._tr("dlg_auth_failed"), msg)
                return False
            user_log = self._active_log_path()
            if self.log_path_edit.text().strip().startswith("/var/log/"):
                self.log_path_edit.setText(user_log)
            if self.new_log_edit.text().strip().startswith("/var/log/"):
                self.new_log_edit.setText(user_log)
            if self.telemetry.log_path.startswith("/var/log/"):
                self.telemetry.log_path = user_log
            self._on_root_unlocked()
            return True

        def _require_root_helper(self) -> bool:
            if self.helper.is_connected:
                return True
            if IS_WINDOWS or IS_MACOS:
                ok, msg = self.helper.start_local()
                if ok:
                    self._on_root_unlocked()
                    return True
                QMessageBox.warning(self, self._tr("dlg_auth_failed"), msg)
                return False
            box = QMessageBox(self)
            box.setWindowTitle(self._tr("dlg_root_req_title"))
            box.setText(self._tr("dlg_root_req_text"))
            box.setInformativeText(self._tr("dlg_root_req_info"))
            btn_sudo = box.addButton(self._tr("dlg_unlock_pw_btn"), QMessageBox.ButtonRole.AcceptRole)
            btn_polkit = box.addButton(self._tr("unlock_polkit_btn"), QMessageBox.ButtonRole.ActionRole)
            btn_user = box.addButton(self._tr("continue_user_mode_btn"), QMessageBox.ButtonRole.ActionRole)
            box.addButton(QMessageBox.StandardButton.Cancel)
            box.exec()
            clicked = box.clickedButton()
            if clicked == btn_sudo:
                return self._unlock_sudo()
            if clicked == btn_polkit:
                self._unlock_pkexec()
                return False
            if clicked == btn_user:
                return self._activate_user_mode()
            return False

        def _reset_after_scan_exit(self, pid: int) -> None:
            cancel_background_precount()
            self._last_active_scan = None
            self._pending_scan_labels.pop(pid, None)
            self._clear_scan_telemetry()
            self._poll_tick()
            self._compact_window_if_idle()

        def _toggle_pause_scan(self) -> None:
            proc = self._current_proc
            if not proc:
                return
            sig = "SIGCONT" if proc["state"] == "T" else "SIGSTOP"
            try:
                if (not IS_WINDOWS) and proc.get("uid") == _uid() and not self.helper.is_connected:
                    os.kill(proc["pid"], getattr(signal, sig))
                else:
                    if not self._require_root_helper():
                        return
                    self.helper.call("signal_proc", {"pid": proc["pid"], "sig": sig})
                self._poll_tick()
            except ProcessLookupError:
                self._reset_after_scan_exit(proc["pid"])
            except Exception as exc:  # noqa: BLE001
                if "no longer exists" in str(exc).lower():
                    self._reset_after_scan_exit(proc["pid"])
                    return
                QMessageBox.warning(self, self._tr("dlg_sig_err"), str(exc))

        def _stop_scan(self) -> None:
            proc = self._current_proc
            if not proc:
                return
            ans = QMessageBox.question(
                self,
                self._tr("dlg_stop_title"),
                self._tr("dlg_stop_msg", pid=proc["pid"]),
            )
            if ans != QMessageBox.StandardButton.Yes:
                return
            try:
                stopped_pid = proc["pid"]
                if (not IS_WINDOWS) and proc.get("uid") == _uid() and not self.helper.is_connected:
                    _terminate_pid_gracefully(stopped_pid, force_cont=(proc.get("state") == "T"))
                else:
                    if not self._require_root_helper():
                        return
                    self.helper.call("signal_proc", {"pid": stopped_pid, "sig": "SIGTERM"})
                self._reset_after_scan_exit(stopped_pid)
            except ProcessLookupError:
                self._reset_after_scan_exit(proc["pid"])
            except Exception as exc:  # noqa: BLE001
                if "no longer exists" in str(exc).lower():
                    self._reset_after_scan_exit(proc["pid"])
                    return
                QMessageBox.warning(self, self._tr("dlg_stop_err"), str(exc))

        def _on_bg_mode_clicked(self, checked: bool) -> None:
            proc = self._current_proc
            if not proc:
                return
            if not self._require_root_helper():
                self.bg_mode_chk.blockSignals(True)
                self.bg_mode_chk.setChecked(int(proc.get("nice", 0)) >= 10)
                self.bg_mode_chk.blockSignals(False)
                return
            mode = "idle" if checked else "normal"
            try:
                self.helper.call("set_priority", {"pid": proc["pid"], "mode": mode})
                self._poll_tick()
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(self, self._tr("dlg_prio_err"), str(exc))

        def _selected_threat_row(self) -> tuple[int, str, str] | None:
            row = self.threats_table.currentRow()
            if row < 0:
                QMessageBox.information(self, self._tr("dlg_no_sel_title"), self._tr("dlg_no_sel_threat"))
                return None
            item_path = self.threats_table.item(row, 0)
            item_sig = self.threats_table.item(row, 1)
            if not item_path:
                return None
            return (row, item_path.text(), item_sig.text() if item_sig else "Detected Threat")

        def _reveal_threat_in_dolphin(self) -> None:
            sel = self._selected_threat_row()
            if not sel:
                return
            _, path, _ = sel
            popen_kwargs: dict[str, Any] = {"creationflags": _SUBPROCESS_NO_WINDOW} if IS_WINDOWS else {"start_new_session": True}
            subprocess.Popen(build_reveal_file_command(path), **popen_kwargs)

        _reveal_threat_in_file_manager = _reveal_threat_in_dolphin

        def _copy_threat_path(self) -> None:
            sel = self._selected_threat_row()
            if not sel:
                return
            QApplication.clipboard().setText(sel[1])

        def _quarantine_selected_threat(self) -> None:
            sel = self._selected_threat_row()
            if not sel or not self._require_root_helper():
                return
            row, path, sig = sel
            qdir = self._active_quarantine_dir()
            ans = QMessageBox.question(
                self,
                self._tr("dlg_quar_title"),
                self._tr("dlg_quar_msg", path=path, qdir=qdir),
            )
            if ans != QMessageBox.StandardButton.Yes:
                return
            try:
                res = self.helper.call(
                    "quarantine_file",
                    {
                        "path": path,
                        "quarantine_dir": qdir,
                        "threat_name": sig,
                    },
                )
                self.threats_table.setItem(
                    row, 2, QTableWidgetItem(self._tr("status_quarantined", dest=res["dest"]))
                )
                self._refresh_quarantine()
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(self, self._tr("dlg_quar_err"), str(exc))

        def _delete_selected_threat(self) -> None:
            sel = self._selected_threat_row()
            if not sel or not self._require_root_helper():
                return
            row, path, _ = sel
            ans = QMessageBox.warning(
                self,
                self._tr("dlg_del_title"),
                self._tr("dlg_del_msg", path=path),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if ans != QMessageBox.StandardButton.Yes:
                return
            try:
                self.helper.call("delete_file", {"path": path})
                self.threats_table.setItem(row, 2, QTableWidgetItem(self._tr("status_deleted")))
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(self, self._tr("dlg_del_err"), str(exc))

        def _refresh_quarantine(self) -> None:
            if not self.helper.is_connected:
                return
            try:
                res = self.helper.call("list_quarantine", {"quarantine_dir": self._active_quarantine_dir()})
                items = res.get("items") or []
                self.quarantine_table.setRowCount(0)
                for item in items:
                    row = self.quarantine_table.rowCount()
                    self.quarantine_table.insertRow(row)
                    self.quarantine_table.setItem(row, 0, QTableWidgetItem(item.get("name", "")))
                    self.quarantine_table.setItem(row, 1, QTableWidgetItem(item.get("original_path", "Unknown")))
                    self.quarantine_table.setItem(row, 2, QTableWidgetItem(item.get("threat_name", "Unknown")))
                    self.quarantine_table.setItem(row, 3, QTableWidgetItem(item.get("date", "")))
                    self.quarantine_table.setItem(row, 4, QTableWidgetItem(format_bytes(item.get("size", 0))))
                self._quarantine_count = len(items)
                self.quarantine_group.setTitle(self._tr("tab_quarantine", count=self._quarantine_count))
                self.tabs.setTabText(1, self._tab_label_threats_quarantine())
            except Exception:  # noqa: BLE001
                pass

        def _selected_quarantine_item(self) -> tuple[str, str] | None:
            row = self.quarantine_table.currentRow()
            if row < 0:
                QMessageBox.information(self, self._tr("dlg_no_sel_title"), self._tr("dlg_no_sel_quar"))
                return None
            name_item = self.quarantine_table.item(row, 0)
            orig_item = self.quarantine_table.item(row, 1)
            if not name_item:
                return None
            return name_item.text(), (orig_item.text() if orig_item else "Unknown")

        def _restore_quarantine(self, pick_dir: bool = False) -> None:
            if not self._require_root_helper():
                return
            sel = self._selected_quarantine_item()
            if not sel:
                return
            name, orig_path = sel
            dest_path = orig_path
            if pick_dir or orig_path == "Unknown" or not os.path.isabs(orig_path):
                chosen_dir = QFileDialog.getExistingDirectory(
                    self, self._tr("dlg_restore_dir"), os.path.expanduser("~")
                )
                if not chosen_dir:
                    return
                dest_path = os.path.join(chosen_dir, name)

            ans = QMessageBox.question(
                self,
                self._tr("dlg_restore_title"),
                self._tr("dlg_restore_msg", name=name, dest=dest_path),
            )
            if ans != QMessageBox.StandardButton.Yes:
                return
            try:
                res = self.helper.call(
                    "restore_quarantine",
                    {"name": name, "dest_path": dest_path, "quarantine_dir": self._active_quarantine_dir()},
                )
                QMessageBox.information(
                    self, self._tr("dlg_restore_ok_title"), self._tr("dlg_restore_ok_msg", dest=res["restored_to"])
                )
                self._refresh_quarantine()
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(self, self._tr("dlg_restore_err"), str(exc))

        def _delete_quarantine_item(self) -> None:
            if not self._require_root_helper():
                return
            sel = self._selected_quarantine_item()
            if not sel:
                return
            name, _ = sel
            ans = QMessageBox.warning(
                self,
                self._tr("dlg_del_q_title"),
                self._tr("dlg_del_q_msg", name=name),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if ans != QMessageBox.StandardButton.Yes:
                return
            try:
                self.helper.call(
                    "delete_quarantine",
                    {"name": name, "quarantine_dir": self._active_quarantine_dir()},
                )
                self._refresh_quarantine()
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(self, self._tr("dlg_del_err"), str(exc))

        def _refresh_history(self) -> None:
            gui_history = load_json_file(HISTORY_FILE_PATH, [])
            if not isinstance(gui_history, list):
                gui_history = []

            combined = list(gui_history)
            seen_keys = {
                (str(item.get("date", ""))[:16], int(item.get("threats", 0))) for item in combined
            }

            log_candidates: list[str] = []
            for cand in (DEFAULT_LOG_PATH, str(APP_DATA_DIR / "clamav-scan.log")):
                if cand and cand not in log_candidates:
                    if cand == DEFAULT_LOG_PATH or (
                        not IS_WINDOWS and (DEFAULT_LOG_PATH.startswith("/var/log/") or self.helper.is_user_mode)
                    ):
                        log_candidates.append(cand)
            for log_p in log_candidates:
                if os.path.exists(log_p) and os.access(log_p, os.R_OK):
                    try:
                        with open(log_p, "r", encoding="utf-8", errors="replace") as fh:
                            log_text = fh.read()
                        for entry in reversed(parse_scan_summaries_from_log(log_text)):
                            key = (str(entry.get("date", ""))[:16], int(entry.get("threats", 0)))
                            if key not in seen_keys:
                                seen_keys.add(key)
                                combined.append(entry)
                    except OSError:
                        pass

            combined.sort(key=lambda item: str(item.get("date", "")), reverse=True)
            self._latest_scan_entry = combined[0] if combined else None
            self.history_table.setRowCount(0)
            for item in combined[:100]:
                row = self.history_table.rowCount()
                self.history_table.insertRow(row)
                threats_n = int(item.get("threats", 0))
                scanned_raw = str(item.get("scanned", ""))
                scanned_disp = self._tr("history_see_log") if scanned_raw == "See log summary" else scanned_raw
                status_disp = self._tr("status_threats_found") if threats_n > 0 else self._tr("status_clean")

                target_raw = str(item.get("target", ""))
                target_disp = (
                    self._tr("history_system_log") if target_raw == "System / Log Scan" else target_raw
                )
                self.history_table.setItem(row, 0, QTableWidgetItem(str(item.get("date", ""))))
                self.history_table.setItem(row, 1, QTableWidgetItem(target_disp))
                self.history_table.setItem(row, 2, QTableWidgetItem(str(item.get("duration", ""))))
                self.history_table.setItem(row, 3, QTableWidgetItem(scanned_disp))
                self.history_table.setItem(row, 4, QTableWidgetItem(str(threats_n)))
                self.history_table.setItem(row, 5, QTableWidgetItem(status_disp))
            if self._current_proc is None:
                self._render_idle_stats_strip()

        def _clear_history(self) -> None:
            ans = QMessageBox.question(self, self._tr("dlg_clear_hist_title"), self._tr("dlg_clear_hist_msg"))
            if ans == QMessageBox.StandardButton.Yes:
                save_json_file(HISTORY_FILE_PATH, [])
                self._refresh_history()

        def _update_sched_day_visibility(self) -> None:
            is_weekly = self.sched_freq_combo.currentData() == "weekly"
            self.sched_day_combo.setEnabled(is_weekly)

        def _refresh_schedule(self) -> None:
            if not self.helper.is_connected:
                return
            try:
                res = self.helper.call("get_schedule", {"user_mode": True} if self.helper.is_user_mode else {})
                self.sched_enabled_chk.setChecked(bool(res.get("enabled")))
                idx_type = self.sched_type_combo.findData(res.get("scan_type", "quick"))
                if idx_type >= 0:
                    self.sched_type_combo.setCurrentIndex(idx_type)
                idx_freq = self.sched_freq_combo.findData(res.get("frequency", "weekly"))
                if idx_freq >= 0:
                    self.sched_freq_combo.setCurrentIndex(idx_freq)
                idx_day = self.sched_day_combo.findData(res.get("day_of_week", "Sun"))
                if idx_day >= 0:
                    self.sched_day_combo.setCurrentIndex(idx_day)
                hh, mm = (str(res.get("time_of_day") or "03:00").split(":") + ["0"])[:2]
                self.sched_time_edit.setTime(QTime(int(hh), int(mm)))
                state_txt = self._tr("sched_enabled" if res.get("enabled") else "sched_disabled")
                next_run = res.get("next_run", "-")
                self.sched_status_lbl.setText(self._tr("sched_timer_status", state=state_txt, next_run=next_run))
                self._update_sched_day_visibility()
            except Exception as exc:  # noqa: BLE001
                self.sched_status_lbl.setText(self._tr("sched_read_err", err=exc))

        def _save_schedule(self) -> None:
            if not self._require_root_helper():
                return
            try:
                sched_payload: dict[str, Any] = {
                    "enabled": self.sched_enabled_chk.isChecked(),
                    "scan_type": self.sched_type_combo.currentData(),
                    "frequency": self.sched_freq_combo.currentData(),
                    "day_of_week": self.sched_day_combo.currentData(),
                    "time_of_day": self.sched_time_edit.time().toString("HH:mm"),
                    "quick_targets": get_quick_scan_targets(),
                }
                if self.helper.is_user_mode:
                    sched_payload["user_mode"] = True
                res = self.helper.call("set_schedule", sched_payload)
                state_txt = self._tr("sched_enabled" if res.get("enabled") else "sched_disabled")
                self.sched_status_lbl.setText(
                    self._tr("sched_saved_status", state=state_txt, next_run=res.get("next_run", "-"))
                )
                if self._current_proc is None:
                    self._render_idle_stats_strip()
                QMessageBox.information(
                    self, self._tr("sched_saved_title"), self._tr("sched_saved_msg", state=state_txt)
                )
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(self, self._tr("sched_save_err"), str(exc))

        def _browse_scan_target(self) -> None:
            chosen = QFileDialog.getExistingDirectory(self, self._tr("dlg_browse_dir"), _system_root_target())
            if chosen:
                self.scan_target_combo.setCurrentText(chosen)

        def _build_scan_command(self) -> tuple[list[str], str]:
            args = ["clamscan"]
            if self.opt_recursive.isChecked():
                args.append("-r")
            if self.opt_infected_only.isChecked():
                args.append("-i")
            if self.opt_exclude_virtual.isChecked() and not IS_WINDOWS:
                for excl in ("^/sys", "^/proc", "^/dev", "^/run"):
                    args.append(f"--exclude-dir={excl}")
            if self.opt_cross_fs.isChecked():
                args.append("--cross-fs=no")

            mb = self.max_size_spin.value()
            args.append(f"--max-filesize={mb}M")
            args.append(f"--max-scansize={mb}M")

            db_dir = _default_db_dir()
            if (IS_WINDOWS or IS_MACOS or (self.helper.is_user_mode and db_dir != "/var/lib/clamav")) and _has_clamav_db_files(db_dir):
                args.append(f"--database={db_dir}")

            action = str(self.infected_action_combo.currentData())
            qdir = self._active_quarantine_dir()
            if action == "move":
                args.append(f"--move={qdir}")
            elif action == "copy":
                args.append(f"--copy={qdir}")

            log_path = self.new_log_edit.text().strip()
            if log_path:
                args.append(f"--log={log_path}")

            target = self.scan_target_combo.currentText().strip() or _system_root_target()
            args.append(target)
            return args, log_path

        def _update_command_preview(self) -> None:
            args, _ = self._build_scan_command()
            self.cmd_preview_edit.setText(" ".join(args))

        def _launch_scan_args(
            self,
            targets: list[str],
            label: str,
            exclude_virtual: bool = False,
            raw_args: list[str] | None = None,
            log_path: str | None = None,
        ) -> None:
            if not self._require_root_helper():
                return
            if log_path is None:
                log_path = self._active_log_path()
            elif self.helper.is_user_mode and log_path.startswith("/var/log/"):
                log_path = self._active_log_path()
            if self._known_procs:
                ans = QMessageBox.question(
                    self,
                    self._tr("dlg_scan_running_title"),
                    self._tr("dlg_scan_running_msg"),
                )
                if ans != QMessageBox.StandardButton.Yes:
                    return

            if raw_args is not None:
                args = list(raw_args)
            else:
                args = ["clamscan", "-r"]
                if exclude_virtual and not IS_WINDOWS:
                    for excl in ("^/sys", "^/proc", "^/dev", "^/run"):
                        args.append(f"--exclude-dir={excl}")
                args.extend(["--max-filesize=100M", "--max-scansize=100M"])
                db_dir = _default_db_dir()
                if (IS_WINDOWS or IS_MACOS or (self.helper.is_user_mode and db_dir != "/var/lib/clamav")) and _has_clamav_db_files(db_dir):
                    args.append(f"--database={db_dir}")
                if log_path:
                    args.append(f"--log={log_path}")
                args.extend(targets)

            try:
                res = self.helper.call("start_scan", {"cmd_args": args, "log_path": log_path})
                new_pid = res.get("pid")
                if isinstance(new_pid, int):
                    self._pending_scan_labels[new_pid] = label
                    if self.bg_mode_chk.isChecked():
                        try:
                            self.helper.call("set_priority", {"pid": new_pid, "mode": "idle"})
                        except Exception:  # noqa: BLE001
                            pass
                self.telemetry.selected_pid = new_pid
                actual_log = str(res.get("log_path") or log_path or "")
                if actual_log:
                    self.log_path_edit.setText(actual_log)
                    self.telemetry.log_path = actual_log
                if self.tabs.isVisible():
                    self.tabs.setCurrentIndex(0)
                self._poll_tick()
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(self, self._tr("dlg_start_err"), str(exc))

        def _start_quick_scan(self) -> None:
            targets = get_quick_scan_targets()
            self._launch_scan_args(targets, label=self._tr("label_quick_scan"), exclude_virtual=False)

        def _start_full_scan(self) -> None:
            self._launch_scan_args([_system_root_target()], label=self._tr("label_full_scan"), exclude_virtual=True)

        def _start_custom_picker_scan(self) -> None:
            dlg = FileOrFolderPickerDialog(self, self._tr("dlg_pick_title"), os.path.expanduser("~"))
            if dlg.exec() != int(QDialog.DialogCode.Accepted):
                return
            targets = dlg.chosen_paths or [p for p in dlg.selectedFiles() if p]
            if not targets:
                return
            first_name = os.path.basename(targets[0]) or targets[0]
            target_desc = first_name if len(targets) == 1 else f"{first_name} (+{len(targets) - 1})"
            root_tgt = _system_root_target()
            self._launch_scan_args(
                targets,
                label=self._tr("label_custom_scan", target=target_desc),
                exclude_virtual=(root_tgt in targets or "/" in targets),
            )

        def _start_new_scan(self) -> None:
            args, log_path = self._build_scan_command()
            target = self.scan_target_combo.currentText().strip() or _system_root_target()
            self._launch_scan_args(
                [target],
                label=self._tr("label_custom_scan", target=target),
                raw_args=args,
                log_path=log_path,
            )

        def _run_freshclam(self) -> None:
            if not self._require_root_helper():
                return
            self._freshclam_running = True
            self.freshclam_btn.setEnabled(False)
            self.freshclam_btn.setText(self._tr("freshclam_updating"))
            self.freshclam_output.setPlainText(self._tr("freshclam_running_msg"))
            fc_params = {"user_mode": True} if self.helper.is_user_mode else {}

            def _worker() -> None:
                try:
                    res = self.helper.call("run_freshclam", fc_params, timeout=185.0)
                    out = res.get("output", "")
                    self.signals.freshclam_done.emit(bool(res.get("success")), out)
                except Exception as exc:  # noqa: BLE001
                    self.signals.freshclam_done.emit(False, str(exc))

            threading.Thread(target=_worker, daemon=True).start()

        def _on_freshclam_done(self, ok: bool, output: str) -> None:
            self._freshclam_running = False
            self.freshclam_btn.setEnabled(True)
            self.freshclam_btn.setText(self._tr("freshclam_btn"))
            status_line = self._tr("freshclam_success" if ok else "freshclam_errors")
            self.freshclam_output.setPlainText(f"[{status_line}]\n{output}")
            self.btn_quick_scan.setSubtitle(self._tr("tile_quick_sub"))
            self.btn_full_scan.setSubtitle(self._tr("tile_full_sub"))
            self.btn_pick_scan.setSubtitle(self._tr("tile_pick_sub"))

            self._refresh_metadata()

        def _show_about_dialog(self) -> None:
            dlg = QDialog(self)
            dlg.setWindowTitle(self._tr("dlg_about_title"))
            dlg.setMinimumWidth(460)
            self._last_about_dialog = dlg

            layout = QVBoxLayout(dlg)
            layout.setContentsMargins(20, 18, 20, 18)
            layout.setSpacing(14)

            top = QHBoxLayout()
            top.setSpacing(14)
            icon_lbl = QLabel()
            icon_lbl.setFixedSize(56, 56)
            icon_lbl.setPixmap(_draw_shield_pixmap(56, "#1f9d68", "check"))
            top.addWidget(icon_lbl)

            title_col = QVBoxLayout()
            title_col.setSpacing(2)
            name_lbl = QLabel(self._tr("app_title"))
            name_font = QFont()
            name_font.setPointSize(14)
            name_font.setBold(True)
            name_lbl.setFont(name_font)
            sub_lbl = QLabel(f"v{APP_VERSION} • {self._last_meta.get('version', 'ClamAV')}")
            sub_lbl.setStyleSheet("color: palette(placeholderText);" if self._dark else "color: #475569;")
            title_col.addWidget(name_lbl)
            title_col.addWidget(sub_lbl)
            top.addLayout(title_col, 1)
            layout.addLayout(top)

            desc_lbl = QLabel(self._tr("about_desc"))
            desc_lbl.setWordWrap(True)
            layout.addWidget(desc_lbl)

            info_frame = QFrame()
            info_frame.setFrameShape(QFrame.Shape.StyledPanel)
            form = QFormLayout(info_frame)
            form.setContentsMargins(14, 12, 14, 12)
            form.setSpacing(8)
            form.addRow(self._tr("about_version_lbl"), QLabel(f"v{APP_VERSION}"))
            form.addRow(self._tr("about_creator_lbl"), QLabel(APP_AUTHOR))
            form.addRow(self._tr("about_license_lbl"), QLabel(APP_LICENSE))

            github_lbl = QLabel(f'<a href="{APP_GITHUB_URL}">{APP_GITHUB_URL}</a>')
            github_lbl.setOpenExternalLinks(True)
            github_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
            form.addRow(self._tr("about_github_lbl"), github_lbl)
            layout.addWidget(info_frame)

            buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
            buttons.rejected.connect(dlg.accept)
            layout.addWidget(buttons)

            dlg.exec()

    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv[:1])
        app.setDesktopFileName("clamav-security-center")
        app.setQuitOnLastWindowClosed(False)
    window = ClamAVMainWindow(auto_poll=auto_poll, initial_lang=lang)
    app.setApplicationName(window._tr("app_title"))
    app.setWindowIcon(window.windowIcon())
    window._qt_app = app
    return window


def launch_gui(lang: str | None = None) -> int:
    """Initialize and run the Qt6 GUI event loop."""
    window = create_main_window(auto_poll=True, lang=lang)
    window.show()
    return int(window._qt_app.exec())


def main() -> int:
    parser = argparse.ArgumentParser(description="ClamAV Security Center")
    parser.add_argument("--helper", action="store_true", help="Run internal root JSON helper")
    parser.add_argument("--self-test", action="store_true", help="Run automated diagnostics")
    parser.add_argument(
        "--lang",
        choices=("auto", *sorted(TRANSLATIONS.keys())),
        default="auto",
        help="UI language (defaults to OS locale)",
    )
    args = parser.parse_args()

    if args.helper:
        return run_helper()
    if args.self_test:
        return run_self_test()
    chosen_lang = None if args.lang == "auto" else args.lang
    return launch_gui(lang=chosen_lang)


if __name__ == "__main__":
    raise SystemExit(main())
