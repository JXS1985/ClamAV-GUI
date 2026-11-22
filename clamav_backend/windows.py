"""Win32 process operations for the scanner adapter."""

from __future__ import annotations

import time


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
