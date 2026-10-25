"""Read-only Windows process handle/creation identity. No process signalling."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import os


class ProcessIdentityUnavailable(ValueError):
    pass


class BoundProcess:
    def __init__(self, pid: int, created: str | None = None):
        if os.name != "nt" or type(pid) is not int or not 5 <= pid <= 0x7fffffff:
            raise ProcessIdentityUnavailable("explicit non-system Windows process PID required")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel.OpenProcess.restype = wintypes.HANDLE
        self.kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
        self.kernel.GetProcessTimes.restype = wintypes.BOOL
        self.kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.kernel.WaitForSingleObject.restype = wintypes.DWORD
        self.kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        self.kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        # SYNCHRONIZE and QUERY_LIMITED_INFORMATION only. Never VM_WRITE/TERMINATE.
        self.handle = self.kernel.OpenProcess(0x101000, False, pid)
        if not self.handle:
            raise ProcessIdentityUnavailable("process identity is unreadable or exited; unknown is not absence")
        try:
            stamp = self.inspect()
            if created is not None and stamp != created:
                raise ProcessIdentityUnavailable("process creation identity differs from selected target")
            image, capacity = ctypes.create_unicode_buffer(32768), wintypes.DWORD(32768)
            if not self.kernel.QueryFullProcessImageNameW(self.handle, 0, image, ctypes.byref(capacity)):
                raise ProcessIdentityUnavailable("process image identity is unreadable")
            self.identity = {"pid": pid, "created_100ns": stamp, "image": image.value}
        except BaseException:
            self.close()
            raise

    def inspect(self) -> str:
        if self.kernel.WaitForSingleObject(self.handle, 0) != 258:
            raise ProcessIdentityUnavailable("selected process exited or liveness is unknown")
        created, exited, kernel_time, user_time = (wintypes.FILETIME() for _ in range(4))
        if not self.kernel.GetProcessTimes(self.handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel_time), ctypes.byref(user_time)):
            raise ProcessIdentityUnavailable("selected process creation identity is unreadable")
        if exited.dwHighDateTime or exited.dwLowDateTime:
            raise ProcessIdentityUnavailable("selected process exited during observation")
        return str((created.dwHighDateTime << 32) | created.dwLowDateTime)

    def check(self) -> None:
        if self.inspect() != self.identity["created_100ns"]:
            raise ProcessIdentityUnavailable("selected process identity changed during observation")

    def close(self) -> None:
        if self.handle:
            if not self.kernel.CloseHandle(self.handle):
                raise OSError("read-only process owner could not release its handle")
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def process_start(pid: int) -> str | None:
    try:
        process = BoundProcess(pid)
    except ProcessIdentityUnavailable:
        return None
    with process:
        return process.identity["created_100ns"]
