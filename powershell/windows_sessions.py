"""Local Windows session identity and post-logout verification via WTS APIs."""
import ctypes
from ctypes import wintypes
import os
import time


class WindowsSessions:
    """Query local sessions without parsing localized command output."""

    def __init__(self) -> None:
        """Bind the Windows API; unsupported platforms fail explicitly."""
        if os.name != "nt":
            raise OSError("Windows session verification requires a real Windows agent")
        self.api = ctypes.WinDLL("wtsapi32.dll", use_last_error=True)

        class SessionInfo(ctypes.Structure):
            _fields_ = [("id", wintypes.DWORD), ("station", wintypes.LPWSTR),
                        ("state", ctypes.c_int)]

        self.session_type = SessionInfo
        self.api.WTSEnumerateSessionsW.argtypes = [wintypes.HANDLE, wintypes.DWORD,
            wintypes.DWORD, ctypes.POINTER(ctypes.POINTER(SessionInfo)), ctypes.POINTER(wintypes.DWORD)]
        self.api.WTSEnumerateSessionsW.restype = wintypes.BOOL
        self.api.WTSQuerySessionInformationW.argtypes = [wintypes.HANDLE,
            wintypes.DWORD, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
        self.api.WTSQuerySessionInformationW.restype = wintypes.BOOL
        self.api.WTSFreeMemory.argtypes = [ctypes.c_void_p]
        self.api.WTSFreeMemory.restype = None

    def session_ids(self) -> set[int]:
        """Return local session IDs; API failure is never treated as absence."""
        buffer = ctypes.POINTER(self.session_type)()
        count = wintypes.DWORD()
        if not self.api.WTSEnumerateSessionsW(None, 0, 1, ctypes.byref(buffer), ctypes.byref(count)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return {int(buffer[index].id) for index in range(count.value)}
        finally:
            self.api.WTSFreeMemory(buffer)

    def _text(self, session_id: int, info_class: int) -> str:
        buffer, count = ctypes.c_void_p(), wintypes.DWORD()
        if not self.api.WTSQuerySessionInformationW(None, session_id, info_class,
                ctypes.byref(buffer), ctypes.byref(count)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.wstring_at(buffer) if buffer.value else ""
        finally:
            self.api.WTSFreeMemory(buffer)

    def validate_target(self, session_id: int, username: str) -> None:
        """Require one non-system session owned by the requested account."""
        if session_id <= 0 or session_id not in self.session_ids():
            raise ValueError("Target session does not exist or is a system session")
        user = self._text(session_id, 5)
        domain = self._text(session_id, 7)
        expected = f"{domain}\\{user}" if "\\" in username else user
        if not user or username.casefold() != expected.casefold():
            raise ValueError("Target username does not own the requested session")

    def verify_gone(self, session_id: int, timeout: float = 10) -> bool:
        """Verify disappearance; disconnected sessions still count as present."""
        deadline = time.monotonic() + timeout
        while True:
            if session_id not in self.session_ids():
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.2)
