import os
import sys

# Configure WebView2 Chromium flags BEFORE importing webview:
# - Prevents GPU occlusion/background throttling when reparented behind SHELLDLL_DefView
# - Strictly mutes all audio (--mute-audio)
# - Disables HTTP/media disk caching (--disk-cache-size=1 --media-cache-size=1) and
#   background telemetry/crashpad folders to keep %APPDATA%\webview_profile minimal.
os.environ.setdefault(
    "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
    "--disable-features=CalculateNativeWinOcclusion,WinUseBrowserSpellChecker,msSmartScreenProtection "
    "--disable-background-timer-throttling "
    "--disable-renderer-backgrounding "
    "--disable-backgrounding-occluded-windows "
    "--autoplay-policy=no-user-gesture-required "
    "--mute-audio "
    "--disk-cache-size=1 "
    "--media-cache-size=1 "
    "--disable-gpu-shader-disk-cache "
    "--disable-component-update "
    "--disable-domain-reliability "
    "--disable-breakpad "
    "--disable-crash-reporter "
    "--disable-sync "
    "--disable-translate "
    "--disable-extensions "
    "--disable-background-networking",
)

import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar
import json
import threading
import random
import shutil
import time
import base64
import ctypes
from ctypes import wintypes
from queue import Queue, Empty
from collections import deque
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import tkinter as tk
from tkinter import ttk

import pystray
from PIL import Image, ImageDraw, ImageTk
import webview

# =============================================================================
# 1. DPI AWARENESS, DPAPI ENCRYPTION & 64-BIT SAFE WIN32 CTYPES DEFINITIONS
# =============================================================================
def enable_dpi_awareness():
    try:
        ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
    except Exception:
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass


enable_dpi_awareness()

user32 = ctypes.windll.user32
crypt32 = ctypes.windll.crypt32
kernel32 = ctypes.windll.kernel32
LONG_PTR = ctypes.c_ssize_t


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


crypt32.CryptProtectData.argtypes = [
    ctypes.POINTER(DATA_BLOB),
    wintypes.LPCWSTR,
    ctypes.POINTER(DATA_BLOB),
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(DATA_BLOB),
]
crypt32.CryptProtectData.restype = wintypes.BOOL

crypt32.CryptUnprotectData.argtypes = [
    ctypes.POINTER(DATA_BLOB),
    ctypes.POINTER(wintypes.LPWSTR),
    ctypes.POINTER(DATA_BLOB),
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(DATA_BLOB),
]
crypt32.CryptUnprotectData.restype = wintypes.BOOL

kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
kernel32.LocalFree.restype = wintypes.HLOCAL

CRYPTPROTECT_UI_FORBIDDEN = 0x1


def dpapi_encrypt(plaintext: str) -> str:
    """Encrypts a plaintext string using Windows DPAPI tied to the current Windows user."""
    if not plaintext:
        return ""
    if plaintext.startswith("dpapi:"):
        return plaintext
    raw = plaintext.encode("utf-8")
    buf = ctypes.create_string_buffer(raw, len(raw))
    blob_in = DATA_BLOB(len(raw), buf)
    blob_out = DATA_BLOB()
    if crypt32.CryptProtectData(
        ctypes.byref(blob_in),
        "DanbooruWallpaperConfig",
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(blob_out),
    ):
        try:
            encrypted_bytes = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            return "dpapi:" + base64.b64encode(encrypted_bytes).decode("ascii")
        finally:
            kernel32.LocalFree(ctypes.cast(blob_out.pbData, wintypes.HLOCAL))
    return ""


def dpapi_decrypt(ciphertext: str) -> str:
    """Decrypts a DPAPI-protected string, supporting transparent fallback for legacy plaintext."""
    if not ciphertext:
        return ""
    if not ciphertext.startswith("dpapi:"):
        return ciphertext
    try:
        raw = base64.b64decode(ciphertext[6:])
        buf = ctypes.create_string_buffer(raw, len(raw))
        blob_in = DATA_BLOB(len(raw), buf)
        blob_out = DATA_BLOB()
        if crypt32.CryptUnprotectData(
            ctypes.byref(blob_in),
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(blob_out),
        ):
            try:
                return ctypes.string_at(blob_out.pbData, blob_out.cbData).decode("utf-8")
            finally:
                kernel32.LocalFree(ctypes.cast(blob_out.pbData, wintypes.HLOCAL))
    except Exception:
        pass
    return ""


SMTO_NORMAL = 0x0000
GWL_STYLE = -16
GWL_EXSTYLE = -20

WS_CAPTION = 0x00C00000
WS_THICKFRAME = 0x00040000
WS_MINIMIZEBOX = 0x00020000
WS_MAXIMIZEBOX = 0x00010000
WS_SYSMENU = 0x00080000
WS_POPUP = 0x80000000
WS_CHILD = 0x40000000
WS_VISIBLE = 0x10000000
WS_CLIPSIBLINGS = 0x04000000
WS_CLIPCHILDREN = 0x02000000

WS_EX_APPWINDOW = 0x00040000
WS_EX_TOOLWINDOW = 0x00000080
WS_EX_LAYERED = 0x00080000
WS_EX_NOACTIVATE = 0x08000000
WS_EX_NOREDIRECTIONBITMAP = 0x00200000

LWA_ALPHA = 0x00000002

SWP_NOSIZE = 0x0001
SWP_NOMOVE = 0x0002
SWP_NOZORDER = 0x0004
SWP_NOACTIVATE = 0x0010
SWP_FRAMECHANGED = 0x0020
SWP_SHOWWINDOW = 0x0040
SWP_HIDEWINDOW = 0x0080

HWND_TOP = 0
HWND_BOTTOM = 1

RDW_INVALIDATE = 0x0001
RDW_UPDATENOW = 0x0100
RDW_ALLCHILDREN = 0x0080
RDW_FRAME = 0x0400

WM_SIZE = 0x0005
SIZE_RESTORED = 0

SM_CXSCREEN = 0
SM_CYSCREEN = 1

WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
MONITORENUMPROC = ctypes.WINFUNCTYPE(
    wintypes.BOOL, wintypes.HMONITOR, wintypes.HDC, ctypes.POINTER(wintypes.RECT), wintypes.LPARAM
)


class MONITORINFOEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("rcMonitor", wintypes.RECT),
        ("rcWork", wintypes.RECT),
        ("dwFlags", wintypes.DWORD),
        ("szDevice", wintypes.WCHAR * 32),
    ]


user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
user32.FindWindowW.restype = wintypes.HWND

user32.FindWindowExW.argtypes = [wintypes.HWND, wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR]
user32.FindWindowExW.restype = wintypes.HWND

user32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
user32.EnumWindows.restype = wintypes.BOOL

user32.EnumChildWindows.argtypes = [wintypes.HWND, WNDENUMPROC, wintypes.LPARAM]
user32.EnumChildWindows.restype = wintypes.BOOL

user32.EnumDisplayMonitors.argtypes = [
    wintypes.HDC, ctypes.POINTER(wintypes.RECT), MONITORENUMPROC, wintypes.LPARAM
]
user32.EnumDisplayMonitors.restype = wintypes.BOOL

user32.GetMonitorInfoW.argtypes = [wintypes.HMONITOR, ctypes.POINTER(MONITORINFOEXW)]
user32.GetMonitorInfoW.restype = wintypes.BOOL

user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetClassNameW.restype = ctypes.c_int

user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL

user32.ScreenToClient.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.POINT)]
user32.ScreenToClient.restype = wintypes.BOOL

user32.RedrawWindow.argtypes = [wintypes.HWND, ctypes.c_void_p, wintypes.HRGN, wintypes.UINT]
user32.RedrawWindow.restype = wintypes.BOOL

user32.SendMessageTimeoutW.argtypes = [
    wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
    wintypes.UINT, wintypes.UINT, ctypes.POINTER(ctypes.c_size_t)
]
user32.SendMessageTimeoutW.restype = wintypes.LPARAM

user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.SendMessageW.restype = wintypes.LPARAM

user32.SetParent.argtypes = [wintypes.HWND, wintypes.HWND]
user32.SetParent.restype = wintypes.HWND

user32.SetWindowPos.argtypes = [
    wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
    ctypes.c_int, ctypes.c_int, wintypes.UINT
]
user32.SetWindowPos.restype = wintypes.BOOL

user32.SetLayeredWindowAttributes.argtypes = [
    wintypes.HWND, wintypes.COLORREF, wintypes.BYTE, wintypes.DWORD
]
user32.SetLayeredWindowAttributes.restype = wintypes.BOOL

GetWindowLongPtrW = getattr(user32, "GetWindowLongPtrW", user32.GetWindowLongW)
GetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int]
GetWindowLongPtrW.restype = LONG_PTR

SetWindowLongPtrW = getattr(user32, "SetWindowLongPtrW", user32.GetWindowLongW)
SetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int, LONG_PTR]
SetWindowLongPtrW.restype = LONG_PTR

INJECTION_LOCK = threading.Lock()


def enumerate_connected_monitors():
    """Enumerates all physical displays via Win32 EnumDisplayMonitors."""
    raw_monitors = []

    def _monitor_enum_proc(hMonitor, hdcMonitor, lprcMonitor, dwData):
        info = MONITORINFOEXW()
        info.cbSize = ctypes.sizeof(MONITORINFOEXW)
        if user32.GetMonitorInfoW(hMonitor, ctypes.byref(info)):
            r = info.rcMonitor
            w = r.right - r.left
            h = r.bottom - r.top
            is_primary = bool(info.dwFlags & 1)
            raw_monitors.append({
                "x": int(r.left),
                "y": int(r.top),
                "width": int(w),
                "height": int(h),
                "is_primary": is_primary,
                "device": info.szDevice,
            })
        return True

    cb = MONITORENUMPROC(_monitor_enum_proc)
    try:
        user32.EnumDisplayMonitors(None, None, cb, 0)
    except Exception:
        pass

    if not raw_monitors:
        sw = user32.GetSystemMetrics(SM_CXSCREEN)
        sh = user32.GetSystemMetrics(SM_CYSCREEN)
        raw_monitors.append({
            "x": 0, "y": 0, "width": sw, "height": sh, "is_primary": True, "device": "DISPLAY1"
        })

    raw_monitors.sort(key=lambda m: (0 if m["is_primary"] else 1, m["x"], m["y"]))

    screens = []
    for idx, m in enumerate(raw_monitors, start=1):
        screen_id = f"screen_{idx}"
        primary_tag = " (Primary)" if m["is_primary"] else ""
        screens.append({
            "id": screen_id,
            "index": idx,
            "name": f"Screen {idx}",
            "label": f"Screen {idx}: {m['width']}x{m['height']}{primary_tag}",
            "x": m["x"],
            "y": m["y"],
            "width": m["width"],
            "height": m["height"],
            "is_primary": m["is_primary"],
        })
    return screens


def has_webview_render_child(hwnd):
    """Checks whether WebView2 has created its internal Chrome_WidgetWin_0/1 child surface."""
    found = [False]
    class_buf = ctypes.create_unicode_buffer(256)

    def _check_child(child_hwnd, lparam):
        if user32.GetClassNameW(child_hwnd, class_buf, 256) > 0:
            cname = class_buf.value
            if cname.startswith("Chrome_WidgetWin_") or cname == "Intermediate D3D Window":
                found[0] = True
                return False
        return True

    cb = WNDENUMPROC(_check_child)
    user32.EnumChildWindows(hwnd, cb, 0)
    return found[0]


def get_webview_hwnd(window, window_title):
    """Retrieves the native Win32 HWND once the nested WebView2 rendering surface is initialized."""
    hwnd = None

    if window is not None and hasattr(window, "native") and window.native is not None:
        try:
            hwnd_val = window.native.Handle.ToInt64()
            if hwnd_val:
                hwnd = hwnd_val
        except Exception:
            pass

    if not hwnd:
        hwnd = user32.FindWindowW(None, window_title)

    if hwnd and has_webview_render_child(hwnd):
        return hwnd
    return None


def enumerate_desktop_topology(progman):
    """
    Sends 0x052C to Progman and resolves the desktop window topology across
    Windows 10, Windows 11 (21H2-23H2), and Windows 11 24H2+.
    """
    result = ctypes.c_size_t(0)
    user32.SendMessageTimeoutW(progman, 0x052C, 0, 0, SMTO_NORMAL, 1000, ctypes.byref(result))
    user32.SendMessageTimeoutW(progman, 0x052C, 0xD, 0x1, SMTO_NORMAL, 1000, ctypes.byref(result))
    time.sleep(0.05)

    progman_ex = GetWindowLongPtrW(progman, GWL_EXSTYLE) & 0xFFFFFFFF
    is_noref_bitmap = bool(progman_ex & WS_EX_NOREDIRECTIONBITMAP)

    shell_view_in_progman = user32.FindWindowExW(progman, 0, "SHELLDLL_DefView", None)
    workerw_in_progman = user32.FindWindowExW(progman, 0, "WorkerW", None)

    classic_workerw = []

    def _enum_proc(top_hwnd, lparam):
        shell_view = user32.FindWindowExW(top_hwnd, 0, "SHELLDLL_DefView", None)
        if shell_view:
            sibling = user32.FindWindowExW(0, top_hwnd, "WorkerW", None)
            if sibling:
                classic_workerw.append(sibling)
                return False
        return True

    enum_cb = WNDENUMPROC(_enum_proc)
    user32.EnumWindows(enum_cb, 0)

    is_win11_24h2 = (
        is_noref_bitmap
        and bool(shell_view_in_progman)
        and bool(workerw_in_progman)
        and not classic_workerw
    )

    return {
        "is_win11_24h2": is_win11_24h2,
        "shell_view_in_progman": shell_view_in_progman,
        "workerw_in_progman": workerw_in_progman,
        "classic_workerw": classic_workerw[0] if classic_workerw else None,
    }


def resize_webview_child_containers(hwnd, screen_w, screen_h):
    """
    Forces all inner WinForms and Chromium host controls to fill (0, 0, screen_w, screen_h).
    Checks the child's own WS_VISIBLE style bit rather than IsWindowVisible() so children are
    properly sized even when the parent HWND is temporarily hidden.
    """
    lparam_size = (screen_h << 16) | (screen_w & 0xFFFF)
    user32.SendMessageW(hwnd, WM_SIZE, SIZE_RESTORED, lparam_size)

    class_buf = ctypes.create_unicode_buffer(256)

    def _resize_child(child_hwnd, lparam):
        child_style = GetWindowLongPtrW(child_hwnd, GWL_STYLE) & 0xFFFFFFFF
        if not (child_style & WS_VISIBLE):
            return True
        if user32.GetClassNameW(child_hwnd, class_buf, 256) > 0:
            cname = class_buf.value
            if (
                cname.startswith("WindowsForms10.")
                or cname.startswith("Chrome_WidgetWin_")
                or cname == "Chrome_RenderWidgetHostHWND"
                or cname == "Intermediate D3D Window"
            ):
                user32.SetWindowPos(
                    child_hwnd, 0, 0, 0, screen_w, screen_h,
                    SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED
                )
                user32.SendMessageW(child_hwnd, WM_SIZE, SIZE_RESTORED, lparam_size)
        return True

    child_cb = WNDENUMPROC(_resize_child)
    user32.EnumChildWindows(hwnd, child_cb, 0)


def sync_all_screens_z_order_and_geometry(target_screen_id=None):
    """
    Synchronizes geometry, visibility, and desktop Z-order across ALL attached monitor HWNDs.
    On Windows 11 24H2+, places every enabled wallpaper HWND directly behind SHELLDLL_DefView
    and pushes Progman's WorkerW to HWND_BOTTOM (1) so WorkerW never occludes secondary screens.
    """
    with INJECTION_LOCK:
        progman = user32.FindWindowW("Progman", None)
        if not progman:
            return
        topo = enumerate_desktop_topology(progman)
        target_parent = (
            progman
            if topo["is_win11_24h2"]
            else (topo["classic_workerw"] or topo["workerw_in_progman"] or progman)
        )
        insert_after = (
            topo["shell_view_in_progman"]
            if (topo["is_win11_24h2"] and topo["shell_view_in_progman"])
            else HWND_TOP
        )

        screens_by_id = {s["id"]: s for s in CONNECTED_SCREENS}

        for sid, hwnd in list(DESKTOP_HWNDS.items()):
            if not hwnd or sid not in screens_by_id:
                continue

            s_info = screens_by_id[sid]
            sc_cfg = get_screen_config(sid)
            enabled = sc_cfg["enabled"]

            screen_w = s_info["width"]
            screen_h = s_info["height"]
            pt = wintypes.POINT(s_info["x"], s_info["y"])
            user32.ScreenToClient(target_parent, ctypes.byref(pt))

            style = GetWindowLongPtrW(hwnd, GWL_STYLE) & 0xFFFFFFFF
            if enabled:
                style |= WS_VISIBLE
                SetWindowLongPtrW(hwnd, GWL_STYLE, LONG_PTR(style))

                # Place directly behind SHELLDLL_DefView and perform 1px swapchain wake-up nudge
                if target_screen_id is None or target_screen_id == sid:
                    user32.SetWindowPos(
                        hwnd, insert_after, pt.x, pt.y, screen_w - 1, screen_h - 1,
                        SWP_NOACTIVATE | SWP_FRAMECHANGED | SWP_SHOWWINDOW
                    )
                user32.SetWindowPos(
                    hwnd, insert_after, pt.x, pt.y, screen_w, screen_h,
                    SWP_NOACTIVATE | SWP_FRAMECHANGED | SWP_SHOWWINDOW
                )
                resize_webview_child_containers(hwnd, screen_w, screen_h)
                user32.RedrawWindow(
                    hwnd, None, None,
                    RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN | RDW_FRAME
                )
                # Chain next enabled screen immediately behind this one so all stay above WorkerW
                insert_after = hwnd
            else:
                style &= ~WS_VISIBLE
                SetWindowLongPtrW(hwnd, GWL_STYLE, LONG_PTR(style))
                user32.SetWindowPos(
                    hwnd, 0, pt.x, pt.y, screen_w, screen_h,
                    SWP_NOZORDER | SWP_NOACTIVATE | SWP_HIDEWINDOW
                )

        # Push Progman's static wallpaper WorkerW to the absolute bottom behind ALL screen HWNDs
        if topo["is_win11_24h2"] and topo["workerw_in_progman"]:
            user32.SetWindowPos(
                topo["workerw_in_progman"],
                wintypes.HWND(HWND_BOTTOM),
                0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE
            )


def attach_window_to_desktop(window, window_title, mon_x=0, mon_y=0, mon_w=None, mon_h=None):
    """
    Injects a pywebview window behind desktop icons at the target monitor's coordinates.
    Supports both Windows 11 24H2+ (Progman layered child Z-order) and Win10/Win11 23H2 (WorkerW sibling).
    """
    hwnd = None
    for _ in range(80):
        hwnd = get_webview_hwnd(window, window_title)
        if hwnd:
            break
        time.sleep(0.1)

    if not hwnd:
        log_event("win32", f"Failed to locate initialized WebView2 HWND for '{window_title}'")
        return None

    with INJECTION_LOCK:
        progman = user32.FindWindowW("Progman", None)
        if not progman:
            log_event("win32", "Failed to locate Progman window.")
            return None

        topo = enumerate_desktop_topology(progman)
        screen_w = mon_w if mon_w is not None else user32.GetSystemMetrics(SM_CXSCREEN)
        screen_h = mon_h if mon_h is not None else user32.GetSystemMetrics(SM_CYSCREEN)

        style = GetWindowLongPtrW(hwnd, GWL_STYLE) & 0xFFFFFFFF
        clear_mask = WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU | WS_POPUP
        style = (style & ~clear_mask) | WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN
        SetWindowLongPtrW(hwnd, GWL_STYLE, LONG_PTR(style))

        ex_style = GetWindowLongPtrW(hwnd, GWL_EXSTYLE) & 0xFFFFFFFF

        if topo["is_win11_24h2"]:
            ex_style = (ex_style & ~WS_EX_APPWINDOW) | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_LAYERED
            SetWindowLongPtrW(hwnd, GWL_EXSTYLE, LONG_PTR(ex_style))
            user32.SetLayeredWindowAttributes(hwnd, 0, 255, LWA_ALPHA)

            target_parent = progman
            user32.SetParent(hwnd, target_parent)

            pt = wintypes.POINT(mon_x, mon_y)
            user32.ScreenToClient(target_parent, ctypes.byref(pt))

            insert_after = topo["shell_view_in_progman"] if topo["shell_view_in_progman"] else HWND_TOP
            user32.SetWindowPos(
                hwnd, insert_after, pt.x, pt.y, screen_w - 1, screen_h - 1,
                SWP_NOACTIVATE | SWP_FRAMECHANGED | SWP_SHOWWINDOW
            )
            user32.SetWindowPos(
                hwnd, insert_after, pt.x, pt.y, screen_w, screen_h,
                SWP_NOACTIVATE | SWP_FRAMECHANGED | SWP_SHOWWINDOW
            )

            if topo["workerw_in_progman"]:
                user32.SetWindowPos(
                    topo["workerw_in_progman"],
                    wintypes.HWND(HWND_BOTTOM),
                    0, 0, 0, 0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE
                )

            log_event(
                "win32",
                f"Win11 24H2+ mode: Attached '{window_title}' HWND {hex(hwnd)} to Progman {hex(progman)} "
                f"at ({pt.x},{pt.y}) {screen_w}x{screen_h}"
            )
        else:
            ex_style = (ex_style & ~(WS_EX_APPWINDOW | WS_EX_LAYERED)) | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE
            SetWindowLongPtrW(hwnd, GWL_EXSTYLE, LONG_PTR(ex_style))

            target_parent = topo["classic_workerw"] or topo["workerw_in_progman"] or progman
            user32.SetParent(hwnd, target_parent)

            pt = wintypes.POINT(mon_x, mon_y)
            user32.ScreenToClient(target_parent, ctypes.byref(pt))

            user32.SetWindowPos(
                hwnd, HWND_TOP, pt.x, pt.y, screen_w - 1, screen_h - 1,
                SWP_NOACTIVATE | SWP_FRAMECHANGED | SWP_SHOWWINDOW
            )
            user32.SetWindowPos(
                hwnd, HWND_TOP, pt.x, pt.y, screen_w, screen_h,
                SWP_NOACTIVATE | SWP_FRAMECHANGED | SWP_SHOWWINDOW
            )
            log_event(
                "win32",
                f"Classic WorkerW mode: Attached '{window_title}' HWND {hex(hwnd)} to WorkerW {hex(target_parent)} "
                f"at ({pt.x},{pt.y}) {screen_w}x{screen_h}"
            )

        resize_webview_child_containers(hwnd, screen_w, screen_h)
        user32.RedrawWindow(
            hwnd, None, None,
            RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN | RDW_FRAME
        )
        return hwnd


# =============================================================================
# 2. PATH ROUTING (sys._MEIPASS), PROFILE PRUNING & PERSISTENT %APPDATA% STORAGE
# =============================================================================
def get_resource_path(relative_path):
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


APPDATA_ROOT = os.getenv("APPDATA") or os.path.expanduser("~")
PERSISTENT_DIR = os.path.join(APPDATA_ROOT, "DanbooruWallpaper")
WEBVIEW_PROFILE_DIR = os.path.join(PERSISTENT_DIR, "webview_profile")
os.makedirs(PERSISTENT_DIR, exist_ok=True)
os.makedirs(WEBVIEW_PROFILE_DIR, exist_ok=True)

SAVED_SEARCHES_FILE = os.path.join(PERSISTENT_DIR, "saved_searches.json")
CONFIG_FILE = os.path.join(PERSISTENT_DIR, "config.json")
PROJECT_JSON_FILE = os.path.join(PERSISTENT_DIR, "project.json")

BUNDLED_HTML_FILE = get_resource_path("index.html")
BUNDLED_PROJECT_JSON = get_resource_path("project.json")


def prune_webview_profile_directory():
    """
    Removes unneeded Chromium cache, shader, crashpad, metrics, and storage subfolders
    inside %APPDATA%\\DanbooruWallpaper\\webview_profile so only the tiny Network cookie
    store (needed for Cloudflare clearance) remains on disk.
    """
    if not os.path.exists(WEBVIEW_PROFILE_DIR):
        return 0

    removed_count = 0
    eb_root = os.path.join(WEBVIEW_PROFILE_DIR, "EBWebView")
    if not os.path.exists(eb_root):
        return 0

    # Top-level EBWebView directories that are safe to delete
    top_level_purge = {
        "Crashpad",
        "BrowserMetrics",
        "ShaderCache",
        "GrShaderCache",
        "GraphiteDawnCache",
        "Subresource Filter",
        " Safe Browsing",
        "Safe Browsing",
        "CertificateRevocation",
        "component_crx_cache",
        "WidevineCdm",
        "ZxcvbnData",
        "SmartScreen",
        "EdgeWallet",
        "AutoLaunchProtocolsComponent",
        "OriginTrials",
        "InterventionPolicyDatabase",
        "MEIPreload",
        "FirstPartySetsPreloaded",
        "PKIMetadata",
        "PnaclTranslationCache",
        "RecoveryImproved",
        " snapshots",
    }

    for entry in list(os.listdir(eb_root)):
        full_p = os.path.join(eb_root, entry)
        if entry in top_level_purge or entry.startswith("BrowserMetrics"):
            try:
                if os.path.isdir(full_p):
                    shutil.rmtree(full_p, ignore_errors=True)
                else:
                    os.remove(full_p)
                removed_count += 1
            except Exception:
                pass

    # Inside Default profile, keep ONLY 'Network' (where cf_clearance cookie lives)
    default_dir = os.path.join(eb_root, "Default")
    if os.path.exists(default_dir):
        for entry in list(os.listdir(default_dir)):
            if entry == "Network":
                continue
            full_p = os.path.join(default_dir, entry)
            try:
                if os.path.isdir(full_p):
                    shutil.rmtree(full_p, ignore_errors=True)
                else:
                    os.remove(full_p)
                removed_count += 1
            except Exception:
                pass

    return removed_count


def get_default_properties_dict():
    return {
        "schemecolor": {"order": 0, "text": "Scheme Color", "type": "color", "value": "0.04 0.04 0.05"},
        "displaymode": {"order": 1, "text": "Display Mode", "type": "combo", "value": "scroll"},
        "scrolldirection": {"order": 2, "text": "Scroll Direction", "type": "combo", "value": "left"},
        "scrollspeed": {
            "order": 3,
            "text": "Scroll Speed (0.1 – 600 px/s)",
            "type": "slider",
            "min": 0.1,
            "max": 600,
            "step": 0.1,
            "precision": 2,
            "value": 120,
        },
        "gapsize": {
            "order": 4,
            "text": "Image Gap (0 – 64 px)",
            "type": "slider",
            "min": 0,
            "max": 64,
            "step": 1,
            "value": 12,
        },
        "dropspeed": {
            "order": 5,
            "text": "Drop Speed (0.2 – 4.0)",
            "type": "slider",
            "min": 0.2,
            "max": 4.0,
            "step": 0.1,
            "precision": 2,
            "value": 1.0,
        },
        "minsize": {
            "order": 6,
            "text": "Minimum Size (120 – 600 px)",
            "type": "slider",
            "min": 120,
            "max": 600,
            "step": 1,
            "value": 220,
        },
        "maxsize": {
            "order": 7,
            "text": "Maximum Size (150 – 900 px)",
            "type": "slider",
            "min": 150,
            "max": 900,
            "step": 1,
            "value": 440,
        },
        "dropdelay": {
            "order": 8,
            "text": "Spawn/Drop Delay (0 – 600 s)",
            "type": "slider",
            "min": 0,
            "max": 600,
            "step": 1,
            "value": 0,
        },
    }


DEFAULT_PROJECT_SCHEMA = {
    "file": "index.html",
    "general": {
        "properties": get_default_properties_dict()
    },
    "screens": {},
    "title": "Danbooru Infinite Scroll & Polaroid Collage",
    "type": "web",
    "version": 1,
}


def init_persistent_storage():
    prune_webview_profile_directory()

    if not os.path.exists(PROJECT_JSON_FILE):
        try:
            if os.path.exists(BUNDLED_PROJECT_JSON):
                shutil.copyfile(BUNDLED_PROJECT_JSON, PROJECT_JSON_FILE)
            else:
                with open(PROJECT_JSON_FILE, "w", encoding="utf-8") as f:
                    json.dump(DEFAULT_PROJECT_SCHEMA, f, indent=2)
        except Exception as e:
            print(f"[INIT] Failed to initialize project.json in APPDATA: {e}")

    if not os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump({}, f, indent=2)
        except Exception:
            pass

    if not os.path.exists(SAVED_SEARCHES_FILE):
        try:
            with open(SAVED_SEARCHES_FILE, "w", encoding="utf-8") as f:
                json.dump([], f, indent=2)
        except Exception:
            pass


init_persistent_storage()

# =============================================================================
# 3. APPLICATION CONSTANTS, CLOUDFLARE MITIGATION & STATE MANAGEMENT
# =============================================================================
DEFAULT_TAGS = "scenery no_humans"
PORT = 8088
WEBVIEW_WINDOW_TITLE_PREFIX = "DanbooruWallpaperRendererHost"

MIN_API_INTERVAL = 2.5

# Max MP4 file size allowed through API metadata & Proxy stream (15 MB = 15,728,640 bytes)
MAX_MP4_FILE_SIZE_BYTES = 15 * 1024 * 1024
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp", "gif", "mp4"}

ALLOWED_MEDIA_HOSTS = {
    "danbooru.donmai.us",
    "cdn.donmai.us",
}

ALLOWED_LOCAL_ORIGINS = {
    f"http://127.0.0.1:{PORT}",
    f"http://localhost:{PORT}",
}

CF_COOKIE_HEADER = ""


class SafeMediaRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevents SSRF via open redirects by validating every redirect target against ALLOWED_MEDIA_HOSTS."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_MEDIA_HOSTS:
            raise urllib.error.HTTPError(
                newurl, 403, f"Redirect to unauthorized media host blocked: {parsed.hostname}", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


SHARED_COOKIE_JAR = http.cookiejar.CookieJar()
SAFE_MEDIA_OPENER = urllib.request.build_opener(
    SafeMediaRedirectHandler,
    urllib.request.HTTPCookieProcessor(SHARED_COOKIE_JAR),
)

USERNAME = ""
USER_ID = ""
API_KEY = ""

BASE_API_HEADERS = {}
BASE_MEDIA_HEADERS = {}


def apply_credentials(user, uid, key):
    global USERNAME, USER_ID, API_KEY, BASE_API_HEADERS, BASE_MEDIA_HEADERS
    USERNAME = user.strip()
    USER_ID = uid.strip()
    API_KEY = key.strip()

    api_user_agent = (
        f"DanbooruWallpaperEngine/1.0 (by {USERNAME}; user #{USER_ID})"
        if USERNAME and USER_ID
        else (f"DanbooruWallpaperEngine/1.0 (by {USERNAME})" if USERNAME else "DanbooruWallpaperEngine/1.0")
    )
    auth_token = (
        base64.b64encode(f"{USERNAME}:{API_KEY}".encode("utf-8")).decode("utf-8")
        if USERNAME and API_KEY
        else ""
    )

    BASE_API_HEADERS = {
        "User-Agent": api_user_agent,
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if auth_token:
        BASE_API_HEADERS["Authorization"] = f"Basic {auth_token}"
    if CF_COOKIE_HEADER:
        BASE_API_HEADERS["Cookie"] = CF_COOKIE_HEADER

    BASE_MEDIA_HEADERS = {
        "User-Agent": api_user_agent,
        "Referer": "https://danbooru.donmai.us/",
        "Accept": "image/avif,image/webp,image/apng,image/*,video/mp4,video/*;q=0.9,*/*;q=0.8",
    }
    if auth_token:
        BASE_MEDIA_HEADERS["Authorization"] = f"Basic {auth_token}"
    if CF_COOKIE_HEADER:
        BASE_MEDIA_HEADERS["Cookie"] = CF_COOKIE_HEADER


CURRENT_TAGS = DEFAULT_TAGS
CURRENT_PAGE = 1
CACHE_EPOCH = 1

MAX_SEEN_IDS = 1500
SEEN_POST_IDS = set()
SEEN_POST_ORDER = deque()

# Per-screen tracking to guarantee unique identifiers across screens from the shared POST_BUFFER
SCREEN_SEEN_IDS = {}

PENDING_TAG_QUEUE = deque(maxlen=20)
POST_BUFFER = deque(maxlen=500)
LOG_HISTORY = deque(maxlen=500)

DATA_LOCK = threading.Lock()
FETCH_CONDITION = threading.Condition(DATA_LOCK)
IS_FETCHING = False
CONSECUTIVE_FAILURES = 0
CONSECUTIVE_EMPTY_PAGES = 0
LAST_API_CALL_TIME = 0.0
NEXT_ALLOWED_FETCH_TIME = 0.0

CDN_DIRECT_REDIRECT_MODE = False
CF_POPUP_ACTIVE = False
CF_POPUP_WINDOW = None

# Pause states (Feature 3 & Feature 4)
APP_PAUSED = False        # Master application pause (freezes display, stops proxy & API calls)
WALLPAPER_PAUSED = False  # Search bar pause (pauses scrolling/collage, keeps GIFs/MP4s playing)

EPOCH_POLL_COUNT = 0
LAST_EPOCH_LOG_TIME = 0.0

LAST_STATUS = {"status": "idle", "page": 0, "count": 0}
IS_RUNNING = True

SUGGESTION_QUEUE = Queue(maxsize=1)

TRAY_ICON = None
TK_ROOT = None
APP_INSTANCE = None
HTTP_SERVER = None
SETTINGS_DIALOG_INSTANCE = None

CONNECTED_SCREENS = enumerate_connected_monitors()
WEBVIEW_WINDOWS = {}       # screen_id -> webview.Window
DESKTOP_HWNDS = {}         # screen_id -> int HWND
DESKTOP_INJECTED_SET = set()


def log_event(category, message):
    timestamp = time.strftime("%H:%M:%S")
    formatted_msg = f"[{timestamp}] [{category.upper()}] {message}"
    print(formatted_msg)
    LOG_HISTORY.append(formatted_msg)
    if TK_ROOT and SETTINGS_DIALOG_INSTANCE and getattr(SETTINGS_DIALOG_INSTANCE, "is_open", False):
        try:
            TK_ROOT.after(0, lambda msg=formatted_msg: SETTINGS_DIALOG_INSTANCE.append_log(msg))
        except (tk.TclError, RuntimeError):
            pass


def load_saved_searches():
    if os.path.exists(SAVED_SEARCHES_FILE):
        try:
            with open(SAVED_SEARCHES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return [str(item).strip() for item in data if str(item).strip()]
        except Exception as e:
            log_event("config", f"Failed to load saved searches: {e}")
    return []


def store_saved_searches(searches):
    try:
        with open(SAVED_SEARCHES_FILE, "w", encoding="utf-8") as f:
            json.dump(searches, f, ensure_ascii=False, indent=2)
    except Exception as e:
        log_event("config", f"Failed to save searches: {e}")


def load_app_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return {}
            raw_key = data.get("API_KEY", "")
            if raw_key:
                was_plaintext = not str(raw_key).startswith("dpapi:")
                data["API_KEY"] = dpapi_decrypt(str(raw_key))
                if was_plaintext and data["API_KEY"]:
                    store_app_config(data)
            return data
        except Exception as e:
            log_event("config", f"Failed to load app config: {e}")
    return {}


def store_app_config(config_data):
    try:
        to_save = dict(config_data)
        if to_save.get("API_KEY"):
            encrypted_key = dpapi_encrypt(str(to_save["API_KEY"]))
            if encrypted_key:
                to_save["API_KEY"] = encrypted_key
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(to_save, f, indent=2)
    except Exception as e:
        log_event("config", f"Failed to save app config: {e}")


def load_project_json():
    if os.path.exists(PROJECT_JSON_FILE):
        try:
            with open(PROJECT_JSON_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                general_props = data.setdefault("general", {}).setdefault("properties", {})
                for k, v in get_default_properties_dict().items():
                    if k not in general_props or not isinstance(general_props[k], dict):
                        general_props[k] = json.loads(json.dumps(v))
                    else:
                        saved_val = general_props[k].get("value", v["value"])
                        merged_meta = json.loads(json.dumps(v))
                        merged_meta["value"] = saved_val
                        general_props[k] = merged_meta
                data.setdefault("screens", {})
                return data
        except Exception as e:
            log_event("config", f"Failed to read project.json: {e}")
    return json.loads(json.dumps(DEFAULT_PROJECT_SCHEMA))


def store_project_json(project_data):
    try:
        with open(PROJECT_JSON_FILE, "w", encoding="utf-8") as f:
            json.dump(project_data, f, indent=2)
    except Exception as e:
        log_event("config", f"Failed to save project.json: {e}")


def get_screen_config(screen_id="screen_1"):
    """Returns {'enabled': bool, 'properties': dict} for the specified screen_id."""
    proj = load_project_json()
    base_props = proj.get("general", {}).get("properties", get_default_properties_dict())
    screens_dict = proj.get("screens", {})

    if screen_id in screens_dict and isinstance(screens_dict[screen_id], dict):
        sc = screens_dict[screen_id]
        enabled = bool(sc.get("enabled", screen_id == "screen_1"))
        merged_props = json.loads(json.dumps(base_props))
        for k, v in sc.get("properties", {}).items():
            if k in merged_props and isinstance(v, dict) and "value" in v:
                merged_props[k]["value"] = v["value"]
            else:
                merged_props[k] = v
        return {"enabled": enabled, "properties": merged_props}

    return {
        "enabled": (screen_id == "screen_1"),
        "properties": json.loads(json.dumps(base_props)),
    }


def push_properties_to_webview(target_screen_id=None):
    """
    Synchronizes Win32 multi-monitor Z-order/visibility and pushes per-screen
    properties and enabled states to one or all WebView instances.
    """
    sync_all_screens_z_order_and_geometry(target_screen_id)

    targets = (
        [(target_screen_id, WEBVIEW_WINDOWS.get(target_screen_id))]
        if target_screen_id and target_screen_id in WEBVIEW_WINDOWS
        else list(WEBVIEW_WINDOWS.items())
    )
    for sid, win in targets:
        if not win:
            continue
        try:
            sc_cfg = get_screen_config(sid)
            enabled = sc_cfg["enabled"]
            props = sc_cfg["properties"]
            payload = json.dumps(props)
            enabled_js = "true" if enabled else "false"
            js_code = (
                f"if (window.setScreenEnabled) {{ window.setScreenEnabled({enabled_js}); }} "
                f"if (window.wallpaperPropertyListener && window.wallpaperPropertyListener.applyUserProperties) {{ "
                f"window.wallpaperPropertyListener.applyUserProperties({payload}); }} "
                f"window.dispatchEvent(new Event('resize'));"
            )
            win.evaluate_js(js_code)
            log_event("webview", f"Applied display properties to {sid} (enabled={enabled}).")
        except Exception as e:
            log_event("webview", f"Failed to push properties to {sid}: {e}")


def push_pause_states_to_webviews():
    """Immediately synchronizes master APP_PAUSED and search bar WALLPAPER_PAUSED states to all screens."""
    app_p = "true" if APP_PAUSED else "false"
    wp_p = "true" if WALLPAPER_PAUSED else "false"
    js_code = f"if (window.applyPauseStates) {{ window.applyPauseStates({app_p}, {wp_p}); }}"
    for sid, win in list(WEBVIEW_WINDOWS.items()):
        if win:
            try:
                win.evaluate_js(js_code)
            except Exception:
                pass


def notify_webviews_auth_resolved():
    """Notifies all active wallpaper WebView2 windows to immediately resume loading after Cloudflare check."""
    js_code = "if (window.onCloudflareVerified) { window.onCloudflareVerified(); }"
    for sid, win in list(WEBVIEW_WINDOWS.items()):
        if win:
            try:
                win.evaluate_js(js_code)
            except Exception:
                pass


def trigger_fill_screen_on_webview(screen_id):
    """Triggers the Collage Fill Screen burst on the specified screen."""
    win = WEBVIEW_WINDOWS.get(screen_id)
    if win:
        try:
            win.evaluate_js("if (window.triggerFillCollageScreen) { window.triggerFillCollageScreen(); }")
            log_event("collage", f"Triggered Fill Screen burst on {screen_id}.")
        except Exception as e:
            log_event("collage", f"Failed to trigger Fill Screen on {screen_id}: {e}")


_initial_cfg = load_app_config()
if _initial_cfg.get("CF_COOKIE"):
    CF_COOKIE_HEADER = _initial_cfg["CF_COOKIE"]

apply_credentials(
    _initial_cfg.get("USERNAME", ""),
    _initial_cfg.get("USER_ID", ""),
    _initial_cfg.get("API_KEY", ""),
)


# =============================================================================
# 4. IN-PROCESS CLOUDFLARE HUMAN VERIFICATION POP-UP (SHARED WEBVIEW2 PROFILE)
# =============================================================================
def extract_cookies_from_webview_window(window):
    """
    Extracts cookies (including HttpOnly cf_clearance) from a pywebview window
    using CoreWebView2CookieManager (window.get_cookies()) and syncs them to Python.
    """
    global CF_COOKIE_HEADER
    cookie_pairs = {}

    if CF_COOKIE_HEADER:
        for part in CF_COOKIE_HEADER.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                cookie_pairs[k.strip()] = v.strip()

    try:
        native_cookies = window.get_cookies()
        if native_cookies:
            for c in native_cookies:
                if hasattr(c, "items"):
                    for k, morsel in c.items():
                        val = getattr(morsel, "value", str(morsel))
                        cookie_pairs[k] = val
                elif hasattr(c, "name") and hasattr(c, "value"):
                    cookie_pairs[str(c.name)] = str(c.value)
    except Exception:
        pass

    try:
        js_cookie = window.evaluate_js("document.cookie")
        if js_cookie and isinstance(js_cookie, str):
            for part in js_cookie.split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    cookie_pairs[k.strip()] = v.strip()
    except Exception:
        pass

    if cookie_pairs:
        new_header = "; ".join(f"{k}={v}" for k, v in cookie_pairs.items() if k)
        if new_header and new_header != CF_COOKIE_HEADER:
            CF_COOKIE_HEADER = new_header
            apply_credentials(USERNAME, USER_ID, API_KEY)
            if APP_INSTANCE:
                APP_INSTANCE.config["CF_COOKIE"] = CF_COOKIE_HEADER
                store_app_config(APP_INSTANCE.config)
            log_event(
                "cloudflare",
                f"Synchronized {len(cookie_pairs)} cookies from shared WebView2 profile "
                f"(cf_clearance={'present' if 'cf_clearance' in cookie_pairs else 'shared-in-webview'})."
            )
            return "cf_clearance" in cookie_pairs
    return False


def open_cloudflare_verification_window(reason="Cloudflare verification requested"):
    """
    Opens an in-process WebView2 pop-up window sharing the exact same WebView2 profile
    (cookies, HttpOnly cf_clearance, TLS session cache) as the desktop wallpaper windows.
    """
    global CF_POPUP_ACTIVE, CF_POPUP_WINDOW
    with DATA_LOCK:
        if CF_POPUP_ACTIVE:
            if CF_POPUP_WINDOW:
                try:
                    CF_POPUP_WINDOW.show()
                except Exception:
                    pass
            return
        CF_POPUP_ACTIVE = True

    log_event("cloudflare", f"Opening in-process Cloudflare verification window ({reason})...")

    def _spawn_in_process_popup():
        global CF_POPUP_ACTIVE, CF_POPUP_WINDOW
        popup_closed_event = threading.Event()

        try:
            popup_win = webview.create_window(
                title="Cloudflare Human Verification — Verify / Log In, Then Close This Window",
                url="https://danbooru.donmai.us/",
                width=560,
                height=640,
                resizable=True,
                on_top=True,
            )
            CF_POPUP_WINDOW = popup_win

            def _on_closed():
                popup_closed_event.set()

            popup_win.events.closed += _on_closed

            start_ts = time.time()
            while not popup_closed_event.is_set() and (time.time() - start_ts) < 300:
                time.sleep(1.5)
                if popup_closed_event.is_set():
                    break
                try:
                    extract_cookies_from_webview_window(popup_win)
                except Exception:
                    pass

        except Exception as e:
            log_event("cloudflare", f"Cloudflare verification window error: {e}")
        finally:
            with DATA_LOCK:
                CF_POPUP_ACTIVE = False
                CF_POPUP_WINDOW = None
            log_event("cloudflare", "Cloudflare verification window closed; resuming wallpaper streams.")
            notify_webviews_auth_resolved()

    threading.Thread(target=_spawn_in_process_popup, daemon=True).start()


# =============================================================================
# 5. ICON GENERATION & DANBOORU API LOGIC
# =============================================================================
def create_cardboard_box_icon():
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    box_base = (194, 142, 86, 255)
    box_dark = (150, 105, 60, 255)
    box_interior = (115, 78, 42, 255)
    flap_color = (212, 162, 106, 255)
    tape_color = (130, 88, 50, 255)

    draw.polygon([(14, 25), (32, 33), (50, 25), (32, 18)], fill=box_interior)
    draw.polygon([(14, 25), (32, 33), (32, 57), (14, 49)], fill=box_dark)
    draw.polygon([(32, 33), (50, 25), (50, 49), (32, 57)], fill=box_base)
    draw.line([(32, 33), (32, 57)], fill=tape_color, width=2)
    draw.polygon([(14, 25), (32, 33), (25, 23), (8, 17)], fill=flap_color)
    draw.line([(14, 25), (8, 17)], fill=box_dark, width=1)
    draw.polygon([(32, 33), (50, 25), (56, 17), (39, 23)], fill=flap_color)
    draw.line([(50, 25), (56, 17)], fill=box_dark, width=1)
    draw.polygon([(14, 25), (32, 18), (28, 11), (11, 16)], fill=flap_color)
    draw.polygon([(32, 18), (50, 25), (53, 16), (36, 11)], fill=flap_color)
    return img


def apply_app_icon(root):
    try:
        box_img = create_cardboard_box_icon()
        tk_icon = ImageTk.PhotoImage(box_img)
        root._app_icon = tk_icon
        root.iconphoto(True, tk_icon)
    except Exception as e:
        log_event("ui", f"Could not set window icon: {e}")


def track_post_id_locked(post_id):
    if post_id not in SEEN_POST_IDS:
        SEEN_POST_IDS.add(post_id)
        SEEN_POST_ORDER.append(post_id)
        if len(SEEN_POST_ORDER) > MAX_SEEN_IDS:
            oldest = SEEN_POST_ORDER.popleft()
            SEEN_POST_IDS.discard(oldest)


def _execute_danbooru_request(tags, page_num):
    if APP_PAUSED:
        raise RuntimeError("Application is currently paused.")
    query_str = urllib.parse.urlencode({
        "tags": tags,
        "limit": 100,
        "page": page_num
    })
    url = f"https://danbooru.donmai.us/posts.json?{query_str}"
    log_event("api", f"Requesting Page {page_num} for tags: '{tags}'")
    req = urllib.request.Request(url, headers=BASE_API_HEADERS)
    with SAFE_MEDIA_OPENER.open(req, timeout=15) as res:
        raw_data = res.read().decode("utf-8", errors="replace")
        return json.loads(raw_data)


def fetch_danbooru_page(tags, page_num):
    global LAST_API_CALL_TIME

    if APP_PAUSED:
        return []

    with DATA_LOCK:
        now = time.time()
        wait_for = max(0.0, (LAST_API_CALL_TIME + MIN_API_INTERVAL) - now)
        LAST_API_CALL_TIME = now + wait_for

    if wait_for > 0:
        time.sleep(wait_for)

    if APP_PAUSED:
        return []

    try:
        data = _execute_danbooru_request(tags, page_num)
    except urllib.error.HTTPError as e:
        tokens = [t for t in tags.split() if t]
        if e.code == 422 and len(tokens) > 2:
            fallback_tags = " ".join(tokens[:2])
            log_event(
                "api",
                f"HTTP 422 (2-tag limit on current account tier). Retrying with '{fallback_tags}'"
            )
            time.sleep(1.0)
            data = _execute_danbooru_request(fallback_tags, page_num)
        elif e.code == 403:
            log_event("cloudflare", "HTTP 403 on API endpoint; launching human verification window.")
            open_cloudflare_verification_window("API HTTP 403")
            raise
        else:
            raise

    if isinstance(data, dict):
        error_msg = data.get("message", data.get("error", "API Error"))
        raise ValueError(f"Danbooru error: {error_msg}")
    if not isinstance(data, list):
        raise ValueError("Invalid format received from Danbooru.")
    return data


def fetch_tag_suggestions(query_prefix):
    if APP_PAUSED:
        return []
    query_str = urllib.parse.urlencode({
        "search[name_matches]": f"*{query_prefix}*",
        "search[order]": "count",
        "limit": 5
    })
    url = f"https://danbooru.donmai.us/tags.json?{query_str}"
    req = urllib.request.Request(url, headers=BASE_API_HEADERS)
    try:
        with SAFE_MEDIA_OPENER.open(req, timeout=4) as res:
            raw_data = res.read().decode("utf-8", errors="replace")
            data = json.loads(raw_data)
            if isinstance(data, list):
                return [(item.get("name"), item.get("post_count", 0)) for item in data if item.get("name")]
    except Exception as e:
        log_event("suggest", f"Suggestion fetch failed: {e}")
    return []


def suggestion_worker_loop():
    while IS_RUNNING:
        try:
            fragment, req_id = SUGGESTION_QUEUE.get(timeout=1.0)
        except Empty:
            continue

        if APP_PAUSED:
            SUGGESTION_QUEUE.task_done()
            continue

        results = fetch_tag_suggestions(fragment)
        if IS_RUNNING and APP_INSTANCE and req_id == APP_INSTANCE._suggest_req_id:
            try:
                if TK_ROOT:
                    TK_ROOT.after(0, lambda r=results, q=req_id: APP_INSTANCE.display_suggestions(r, q))
            except (tk.TclError, RuntimeError):
                pass
        SUGGESTION_QUEUE.task_done()


def fill_post_buffer(wait_if_busy=False):
    global CURRENT_TAGS, CURRENT_PAGE, LAST_STATUS, IS_FETCHING
    global CONSECUTIVE_FAILURES, CONSECUTIVE_EMPTY_PAGES, NEXT_ALLOWED_FETCH_TIME

    if APP_PAUSED:
        return

    with FETCH_CONDITION:
        if IS_FETCHING:
            if wait_if_busy:
                FETCH_CONDITION.wait(timeout=20.0)
            return

        now = time.time()
        if now < NEXT_ALLOWED_FETCH_TIME and not PENDING_TAG_QUEUE:
            return

        IS_FETCHING = True

    try:
        while IS_RUNNING and not APP_PAUSED:
            with DATA_LOCK:
                if PENDING_TAG_QUEUE:
                    CURRENT_TAGS = PENDING_TAG_QUEUE.popleft()
                    CURRENT_PAGE = 1
                    CONSECUTIVE_EMPTY_PAGES = 0
                    SEEN_POST_IDS.clear()
                    SEEN_POST_ORDER.clear()
                    SCREEN_SEEN_IDS.clear()

                target_tags = CURRENT_TAGS
                target_page = CURRENT_PAGE
                epoch = CACHE_EPOCH

            posts = fetch_danbooru_page(target_tags, target_page)

            with DATA_LOCK:
                if epoch != CACHE_EPOCH or APP_PAUSED:
                    continue

            if not posts:
                if target_page == 1:
                    with DATA_LOCK:
                        CONSECUTIVE_FAILURES += 1
                        backoff = min(30, max(5, 2 ** CONSECUTIVE_FAILURES))
                        NEXT_ALLOWED_FETCH_TIME = time.time() + backoff
                        LAST_STATUS = {"status": "error", "page": 1, "count": 0}
                    log_event("error", f"No posts found for '{target_tags}'. Backing off {backoff}s...")
                    return

                with DATA_LOCK:
                    CURRENT_PAGE = 1
                    CONSECUTIVE_EMPTY_PAGES = 0
                    SEEN_POST_IDS.clear()
                    SEEN_POST_ORDER.clear()
                    SCREEN_SEEN_IDS.clear()
                target_page = 1
                posts = fetch_danbooru_page(target_tags, target_page)

                with DATA_LOCK:
                    if epoch != CACHE_EPOCH or APP_PAUSED:
                        continue

            new_items = []
            skipped_large_mp4 = 0
            with DATA_LOCK:
                if epoch != CACHE_EPOCH:
                    continue

                for p in posts:
                    if not isinstance(p, dict):
                        continue
                    pid = p.get("id")
                    file_url = p.get("file_url")
                    ext = p.get("file_ext", "").lower()
                    file_size = int(p.get("file_size") or 0)

                    if not pid or pid in SEEN_POST_IDS or not file_url or ext not in ALLOWED_EXTENSIONS:
                        continue

                    # Feature 1: Filter out large MP4 files (> 15 MB) so there is no lag, stuttering, or memory bloat
                    if ext == "mp4" and (file_size <= 0 or file_size > MAX_MP4_FILE_SIZE_BYTES):
                        skipped_large_mp4 += 1
                        continue

                    track_post_id_locked(pid)
                    safe_url = urllib.parse.quote(file_url, safe="")
                    p["proxy_url"] = f"http://127.0.0.1:{PORT}/image?url={safe_url}&ext={ext}&size={file_size}"
                    p["direct_url"] = file_url
                    p["epoch"] = epoch
                    new_items.append(p)

                random.shuffle(new_items)
                POST_BUFFER.extend(new_items)
                CURRENT_PAGE = target_page + 1
                LAST_STATUS = {"status": "ok", "page": target_page, "count": len(new_items)}
                CONSECUTIVE_FAILURES = 0

                if len(new_items) == 0:
                    CONSECUTIVE_EMPTY_PAGES += 1
                    if CONSECUTIVE_EMPTY_PAGES >= 2:
                        NEXT_ALLOWED_FETCH_TIME = time.time() + 10.0
                        log_event("fetch", f"Multiple pages returned 0 usable items for '{target_tags}'. Cooling down 10s.")
                    else:
                        NEXT_ALLOWED_FETCH_TIME = time.time() + MIN_API_INTERVAL
                else:
                    CONSECUTIVE_EMPTY_PAGES = 0
                    NEXT_ALLOWED_FETCH_TIME = time.time() + MIN_API_INTERVAL

            extra_msg = f" (filtered {skipped_large_mp4} oversized MP4s)" if skipped_large_mp4 else ""
            log_event(
                "fetch",
                f"Fetched and shuffled {len(new_items)} media items (Page {target_page}) for '{target_tags}'{extra_msg}."
            )
            break

    except Exception as e:
        with DATA_LOCK:
            CONSECUTIVE_FAILURES += 1
            backoff = min(30, max(4, 2 ** CONSECUTIVE_FAILURES))
            NEXT_ALLOWED_FETCH_TIME = time.time() + backoff
            LAST_STATUS = {"status": "error", "page": CURRENT_PAGE, "count": 0}

        log_event("error", f"Fetch error: {e}. Backing off {backoff}s...")
    finally:
        with FETCH_CONDITION:
            IS_FETCHING = False
            FETCH_CONDITION.notify_all()


# =============================================================================
# 6. HTTP SERVER & HARDENED SAME-ORIGIN PROXY HANDLER
# =============================================================================
class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


class ProxyHandler(BaseHTTPRequestHandler):
    def _is_authorized_local_request(self):
        origin = self.headers.get("Origin")
        sec_site = self.headers.get("Sec-Fetch-Site")
        if origin and origin not in ALLOWED_LOCAL_ORIGINS:
            log_event("security", f"Blocked unauthorized cross-origin request from Origin: {origin}")
            return False
        if sec_site and sec_site not in ("same-origin", "none"):
            log_event("security", f"Blocked external browser request (Sec-Fetch-Site: {sec_site})")
            return False
        return True

    def do_OPTIONS(self):
        if not self._is_authorized_local_request():
            self.send_response(403)
            self.send_header("Connection", "close")
            self.end_headers()
            return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", f"http://127.0.0.1:{PORT}")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Range")
        self.send_header("Connection", "close")
        self.end_headers()

    def do_POST(self):
        if not self._is_authorized_local_request():
            self.send_response(403)
            self.send_header("Connection", "close")
            self.end_headers()
            return

        parsed_url = urllib.parse.urlparse(self.path)
        if parsed_url.path == "/cf_challenge_needed":
            if not APP_PAUSED:
                open_cloudflare_verification_window("WebView2 media challenge detected")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            return

        self.send_response(404)
        self.send_header("Connection", "close")
        self.end_headers()

    def do_GET(self):
        global EPOCH_POLL_COUNT, LAST_EPOCH_LOG_TIME, CDN_DIRECT_REDIRECT_MODE

        if not self._is_authorized_local_request():
            self.send_response(403)
            self.send_header("Connection", "close")
            self.end_headers()
            return

        parsed_url = urllib.parse.urlparse(self.path)
        path_only = parsed_url.path
        query_params = urllib.parse.parse_qs(parsed_url.query)
        screen_id = query_params.get("screen", ["screen_1"])[0]

        if path_only in ("/", "/index.html"):
            try:
                with open(BUNDLED_HTML_FILE, "rb") as f:
                    html_bytes = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html_bytes)))
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(html_bytes)
            except Exception as e:
                log_event("server", f"Error serving index.html: {e}")
                self.send_response(500)
                self.end_headers()
            return

        if path_only == "/properties":
            try:
                sc_cfg = get_screen_config(screen_id)
                payload = {
                    "enabled": sc_cfg["enabled"],
                    "properties": sc_cfg["properties"],
                    "app_paused": APP_PAUSED,
                    "wallpaper_paused": WALLPAPER_PAUSED,
                }
                props_body = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(props_body)))
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(props_body)
            except Exception:
                pass
            return

        if path_only == "/epoch":
            now = time.time()
            should_log_ping = False
            poll_count_snapshot = 0
            elapsed_snapshot = 0

            with DATA_LOCK:
                if LAST_EPOCH_LOG_TIME == 0.0:
                    LAST_EPOCH_LOG_TIME = now

                EPOCH_POLL_COUNT += 1
                res_body = json.dumps({
                    "epoch": CACHE_EPOCH,
                    "app_paused": APP_PAUSED,
                    "wallpaper_paused": WALLPAPER_PAUSED,
                }).encode("utf-8")

                elapsed = now - LAST_EPOCH_LOG_TIME
                if elapsed >= 60.0:
                    should_log_ping = True
                    poll_count_snapshot = EPOCH_POLL_COUNT
                    elapsed_snapshot = int(elapsed)
                    EPOCH_POLL_COUNT = 0
                    LAST_EPOCH_LOG_TIME = now

            if should_log_ping and not APP_PAUSED:
                log_event("ping", f"Client polled /epoch ({poll_count_snapshot} times in last {elapsed_snapshot}s)")

            try:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(res_body)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                pass
            return

        if path_only == "/api":
            if APP_PAUSED:
                try:
                    empty_body = b"[]"
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(empty_body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(empty_body)
                except Exception:
                    pass
                return

            log_event("server", f"Client '{screen_id}' requested batch from /api")
            try:
                with DATA_LOCK:
                    needs_blocking_fill = (len(POST_BUFFER) == 0)

                if needs_blocking_fill:
                    fill_post_buffer(wait_if_busy=True)

                # Feature 2: Pull from the shared POST_BUFFER while tracking unique post IDs per screen
                batch = []
                active_screen_count = max(1, sum(1 for s in CONNECTED_SCREENS if get_screen_config(s["id"])["enabled"]))
                batch_target = 25 if active_screen_count > 1 else 40

                with DATA_LOCK:
                    screen_seen = SCREEN_SEEN_IDS.setdefault(screen_id, set())
                    skipped_for_this_screen = []

                    while POST_BUFFER and len(batch) < batch_target:
                        candidate = POST_BUFFER.popleft()
                        cid = candidate.get("id")
                        if cid and cid not in screen_seen:
                            screen_seen.add(cid)
                            if len(screen_seen) > 1000:
                                screen_seen.clear()
                                screen_seen.add(cid)
                            batch.append(candidate)
                        else:
                            skipped_for_this_screen.append(candidate)

                    for item in reversed(skipped_for_this_screen):
                        POST_BUFFER.appendleft(item)

                    active_epoch = CACHE_EPOCH
                    now = time.time()
                    needs_background_refill = (
                        len(POST_BUFFER) < 30
                        and not IS_FETCHING
                        and now >= NEXT_ALLOWED_FETCH_TIME
                    )

                if needs_background_refill and not APP_PAUSED:
                    threading.Thread(target=fill_post_buffer, daemon=True).start()

                response_body = json.dumps(batch).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response_body)))
                self.send_header("X-Danbooru-Epoch", str(active_epoch))
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(response_body)

            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                pass
            except Exception as e:
                log_event("error", f"API dispatch error: {e}")
                try:
                    err_payload = json.dumps([]).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(err_payload)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                    pass
            return

        if path_only == "/image":
            # Feature 3: Immediately block proxy stream requests when APP_PAUSED is active
            if APP_PAUSED:
                self.send_response(503)
                self.send_header("Connection", "close")
                self.end_headers()
                return

            target_url = query_params.get("url", [None])[0]
            ext_hint = query_params.get("ext", [""])[0].lower()
            size_hint_str = query_params.get("size", ["0"])[0]

            if not target_url:
                self.send_response(400)
                self.send_header("Connection", "close")
                self.end_headers()
                return

            parsed_target = urllib.parse.urlparse(target_url)
            if parsed_target.scheme != "https" or parsed_target.hostname not in ALLOWED_MEDIA_HOSTS:
                log_event("security", f"Blocked unauthorized media host: {parsed_target.hostname}")
                self.send_response(403)
                self.send_header("Connection", "close")
                self.end_headers()
                return

            is_mp4 = ext_hint == "mp4" or parsed_target.path.lower().endswith(".mp4")

            # Feature 1: Enforce 15 MB MP4 cap before streaming or redirecting
            if is_mp4:
                try:
                    if int(size_hint_str) > MAX_MP4_FILE_SIZE_BYTES:
                        log_event("proxy", f"Filtered oversized MP4 ({size_hint_str} bytes > 15 MB): {target_url}")
                        self.send_response(413)
                        self.send_header("Connection", "close")
                        self.end_headers()
                        return
                except ValueError:
                    pass

            if CDN_DIRECT_REDIRECT_MODE:
                self.send_response(307)
                self.send_header("Location", target_url)
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.end_headers()
                return

            req_headers = dict(BASE_MEDIA_HEADERS)
            if is_mp4:
                client_range = self.headers.get("Range")
                if client_range:
                    req_headers["Range"] = client_range

            req = urllib.request.Request(target_url, headers=req_headers)
            headers_sent = False

            try:
                with SAFE_MEDIA_OPENER.open(req, timeout=20) as res:
                    status_code = getattr(res, "status", 200) or 200
                    content_type = res.headers.get(
                        "Content-Type", "video/mp4" if is_mp4 else "image/jpeg"
                    )
                    content_len_str = res.headers.get("Content-Length")
                    content_range = res.headers.get("Content-Range")

                    if "video/mp4" in content_type.lower():
                        is_mp4 = True

                    # Feature 1: Enforce max MP4 size (15 MB) on upstream Content-Length
                    if is_mp4 and content_len_str:
                        try:
                            if int(content_len_str) > MAX_MP4_FILE_SIZE_BYTES:
                                log_event(
                                    "proxy",
                                    f"Filtered oversized MP4 from proxy stream ({int(content_len_str):,} bytes > 15 MB): {target_url}"
                                )
                                self.send_response(413)
                                self.send_header("Connection", "close")
                                self.end_headers()
                                return
                        except ValueError:
                            pass

                    self.send_response(status_code)
                    self.send_header("Content-Type", content_type)
                    if content_len_str:
                        self.send_header("Content-Length", content_len_str)
                    if content_range:
                        self.send_header("Content-Range", content_range)
                    self.send_header("Accept-Ranges", "bytes")
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    headers_sent = True

                    bytes_streamed = 0
                    while True:
                        if APP_PAUSED:
                            break
                        chunk = res.read(65536)
                        if not chunk:
                            break
                        bytes_streamed += len(chunk)
                        if is_mp4 and bytes_streamed > MAX_MP4_FILE_SIZE_BYTES:
                            log_event("proxy", f"Aborted MP4 stream exceeding 15 MB cap: {target_url}")
                            break
                        self.wfile.write(chunk)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass
            except urllib.error.HTTPError as e:
                if e.code == 403 and not headers_sent:
                    with DATA_LOCK:
                        was_already_direct = CDN_DIRECT_REDIRECT_MODE
                        CDN_DIRECT_REDIRECT_MODE = True
                    if not was_already_direct:
                        log_event(
                            "proxy",
                            "CDN rejected Python urllib TLS signature (HTTP 403); routing /image "
                            "via WebView2 native Chromium TLS 1.3 redirect."
                        )
                    try:
                        self.send_response(307)
                        self.send_header("Location", target_url)
                        self.send_header("Referrer-Policy", "no-referrer")
                        self.send_header("Cache-Control", "no-store")
                        self.send_header("Connection", "close")
                        self.end_headers()
                        return
                    except Exception:
                        pass
                else:
                    log_event("proxy", f"Proxy stream HTTP error for {target_url}: {e}")
                    if not headers_sent:
                        try:
                            self.send_response(e.code if e.code else 502)
                            self.send_header("Connection", "close")
                            self.end_headers()
                        except Exception:
                            pass
            except Exception as e:
                log_event("proxy", f"Proxy stream dropped for {target_url}: {e}")
                if not headers_sent:
                    try:
                        self.send_response(502)
                        self.send_header("Connection", "close")
                        self.end_headers()
                    except Exception:
                        pass
            return

        self.send_response(404)
        self.send_header("Connection", "close")
        self.end_headers()

    def log_message(self, format, *args):
        pass


# =============================================================================
# 7. TABBED SETTINGS DIALOG (CREDENTIALS, MULTI-SCREEN DISPLAY, LOGS) & SEARCH BAR
# =============================================================================
class SettingsDialog(tk.Toplevel):
    """
    Unified tabbed settings dialog containing:
    - Tab 1: Credentials (account credentials, search bar lock/unlock, Cloudflare check, cache purge)
    - Tab 2: Display (per-screen selector, enable checkbox, dual slider + 25%-width number inputs, Fill Screen + 30s timer)
    - Tab 3: Logs (PAUSE APPLICATION master button [green/red], Clear button, smart-scrolling log history)
    """
    NUMERIC_SPECS = {
        "scrollspeed": {
            "label": "Scroll Speed (0.1 – 600 px/s):",
            "min": 0.1,
            "max": 600.0,
            "default": 120,
            "is_float": True,
            "precision": 2,
        },
        "gapsize": {
            "label": "Image Gap (0 – 64 px):",
            "min": 0,
            "max": 64,
            "default": 12,
            "is_float": False,
            "precision": 0,
        },
        "dropspeed": {
            "label": "Drop Speed (0.2 – 4.0):",
            "min": 0.2,
            "max": 4.0,
            "default": 1.0,
            "is_float": True,
            "precision": 2,
        },
        "minsize": {
            "label": "Minimum Size (120 – 600 px):",
            "min": 120,
            "max": 600,
            "default": 220,
            "is_float": False,
            "precision": 0,
        },
        "maxsize": {
            "label": "Maximum Size (150 – 900 px):",
            "min": 150,
            "max": 900,
            "default": 440,
            "is_float": False,
            "precision": 0,
        },
        "dropdelay": {
            "label": "Spawn/Drop Delay (0 – 600 s):",
            "min": 0,
            "max": 600,
            "default": 0,
            "is_float": False,
            "precision": 0,
        },
    }

    def __init__(self, parent, on_save_credentials_callback, initial_values=None):
        super().__init__(parent)
        self.on_save_credentials_callback = on_save_credentials_callback
        self.is_open = True
        self._drag_x = 0
        self._drag_y = 0
        self._fill_cooldown_remaining = 0
        self._fill_timer_job = None
        self._live_apply_job = None
        self._syncing_controls = False

        self.overrideredirect(True)
        self.attributes("-alpha", 0.97)
        self.attributes("-topmost", True)

        self.bg_base = "#f6f6f8"
        self.input_bg = "#ffffff"
        self.border_col = "#dcdce0"
        self.text_dark = "#1c1c1c"
        self.text_muted = "#5c5c5c"

        self.configure(bg=self.border_col)

        width = 600
        height = 560
        parent.update_idletasks()
        px = parent.winfo_x()
        py = parent.winfo_y()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()

        x = max(20, min(px + (parent.winfo_width() - width) // 2, sw - width - 20))
        y = max(20, min(py - height - 10 if py - height - 10 > 0 else py + 60, sh - height - 20))
        self.geometry(f"{width}x{height}+{x}+{y}")

        container = tk.Frame(self, bg=self.bg_base, highlightthickness=1, highlightbackground=self.border_col)
        container.pack(fill="both", expand=True, padx=1, pady=1)

        header = tk.Frame(container, bg=self.bg_base)
        header.pack(fill="x", padx=14, pady=(10, 6))

        title = tk.Label(
            header, text="⚙ APPLICATION SETTINGS", font=("Segoe UI", 10, "bold"),
            fg=self.text_dark, bg=self.bg_base
        )
        title.pack(side="left")

        close_btn = tk.Label(
            header, text="✕", font=("Segoe UI", 10, "bold"),
            fg=self.text_muted, bg=self.bg_base, cursor="hand2"
        )
        close_btn.pack(side="right")
        close_btn.bind("<Button-1>", lambda e: self.close_dialog())

        header.bind("<Button-1>", self.start_move)
        header.bind("<B1-Motion>", self.do_move)
        title.bind("<Button-1>", self.start_move)
        title.bind("<B1-Motion>", self.do_move)

        style = ttk.Style(self)
        try:
            style.configure("TNotebook", background=self.bg_base, borderwidth=0)
            style.configure("TNotebook.Tab", font=("Segoe UI", 9, "bold"), padding=(14, 5))
            style.configure("Display.Horizontal.TScale", background=self.bg_base)
        except Exception:
            pass

        self.notebook = ttk.Notebook(container)
        self.notebook.pack(fill="both", expand=True, padx=12, pady=(4, 12))

        self.tab_credentials = tk.Frame(self.notebook, bg=self.bg_base)
        self.tab_display = tk.Frame(self.notebook, bg=self.bg_base)
        self.tab_logs = tk.Frame(self.notebook, bg=self.bg_base)

        self.notebook.add(self.tab_credentials, text="Credentials")
        self.notebook.add(self.tab_display, text="Display")
        self.notebook.add(self.tab_logs, text="Logs")

        self._build_credentials_tab(initial_values or {})
        self._build_display_tab()
        self._build_logs_tab()

        self.bind("<Escape>", lambda e: self.close_dialog())

    # -------------------------------------------------------------------------
    # TAB 1: CREDENTIALS
    # -------------------------------------------------------------------------
    def _build_credentials_tab(self, vals):
        pad_frame = tk.Frame(self.tab_credentials, bg=self.bg_base)
        pad_frame.pack(fill="both", expand=True, padx=16, pady=14)

        sec_lbl = tk.Label(
            pad_frame, text="DANBOORU ACCOUNT CREDENTIALS",
            font=("Segoe UI", 8, "bold"), fg=self.text_muted, bg=self.bg_base
        )
        sec_lbl.pack(anchor="w", pady=(0, 8))

        self.cred_entries = {}
        fields = [
            ("USERNAME", "Username:"),
            ("USER_ID", "User ID:"),
            ("API_KEY", "API Key (DPAPI):"),
        ]

        for key, label_text in fields:
            row = tk.Frame(pad_frame, bg=self.bg_base)
            row.pack(fill="x", pady=5)

            lbl = tk.Label(
                row, text=label_text, width=16, anchor="w",
                font=("Segoe UI", 9), fg=self.text_dark, bg=self.bg_base
            )
            lbl.pack(side="left")

            entry_box = tk.Frame(row, bg=self.input_bg, highlightthickness=1, highlightbackground=self.border_col)
            entry_box.pack(side="right", fill="x", expand=True)

            entry = tk.Entry(
                entry_box, bg=self.input_bg, fg=self.text_dark, insertbackground=self.text_dark,
                bd=0, font=("Segoe UI", 9), relief="flat"
            )
            entry.pack(fill="x", padx=6, pady=4)
            if key == "API_KEY":
                entry.configure(show="•")
            if vals.get(key):
                entry.insert(0, vals[key])
            self.cred_entries[key] = entry

        sep = tk.Frame(pad_frame, bg=self.border_col, height=1)
        sep.pack(fill="x", pady=14)

        lock_row = tk.Frame(pad_frame, bg=self.bg_base)
        lock_row.pack(fill="x", pady=4)

        tk.Label(
            lock_row, text="Search Bar Position:", width=16, anchor="w",
            font=("Segoe UI", 9), fg=self.text_dark, bg=self.bg_base
        ).pack(side="left")

        is_locked_now = APP_INSTANCE.is_locked if APP_INSTANCE else False
        self.lock_btn = tk.Button(
            lock_row,
            text="🔒 Locked" if is_locked_now else "🔓 Unlocked",
            fg=self.text_dark, bg="#e8e8ed", activebackground="#dcdce0",
            bd=0, relief="flat", font=("Segoe UI Emoji", 9, "bold"), cursor="hand2",
            padx=14, pady=4, command=self.toggle_search_lock
        )
        self.lock_btn.pack(side="left")

        cf_row = tk.Frame(pad_frame, bg=self.bg_base)
        cf_row.pack(fill="x", pady=8)

        tk.Label(
            cf_row, text="Cloudflare / Cache:", width=16, anchor="w",
            font=("Segoe UI", 9), fg=self.text_dark, bg=self.bg_base
        ).pack(side="left")

        cf_btn = tk.Button(
            cf_row,
            text="🛡 Verify Human",
            fg=self.text_dark, bg="#e8e8ed", activebackground="#dcdce0",
            bd=0, relief="flat", font=("Segoe UI", 9), cursor="hand2",
            padx=10, pady=4,
            command=lambda: open_cloudflare_verification_window("Manual user verification")
        )
        cf_btn.pack(side="left", padx=(0, 8))

        purge_btn = tk.Button(
            cf_row,
            text="🧹 Purge Profile Cache",
            fg=self.text_dark, bg="#e8e8ed", activebackground="#dcdce0",
            bd=0, relief="flat", font=("Segoe UI", 9), cursor="hand2",
            padx=10, pady=4,
            command=self._on_purge_profile_cache
        )
        purge_btn.pack(side="left")

        btn_row = tk.Frame(pad_frame, bg=self.bg_base)
        btn_row.pack(fill="x", side="bottom", pady=(10, 0))

        save_cred_btn = tk.Button(
            btn_row, text="Save Credentials", bg="#0067c0", fg="#ffffff",
            activebackground="#005da6", activeforeground="#ffffff",
            font=("Segoe UI", 9, "bold"), bd=0, relief="flat",
            padx=20, pady=6, cursor="hand2", command=self.save_credentials_only
        )
        save_cred_btn.pack(side="right")

    def _on_purge_profile_cache(self):
        removed = prune_webview_profile_directory()
        log_event("config", f"Pruned {removed} non-cookie cache items from webview_profile.")

    def toggle_search_lock(self):
        if APP_INSTANCE:
            APP_INSTANCE.toggle_lock()
            self.lock_btn.configure(text="🔒 Locked" if APP_INSTANCE.is_locked else "🔓 Unlocked")

    def save_credentials_only(self):
        user = self.cred_entries["USERNAME"].get().strip()
        uid = self.cred_entries["USER_ID"].get().strip()
        key = self.cred_entries["API_KEY"].get().strip()
        self.on_save_credentials_callback(user, uid, key)

    # -------------------------------------------------------------------------
    # TAB 2: DISPLAY (MULTI-SCREEN + DUAL SLIDER/INPUT CONTROLS + LIVE PREVIEW)
    # -------------------------------------------------------------------------
    def _build_display_tab(self):
        self.prop_entries = {}
        self.prop_sliders = {}
        self.prop_vars = {}

        pad_frame = tk.Frame(self.tab_display, bg=self.bg_base)
        pad_frame.pack(fill="both", expand=True, padx=16, pady=10)

        global CONNECTED_SCREENS
        CONNECTED_SCREENS = enumerate_connected_monitors()
        self.screen_map = {s["label"]: s["id"] for s in CONNECTED_SCREENS}
        screen_labels = [s["label"] for s in CONNECTED_SCREENS]

        screen_row = tk.Frame(pad_frame, bg=self.bg_base)
        screen_row.pack(fill="x", pady=3)
        tk.Label(
            screen_row, text="Select Screen:", width=26, anchor="w",
            font=("Segoe UI", 9, "bold"), fg=self.text_dark, bg=self.bg_base
        ).pack(side="left")

        self.selected_screen_label = tk.StringVar(value=screen_labels[0])
        self.screen_combo = ttk.Combobox(
            screen_row, textvariable=self.selected_screen_label,
            values=screen_labels, state="readonly"
        )
        self.screen_combo.pack(side="right", fill="x", expand=True)
        self.screen_combo.bind("<<ComboboxSelected>>", self._on_screen_selection_changed)

        enable_row = tk.Frame(pad_frame, bg=self.bg_base)
        enable_row.pack(fill="x", pady=(4, 6))
        self.screen_enabled_var = tk.BooleanVar(value=True)
        self.screen_enable_chk = tk.Checkbutton(
            enable_row,
            text="Display wallpaper on this screen",
            variable=self.screen_enabled_var,
            bg=self.bg_base, fg=self.text_dark, activebackground=self.bg_base,
            font=("Segoe UI", 9, "bold"), cursor="hand2",
            command=self._schedule_live_apply
        )
        self.screen_enable_chk.pack(anchor="w")

        sep = tk.Frame(pad_frame, bg=self.border_col, height=1)
        sep.pack(fill="x", pady=4)

        mode_row = tk.Frame(pad_frame, bg=self.bg_base)
        mode_row.pack(fill="x", pady=3)
        tk.Label(
            mode_row, text="Display Mode:", width=26, anchor="w",
            font=("Segoe UI", 9), fg=self.text_dark, bg=self.bg_base
        ).pack(side="left")
        self.mode_var = tk.StringVar(value="scroll")
        self.mode_combo = ttk.Combobox(
            mode_row, textvariable=self.mode_var, values=["scroll", "collage"], state="readonly"
        )
        self.mode_combo.pack(side="right", fill="x", expand=True)
        self.mode_combo.bind(
            "<<ComboboxSelected>>",
            lambda e: (self._update_fill_btn_state(), self._schedule_live_apply())
        )

        # Side Scroll Settings Section
        tk.Label(
            pad_frame, text="SIDE SCROLL SETTINGS",
            font=("Segoe UI", 8, "bold"), fg=self.text_muted, bg=self.bg_base
        ).pack(anchor="w", pady=(6, 2))

        dir_row = tk.Frame(pad_frame, bg=self.bg_base)
        dir_row.pack(fill="x", pady=2)
        tk.Label(
            dir_row, text="Scroll Direction:", width=26, anchor="w",
            font=("Segoe UI", 9), fg=self.text_dark, bg=self.bg_base
        ).pack(side="left")
        self.dir_var = tk.StringVar(value="left")
        dir_combo = ttk.Combobox(
            dir_row, textvariable=self.dir_var, values=["left", "right"], state="readonly"
        )
        dir_combo.pack(side="right", fill="x", expand=True)
        dir_combo.bind("<<ComboboxSelected>>", lambda e: self._schedule_live_apply())

        for pkey in ("scrollspeed", "gapsize"):
            self._create_numeric_row(pad_frame, pkey, self.NUMERIC_SPECS[pkey])

        # Collage Settings Section
        tk.Label(
            pad_frame, text="COLLAGE SETTINGS",
            font=("Segoe UI", 8, "bold"), fg=self.text_muted, bg=self.bg_base
        ).pack(anchor="w", pady=(8, 2))

        for pkey in ("dropspeed", "minsize", "maxsize", "dropdelay"):
            self._create_numeric_row(pad_frame, pkey, self.NUMERIC_SPECS[pkey])

        # Feature 5: Fill Screen Button + 30-second Countdown Timer to the right
        fill_row = tk.Frame(pad_frame, bg=self.bg_base)
        fill_row.pack(fill="x", pady=(6, 4))

        tk.Label(
            fill_row, text="Collage Action:", width=26, anchor="w",
            font=("Segoe UI", 9), fg=self.text_dark, bg=self.bg_base
        ).pack(side="left")

        self.fill_screen_btn = tk.Button(
            fill_row, text="Fill Screen", bg="#0067c0", fg="#ffffff",
            activebackground="#005da6", activeforeground="#ffffff",
            disabledforeground="#a0a0a5",
            font=("Segoe UI", 9, "bold"), bd=0, relief="flat",
            padx=14, pady=4, cursor="hand2", command=self._on_fill_screen_clicked
        )
        self.fill_screen_btn.pack(side="left")

        self.fill_timer_lbl = tk.Label(
            fill_row, text="", font=("Segoe UI", 9, "bold"),
            fg="#d13438", bg=self.bg_base
        )
        self.fill_timer_lbl.pack(side="left", padx=(10, 0))

        btn_row = tk.Frame(pad_frame, bg=self.bg_base)
        btn_row.pack(fill="x", side="bottom", pady=(6, 0))

        save_disp_btn = tk.Button(
            btn_row, text="Save & Apply Display Settings", bg="#0067c0", fg="#ffffff",
            activebackground="#005da6", activeforeground="#ffffff",
            font=("Segoe UI", 9, "bold"), bd=0, relief="flat",
            padx=18, pady=6, cursor="hand2", command=self.save_display_settings
        )
        save_disp_btn.pack(side="right")

        self._load_screen_values_into_form(self._get_current_selected_screen_id())

    def _format_numeric_value(self, pkey, val):
        spec = self.NUMERIC_SPECS[pkey]
        if not spec["is_float"]:
            return str(int(round(float(val))))
        rounded = round(float(val), spec["precision"])
        if pkey == "scrollspeed" and rounded.is_integer():
            return str(int(rounded))
        text = f"{rounded:.{spec['precision']}f}".rstrip("0").rstrip(".")
        if pkey == "dropspeed" and "." not in text:
            text += ".0"
        return text

    def _clamp_numeric_value(self, pkey, raw_val):
        spec = self.NUMERIC_SPECS[pkey]
        clamped = max(float(spec["min"]), min(float(spec["max"]), float(raw_val)))
        if spec["is_float"]:
            res = round(clamped, spec["precision"])
            if pkey == "scrollspeed" and res.is_integer():
                return int(res)
            return res
        return int(round(clamped))

    def _create_numeric_row(self, parent_frame, pkey, spec):
        prow = tk.Frame(parent_frame, bg=self.bg_base)
        prow.pack(fill="x", pady=2)

        tk.Label(
            prow, text=spec["label"], width=26, anchor="w",
            font=("Segoe UI", 9), fg=self.text_dark, bg=self.bg_base
        ).pack(side="left")

        # Right-hand container arranged as 1:3 grid (25% compact number input + 75% inline slider)
        ctrl_container = tk.Frame(prow, bg=self.bg_base)
        ctrl_container.pack(side="right", fill="x", expand=True)
        ctrl_container.columnconfigure(0, weight=1, uniform="dual_ctrl")
        ctrl_container.columnconfigure(1, weight=3, uniform="dual_ctrl")

        pbox = tk.Frame(
            ctrl_container, bg=self.input_bg,
            highlightthickness=1, highlightbackground=self.border_col
        )
        pbox.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        pentry = tk.Entry(
            pbox, bg=self.input_bg, fg=self.text_dark,
            bd=0, width=6, font=("Segoe UI", 9), relief="flat"
        )
        pentry.pack(fill="x", padx=6, pady=2)
        pentry.insert(0, self._format_numeric_value(pkey, spec["default"]))

        slider_var = tk.DoubleVar(value=float(spec["default"]))
        slider = ttk.Scale(
            ctrl_container,
            from_=float(spec["min"]),
            to=float(spec["max"]),
            orient="horizontal",
            variable=slider_var,
            style="Display.Horizontal.TScale",
            command=lambda val, k=pkey: self._on_slider_moved(k, val),
        )
        slider.grid(row=0, column=1, sticky="ew")

        pentry.bind("<KeyRelease>", lambda e, k=pkey: self._on_entry_key_release(k, e))
        pentry.bind("<FocusOut>", lambda e, k=pkey: self._on_entry_commit(k, e))
        pentry.bind("<Return>", lambda e, k=pkey: self._on_entry_commit(k, e))

        self.prop_entries[pkey] = pentry
        self.prop_sliders[pkey] = slider
        self.prop_vars[pkey] = slider_var

    def _enforce_size_bounds(self, changed_key):
        if changed_key not in ("minsize", "maxsize"):
            return
        try:
            min_v = int(round(float(self.prop_vars["minsize"].get())))
            max_v = int(round(float(self.prop_vars["maxsize"].get())))
        except (ValueError, KeyError):
            return

        if changed_key == "minsize" and min_v > max_v:
            new_max = self._clamp_numeric_value("maxsize", min_v)
            self.prop_vars["maxsize"].set(float(new_max))
            self.prop_entries["maxsize"].delete(0, tk.END)
            self.prop_entries["maxsize"].insert(0, str(new_max))
        elif changed_key == "maxsize" and max_v < min_v:
            new_min = self._clamp_numeric_value("minsize", max_v)
            self.prop_vars["minsize"].set(float(new_min))
            self.prop_entries["minsize"].delete(0, tk.END)
            self.prop_entries["minsize"].insert(0, str(new_min))

    def _on_slider_moved(self, pkey, raw_val):
        if self._syncing_controls:
            return
        try:
            clamped = self._clamp_numeric_value(pkey, float(raw_val))
        except ValueError:
            return

        self._syncing_controls = True
        try:
            self.prop_vars[pkey].set(float(clamped))
            entry = self.prop_entries[pkey]
            entry.delete(0, tk.END)
            entry.insert(0, self._format_numeric_value(pkey, clamped))
            self._enforce_size_bounds(pkey)
        finally:
            self._syncing_controls = False

        self._schedule_live_apply()

    def _on_entry_key_release(self, pkey, event):
        if self._syncing_controls:
            return
        if event and event.keysym in (
            "Left", "Right", "Up", "Down", "Home", "End",
            "Tab", "Shift_L", "Shift_R", "Control_L", "Control_R", "Return"
        ):
            return

        raw_text = self.prop_entries[pkey].get().strip()
        if not raw_text or raw_text in ("-", ".", "-."):
            return
        try:
            typed_val = float(raw_text)
        except ValueError:
            return

        spec = self.NUMERIC_SPECS[pkey]
        slider_pos = max(float(spec["min"]), min(float(spec["max"]), typed_val))

        self._syncing_controls = True
        try:
            self.prop_vars[pkey].set(slider_pos)
        finally:
            self._syncing_controls = False

        if float(spec["min"]) <= typed_val <= float(spec["max"]):
            self._schedule_live_apply()

    def _on_entry_commit(self, pkey, event=None):
        if self._syncing_controls:
            return
        spec = self.NUMERIC_SPECS[pkey]
        raw_text = self.prop_entries[pkey].get().strip()
        try:
            parsed = float(raw_text)
        except ValueError:
            parsed = float(self.prop_vars[pkey].get() if pkey in self.prop_vars else spec["default"])

        clamped = self._clamp_numeric_value(pkey, parsed)
        self._syncing_controls = True
        try:
            self.prop_vars[pkey].set(float(clamped))
            entry = self.prop_entries[pkey]
            entry.delete(0, tk.END)
            entry.insert(0, self._format_numeric_value(pkey, clamped))
            self._enforce_size_bounds(pkey)
        finally:
            self._syncing_controls = False

        self.save_display_settings()

    def _schedule_live_apply(self):
        if self._live_apply_job is not None:
            try:
                self.after_cancel(self._live_apply_job)
            except Exception:
                pass
        self._live_apply_job = self.after(40, self._execute_live_apply)

    def _execute_live_apply(self):
        self._live_apply_job = None
        if self.is_open:
            self.save_display_settings(clamp_entries=False)

    def _get_current_selected_screen_id(self):
        lbl = self.selected_screen_label.get()
        return self.screen_map.get(lbl, "screen_1")

    def _on_screen_selection_changed(self, event=None):
        sid = self._get_current_selected_screen_id()
        self._load_screen_values_into_form(sid)

    def _load_screen_values_into_form(self, screen_id):
        sc_cfg = get_screen_config(screen_id)
        self.screen_enabled_var.set(sc_cfg["enabled"])
        props = sc_cfg["properties"]

        self.mode_var.set(props.get("displaymode", {}).get("value", "scroll"))
        self.dir_var.set(props.get("scrolldirection", {}).get("value", "left"))

        self._syncing_controls = True
        try:
            for key, spec in self.NUMERIC_SPECS.items():
                raw_val = props.get(key, {}).get("value", spec["default"])
                try:
                    clamped = self._clamp_numeric_value(key, raw_val)
                except (ValueError, TypeError):
                    clamped = spec["default"]

                entry = self.prop_entries.get(key)
                if entry:
                    entry.delete(0, tk.END)
                    entry.insert(0, self._format_numeric_value(key, clamped))
                if key in self.prop_vars:
                    self.prop_vars[key].set(float(clamped))
        finally:
            self._syncing_controls = False

        self._update_fill_btn_state()

    def _update_fill_btn_state(self):
        is_collage = (self.mode_var.get() == "collage")
        if is_collage and self._fill_cooldown_remaining <= 0:
            self.fill_screen_btn.configure(state="normal", bg="#0067c0", cursor="hand2")
        else:
            self.fill_screen_btn.configure(state="disabled", bg="#c8c8d0", cursor="arrow")

    def _on_fill_screen_clicked(self):
        if self.mode_var.get() != "collage" or self._fill_cooldown_remaining > 0:
            return
        self.save_display_settings()
        sid = self._get_current_selected_screen_id()
        trigger_fill_screen_on_webview(sid)

        self._fill_cooldown_remaining = 30
        self._update_fill_btn_state()
        self._tick_fill_cooldown()

    def _tick_fill_cooldown(self):
        if not self.is_open:
            return
        if self._fill_cooldown_remaining > 0:
            self.fill_timer_lbl.configure(text=f"{self._fill_cooldown_remaining}s")
            self._fill_cooldown_remaining -= 1
            self._fill_timer_job = self.after(1000, self._tick_fill_cooldown)
        else:
            self.fill_timer_lbl.configure(text="")
            self._update_fill_btn_state()

    def save_display_settings(self, clamp_entries=True):
        sid = self._get_current_selected_screen_id()
        project_data = load_project_json()

        base_props = project_data.setdefault("general", {}).setdefault(
            "properties", get_default_properties_dict()
        )
        screens_dict = project_data.setdefault("screens", {})
        screen_entry = screens_dict.setdefault(sid, {
            "enabled": True,
            "properties": json.loads(json.dumps(base_props)),
        })

        screen_entry["enabled"] = bool(self.screen_enabled_var.get())
        s_props = screen_entry.setdefault("properties", json.loads(json.dumps(base_props)))

        s_props.setdefault("displaymode", {})["value"] = self.mode_var.get()
        s_props.setdefault("scrolldirection", {})["value"] = self.dir_var.get()

        self._syncing_controls = True
        try:
            for key, spec in self.NUMERIC_SPECS.items():
                raw_str = self.prop_entries[key].get().strip()
                try:
                    parsed = float(raw_str)
                except ValueError:
                    parsed = float(self.prop_vars[key].get())

                clamped = self._clamp_numeric_value(key, parsed)
                s_props.setdefault(key, {})["value"] = clamped
                self.prop_vars[key].set(float(clamped))

                if clamp_entries:
                    self.prop_entries[key].delete(0, tk.END)
                    self.prop_entries[key].insert(0, self._format_numeric_value(key, clamped))
        finally:
            self._syncing_controls = False

        if sid == "screen_1":
            for k, val_obj in s_props.items():
                if k in base_props and isinstance(val_obj, dict) and "value" in val_obj:
                    base_props[k]["value"] = val_obj["value"]

        store_project_json(project_data)
        push_properties_to_webview(sid)
        self._update_fill_btn_state()

    # -------------------------------------------------------------------------
    # TAB 3: LOGS (PAUSE APPLICATION BUTTON + SMART HISTORICAL LOG SCROLLING)
    # -------------------------------------------------------------------------
    def _build_logs_tab(self):
        pad_frame = tk.Frame(self.tab_logs, bg=self.bg_base)
        pad_frame.pack(fill="both", expand=True, padx=12, pady=10)

        top_bar = tk.Frame(pad_frame, bg=self.bg_base)
        top_bar.pack(fill="x", pady=(0, 8))

        self.pause_app_btn = tk.Button(
            top_bar,
            text="PAUSE APPLICATION",
            bg="#d13438" if APP_PAUSED else "#107c10",
            fg="#ffffff",
            activebackground="#b02a2e" if APP_PAUSED else "#0e6b0e",
            activeforeground="#ffffff",
            font=("Segoe UI", 9, "bold"),
            bd=0, relief="flat", padx=16, pady=5, cursor="hand2",
            command=self.toggle_application_pause
        )
        self.pause_app_btn.pack(side="left")

        clear_btn = tk.Button(
            top_bar, text="Clear Logs", fg="#0067c0", bg="#e8e8ed",
            activebackground="#dcdce0", font=("Segoe UI", 8, "bold"),
            bd=0, relief="flat", padx=10, pady=4, cursor="hand2",
            command=self.clear_logs
        )
        clear_btn.pack(side="right")

        text_box_frame = tk.Frame(pad_frame, bg=self.input_bg, highlightthickness=1, highlightbackground=self.border_col)
        text_box_frame.pack(fill="both", expand=True)

        self.log_text = tk.Text(
            text_box_frame, bg=self.input_bg, fg=self.text_dark, wrap="word",
            font=("Consolas", 8), bd=0, relief="flat", state="disabled"
        )
        scrollbar = ttk.Scrollbar(text_box_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        self.log_text.pack(side="left", fill="both", expand=True, padx=4, pady=4)

        if LOG_HISTORY:
            self.log_text.configure(state="normal")
            self.log_text.insert(tk.END, "\n".join(LOG_HISTORY) + "\n")
            self.log_text.see(tk.END)
            self.log_text.configure(state="disabled")

    def toggle_application_pause(self):
        global APP_PAUSED
        APP_PAUSED = not APP_PAUSED
        if APP_PAUSED:
            self.pause_app_btn.configure(bg="#d13438", activebackground="#b02a2e")
            log_event("app", "Application PAUSED (display frozen, proxy streams & API calls stopped).")
        else:
            self.pause_app_btn.configure(bg="#107c10", activebackground="#0e6b0e")
            log_event("app", "Application RESUMED.")
            if len(POST_BUFFER) < 20 and not IS_FETCHING:
                threading.Thread(target=fill_post_buffer, daemon=True).start()

        push_pause_states_to_webviews()

    def append_log(self, message):
        try:
            _, bottom_fraction = self.log_text.yview()
            was_at_bottom = (bottom_fraction >= 0.99)

            self.log_text.configure(state="normal")
            self.log_text.insert(tk.END, message + "\n")
            line_count = int(self.log_text.index("end-1c").split(".")[0])
            if line_count > 500:
                self.log_text.delete("1.0", f"{line_count - 500 + 1}.0")

            if was_at_bottom:
                self.log_text.see(tk.END)
            self.log_text.configure(state="disabled")
        except tk.TclError:
            pass

    def clear_logs(self):
        LOG_HISTORY.clear()
        try:
            self.log_text.configure(state="normal")
            self.log_text.delete("1.0", tk.END)
            self.log_text.configure(state="disabled")
        except tk.TclError:
            pass

    def start_move(self, event):
        self._drag_x = event.x
        self._drag_y = event.y

    def do_move(self, event):
        x = self.winfo_x() + (event.x - self._drag_x)
        y = self.winfo_y() + (event.y - self._drag_y)
        self.geometry(f"+{x}+{y}")

    def close_dialog(self):
        self.is_open = False
        if getattr(self, "_live_apply_job", None):
            try:
                self.after_cancel(self._live_apply_job)
            except Exception:
                pass
        if self._fill_timer_job:
            try:
                self.after_cancel(self._fill_timer_job)
            except Exception:
                pass
        self.destroy()


class FloatingSearchBar:
    def __init__(self, root):
        self.root = root

        self.root.overrideredirect(True)
        self.root.attributes("-alpha", 0.92)
        self.root.attributes("-topmost", True)

        self.bar_width = 680
        self.bar_height = 48

        self.config = load_app_config()
        self.is_locked = self.config.get("locked", False)

        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()

        default_x = max(0, (screen_w - self.bar_width) // 2)
        default_y = max(0, screen_h - 100)

        initial_x = self.config.get("pos_x", default_x)
        initial_y = self.config.get("pos_y", default_y)

        initial_x = max(0, min(initial_x, screen_w - self.bar_width))
        initial_y = max(0, min(initial_y, screen_h - self.bar_height))

        self.root.geometry(f"{self.bar_width}x{self.bar_height}+{initial_x}+{initial_y}")

        self.bg_base = "#f6f6f8"
        self.input_bg = "#ffffff"
        self.border_col = "#dcdce0"
        self.text_dark = "#1c1c1c"
        self.text_muted = "#5c5c5c"

        self.root.configure(bg=self.bg_base)

        self.main_frame = tk.Frame(root, bg=self.bg_base, highlightthickness=1, highlightbackground=self.border_col)
        self.main_frame.pack(fill="both", expand=True)

        self.min_bar = tk.Frame(self.main_frame, bg="#cfcfd4", width=8, cursor="hand2")
        self.min_bar.pack(side="left", fill="y")
        self.min_bar.pack_propagate(False)

        self.min_bar.bind("<Button-1>", lambda e: self.minimize_to_tray())
        self.min_bar.bind("<Enter>", lambda e: self.min_bar.configure(bg="#0067c0"))
        self.min_bar.bind("<Leave>", lambda e: self.min_bar.configure(bg="#cfcfd4"))

        self.drag_handle = tk.Label(
            self.main_frame, text=" ✥ ", fg=self.text_muted, bg=self.bg_base,
            font=("Segoe UI", 10, "bold"), cursor="arrow" if self.is_locked else "fleur"
        )
        self.drag_handle.pack(side="left", padx=(4, 4))

        self.status_label = tk.Label(
            self.main_frame, text="● Ready", fg=self.text_muted, bg="#e8e8ed",
            font=("Segoe UI", 8, "bold"), padx=8, pady=3
        )
        self.status_label.pack(side="left", padx=(0, 6), pady=8)

        self.tag_label = tk.Label(
            self.main_frame, text="TAGS =", fg=self.text_dark, bg=self.bg_base,
            font=("Segoe UI", 9, "bold")
        )
        self.tag_label.pack(side="left", padx=(0, 4))

        # Feature 4: "PAUSE" button placed on the far right-hand side of the search bar
        self.pause_btn = tk.Button(
            self.main_frame,
            text="PAUSE",
            fg=self.text_dark,
            bg="#e8e8ed",
            activebackground="#dcdce0",
            bd=0,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
            cursor="hand2",
            padx=10,
            pady=4,
            command=self.toggle_wallpaper_pause
        )
        self.pause_btn.pack(side="right", padx=(2, 6), pady=7)

        self.refresh_btn = tk.Button(
            self.main_frame, text="⟳", fg=self.text_dark, bg=self.bg_base, activebackground="#e8e8e8",
            activeforeground="#0067c0", bd=0, relief="flat", font=("Segoe UI", 12, "bold"),
            cursor="hand2", padx=8, command=self.immediate_refresh
        )
        self.refresh_btn.pack(side="right", padx=(0, 2), pady=6)

        self.search_container = tk.Frame(self.main_frame, bg=self.input_bg, highlightthickness=1, highlightbackground=self.border_col)
        self.search_container.pack(side="left", fill="both", expand=True, padx=(0, 4), pady=7)

        self.entry = tk.Entry(
            self.search_container, bg=self.input_bg, fg=self.text_dark, insertbackground=self.text_dark,
            bd=0, font=("Segoe UI", 9), relief="flat"
        )
        self.entry.insert(0, DEFAULT_TAGS)
        self.entry.pack(side="left", fill="both", expand=True, padx=(8, 0))

        self.saved_arrow_btn = tk.Button(
            self.search_container, text="▲", fg=self.text_muted, bg="#f0f0f3",
            activebackground="#e5e5ea", activeforeground=self.text_dark, bd=0, relief="flat",
            font=("Segoe UI", 7), width=3, cursor="hand2", command=self.toggle_saved_dropdown
        )
        self.saved_arrow_btn.pack(side="right", fill="y")

        self.entry.bind("<KeyRelease>", self.on_key_release)
        self.entry.bind("<Down>", self.focus_suggestion_down)
        self.entry.bind("<Up>", self.focus_suggestion_up)
        self.entry.bind("<Return>", self.on_enter_pressed)
        self.entry.bind("<Shift-Return>", self.immediate_refresh)

        self.root.bind("<Escape>", self.on_escape)
        self.root.bind("<FocusOut>", self.on_focus_out)

        for widget in [self.drag_handle, self.tag_label, self.main_frame]:
            widget.bind("<Button-1>", self.start_move)
            widget.bind("<B1-Motion>", self.do_move)
            widget.bind("<ButtonRelease-1>", self.stop_move)

        self._drag_start_x = 0
        self._drag_start_y = 0
        self._moved = False

        self.dropdown = tk.Toplevel(self.root)
        self.dropdown.overrideredirect(True)
        self.dropdown.attributes("-alpha", 0.95)
        self.dropdown.attributes("-topmost", True)
        self.dropdown.configure(bg=self.border_col)
        self.dropdown.withdraw()

        self.suggest_labels = []
        self.suggest_items = []
        self.selected_index = -1
        self._debounce_timer = None
        self._suggest_req_id = 0

        for i in range(5):
            lbl = tk.Label(
                self.dropdown, text="", anchor="w", fg=self.text_dark, bg=self.input_bg,
                font=("Segoe UI", 9), padx=10, pady=5, cursor="hand2"
            )
            lbl.pack(fill="x", padx=1, pady=1)
            lbl.bind("<Enter>", lambda e, idx=i: self.highlight_index(idx))
            lbl.bind("<Button-1>", lambda e, idx=i: self.select_suggestion(idx))
            self.suggest_labels.append(lbl)

        self.saved_dropdown = tk.Toplevel(self.root)
        self.saved_dropdown.overrideredirect(True)
        self.saved_dropdown.attributes("-alpha", 0.95)
        self.saved_dropdown.attributes("-topmost", True)
        self.saved_dropdown.configure(bg=self.border_col)
        self.saved_dropdown.withdraw()

        self.saved_list = load_saved_searches()
        self.poll_status()

        self.root.after(200, self.check_credentials_on_startup)

    def toggle_wallpaper_pause(self):
        global WALLPAPER_PAUSED
        WALLPAPER_PAUSED = not WALLPAPER_PAUSED
        if WALLPAPER_PAUSED:
            self.pause_btn.configure(bg="#0067c0", fg="#ffffff", activebackground="#005da6")
            log_event("ui", "Wallpaper motion paused via search bar (GIFs and MP4 videos remain playing).")
        else:
            self.pause_btn.configure(bg="#e8e8ed", fg=self.text_dark, activebackground="#dcdce0")
            log_event("ui", "Wallpaper motion resumed via search bar.")
        push_pause_states_to_webviews()

    def check_credentials_on_startup(self):
        user = self.config.get("USERNAME", "")
        uid = self.config.get("USER_ID", "")
        key = self.config.get("API_KEY", "")

        apply_credentials(user, uid, key)
        if user and uid and key:
            log_event("auth", f"Loaded DPAPI-protected credentials for user '{user}' (#{uid})")
        else:
            log_event("auth", "Starting in anonymous mode (2-tag search limit).")
            self.open_settings_dialog()

        threading.Thread(target=fill_post_buffer, daemon=True).start()

    def open_settings_dialog(self):
        global SETTINGS_DIALOG_INSTANCE
        if SETTINGS_DIALOG_INSTANCE and getattr(SETTINGS_DIALOG_INSTANCE, "is_open", False):
            try:
                SETTINGS_DIALOG_INSTANCE.lift()
                return
            except tk.TclError:
                pass

        initial = {
            "USERNAME": self.config.get("USERNAME", USERNAME),
            "USER_ID": self.config.get("USER_ID", USER_ID),
            "API_KEY": self.config.get("API_KEY", API_KEY)
        }
        SETTINGS_DIALOG_INSTANCE = SettingsDialog(self.root, self.save_credentials, initial_values=initial)

    def save_credentials(self, user, uid, key):
        old_creds = (self.config.get("USERNAME", ""), self.config.get("USER_ID", ""), self.config.get("API_KEY", ""))
        new_creds = (user, uid, key)

        self.config["USERNAME"] = user
        self.config["USER_ID"] = uid
        self.config["API_KEY"] = key
        store_app_config(self.config)
        apply_credentials(user, uid, key)
        log_event("auth", f"Credentials saved to %APPDATA% for user '{user or 'anonymous'}'.")

        if old_creds != new_creds or len(POST_BUFFER) == 0:
            self.immediate_refresh()

    def minimize_to_tray(self):
        self.hide_dropdown()
        self.saved_dropdown.withdraw()
        self.root.withdraw()

    def restore_from_tray(self):
        self.root.deiconify()
        self.root.lift()

    def toggle_lock(self):
        self.is_locked = not self.is_locked
        self.drag_handle.configure(cursor="arrow" if self.is_locked else "fleur")

        self.config["pos_x"] = self.root.winfo_x()
        self.config["pos_y"] = self.root.winfo_y()
        self.config["locked"] = self.is_locked
        store_app_config(self.config)
        log_event("ui", f"Search bar lock state set to: {self.is_locked}")

    def start_move(self, event):
        if self.is_locked:
            return
        self._drag_start_x = event.x
        self._drag_start_y = event.y
        self._moved = False

    def do_move(self, event):
        if self.is_locked:
            return
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()

        target_x = self.root.winfo_pointerx() - self._drag_start_x
        target_y = self.root.winfo_pointery() - self._drag_start_y

        x = max(0, min(target_x, screen_w - self.bar_width))
        y = max(0, min(target_y, screen_h - self.bar_height))

        self.root.geometry(f"+{x}+{y}")

        self.config["pos_x"] = x
        self.config["pos_y"] = y
        self._moved = True

        self.hide_dropdown()
        self.saved_dropdown.withdraw()

    def stop_move(self, event):
        if self._moved:
            self._moved = False
            store_app_config(self.config)

    def on_focus_out(self, event):
        if event.widget == self.root:
            self.root.after(150, self._check_focus_and_hide)

    def _check_focus_and_hide(self):
        try:
            focus_widget = self.root.focus_get()
            if focus_widget is None:
                self.hide_dropdown()
                self.saved_dropdown.withdraw()
        except tk.TclError:
            pass

    def toggle_saved_dropdown(self):
        if self.saved_dropdown.winfo_viewable():
            self.saved_dropdown.withdraw()
            return
        self.hide_dropdown()
        self.render_saved_dropdown()

    def render_saved_dropdown(self):
        for widget in self.saved_dropdown.winfo_children():
            widget.destroy()

        save_btn = tk.Label(
            self.saved_dropdown, text="💾 Save Current Search", anchor="w",
            fg="#0067c0", bg="#ffffff", font=("Segoe UI", 9, "bold"),
            padx=10, pady=6, cursor="hand2"
        )
        save_btn.pack(fill="x", padx=1, pady=(1, 2))
        save_btn.bind("<Enter>", lambda e: save_btn.configure(bg="#f0f7ff"))
        save_btn.bind("<Leave>", lambda e: save_btn.configure(bg="#ffffff"))
        save_btn.bind("<Button-1>", lambda e: self.save_current_search())

        if not self.saved_list:
            empty_lbl = tk.Label(
                self.saved_dropdown, text="(No saved searches)", anchor="w",
                fg=self.text_muted, bg="#f9f9fb", font=("Segoe UI", 8, "italic"),
                padx=10, pady=5
            )
            empty_lbl.pack(fill="x", padx=1, pady=1)
        else:
            for item in self.saved_list:
                row = tk.Frame(self.saved_dropdown, bg="#ffffff")
                row.pack(fill="x", padx=1, pady=1)

                item_lbl = tk.Label(
                    row, text=item, anchor="w", fg=self.text_dark, bg="#ffffff",
                    font=("Segoe UI", 9), padx=10, pady=4, cursor="hand2"
                )
                item_lbl.pack(side="left", fill="x", expand=True)

                del_btn = tk.Label(
                    row, text=" - ", fg="#d83b01", bg="#ffffff",
                    font=("Segoe UI", 10, "bold"), padx=8, cursor="hand2"
                )
                del_btn.pack(side="right")

                item_lbl.bind("<Enter>", lambda e, r=row, d=del_btn, il=item_lbl: (r.configure(bg="#f0f0f3"), il.configure(bg="#f0f0f3"), d.configure(bg="#f0f0f3")))
                item_lbl.bind("<Leave>", lambda e, r=row, d=del_btn, il=item_lbl: (r.configure(bg="#ffffff"), il.configure(bg="#ffffff"), d.configure(bg="#ffffff")))
                item_lbl.bind("<Button-1>", lambda e, text=item: self.apply_saved_search(text))

                del_btn.bind("<Enter>", lambda e, d=del_btn: d.configure(fg="#a80000", bg="#f0f0f3"))
                del_btn.bind("<Leave>", lambda e, d=del_btn: d.configure(fg="#d83b01", bg="#ffffff"))
                del_btn.bind("<Button-1>", lambda e, text=item: self.delete_saved_search(text))

        self.root.update_idletasks()
        rx = self.search_container.winfo_rootx()
        rw = self.search_container.winfo_width()

        item_count = max(1, len(self.saved_list))
        calc_height = 36 + (item_count * 28) + 4

        if self.root.winfo_y() - calc_height - 2 < 0:
            ry = self.search_container.winfo_rooty() + self.search_container.winfo_height() + 2
        else:
            ry = self.search_container.winfo_rooty() - calc_height - 2

        self.saved_dropdown.geometry(f"{rw}x{calc_height}+{rx}+{ry}")
        self.saved_dropdown.deiconify()
        self.saved_dropdown.lift()

    def save_current_search(self):
        query = self.entry.get().strip()
        if query and query not in self.saved_list:
            self.saved_list.insert(0, query)
            store_saved_searches(self.saved_list)
            log_event("search", f"Saved query to bookmarks: '{query}'")
        self.render_saved_dropdown()

    def apply_saved_search(self, saved_tags):
        self.entry.delete(0, tk.END)
        self.entry.insert(0, saved_tags)
        self.saved_dropdown.withdraw()
        self.immediate_refresh()

    def delete_saved_search(self, target_tags):
        if target_tags in self.saved_list:
            self.saved_list.remove(target_tags)
            store_saved_searches(self.saved_list)
            log_event("search", f"Removed query from bookmarks: '{target_tags}'")
        self.render_saved_dropdown()

    def get_current_tag_fragment(self):
        cursor_pos = self.entry.index(tk.INSERT)
        text_before = self.entry.get()[:cursor_pos]
        parts = text_before.split(" ")
        return parts[-1] if parts else ""

    def on_key_release(self, event):
        if event.keysym in ("Up", "Down", "Return", "Shift_L", "Shift_R", "Escape", "Left", "Right"):
            return

        if self._debounce_timer:
            self.root.after_cancel(self._debounce_timer)

        fragment = self.get_current_tag_fragment().strip()
        if len(fragment) < 2:
            self.hide_dropdown()
            return

        self._suggest_req_id += 1
        current_req = self._suggest_req_id
        self._debounce_timer = self.root.after(450, lambda: self.request_suggestions(fragment, current_req))

    def request_suggestions(self, fragment, req_id):
        while not SUGGESTION_QUEUE.empty():
            try:
                SUGGESTION_QUEUE.get_nowait()
            except Empty:
                break
        SUGGESTION_QUEUE.put((fragment, req_id))

    def display_suggestions(self, results, req_id):
        if req_id != self._suggest_req_id:
            return

        self.suggest_items = results
        self.selected_index = -1

        if not results:
            self.hide_dropdown()
            return

        self.saved_dropdown.withdraw()
        self.root.update_idletasks()
        rx = self.entry.winfo_rootx()
        rw = self.entry.winfo_width()

        for i in range(5):
            if i < len(results):
                tag_name, count = results[i]
                count_str = f"({count:,})" if count else ""
                self.suggest_labels[i].configure(
                    text=f"{tag_name}  {count_str}",
                    bg=self.input_bg,
                    fg=self.text_dark
                )
                self.suggest_labels[i].pack(fill="x", padx=1, pady=1)
            else:
                self.suggest_labels[i].pack_forget()

        calc_height = len(results) * 28 + 4
        if self.root.winfo_y() - calc_height - 2 < 0:
            ry = self.entry.winfo_rooty() + self.entry.winfo_height() + 2
        else:
            ry = self.entry.winfo_rooty() - calc_height - 2

        self.dropdown.geometry(f"{rw}x{calc_height}+{rx}+{ry}")
        self.dropdown.deiconify()
        self.dropdown.lift()

    def hide_dropdown(self):
        self.dropdown.withdraw()
        self.selected_index = -1

    def highlight_index(self, index):
        self.selected_index = index
        for i, lbl in enumerate(self.suggest_labels):
            if i == index:
                lbl.configure(bg="#f0f7ff", fg="#0067c0")
            else:
                lbl.configure(bg=self.input_bg, fg=self.text_dark)

    def focus_suggestion_down(self, event):
        if not self.suggest_items or not self.dropdown.winfo_viewable():
            return
        new_idx = self.selected_index + 1
        if new_idx >= len(self.suggest_items):
            new_idx = 0
        self.highlight_index(new_idx)
        return "break"

    def focus_suggestion_up(self, event):
        if not self.suggest_items or not self.dropdown.winfo_viewable():
            return
        new_idx = self.selected_index - 1
        if new_idx < 0:
            new_idx = len(self.suggest_items) - 1
        self.highlight_index(new_idx)
        return "break"

    def select_suggestion(self, index):
        if index < 0 or index >= len(self.suggest_items):
            return
        chosen_tag, _ = self.suggest_items[index]

        cursor_pos = self.entry.index(tk.INSERT)
        full_text = self.entry.get()
        before_cursor = full_text[:cursor_pos]
        after_cursor = full_text[cursor_pos:]

        words = before_cursor.split(" ")
        words[-1] = chosen_tag
        new_before = " ".join(words) + " "

        self.entry.delete(0, tk.END)
        self.entry.insert(0, new_before + after_cursor)
        self.entry.icursor(len(new_before))
        self.hide_dropdown()

    def on_enter_pressed(self, event):
        if self.dropdown.winfo_viewable() and self.selected_index >= 0:
            self.select_suggestion(self.selected_index)
            return "break"

        self.hide_dropdown()
        self.saved_dropdown.withdraw()
        self.enqueue_search()
        return "break"

    def on_escape(self, event):
        if self.saved_dropdown.winfo_viewable():
            self.saved_dropdown.withdraw()
        elif self.dropdown.winfo_viewable():
            self.hide_dropdown()
        else:
            self.minimize_to_tray()

    def enqueue_search(self, event=None):
        if self._debounce_timer:
            self.root.after_cancel(self._debounce_timer)
            self._debounce_timer = None
        self._suggest_req_id += 1
        self.hide_dropdown()
        self.saved_dropdown.withdraw()
        query = self.entry.get().strip()
        if query:
            with DATA_LOCK:
                PENDING_TAG_QUEUE.append(query)
            log_event("search", f"Queued tags: '{query}'")
            self.entry.configure(bg="#e8f0fe")
            self.root.after(150, lambda: self.entry.configure(bg=self.input_bg))

    def immediate_refresh(self, event=None):
        global CURRENT_TAGS, CURRENT_PAGE, CACHE_EPOCH
        global CONSECUTIVE_FAILURES, CONSECUTIVE_EMPTY_PAGES, NEXT_ALLOWED_FETCH_TIME

        if self._debounce_timer:
            self.root.after_cancel(self._debounce_timer)
            self._debounce_timer = None
        self._suggest_req_id += 1

        self.hide_dropdown()
        self.saved_dropdown.withdraw()
        query = self.entry.get().strip()
        if not query:
            return

        with DATA_LOCK:
            CURRENT_TAGS = query
            CURRENT_PAGE = 1
            CACHE_EPOCH += 1
            CONSECUTIVE_FAILURES = 0
            CONSECUTIVE_EMPTY_PAGES = 0
            NEXT_ALLOWED_FETCH_TIME = 0.0
            PENDING_TAG_QUEUE.clear()
            POST_BUFFER.clear()
            SEEN_POST_IDS.clear()
            SEEN_POST_ORDER.clear()
            SCREEN_SEEN_IDS.clear()
            should_spawn_worker = not IS_FETCHING and not APP_PAUSED

        log_event("refresh", f"Immediate refresh triggered. Epoch: {CACHE_EPOCH} | Tags: '{query}'")

        self.refresh_btn.configure(fg="#0067c0")
        self.entry.configure(bg="#e8f0fe")
        self.root.after(200, lambda: (
            self.refresh_btn.configure(fg=self.text_dark),
            self.entry.configure(bg=self.input_bg)
        ))

        if should_spawn_worker:
            threading.Thread(target=fill_post_buffer, daemon=True).start()

    def poll_status(self):
        if not IS_RUNNING:
            return

        with DATA_LOCK:
            status_data = dict(LAST_STATUS)

        status = status_data.get("status")
        try:
            if APP_PAUSED:
                self.status_label.configure(
                    text="⏸ App Paused",
                    fg="#a80000",
                    bg="#fde7e9"
                )
            elif status == "ok":
                page = status_data.get("page", 1)
                count = status_data.get("count", 0)
                self.status_label.configure(
                    text=f"✔ P:{page} ({count} items)",
                    fg="#0f7b0f",
                    bg="#dff6dd"
                )
            elif status == "error":
                self.status_label.configure(
                    text="✖ Error",
                    fg="#a80000",
                    bg="#fde7e9"
                )

            if IS_RUNNING:
                self.root.after(500, self.poll_status)
        except tk.TclError:
            pass


# =============================================================================
# 8. SYSTEM TRAY, TKINTER THREAD & MULTI-SCREEN PYWEBVIEW LIFECYCLE
# =============================================================================
def on_tray_show(icon=None, item=None):
    if APP_INSTANCE and TK_ROOT:
        TK_ROOT.after(0, APP_INSTANCE.restore_from_tray)


def on_tray_settings(icon=None, item=None):
    if APP_INSTANCE and TK_ROOT:
        TK_ROOT.after(0, APP_INSTANCE.open_settings_dialog)


def shutdown_app(icon=None, item=None):
    global IS_RUNNING
    if not IS_RUNNING:
        return
    IS_RUNNING = False
    log_event("app", "Shutting down application...")

    if TRAY_ICON:
        try:
            TRAY_ICON.stop()
        except Exception:
            pass
    if TK_ROOT:
        try:
            TK_ROOT.after(0, TK_ROOT.destroy)
        except Exception:
            pass
    if HTTP_SERVER:
        try:
            HTTP_SERVER.server_close()
        except Exception:
            pass
    for win in list(WEBVIEW_WINDOWS.values()):
        try:
            win.destroy()
        except Exception:
            pass

    prune_webview_profile_directory()
    os._exit(0)


def setup_tray():
    global TRAY_ICON
    box_icon = create_cardboard_box_icon()
    menu = pystray.Menu(
        pystray.MenuItem("Show Search Bar", on_tray_show, default=True),
        pystray.MenuItem("Settings", on_tray_settings),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Exit", shutdown_app)
    )
    TRAY_ICON = pystray.Icon("DanbooruService", box_icon, "Danbooru Wallpaper Service", menu)
    TRAY_ICON.run()


def run_tkinter_ui():
    global TK_ROOT, APP_INSTANCE
    TK_ROOT = tk.Tk()
    apply_app_icon(TK_ROOT)
    APP_INSTANCE = FloatingSearchBar(TK_ROOT)
    try:
        TK_ROOT.mainloop()
    except Exception as e:
        log_event("ui", f"Tkinter loop exited: {e}")


def inject_and_sync_screen(screen_info, window, win_title):
    sid = screen_info["id"]
    with INJECTION_LOCK:
        if sid in DESKTOP_INJECTED_SET:
            return
        DESKTOP_INJECTED_SET.add(sid)

    hwnd = attach_window_to_desktop(
        window,
        win_title,
        mon_x=screen_info["x"],
        mon_y=screen_info["y"],
        mon_w=screen_info["width"],
        mon_h=screen_info["height"],
    )
    if hwnd:
        with INJECTION_LOCK:
            DESKTOP_HWNDS[sid] = hwnd
    else:
        with INJECTION_LOCK:
            DESKTOP_INJECTED_SET.discard(sid)
        return

    push_properties_to_webview(sid)
    push_pause_states_to_webviews()


def on_webview_started():
    for screen_info in CONNECTED_SCREENS:
        sid = screen_info["id"]
        win = WEBVIEW_WINDOWS.get(sid)
        win_title = f"{WEBVIEW_WINDOW_TITLE_PREFIX}_{sid}"
        if win:
            win.events.loaded += (
                lambda s=screen_info, w=win, t=win_title: threading.Thread(
                    target=inject_and_sync_screen, args=(s, w, t), daemon=True
                ).start()
            )
    time.sleep(2.0)
    for screen_info in CONNECTED_SCREENS:
        sid = screen_info["id"]
        if sid not in DESKTOP_INJECTED_SET and sid in WEBVIEW_WINDOWS:
            win_title = f"{WEBVIEW_WINDOW_TITLE_PREFIX}_{sid}"
            inject_and_sync_screen(screen_info, WEBVIEW_WINDOWS[sid], win_title)

    # Final pass once all monitors are attached to ensure WorkerW sits at HWND_BOTTOM behind all screens
    sync_all_screens_z_order_and_geometry()


if __name__ == "__main__":
    HTTP_SERVER = ReusableThreadingHTTPServer(("127.0.0.1", PORT), ProxyHandler)
    server_thread = threading.Thread(target=HTTP_SERVER.serve_forever, daemon=True)
    server_thread.start()
    log_event("server", f"Service running on http://127.0.0.1:{PORT}")

    suggestion_thread = threading.Thread(target=suggestion_worker_loop, daemon=True)
    suggestion_thread.start()

    tray_thread = threading.Thread(target=setup_tray, daemon=True)
    tray_thread.start()

    tk_thread = threading.Thread(target=run_tkinter_ui, daemon=True)
    tk_thread.start()

    CONNECTED_SCREENS = enumerate_connected_monitors()
    for screen_info in CONNECTED_SCREENS:
        sid = screen_info["id"]
        win_title = f"{WEBVIEW_WINDOW_TITLE_PREFIX}_{sid}"
        win = webview.create_window(
            title=win_title,
            url=f"http://127.0.0.1:{PORT}/?screen={sid}",
            x=screen_info["x"],
            y=screen_info["y"],
            width=screen_info["width"],
            height=screen_info["height"],
            frameless=True,
            easy_drag=False,
            background_color="#0b0b0d",
        )
        WEBVIEW_WINDOWS[sid] = win

    try:
        webview.start(
            on_webview_started,
            debug=False,
            private_mode=False,
            storage_path=WEBVIEW_PROFILE_DIR,
        )
    except KeyboardInterrupt:
        pass
    finally:
        shutdown_app()