"""uiaunlock.w32 —— Win32 API 的薄封装层。

设计原则（很重要，踩过的坑都写在这里）：

1. **只做薄封装**：一个函数基本对应一个 Win32 API，不做业务判断，
   这样上层（probe/report/provider）出错时容易判断是 API 用错还是逻辑错。
2. **所有句柄一律 ``restype = c_void_p``**：HANDLE / HMODULE / HWND 在 64 位下是 8 字节，
   如果按 ctypes 默认的 ``c_int`` 返回，会被截断成 32 位（负数/野指针），
   之后再传给别的 API 就会得到 "参数错误 (87)" 或直接崩。这是最常见的坑。
3. **所有 argtypes 显式声明**：不做隐式转换。特别是 LPARAM 要带符号
   （WM_GETOBJECT 的 lParam 可能是 -4 / -25，负值必须原样传给窗口）。
4. 出错一律抛 :class:`W32Error`，并带上 Win32 错误码和可读提示，
   避免上层只拿到一个 "False" 不知道是权限问题还是对象不存在。

本模块只在 Windows 上可用；导入即检查平台。
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

if os.name != "nt":  # pragma: no cover - 目标平台是 Windows
    raise ImportError("uiaunlock 仅支持 Windows（需要 user32/psapi/oleacc）")

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
version_dll = ctypes.WinDLL("version", use_last_error=True)

# ---------------------------------------------------------------- 常量

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_CREATE_THREAD = 0x0002
PROCESS_SYNCHRONIZE = 0x00100000

LIST_MODULES_ALL = 0x0003

SMTO_BLOCK = 0x0001
SMTO_ABORTIFHUNG = 0x0002

SW_HIDE = 0
SW_SHOW = 5
SW_MINIMIZE = 6
SW_RESTORE = 9

SPI_GETSCREENREADER = 0x0046

TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260
STILL_ACTIVE = 259


# ---------------------------------------------------------------- 异常


class W32Error(RuntimeError):
    """Win32 调用失败。

    ``code`` 是 GetLastError 的返回值；``hint`` 是给人类看的下一步建议。
    """

    def __init__(self, message: str, code: Optional[int] = None, hint: str = "") -> None:
        self.code = code
        self.hint = hint
        super().__init__(self._format(message))

    def _format(self, message: str) -> str:
        if self.code is None:
            return message
        text = f"{message} (WinError {self.code})"
        if self.hint:
            text += f"；提示：{self.hint}"
        return text


def _err(code: Optional[int] = None) -> int:
    """取 Win32 错误码；ctypes 的 use_last_error 保证拿到的是本线程最后一次错误。"""
    return ctypes.get_last_error() if code is None else code


# ---------------------------------------------------------------- 签名

kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.OpenProcess.restype = ctypes.c_void_p  # 关键：不能用默认 c_int
kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
kernel32.CloseHandle.restype = wt.BOOL
kernel32.IsWow64Process.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.BOOL)]
kernel32.IsWow64Process.restype = wt.BOOL
kernel32.QueryFullProcessImageNameW.argtypes = [
    ctypes.c_void_p, wt.DWORD, ctypes.c_wchar_p, ctypes.POINTER(wt.DWORD)
]
kernel32.QueryFullProcessImageNameW.restype = wt.BOOL
kernel32.ReadProcessMemory.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wt.BOOL
kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
kernel32.Process32FirstW.restype = wt.BOOL
kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
kernel32.Process32NextW.restype = wt.BOOL

psapi.EnumProcessModulesEx.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), wt.DWORD,
    ctypes.POINTER(wt.DWORD), wt.DWORD,
]
psapi.EnumProcessModulesEx.restype = wt.BOOL
psapi.GetModuleBaseNameW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, wt.DWORD]
psapi.GetModuleBaseNameW.restype = wt.DWORD
psapi.GetModuleFileNameExW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, wt.DWORD]
psapi.GetModuleFileNameExW.restype = wt.DWORD


class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", wt.DWORD),
        ("EntryPoint", ctypes.c_void_p),
    ]


psapi.GetModuleInformation.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(MODULEINFO), wt.DWORD
]
psapi.GetModuleInformation.restype = wt.BOOL

user32.EnumWindows.argtypes = [ctypes.c_void_p, wt.LPARAM]
user32.EnumWindows.restype = wt.BOOL
user32.GetWindow.argtypes = [wt.HWND, wt.UINT]
user32.GetWindow.restype = wt.HWND
_GetWindowLongPtr = getattr(user32, "GetWindowLongPtrW", user32.GetWindowLongW)
_GetWindowLongPtr.argtypes = [wt.HWND, wt.INT]
_GetWindowLongPtr.restype = ctypes.c_ssize_t
user32.GetClassNameW.argtypes = [wt.HWND, ctypes.c_wchar_p, wt.INT]
user32.GetClassNameW.restype = wt.INT
user32.GetWindowTextW.argtypes = [wt.HWND, ctypes.c_wchar_p, wt.INT]
user32.GetWindowTextW.restype = wt.INT
user32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
user32.GetWindowThreadProcessId.restype = wt.DWORD
user32.IsWindowVisible.argtypes = [wt.HWND]
user32.IsWindowVisible.restype = wt.BOOL
user32.IsIconic.argtypes = [wt.HWND]
user32.IsIconic.restype = wt.BOOL
user32.IsWindow.argtypes = [wt.HWND]
user32.IsWindow.restype = wt.BOOL
user32.ShowWindow.argtypes = [wt.HWND, wt.INT]
user32.ShowWindow.restype = wt.BOOL
user32.GetWindowRect.argtypes = [wt.HWND, ctypes.POINTER(wt.RECT)]
user32.GetWindowRect.restype = wt.BOOL
user32.SendMessageTimeoutW.argtypes = [
    wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM, wt.UINT, wt.UINT,
    ctypes.POINTER(ctypes.c_ssize_t),
]
user32.SendMessageTimeoutW.restype = ctypes.c_ssize_t  # LRESULT，带符号
user32.SystemParametersInfoW.argtypes = [wt.UINT, wt.UINT, ctypes.c_void_p, wt.UINT]
user32.SystemParametersInfoW.restype = wt.BOOL

shell32.IsUserAnAdmin.argtypes = []
shell32.IsUserAnAdmin.restype = wt.BOOL

version_dll.GetFileVersionInfoSizeW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(wt.DWORD)]
version_dll.GetFileVersionInfoSizeW.restype = wt.DWORD
version_dll.GetFileVersionInfoW.argtypes = [
    ctypes.c_wchar_p, wt.DWORD, wt.DWORD, ctypes.c_void_p
]
version_dll.GetFileVersionInfoW.restype = wt.BOOL
version_dll.VerQueryValueW.argtypes = [
    ctypes.c_void_p, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(wt.UINT),
]
version_dll.VerQueryValueW.restype = wt.BOOL


# ---------------------------------------------------------------- 数据结构


@dataclass
class ModuleInfo:
    """一个已加载模块的信息。``base`` 是加载基址（运行时地址），``size`` 是镜像大小。"""

    name: str
    path: str
    base: int
    size: int = 0

    @property
    def lower(self) -> str:
        return self.name.lower()


@dataclass
class WindowInfo:
    hwnd: int
    pid: int
    class_name: str
    title: str
    visible: bool
    iconic: bool

    def __str__(self) -> str:
        return (
            f"hwnd=0x{self.hwnd:X} pid={self.pid} class={self.class_name!r} "
            f"title={self.title!r} visible={self.visible} iconic={self.iconic}"
        )


# ---------------------------------------------------------------- 进程 / 权限


def host_bitness() -> int:
    """当前 Python 解释器位数（32/64）。"""
    return 64 if ctypes.sizeof(ctypes.c_void_p) == 8 else 32


def open_process(pid: int, access: int = 0) -> int:
    """打开进程，返回句柄（int 值）。调用方负责 :func:`close_handle`。

    默认权限包含查询与读内存；要做远程线程调用时，调用方传入
    ``PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION`` 等。
    """
    if access == 0:
        access = (
            PROCESS_QUERY_INFORMATION
            | PROCESS_VM_READ
            | PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE
        )
    handle = kernel32.OpenProcess(access, False, int(pid))
    if not handle:
        code = _err()
        hint = ""
        if code == 5:
            hint = "权限不足：尝试以管理员身份运行，或确认没有被安全软件拦截"
        elif code == 87:
            hint = "参数错误：pid 是否有效？进程是否已退出？"
        raise W32Error(f"OpenProcess(pid={pid}) 失败", code, hint)
    return int(handle)


def close_handle(handle: int) -> None:
    if handle:
        kernel32.CloseHandle(ctypes.c_void_p(int(handle)))


class ProcessHandle:
    """``with ProcessHandle(pid) as h: ...`` 形式的上下文管理器，保证句柄关闭。"""

    def __init__(self, pid: int, access: int = 0) -> None:
        self.pid = int(pid)
        self.access = access
        self.handle = 0

    def __enter__(self) -> int:
        self.handle = open_process(self.pid, self.access)
        return self.handle

    def __exit__(self, *exc_info) -> None:
        close_handle(self.handle)
        self.handle = 0


def _is_wow64_handle(handle: int) -> bool:
    """句柄层面判断是否 WOW64（32 位进程跑在 64 位系统上）。

    32 位宿主上 IsWow64Process 恒为 False —— 那种情况下"位数"就是 32。
    """
    if host_bitness() == 32:
        return False
    wow64 = wt.BOOL()
    ok = kernel32.IsWow64Process(ctypes.c_void_p(int(handle)), ctypes.byref(wow64))
    if not ok:
        # 权限不足时保守地当作 64 位；真正的处理在 process_bitness 里
        raise W32Error("IsWow64Process 失败", _err(), "通常是 OpenProcess 权限不足")
    return bool(wow64.value)


def process_bitness(pid: int) -> int:
    """返回目标进程位数（32 或 64）。"""
    with ProcessHandle(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION) as h:
        return 32 if _is_wow64_handle(h) else (64 if host_bitness() == 64 else 32)


def process_image_path(pid: int) -> str:
    """取进程的可执行文件全路径（PROCESS_QUERY_LIMITED_INFORMATION 就够，普通用户可用）。"""
    with ProcessHandle(pid, PROCESS_QUERY_LIMITED_INFORMATION) as h:
        size = wt.DWORD(1024)
        buf = ctypes.create_unicode_buffer(1024)
        if not kernel32.QueryFullProcessImageNameW(
            ctypes.c_void_p(h), 0, buf, ctypes.byref(size)
        ):
            raise W32Error(f"QueryFullProcessImageNameW(pid={pid}) 失败", _err())
        return buf.value


# ---------------------------------------------------------------- Toolhelp 枚举


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),  # ULONG_PTR，64 位下 8 字节
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", wt.LONG),
        ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_wchar * MAX_PATH),
    ]


def iter_processes() -> Iterable[Tuple[int, str]]:
    """遍历 (pid, exe 文件名)。用 Toolhelp 快照，不需要任何进程权限。"""
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or int(snap) == -1:
        raise W32Error("CreateToolhelp32Snapshot 失败", _err())
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(ctypes.c_void_p(int(snap)), ctypes.byref(entry))
        while ok:
            yield int(entry.th32ProcessID), entry.szExeFile
            ok = kernel32.Process32NextW(ctypes.c_void_p(int(snap)), ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(int(snap)))


def find_pids_by_exe(exe: str) -> List[int]:
    """按 exe 路径或文件名找 pid。

    - 传 ``C:\\...\\WXWork.exe``：逐个比较完整路径（大小写不敏感）。
    - 传 ``WXWork.exe``：只比较文件名（更快，也不会因为路径权限失败）。
    """
    want_full = os.path.isabs(exe) or ("\\" in exe or "/" in exe)
    name = os.path.basename(exe).lower()
    result: List[int] = []
    for pid, exe_name in iter_processes():
        if exe_name.lower() != name:
            continue
        if want_full:
            try:
                actual = process_image_path(pid)
            except W32Error:
                continue
            if os.path.normcase(os.path.abspath(actual)) != os.path.normcase(os.path.abspath(exe)):
                continue
        result.append(pid)
    return result


# ---------------------------------------------------------------- 模块


def enum_modules(pid: int, include_32bit: bool = True) -> List[ModuleInfo]:
    """枚举目标进程已加载模块。

    **位数坑（务必注意）**：64 位宿主枚举 32 位进程时，必须使用
    ``LIST_MODULES_ALL``，否则只能枚举到 64 位的模块（几乎为空）。
    另外 32 位进程的模块基址都在 ``< 0x7FFF0000``；如果发现基址落在
    64 位地址空间，通常说明枚举参数用错或拿错了进程。
    """
    with ProcessHandle(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) as h:
        capacity = 4096
        while True:
            arr = (ctypes.c_void_p * capacity)()
            need = wt.DWORD(0)
            flags = LIST_MODULES_ALL if include_32bit else 0x0001  # 0x1 = LIST_MODULES_64BIT
            ok = psapi.EnumProcessModulesEx(
                ctypes.c_void_p(h), arr, ctypes.sizeof(arr), ctypes.byref(need), flags
            )
            if not ok:
                code = _err()
                hint = "权限不足或进程已退出" if code == 5 else ""
                raise W32Error(f"EnumProcessModulesEx(pid={pid}) 失败", code, hint)
            count = need.value // ctypes.sizeof(ctypes.c_void_p)
            if count <= capacity:
                break
            capacity = count + 64  # 模块数量比预估多，扩容重来

        out: List[ModuleInfo] = []
        for i in range(count):
            base = int(arr[i] or 0)
            if base == 0:
                continue
            name_buf = ctypes.create_unicode_buffer(1024)
            path_buf = ctypes.create_unicode_buffer(2048)
            psapi.GetModuleBaseNameW(ctypes.c_void_p(h), ctypes.c_void_p(base), name_buf, 1024)
            psapi.GetModuleFileNameExW(ctypes.c_void_p(h), ctypes.c_void_p(base), path_buf, 2048)
            info = MODULEINFO()
            size = 0
            if psapi.GetModuleInformation(
                ctypes.c_void_p(h), ctypes.c_void_p(base), ctypes.byref(info),
                ctypes.sizeof(MODULEINFO),
            ):
                size = int(info.SizeOfImage)
            out.append(
                ModuleInfo(name=name_buf.value, path=path_buf.value, base=base, size=size)
            )
        return out


def find_module(pid: int, name: str) -> Optional[ModuleInfo]:
    """按模块名（不区分大小写）查找已加载模块，找不到返回 None。"""
    target = name.lower()
    for m in enum_modules(pid):
        if m.name.lower() == target:
            return m
    return None


def modules_matching(pid: int, prefixes: Iterable[str]) -> List[ModuleInfo]:
    """按前缀匹配模块名，例如 ``["qt5", "qt6"]``。"""
    lows = [p.lower() for p in prefixes]
    return [m for m in enum_modules(pid) if any(m.name.lower().startswith(p) for p in lows)]


# ---------------------------------------------------------------- 窗口


def get_window_pid(hwnd: int) -> int:
    pid = wt.DWORD(0)
    user32.GetWindowThreadProcessId(wt.HWND(hwnd), ctypes.byref(pid))
    return int(pid.value)


def get_class_name(hwnd: int) -> str:
    buf = ctypes.create_unicode_buffer(512)
    if not user32.GetClassNameW(wt.HWND(hwnd), buf, 512):
        return ""
    return buf.value


def get_window_text(hwnd: int) -> str:
    buf = ctypes.create_unicode_buffer(1024)
    if not user32.GetWindowTextW(wt.HWND(hwnd), buf, 1024):
        return ""
    return buf.value


def is_window_visible(hwnd: int) -> bool:
    return bool(user32.IsWindowVisible(wt.HWND(hwnd)))


def is_window_iconic(hwnd: int) -> bool:
    return bool(user32.IsIconic(wt.HWND(hwnd)))


def is_window(hwnd: int) -> bool:
    return bool(user32.IsWindow(wt.HWND(hwnd)))


def window_rect(hwnd: int) -> Tuple[int, int, int, int]:
    """返回 (left, top, right, bottom)；失败返回全 0。"""
    rect = wt.RECT()
    if not user32.GetWindowRect(wt.HWND(hwnd), ctypes.byref(rect)):
        return (0, 0, 0, 0)
    return (rect.left, rect.top, rect.right, rect.bottom)


def window_state(hwnd: int) -> Dict[str, object]:
    left, top, right, bottom = window_rect(hwnd)
    return {
        "hwnd": hwnd,
        "hwnd_hex": f"0x{hwnd:X}",
        "class": get_class_name(hwnd),
        "title": get_window_text(hwnd),
        "visible": is_window_visible(hwnd),
        "iconic": is_window_iconic(hwnd),
        "rect": [left, top, right, bottom],
        "width": max(0, right - left),
        "height": max(0, bottom - top),
    }


_WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)


def enum_windows(
    pid: Optional[int] = None,
    class_name: Optional[str] = None,
    visible_only: bool = False,
) -> List[WindowInfo]:
    """枚举顶层窗口，可按 pid / 类名过滤。

    注意：EnumWindows 只返回顶层窗口；自绘框架（DuiLib/Qt）的控件不是 HWND，
    所以这里看不到它们 —— 这正是需要 UIA/MSAA 的原因。
    """
    result: List[WindowInfo] = []

    def _cb(hwnd, _lparam):
        h = int(hwnd)
        if visible_only and not is_window_visible(h):
            return True
        cls = get_class_name(h)
        if class_name is not None and cls != class_name:
            return True
        wpid = get_window_pid(h)
        if pid is not None and wpid != int(pid):
            return True
        result.append(
            WindowInfo(
                hwnd=h,
                pid=wpid,
                class_name=cls,
                title=get_window_text(h),
                visible=is_window_visible(h),
                iconic=is_window_iconic(h),
            )
        )
        return True

    user32.EnumWindows(_WNDENUMPROC(_cb), 0)
    return result


def window_ex_style(hwnd: int) -> int:
    """取扩展窗口样式（GWL_EXSTYLE）。WS_EX_TOOLWINDOW=0x80 的窗口通常不是主窗口。"""
    return int(_GetWindowLongPtr(wt.HWND(hwnd), -20) or 0)


def window_owner(hwnd: int) -> int:
    """取 owner 窗口（GW_OWNER=4）。非 0 说明它是别人的对话框/弹出窗。"""
    owner = user32.GetWindow(wt.HWND(hwnd), 4)
    return int(owner or 0)


def find_main_window(pid: int) -> int:
    """在目标进程里挑一个"最像主窗口"的顶层窗口，返回 hwnd（找不到返回 0）。

    打分规则（踩过坑之后的版本）：
    - 面积为 0 的窗口直接排除（IME、MSCTFIME、消息窗都是 0x0）；
    - 有标题 +1e7：企业微信主窗口标题是 "企业微信"；
    - 可见 +1e6；
    - **无 owner** +1e8：主窗口通常不被别人拥有，对话框/弹出面板有 owner；
    - 面积作为主要量纲。

    为什么不能只挑"可见窗口"：企业微信的主窗口在搜索面板打开、或用户点了托盘图标时
    可能被临时隐藏（IsWindowVisible=False），此时唯一"可见"的窗口是 1x1 的
    WedocHostWindow —— 只按可见性挑就会扫错对象（本库实测踩过这个坑）。
    """
    best = 0
    best_score = -1
    for w in enum_windows(pid=pid):
        left, top, right, bottom = window_rect(w.hwnd)
        area = max(0, right - left) * max(0, bottom - top)
        if area <= 0:
            continue
        if window_ex_style(w.hwnd) & 0x00000080:  # WS_EX_TOOLWINDOW
            continue
        score = area
        if w.title:
            score += 10_000_000
        if w.visible:
            score += 1_000_000
        if not window_owner(w.hwnd):
            score += 100_000_000
        if score > best_score:
            best_score = score
            best = w.hwnd
    return best


def ensure_window_visible(hwnd: int, settle: float = 0.6) -> Dict[str, object]:
    """保证窗口处于"可测"状态：最小化则还原，隐藏则显示。

    为什么必须做：UIA 客户端对最小化/隐藏窗口通常只返回一个根节点，
    会把"窗口没显示"误判成"应用没有无障碍树"，这是最常见的假阳性。
    """
    changed = False
    if is_window_iconic(hwnd):
        user32.ShowWindow(wt.HWND(hwnd), SW_RESTORE)
        changed = True
    elif not is_window_visible(hwnd):
        user32.ShowWindow(wt.HWND(hwnd), SW_SHOW)
        changed = True
    if changed:
        time.sleep(settle)
    return {"changed": changed, "state": window_state(hwnd)}


# ---------------------------------------------------------------- 消息


def send_message_timeout(
    hwnd: int, msg: int, wparam: int = 0, lparam: int = 0, timeout_ms: int = 2000
) -> Tuple[bool, int]:
    """同步发消息（带超时），返回 ``(是否成功, LRESULT)``。

    用 SendMessageTimeout 而不是 SendMessage：目标进程若卡死，
    SendMessage 会把我们自己也挂住；超时后返回 False + lresult=0。

    lParam 用有符号 LPARAM：WM_GETOBJECT 里传的是 -4 / -25 这种负值，
    如果按无符号处理会变成 0xFFFFFFFC，语义就错了。
    """
    result = ctypes.c_ssize_t(0)
    ok = user32.SendMessageTimeoutW(
        wt.HWND(hwnd), wt.UINT(msg), wt.WPARAM(wparam), wt.LPARAM(lparam),
        SMTO_BLOCK | SMTO_ABORTIFHUNG, wt.UINT(timeout_ms), ctypes.byref(result),
    )
    return bool(ok), int(result.value)


# ---------------------------------------------------------------- 系统状态


def is_admin() -> bool:
    try:
        return bool(shell32.IsUserAnAdmin())
    except Exception:  # pragma: no cover
        return False


def screen_reader_enabled() -> bool:
    """读取 SPI_GETSCREENREADER（系统"屏幕阅读器"标志）。

    为什么关心它：Chromium/Qt 等框架会用这个标志决定是否启用无障碍，
    某些机器上它是 TRUE，会让"默认态就有节点"和"框架默认关闭"混在一起，
    做 A/B 对照时必须把它记录下来。
    """
    flag = wt.BOOL()
    ok = user32.SystemParametersInfoW(
        SPI_GETSCREENREADER, 0, ctypes.byref(flag), 0
    )
    return bool(ok and flag.value)


def file_version(path: str) -> str:
    """取文件版本号（"a.b.c.d"）。取不到返回空字符串，不抛异常。"""
    try:
        dummy = wt.DWORD(0)
        size = version_dll.GetFileVersionInfoSizeW(path, ctypes.byref(dummy))
        if not size:
            return ""
        buf = ctypes.create_string_buffer(size)
        if not version_dll.GetFileVersionInfoW(path, 0, size, buf):
            return ""
        ptr = ctypes.c_void_p()
        length = wt.UINT(0)
        if not version_dll.VerQueryValueW(buf, "\\", ctypes.byref(ptr), ctypes.byref(length)):
            return ""
        if not ptr or length.value < 52:
            return ""

        class VS_FIXEDFILEINFO(ctypes.Structure):
            _fields_ = [
                ("dwSignature", wt.DWORD),
                ("dwStrucVersion", wt.DWORD),
                ("dwFileVersionMS", wt.DWORD),
                ("dwFileVersionLS", wt.DWORD),
                ("dwProductVersionMS", wt.DWORD),
                ("dwProductVersionLS", wt.DWORD),
                ("dwFileFlagsMask", wt.DWORD),
                ("dwFileFlags", wt.DWORD),
                ("dwFileOS", wt.DWORD),
                ("dwFileType", wt.DWORD),
                ("dwFileSubtype", wt.DWORD),
                ("dwFileDateMS", wt.DWORD),
                ("dwFileDateLS", wt.DWORD),
            ]

        info = ctypes.cast(ptr, ctypes.POINTER(VS_FIXEDFILEINFO)).contents
        ms = int(info.dwFileVersionMS)
        ls = int(info.dwFileVersionLS)
        return "%d.%d.%d.%d" % (
            ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF
        )
    except Exception:
        return ""


# ---------------------------------------------------------------- 远程内存读


class MemoryReader:
    """读取目标进程内存的小工具，供 PE 导出表解析使用。

    以类而不是单函数存在的原因：解析一个导出表要读几十次内存，
    每次 OpenProcess 既慢又容易掩盖权限错误，复用句柄更稳。
    """

    def __init__(self, pid: int):
        self.pid = int(pid)
        self._handle = open_process(
            pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        )

    def read(self, address: int, size: int) -> bytes:
        if size <= 0:
            return b""
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(
            ctypes.c_void_p(self._handle), ctypes.c_void_p(int(address)), buf,
            ctypes.c_size_t(size), ctypes.byref(got),
        )
        if not ok:
            raise W32Error(
                f"ReadProcessMemory(addr=0x{int(address):X}, size={size}) 失败",
                _err(),
                "地址可能无效或进程已退出；模块基址是否取自本进程枚举结果？",
            )
        return buf.raw[: got.value]

    def close(self) -> None:
        close_handle(self._handle)
        self._handle = 0

    def __enter__(self) -> "MemoryReader":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
