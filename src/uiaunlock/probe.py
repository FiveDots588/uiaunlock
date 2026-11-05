"""uiaunlock.probe —— 无障碍探针（只读，不改目标进程）。

探针回答三个问题：

1. 目标窗口对三种 ``WM_GETOBJECT`` 请求有没有响应？
   - ``OBJID_CLIENT (-4)``：MSAA 的客户区对象（大多数自绘框架会返回一个 IAccessible）
   - ``OBJID_WINDOW (0)``：MSAA 的窗口对象
   - ``UiaRootObjectId (-25)``：UIA 的根对象（**返回 0 不代表没有 UIA**，
     Qt5 等只提供 MSAA 的框架对 -25 永远返回 0，UIA 客户端靠 MSAA 桥接工作）
2. ``AccessibleObjectFromWindow`` 能不能真的拿到 IAccessible 接口（HRESULT）。
3. UIA/MSAA 客户端实际能遍历到多少个节点、都是什么 ControlType。

重要经验（会直接影响结论正确性）：
- **窗口必须可见且非最小化**，否则绝大多数应用只返回 1 个根节点；
- 只能拿到 1 个节点 + ``OBJID_CLIENT`` 的 lresult 非 0，说明"有 provider 但树没建"，
  大概率是特性开关（feature gate）关着；
- ``UiaRootObjectId == 0`` 不等于不支持 UIA，要结合节点数与 ControlType 判断；
- 计数必须用"同一进程、同一窗口、前后两次"对比，单次数字没有意义。
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import w32

user32 = w32.user32
oleacc = ctypes.WinDLL("oleacc", use_last_error=True)

WM_GETOBJECT = 0x003D

OBJID_WINDOW = 0
OBJID_CLIENT = -4
UIA_ROOT_OBJECT_ID = -25  # UIA 的 UiaRootObjectId，也允许用于 WM_GETOBJECT

VT_EMPTY = 0
VT_I4 = 3
VT_DISPATCH = 9

PROBE_TIMEOUT_MS = 2000


# ---------------------------------------------------------------- 结构定义


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]


# IID_IAccessible = {618736E0-3C3D-11CF-810C-00AA00389B71}
IID_IAccessible = GUID(
    0x618736E0, 0x3C3D, 0x11CF,
    (ctypes.c_ubyte * 8)(0x81, 0x0C, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71),
)


class _BRECORD(ctypes.Structure):
    """VARIANT 里最"大"的成员（两个指针）。

    必须把它放进 union，否则 64 位下 union 只有 8 字节、VARIANT 只有 16 字节，
    而系统 ABI 要求 24 字节 —— AccessibleChildren 会按 24 字节步长写数组，
    直接踩坏我们的栈内存（这是本库自测时真实踩到的坑）。
    """

    _fields_ = [("pvRecord", ctypes.c_void_p), ("pRecInfo", ctypes.c_void_p)]


class _VARIANT_UNION(ctypes.Union):
    _fields_ = [
        ("llVal", ctypes.c_longlong),
        ("lVal", ctypes.c_long),
        ("dblVal", ctypes.c_double),
        ("pdispVal", ctypes.c_void_p),
        ("bstrVal", ctypes.c_void_p),
        ("punkVal", ctypes.c_void_p),
        ("brecord", _BRECORD),
    ]


class VARIANT(ctypes.Structure):
    """COM VARIANT。

    大小必须精确：32 位下 16 字节，64 位下 24 字节。如果结构体大小不对，
    ``AccessibleChildren`` 会按错误的步长写数组，读出来的指针全是垃圾。
    """

    _fields_ = [
        ("vt", ctypes.c_ushort),
        ("wReserved1", ctypes.c_ushort),
        ("wReserved2", ctypes.c_ushort),
        ("wReserved3", ctypes.c_ushort),
        ("u", _VARIANT_UNION),
    ]


oleacc.AccessibleObjectFromWindow.argtypes = [
    wt.HWND, wt.DWORD, ctypes.POINTER(GUID), ctypes.POINTER(ctypes.c_void_p),
]
oleacc.AccessibleObjectFromWindow.restype = ctypes.c_long  # HRESULT
oleacc.AccessibleChildren.argtypes = [
    ctypes.c_void_p, ctypes.c_long, ctypes.c_long,
    ctypes.POINTER(VARIANT), ctypes.POINTER(ctypes.c_long),
]
oleacc.AccessibleChildren.restype = ctypes.c_long

_vt_release = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)


def _com_release(ptr: int) -> None:
    """手工调用 COM 对象的 Release（vtable 第 3 个槽位）。

    为什么要手工：本库核心不依赖 comtypes，拿到的 IAccessible 必须自己释放，
    否则每次探测都会泄漏一个引用，长跑脚本会把目标进程的引用计数耗光。
    """
    if not ptr:
        return
    try:
        vtable = ctypes.cast(
            ctypes.c_void_p(ptr),
            ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)),
        ).contents
        release = _vt_release(vtable[2])
        release(ctypes.c_void_p(ptr))
    except Exception:
        pass


# ---------------------------------------------------------------- WM_GETOBJECT


@dataclass
class ProbeHit:
    """一种 WM_GETOBJECT 对象 ID 的探测结果。"""

    name: str
    objid: int
    ok: bool                      # SendMessageTimeout 是否成功
    lresult: int                  # 返回的 LRESULT（0 表示没给对象）
    accessible_hr: Optional[int]  # AccessibleObjectFromWindow 的 HRESULT（-25 不适用）
    accessible_ok: bool

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "objid": self.objid,
            "ok": self.ok,
            "lresult": self.lresult,
            "lresult_hex": f"0x{self.lresult & 0xFFFFFFFFFFFFFFFF:X}",
            "accessible_hr": self.accessible_hr,
            "accessible_hr_hex": (
                None if self.accessible_hr is None else f"0x{self.accessible_hr & 0xFFFFFFFF:X}"
            ),
            "accessible_ok": self.accessible_ok,
        }


def wm_getobject(hwnd: int, objid: int, timeout_ms: int = PROBE_TIMEOUT_MS) -> tuple:
    """发一条 WM_GETOBJECT，返回 ``(ok, lresult)``。

    无副作用：这只是"问窗口要一个无障碍对象"，不会修改任何状态。
    （对 Chromium 系应用，这个请求本身可能顺带唤醒其无障碍子系统，
    这是浏览器的既有行为，不是本库做的修改。）
    """
    return w32.send_message_timeout(
        hwnd, WM_GETOBJECT, 0, int(objid), timeout_ms
    )


def accessible_object(hwnd: int, objid: int) -> tuple:
    """``AccessibleObjectFromWindow``，返回 ``(hr, IAccessible 指针)``。

    HRESULT ``S_OK=0`` 表示拿到对象；常见失败：
    - ``0x80004005 (E_FAIL)``：窗口没有 MSAA provider
    - ``0x80070005 (E_ACCESSDENIED)``：跨权限级别（UAC）拿不到
    """
    ptr = ctypes.c_void_p(0)
    hr = oleacc.AccessibleObjectFromWindow(
        wt.HWND(hwnd), wt.DWORD(int(objid) & 0xFFFFFFFF),
        ctypes.byref(IID_IAccessible), ctypes.byref(ptr),
    )
    return int(hr), int(ptr.value or 0)


def probe_window(hwnd: int, timeout_ms: int = PROBE_TIMEOUT_MS) -> List[ProbeHit]:
    """对同一窗口做三种探针。返回值顺序固定：OBJID_CLIENT / OBJID_WINDOW / UiaRoot。"""
    hits: List[ProbeHit] = []
    for name, objid in (
        ("OBJID_CLIENT", OBJID_CLIENT),
        ("OBJID_WINDOW", OBJID_WINDOW),
        ("UiaRootObjectId", UIA_ROOT_OBJECT_ID),
    ):
        ok, lresult = wm_getobject(hwnd, objid, timeout_ms)
        if objid in (OBJID_CLIENT, OBJID_WINDOW):
            hr, ptr = accessible_object(hwnd, objid)
            _com_release(ptr)
            accessible_hr: Optional[int] = hr
            accessible_ok = hr == 0
        else:
            accessible_hr = None
            accessible_ok = False
        hits.append(
            ProbeHit(
                name=name, objid=objid, ok=ok, lresult=lresult,
                accessible_hr=accessible_hr, accessible_ok=accessible_ok,
            )
        )
    return hits


# ---------------------------------------------------------------- 节点计数


@dataclass
class NodeCount:
    """一次节点统计结果。

    ``backend`` 取值：``uia``（uiautomation 库）、``msaa``（本库 ctypes 遍历）、
    ``none``（两种都失败）。
    """

    count: int
    backend: str
    control_types: Dict[str, int] = field(default_factory=dict)
    truncated: bool = False
    error: str = ""

    def as_dict(self) -> dict:
        return {
            "count": self.count,
            "backend": self.backend,
            "control_types": self.control_types,
            "truncated": self.truncated,
            "error": self.error,
        }


def uiautomation_available() -> bool:
    try:
        import uiautomation  # noqa: F401
        return True
    except Exception:
        return False


def _count_uia(hwnd: int, max_depth: int, limit: int) -> NodeCount:
    import uiautomation as auto

    root = auto.ControlFromHandle(hwnd)
    counter: Counter = Counter()
    state = {"n": 0, "truncated": False}

    def walk(ctrl, depth: int) -> None:
        if state["n"] >= limit:
            state["truncated"] = True
            return
        state["n"] += 1
        try:
            counter[ctrl.ControlTypeName or "Unknown"] += 1
        except Exception:
            counter["Unknown"] += 1
        if depth >= max_depth:
            return
        try:
            children = ctrl.GetChildren()
        except Exception:
            return
        for child in children:
            walk(child, depth + 1)

    walk(root, 0)
    return NodeCount(
        count=state["n"], backend="uia", control_types=dict(counter),
        truncated=state["truncated"],
    )


def _msaa_children_count(obj: int, max_depth: int, limit: int, depth: int = 0) -> int:
    """用 oleacc!AccessibleChildren 递归计数节点。

    只统计"有对象"的子项（VT_DISPATCH）；VT_I4 表示简单子元素（无独立对象），
    也计入数量，因为对用户来说它同样是一个可访问的单元。
    """
    if depth >= max_depth:
        return 0
    total = 0
    start = 0
    chunk = 100
    arr = (VARIANT * chunk)()
    while True:
        obtained = ctypes.c_long(0)
        hr = oleacc.AccessibleChildren(
            ctypes.c_void_p(obj), ctypes.c_long(start), ctypes.c_long(chunk),
            arr, ctypes.byref(obtained),
        )
        if hr != 0 or obtained.value == 0:
            break
        for i in range(obtained.value):
            total += 1
            v = arr[i]
            if total >= limit:
                return total
            if v.vt == VT_DISPATCH and v.u.pdispVal:
                child = int(v.u.pdispVal)
                try:
                    total += _msaa_children_count(child, max_depth, limit, depth + 1)
                finally:
                    _com_release(child)
        start += obtained.value
        if obtained.value < chunk or total >= limit:
            break
    return total


def _count_msaa(hwnd: int, max_depth: int, limit: int) -> NodeCount:
    for objid in (OBJID_CLIENT, OBJID_WINDOW):
        hr, ptr = accessible_object(hwnd, objid)
        if hr == 0 and ptr:
            try:
                n = 1 + _msaa_children_count(ptr, max_depth, limit)
                return NodeCount(
                    count=n, backend="msaa",
                    control_types={"MSAAObject": n},
                )
            finally:
                _com_release(ptr)
    return NodeCount(count=0, backend="none", error="AccessibleObjectFromWindow 失败")


def count_nodes(
    hwnd: int,
    max_depth: int = 6,
    limit: int = 3000,
    backend: str = "auto",
) -> NodeCount:
    """统计窗口下 UIA 树的节点数。

    ``backend``：
    - ``auto``：优先 uiautomation（更准，能拿到 ControlType）；失败/没装则 MSAA
    - ``uia`` / ``msaa``：强制指定，便于排查差异

    为什么 auto 优先 uia：UIA 客户端看到的才是"用户真正能用 uiautomation 操作"的树；
    MSAA 只能反映 provider 是否存在，不能区分 UIA 桥接是否生效。
    """
    if backend in ("auto", "uia") and uiautomation_available():
        try:
            res = _count_uia(hwnd, max_depth, limit)
            if res.count > 0:
                return res
        except Exception as exc:  # uiautomation 在无 provider 时会抛异常
            if backend == "uia":
                return NodeCount(count=0, backend="uia", error=str(exc))
    if backend == "uia":
        return NodeCount(count=0, backend="uia", error="UIA 客户端不可用或返回 0")
    return _count_msaa(hwnd, max_depth, limit)


def wait_node_count(
    hwnd: int,
    predicate,
    timeout_s: float = 5.0,
    interval_s: float = 0.4,
    max_depth: int = 6,
) -> NodeCount:
    """轮询节点数直到 ``predicate(NodeCount)`` 为真或超时。

    为什么要轮询：远程调用只是"把开关拨过去"，UI 线程重建 provider 是异步的，
    立刻读节点数经常还是旧值，单次读取会误判为失败。
    """
    deadline = time.time() + timeout_s
    last = count_nodes(hwnd, max_depth=max_depth)
    while time.time() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = count_nodes(hwnd, max_depth=max_depth)
    return last


def prepare_window(hwnd: int) -> dict:
    """把窗口调整到可测状态并返回状态（scan 也会调用，属于只读范畴的"显示窗口"）。"""
    return w32.ensure_window_visible(hwnd)
