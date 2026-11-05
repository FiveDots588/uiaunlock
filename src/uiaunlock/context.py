"""uiaunlock.context —— 目标应用上下文（框架识别 + 探针结果）。

一个 :class:`TargetContext` 代表"此刻正在被诊断的那个窗口/进程"，
provider 的 detect/plan/unlock/verify 都只读它、不自己再去枚举一遍，
这样报告里记录的 pid / 窗口 / 模块与 provider 判断时看到的是同一份数据。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import probe, w32
from .probe import NodeCount, ProbeHit
from .w32 import ModuleInfo, W32Error


class TargetError(RuntimeError):
    """无法定位目标（进程没启动、hwnd 无效、路径不对等）。"""


# 框架识别结果：(id, 中文名, 判据列表)
FRAMEWORK_LABELS = {
    "duilib": "DuiLib 自绘（DirectUI）",
    "qt5": "Qt 5（Widgets/自绘）",
    "qt6": "Qt 6（Widgets/自绘）",
    "cef": "Chromium / CEF",
    "electron": "Electron",
    "java": "Java（Swing/SWT/AWT）",
    "unity": "Unity",
    "flutter": "Flutter",
    "wpf": "WPF / WinForms（.NET）",
    "uwp": "UWP / WinUI",
    "native": "Win32 原生控件",
    "unknown": "未识别的自绘框架",
}


@dataclass
class TargetContext:
    """一次诊断的完整上下文。字段全部是"观测值"，不做任何推断性修改。"""

    pid: int
    hwnd: int
    exe_path: str
    exe_version: str
    process_name: str
    bitness: int
    host_bitness: int
    window: Dict[str, object]
    modules: List[ModuleInfo]
    framework: str
    framework_evidence: List[str]
    probes: List[ProbeHit]
    node_count: NodeCount
    is_admin: bool
    screen_reader: bool
    uia_available: bool
    depth: int = 6
    notes: List[str] = field(default_factory=list)

    # ------------------------------------------------------------ 查询辅助

    @property
    def window_class(self) -> str:
        return str(self.window.get("class", ""))

    @property
    def window_title(self) -> str:
        return str(self.window.get("title", ""))

    @property
    def framework_label(self) -> str:
        return FRAMEWORK_LABELS.get(self.framework, self.framework)

    def module(self, name: str) -> Optional[ModuleInfo]:
        target = name.lower()
        for m in self.modules:
            if m.name.lower() == target:
                return m
        return None

    def modules_with_prefix(self, *prefixes: str) -> List[ModuleInfo]:
        lows = [p.lower() for p in prefixes]
        return [
            m for m in self.modules
            if any(m.name.lower().startswith(p) for p in lows)
        ]

    def has_module(self, *names: str) -> bool:
        return any(self.module(n) is not None for n in names)

    def module_names(self, limit: Optional[int] = None) -> List[str]:
        names = [m.name for m in self.modules]
        return names[:limit] if limit else names

    def probe_hit(self, name: str) -> Optional[ProbeHit]:
        for hit in self.probes:
            if hit.name == name:
                return hit
        return None

    @property
    def node_total(self) -> int:
        return int(self.node_count.count)

    def brief(self) -> str:
        return (
            f"pid={self.pid} hwnd=0x{self.hwnd:X} "
            f"{self.bitness}-bit class={self.window_class!r} "
            f"framework={self.framework} nodes={self.node_total}({self.node_count.backend})"
        )

    def to_dict(self) -> Dict[str, object]:
        return {
            "pid": self.pid,
            "hwnd": self.hwnd,
            "hwnd_hex": f"0x{self.hwnd:X}",
            "exe_path": self.exe_path,
            "exe_version": self.exe_version,
            "process_name": self.process_name,
            "bitness": self.bitness,
            "host_bitness": self.host_bitness,
            "window": self.window,
            "framework": {
                "id": self.framework,
                "label": self.framework_label,
                "evidence": self.framework_evidence,
            },
            "modules": [
                {"name": m.name, "path": m.path, "base": f"0x{m.base:X}", "size": m.size}
                for m in self.modules
            ],
            "module_names": self.module_names(),
            "probes": [h.as_dict() for h in self.probes],
            "nodes": self.node_count.as_dict(),
            "host": {
                "is_admin": self.is_admin,
                "screen_reader": self.screen_reader,
                "uiautomation_available": self.uia_available,
            },
            "notes": self.notes,
        }


# ---------------------------------------------------------------- 框架识别


def detect_framework(modules: List[ModuleInfo], window_class: str) -> Tuple[str, List[str]]:
    """根据"已加载模块 + 窗口类名"判断 UI 框架。

    判据优先级（从上到下命中即返回）：
    1. 专用运行时 DLL 最可靠（duilib.dll / Qt5Core.dll / libcef.dll / jvm.dll ...）
    2. 窗口类名次之（WeWorkWindow / Qt5QWindowIcon / Chrome_WidgetWin_1 / HwndWrapper[...]）
    3. 都没有 → unknown

    为什么先看模块：窗口类名可以被应用随意改，模块名改起来成本高得多。
    """
    names = {m.name.lower() for m in modules}
    evidence: List[str] = []

    def add(msg: str) -> None:
        evidence.append(msg)

    if "duilib.dll" in names:
        add("已加载 duilib.dll（DuiLib 自绘库）")
        if window_class == "WeWorkWindow":
            add(f"窗口类 {window_class!r} 是企业微信主窗口")
        return "duilib", evidence

    if "flutter_windows.dll" in names:
        add("已加载 flutter_windows.dll")
        return "flutter", evidence

    if "qt6core.dll" in names or any(n.startswith("qt6") for n in names):
        add("已加载 Qt6 运行时（Qt6Core.dll）")
        if window_class.startswith("Qt"):
            add(f"窗口类 {window_class!r} 以 Qt 开头")
        return "qt6", evidence

    if "qt5core.dll" in names or any(n.startswith("qt5") for n in names):
        add("已加载 Qt5 运行时（Qt5Core.dll）")
        if window_class.startswith("Qt"):
            add(f"窗口类 {window_class!r} 以 Qt 开头")
        return "qt5", evidence

    if "unityplayer.dll" in names or "unityengine.coremodule.dll" in names:
        add("已加载 UnityPlayer/UnityEngine 模块")
        return "unity", evidence

    if "electron.exe" in (os.path.basename(m.path).lower() for m in modules):
        add("进程目录中存在 electron.exe")
        return "electron", evidence

    if "libcef.dll" in names or "chrome_elf.dll" in names:
        add("已加载 libcef.dll / chrome_elf.dll（Chromium 内核）")
        if window_class.startswith("Chrome_WidgetWin"):
            add(f"窗口类 {window_class!r} 是 Chromium 的顶层窗口")
        return "cef", evidence

    if "jvm.dll" in names:
        add("已加载 jvm.dll（Java 运行时）")
        return "java", evidence

    if window_class.startswith("HwndWrapper[") or "presentationframework" in " ".join(names):
        add(f"窗口类 {window_class!r} 是 .NET/WPF 的包装窗口")
        return "wpf", evidence

    if "windows.ui.core" in names or window_class == "ApplicationFrameWindow":
        add("检测到 UWP/WinUI 宿主（ApplicationFrameWindow）")
        return "uwp", evidence

    if window_class in ("#32770", "Button", "Edit", "Notepad"):
        add(f"窗口类 {window_class!r} 是标准 Win32 控件")
        return "native", evidence

    add("未匹配到已知自绘框架的模块/窗口类")
    return "unknown", evidence


# ---------------------------------------------------------------- 目标定位


def _pick_pid(candidates: List[int]) -> int:
    """多个候选进程时，优先选"有可见主窗口"的那个（其余通常是子进程/托盘进程）。"""
    best_pid = 0
    best_score = -1
    for pid in candidates:
        hwnd = w32.find_main_window(pid)
        score = 0
        if hwnd:
            score = 100
            if w32.is_window_visible(hwnd):
                score += 100
            if w32.get_window_text(hwnd):
                score += 50
        if score > best_score:
            best_score = score
            best_pid = pid
    return best_pid


def resolve_target(
    pid: Optional[int] = None,
    exe: Optional[str] = None,
    hwnd: Optional[int] = None,
) -> Tuple[int, int]:
    """把 ``--pid`` / ``--exe`` / ``--hwnd`` 统一解析成 ``(pid, hwnd)``。

    优先级：hwnd > pid > exe。三者都空时抛错，避免"猜一个进程去操作"的危险行为。
    """
    if hwnd:
        if not w32.is_window(int(hwnd)):
            raise TargetError(
                f"hwnd=0x{int(hwnd):X} 不是有效窗口（可能已关闭）；"
                "可用 `uiaunlock scan --exe <路径>` 自动找主窗口"
            )
        pid = w32.get_window_pid(int(hwnd))
        if pid == 0:
            raise TargetError(f"hwnd=0x{int(hwnd):X} 取不到所属进程")
        return int(pid), int(hwnd)

    if pid:
        pid = int(pid)
        if not any(p == pid for p, _ in w32.iter_processes()):
            raise TargetError(f"进程 pid={pid} 不存在（是否已退出？）")
        win = w32.find_main_window(pid)
        if not win:
            raise TargetError(
                f"pid={pid} 没有可用的顶层窗口：可能是后台/托盘进程。"
                "请用 --exe 指定主程序路径，或先手动打开它的主界面"
            )
        return pid, win

    if exe:
        pids = w32.find_pids_by_exe(exe)
        if not pids:
            raise TargetError(
                f"没有找到正在运行的进程：{exe}\n"
                "请确认路径/文件名正确，并且程序已启动"
            )
        chosen = _pick_pid(pids)
        win = w32.find_main_window(chosen)
        if not win:
            raise TargetError(
                f"{exe} 有 {len(pids)} 个进程，但都没有顶层窗口；"
                "请先打开它的主界面再扫描"
            )
        if len(pids) > 1:
            pass  # 多进程是常态（企业微信有 broker/渲染/账号子进程），不算错误
        return chosen, win

    raise TargetError("必须提供 --pid / --exe / --hwnd 之一（本库不会自动猜目标）")


def build_context(
    pid: int,
    hwnd: int,
    depth: int = 6,
    with_probe: bool = True,
) -> TargetContext:
    """采集一次完整上下文（模块、框架、探针、节点数）。

    这一步是**只读**的：除了"把最小化的窗口还原"以外不改变目标状态。
    还原窗口是必要的副作用 —— 否则所有应用在最小化时都只有 1 个节点，
    会把诊断结论带偏。
    """
    notes: List[str] = []
    try:
        modules = w32.enum_modules(pid)
    except W32Error as exc:
        raise TargetError(
            f"无法枚举 pid={pid} 的模块：{exc}\n"
            "常见原因：目标以管理员运行而当前不是；或目标位数与枚举参数不匹配（需要 LIST_MODULES_ALL）"
        ) from exc

    bitness = w32.process_bitness(pid)
    try:
        exe_path = w32.process_image_path(pid)
    except W32Error:
        exe_path = ""
        notes.append("取进程路径失败（权限不足），报告中的 exe_path 可能为空")

    process_name = os.path.basename(exe_path) if exe_path else ""
    exe_version = w32.file_version(exe_path) if exe_path else ""

    # 还原窗口，确保后续节点数与探针结果反映"正常显示"状态
    state = probe.prepare_window(hwnd)
    window = state["state"] if isinstance(state.get("state"), dict) else w32.window_state(hwnd)

    framework, evidence = detect_framework(modules, str(window.get("class", "")))

    hits: List[ProbeHit] = probe.probe_window(hwnd) if with_probe else []
    nodes = probe.count_nodes(hwnd, max_depth=depth)

    # 没装 uiautomation 时节点计数会退化成 MSAA：DuiLib/Qt 这类自绘界面只能数到 1，
    # 必须在 notes 里讲清楚，避免用户把"计数能力不足"误读成"解锁失败"。
    if not probe.uiautomation_available():
        notes.append(
            "未安装 uiautomation，节点计数降级为 MSAA，自绘界面通常只能数到 1；"
            "请安装 uiaunlock[uia] 后再诊断"
        )

    if window.get("iconic"):
        notes.append("窗口处于最小化状态，节点数可能偏少")
    if not window.get("visible"):
        notes.append("窗口不可见（可能被隐藏），节点数可能为 0")

    return TargetContext(
        pid=int(pid),
        hwnd=int(hwnd),
        exe_path=exe_path,
        exe_version=exe_version,
        process_name=process_name,
        bitness=bitness,
        host_bitness=w32.host_bitness(),
        window=window,
        modules=modules,
        framework=framework,
        framework_evidence=evidence,
        probes=hits,
        node_count=nodes,
        is_admin=w32.is_admin(),
        screen_reader=w32.screen_reader_enabled(),
        uia_available=probe.uiautomation_available(),
        depth=depth,
        notes=notes,
    )


def refresh_nodes(ctx: TargetContext, max_depth: Optional[int] = None) -> NodeCount:
    """重新统计节点数并写回 ctx（unlock/verify 前后对比用）。"""
    ctx.node_count = probe.count_nodes(
        ctx.hwnd, max_depth=max_depth or ctx.depth
    )
    return ctx.node_count
