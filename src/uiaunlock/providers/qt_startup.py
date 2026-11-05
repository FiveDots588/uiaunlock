"""uiaunlock.providers.qt_startup —— Qt 5/6 的启动期无障碍开关。

实测结论（2026-11，本机 Window 11 + Qt 5.15 应用）：

- Qt 属于 **启动期** 类型（kind=startup），进程起来后再调用
  ``QAccessible::setActive(true)`` 也无效（节点数 7 -> 7，WM_GETOBJECT 仍为 0）；
- Qt5 默认只暴露 **MSAA**（Qt 的 windows 插件把 QWidget 映射成 IAccessible），
  因此 ``UiaRootObjectId(-25)`` 永远返回 0 —— 这不是"不支持 UIA"的证据，
  UIA 客户端会通过 MSAA 桥接看到树；
- 激活靠环境变量 ``QT_ACCESSIBILITY=1``，且必须在**进程启动前**设置；
  ``QT_LINUX_ACCESSIBILITY_ALWAYS_ON`` 是 Linux 专用，Windows 上无效；
- 系统“屏幕阅读器”标志（SPI_GETSCREENREADER）为 TRUE 的机器上，
  Qt 应用默认可能已经激活，做 A/B 时必须记录该标志，否则会得出错误结论。

所以本 provider **不做任何注入**，只输出诊断与现成的启动方式。
"""
from __future__ import annotations

from typing import List

from .base import (
    KIND_STARTUP,
    KIND_UNSUPPORTED,
    Plan,
    Provider,
    UnlockResult,
    VerifyResult,
)

QTCORE_MODULES = ("qt5core.dll", "qt6core.dll", "qt5widgets.dll", "qt6widgets.dll")
NATIVE_ONLY_TYPES = {
    "WindowControl", "PaneControl", "TitleBarControl", "MenuBarControl",
    "ScrollBarControl", "Unknown", "CustomControl",
}


class QtStartupProvider(Provider):
    id = "qt_startup"
    display_name = "Qt 5/6 启动期无障碍（QT_ACCESSIBILITY=1）"
    kind = KIND_STARTUP
    priority = 70
    notes = (
        "Qt 无可靠的进程内热开方案：必须在启动前设置 QT_ACCESSIBILITY=1。"
        "Qt5 只提供 MSAA，UiaRootObjectId 返回 0 属正常现象。"
    )

    # ------------------------------------------------------------ 识别

    def detect(self, ctx) -> float:
        if ctx.framework in ("qt5", "qt6"):
            return 0.95
        if ctx.has_module(*QTCORE_MODULES):
            return 0.85
        # 窗口类名兜底：Qt5QWindowIcon / Qt515... 之类
        if ctx.window_class.startswith(("Qt5", "Qt6")):
            return 0.7
        return 0.0

    def kind_for(self, ctx) -> str:
        """只有"原生边框节点"时降级为 unsupported。

        判据：节点数 <= 10，且 ControlType 全部属于窗口/面板/标题栏这类
        "框架壳"类型 —— 说明 Qt 控件一个都没暴露，属于当前目标确实无解。
        """
        if ctx.node_total <= 10 and ctx.node_count.control_types:
            types = set(ctx.node_count.control_types.keys())
            if types <= NATIVE_ONLY_TYPES:
                return KIND_UNSUPPORTED
        return self.kind

    # ------------------------------------------------------------ 计划

    def _startup_commands(self, ctx) -> List[str]:
        exe = ctx.exe_path or "<目标程序路径>"
        lines = [
            "# PowerShell（只对本次启动生效，关闭窗口后自动失效）",
            f'$env:QT_ACCESSIBILITY = "1"; & "{exe}"',
            "",
            "# cmd.exe",
            f'set QT_ACCESSIBILITY=1 && "{exe}"',
            "",
            "# 永久（用户级环境变量，需要重新登录/重启应用才生效；可逆：setx QT_ACCESSIBILITY 0）",
            "setx QT_ACCESSIBILITY 1",
        ]
        if ctx.screen_reader:
            lines.append("")
            lines.append(
                "# 注意：本机 SPI_GETSCREENREADER=TRUE，Qt 可能默认已激活；"
                "做对照实验前应先把该标志恢复为 FALSE，否则测不出差异"
            )
        return lines

    def plan(self, ctx) -> Plan:
        kind = self.kind_for(ctx)
        warnings = [
            "Qt 无法通过进程内调用可靠热开（实测 QAccessible::setActive(true) 无效）",
            "QT_ACCESSIBILITY 必须在进程启动前设置；应用重启后才生效",
            "QT_LINUX_ACCESSIBILITY_ALWAYS_ON 只对 Linux 有效，Windows 上不要用",
            "Qt5 只提供 MSAA，UiaRootObjectId(-25) 返回 0 是正常的，不要据此判定'不支持'",
            "若机器上 SPI_GETSCREENREADER=TRUE，Qt 可能默认已激活，做 A/B 前需记录/还原该标志",
        ]
        steps = [
            "关闭目标程序（确认进程完全退出，包括托盘进程）",
            "在启动前设置环境变量 QT_ACCESSIBILITY=1",
            "重新启动程序，等待主窗口出现",
            "用 `uiaunlock scan --exe <路径>` 对比节点数（Qt Widgets 通常从几个升到几十个）",
        ]
        reason = (
            "当前窗口只有原生边框节点，Qt 控件未暴露，属于无解状态（需要应用自身改造）"
            if kind == KIND_UNSUPPORTED else
            "Qt 属于启动期开关，本库不做进程内注入"
        )
        return Plan(
            provider_id=self.id, display_name=self.display_name, kind=kind,
            pid=ctx.pid, bitness=ctx.bitness, allowed=False, reason=reason,
            steps=steps, warnings=warnings,
            startup=self._startup_commands(ctx),
        )

    # ------------------------------------------------------------ 动作

    def unlock(self, ctx) -> UnlockResult:
        plan = self.plan(ctx)
        return UnlockResult(
            provider_id=self.id,
            ok=ctx.node_total >= 10,  # 已经能看到控件 = 已经是"开"的状态
            pid=ctx.pid,
            message=(
                f"Qt 不支持进程内解锁，当前节点数 {ctx.node_total}。"
                "请按 plan 里的启动命令带 QT_ACCESSIBILITY=1 重启目标程序"
            ),
            before_nodes=ctx.node_total, after_nodes=ctx.node_total,
            evidence={"plan": plan.as_dict()},
        )

    def verify(self, ctx) -> VerifyResult:
        """Qt 只能做"单次观测"，无法制造可逆跳变 —— 如实返回 ok=False。"""
        return VerifyResult(
            provider_id=self.id, ok=False, pid=ctx.pid,
            message=(
                f"Qt 无法做可逆跳变验证（启动期开关）。当前节点数={ctx.node_total}，"
                "Backend=" + ctx.node_count.backend + "；"
                "验证方法：带/不带 QT_ACCESSIBILITY=1 分别启动，比较节点数"
            ),
            evidence={
                "nodes": ctx.node_total,
                "control_types": ctx.node_count.control_types,
                "screen_reader": ctx.screen_reader,
                "uia_root_lresult": (
                    ctx.probe_hit("UiaRootObjectId").lresult
                    if ctx.probe_hit("UiaRootObjectId") else None
                ),
            },
        )
