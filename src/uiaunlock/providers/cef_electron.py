"""uiaunlock.providers.cef_electron —— Chromium / CEF / Electron 的启动期开关。

Chromium 的渲染进程默认不构建无障碍树（性能考虑），要显式打开：

- ``--force-renderer-accessibility``：启动参数，最直接；
- CDP（Chrome DevTools Protocol）``Accessibility.enable``：只对已开启
  ``--remote-debugging-port`` 的调试会话有效，不适合生产环境；
- 系统屏幕阅读器标志（SPI_GETSCREENREADER）为 TRUE 时，Chromium 会自行开启；
- Electron 还可以在代码里调用 ``app.setAccessibilitySupportEnabled(true)``（应用侧）。

这些都属于 **启动期**，且本库不做注入。
"""
from __future__ import annotations

from typing import List

from .base import KIND_STARTUP, Plan, Provider, UnlockResult, VerifyResult


class CefElectronProvider(Provider):
    id = "cef_electron"
    display_name = "Chromium / CEF / Electron 启动期无障碍"
    kind = KIND_STARTUP
    priority = 75
    notes = (
        "通过 --force-renderer-accessibility 或 CDP Accessibility.enable 打开；"
        "均需重启/调试会话，不能靠进程内远程调用。"
    )

    def detect(self, ctx) -> float:
        if ctx.framework in ("cef", "electron"):
            return 0.95
        if ctx.has_module("libcef.dll", "chrome_elf.dll"):
            return 0.9
        if ctx.window_class.startswith("Chrome_WidgetWin"):
            return 0.8
        if ctx.window_class == "Intermediate D3D Window":  # 某些 Electron 变体
            return 0.4
        return 0.0

    def plan(self, ctx) -> Plan:
        exe = ctx.exe_path or "<目标程序路径>"
        startup: List[str] = [
            "# 关闭目标程序后，用启动参数重新打开（对本次会话生效）",
            f'& "{exe}" --force-renderer-accessibility',
            "",
            "# 需要程序化抓取时，可临时开调试端口，再走 CDP：",
            f'& "{exe}" --force-renderer-accessibility --remote-debugging-port=9222',
            "# 然后向 http://127.0.0.1:9222/json 找到页面，发送 Accessibility.enable",
            "# 注意：调试端口会暴露本机控制权，验证完必须关闭",
            "",
            "# Electron 应用若支持，可在其代码中调用 app.setAccessibilitySupportEnabled(true)",
        ]
        if ctx.screen_reader:
            startup.append("")
            startup.append(
                "# 本机 SPI_GETSCREENREADER=TRUE，Chromium 可能已自动开启无障碍；"
                "对照实验前应确认该标志，否则看不到差异"
            )
        warnings = [
            "启动参数必须写在程序启动时，运行中追加无效",
            "CDP 仅适用于自己可控的调试会话，不要在生产环境开 remote-debugging-port",
            "部分 Electron 应用会忽略该参数（由应用自身控制），需要具体验证",
            "系统屏幕阅读器标志为 TRUE 时可能'默认就有树'，容易误判为参数生效",
        ]
        return Plan(
            provider_id=self.id, display_name=self.display_name, kind=self.kind,
            pid=ctx.pid, bitness=ctx.bitness, allowed=False,
            reason="Chromium 系框架属于启动期开关，本库不做进程内注入",
            steps=[
                "完全退出目标程序（任务管理器确认无残留进程）",
                "带 --force-renderer-accessibility 启动",
                "用 uiaunlock scan 对比节点数（渲染区应从少量壳节点变成大量控件）",
            ],
            warnings=warnings, startup=startup,
        )

    def unlock(self, ctx) -> UnlockResult:
        plan = self.plan(ctx)
        return UnlockResult(
            provider_id=self.id, ok=False, pid=ctx.pid,
            message=(
                f"Chromium/CEF/Electron 不支持进程内解锁，当前节点数 {ctx.node_total}。"
                "请按 plan 带 --force-renderer-accessibility 重启目标程序"
            ),
            before_nodes=ctx.node_total, after_nodes=ctx.node_total,
            evidence={"plan": plan.as_dict()},
        )

    def verify(self, ctx) -> VerifyResult:
        return VerifyResult(
            provider_id=self.id, ok=False, pid=ctx.pid,
            message=(
                "启动期开关无法制造可逆跳变；请用'带参数/不带参数'两次启动分别 scan 对比节点数"
            ),
            evidence={
                "nodes": ctx.node_total,
                "control_types": ctx.node_count.control_types,
                "screen_reader": ctx.screen_reader,
            },
        )
