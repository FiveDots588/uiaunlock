"""uiaunlock.providers.generic —— 兜底方案：只做只读探查，不做任何侵入操作。

当框架识别不出来时，这个 provider 负责：

1. 列出目标进程里"看起来像 UI 框架"的模块；
2. 解析这些模块的导出表，找与无障碍相关的符号（Accessibility / ScreenReader / UIA / Notifier ...）；
3. 给出下一步实验建议（启动期开关 → 进程内调用 → 新增 provider）。

它永远 ``kind=unsupported``：**不做注入、不做远程调用**。
如果探查发现可疑的静态导出，正确做法是按 ``docs/ADD_PROVIDER.md``
新增一个专用 provider，而不是让兜底方案去乱调。
"""
from __future__ import annotations

import os
from typing import Dict, List

from .. import pe, w32
from .base import KIND_UNSUPPORTED, Plan, Provider, UnlockResult, VerifyResult

# 名字看起来像 GUI 框架的模块（前缀匹配，小写）
CANDIDATE_PREFIXES = (
    "duilib", "qt5", "qt6", "qwindows", "qaccessible", "libcef", "chrome_elf",
    "jvm", "mshtml", "windows.ui", "unity", "flutter", "electron", "directui",
    "wxwidgets", "wxmsw", "gtk", "libgtk", "avalonia", "cefsharp",
)

# 导出名里出现这些关键字，说明该 DLL 很可能管着无障碍开关
ACCESSIBILITY_KEYWORDS = (
    "Accessibility", "Accessible", "ScreenReader", "UIA", "Automation",
    "EnableAA", "Notifier", "msaa", "IAccessible",
)


class GenericProvider(Provider):
    id = "generic"
    display_name = "通用只读探查（不执行任何操作）"
    kind = KIND_UNSUPPORTED
    priority = 10
    notes = (
        "兜底方案：只列出候选模块与可疑导出，给出下一步实验建议；"
        "永远不注入、不远程调用。"
    )

    def __init__(self) -> None:
        self._cache_key = None
        self._cache: Dict[str, Dict[str, int]] = {}

    # ------------------------------------------------------------ 识别

    def detect(self, ctx) -> float:
        """未知框架时给 0.35（低于 best() 的 0.5 阈值，不会被自动选中）；
        已知框架时给 0.05，只作为列表里的兜底项。"""
        return 0.05 if ctx.framework not in ("unknown", "") else 0.35

    # ------------------------------------------------------------ 探查

    def scan_candidates(self, ctx) -> Dict[str, Dict[str, int]]:
        """解析候选模块的导出表，返回 ``{模块名: {可疑导出名: RVA}}``。

        只读文件，不碰目标进程。模块数量做上限（最多 8 个），避免 scan 太慢；
        已加载模块的磁盘文件可能被删除，读不到就跳过（不算错误）。
        """
        key = (ctx.pid, tuple(m.name for m in ctx.modules))
        if self._cache_key == key:
            return self._cache

        result: Dict[str, Dict[str, int]] = {}
        count = 0
        for mod in ctx.modules:
            if count >= 8:
                break
            low = mod.name.lower()
            if not any(low.startswith(p) for p in CANDIDATE_PREFIXES):
                continue
            if not mod.path or not os.path.exists(mod.path):
                continue
            try:
                table = pe.parse_exports_file(mod.path)
            except (OSError, pe.PEError):
                continue
            hits = pe.find_matching_exports(table, list(ACCESSIBILITY_KEYWORDS))
            if hits:
                result[mod.name] = hits
                count += 1
        self._cache_key = key
        self._cache = result
        return result

    # ------------------------------------------------------------ 计划

    def plan(self, ctx) -> Plan:
        hits = self.scan_candidates(ctx)
        steps: List[str] = [
            "确认窗口可见/未最小化（最小化时所有应用都只有 1 个节点）",
            "记录三种 WM_GETOBJECT 的 lresult 与 AccessibleObjectFromWindow 的 HRESULT"
            "（`uiaunlock scan` 已包含）",
            "仔细阅读 scan 输出里的模块列表，确认框架（Qt/DuiLib/CEF/Java...）",
            "尝试启动期开关：环境变量、命令行参数、注册表，然后重启进程再 scan 对比",
            "如果导出表里出现 Enable/Notifier/Accessibility 等静态函数，"
            "按 docs/ADD_PROVIDER.md 新增专用 provider（不要在这里直接调用）",
        ]
        if hits:
            detail = "；".join(
                f"{mod}: " + ", ".join(sorted(names.keys())[:4]) + ("..." if len(names) > 4 else "")
                for mod, names in hits.items()
            )
            steps.insert(0, f"发现可疑无障碍导出（只读发现，未调用）：{detail}")
        else:
            steps.insert(0, "未在候选模块的导出表里发现无障碍相关符号")

        warnings = [
            "本 provider 不会执行任何远程调用/注入，不能直接解锁",
            "导出名出现关键字不等于可以安全调用：ABI、参数、线程上下文都需要单独验证",
            "目标应用升级后所有 RVA 都会变化，必须重新探查",
        ]
        return Plan(
            provider_id=self.id, display_name=self.display_name, kind=self.kind,
            pid=ctx.pid, bitness=ctx.bitness, allowed=False,
            reason="兜底方案只做只读探查，不支持执行解锁",
            steps=steps, warnings=warnings,
        )

    def unlock(self, ctx) -> UnlockResult:
        plan = self.plan(ctx)
        return UnlockResult(
            provider_id=self.id, ok=False, pid=ctx.pid,
            message=(
                "generic provider 不会修改目标进程。请先按 plan 的步骤确认框架与开关类型，"
                "再决定是'启动期重启'还是'新增 in_process provider'"
            ),
            before_nodes=ctx.node_total, after_nodes=ctx.node_total,
            evidence={"plan": plan.as_dict()},
        )

    def verify(self, ctx) -> VerifyResult:
        return VerifyResult(
            provider_id=self.id, ok=False, pid=ctx.pid,
            message="generic provider 不执行任何操作，无法验证",
            evidence={"nodes": ctx.node_total, "framework": ctx.framework},
        )
