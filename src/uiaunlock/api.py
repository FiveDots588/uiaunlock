"""uiaunlock.api —— 公共 API 实现（scan / diagnose / unlock / verify）。

对库使用者来说，只需要 ``from uiaunlock import scan, unlock, verify, diagnose``。
这里的所有函数都接受 ``pid=`` / ``exe=`` / ``hwnd=`` 三种目标定位方式之一。
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from . import report as report_mod
from .context import TargetContext, build_context, resolve_target
from .providers import registry
from .providers.base import (
    KIND_IN_PROCESS,
    KIND_LABELS,
    Plan,
    Provider,
    UnlockResult,
    VerifyResult,
)


@dataclass
class ScanResult:
    """scan 的返回值。

    ``scores`` 是 ``[(provider, 0~1 置信度)]``，按置信度降序；
    ``verdict`` 是结论字典（available/summary/confidence/next_steps）。
    """

    ctx: TargetContext
    scores: List[Tuple[Provider, float]]
    verdict: Dict[str, object]

    def to_dict(self) -> Dict[str, object]:
        return {
            "target": self.ctx.to_dict(),
            "providers": [
                {
                    "id": p.id,
                    "display_name": p.display_name,
                    "declared_kind": p.kind,
                    "effective_kind": p.kind_for(self.ctx),
                    "confidence": round(float(s), 3),
                }
                for p, s in self.scores
            ],
            "verdict": self.verdict,
        }

    def summary_lines(self) -> List[str]:
        """scan 的人类可读输出（CLI 直接打印）。"""
        ctx = self.ctx
        lines: List[str] = []
        lines.append(
            "目标：pid={pid} {name} {ver}  {bits} 位   管理员={admin}".format(
                pid=ctx.pid,
                name=ctx.process_name or "(未知)",
                ver=("v" + ctx.exe_version) if ctx.exe_version else "",
                bits=ctx.bitness,
                admin="是" if ctx.is_admin else "否",
            )
        )
        if ctx.exe_path:
            lines.append(f"路径：{ctx.exe_path}")
        lines.append(
            "窗口：hwnd=0x{hwnd:X} class={cls!r} title={title!r} "
            "visible={vis} iconic={ico} size={w}x{h}".format(
                hwnd=ctx.hwnd,
                cls=ctx.window_class,
                title=ctx.window_title,
                vis=ctx.window.get("visible"),
                ico=ctx.window.get("iconic"),
                w=ctx.window.get("width"),
                h=ctx.window.get("height"),
            )
        )
        lines.append(f"框架：{ctx.framework_label}（{ctx.framework}）")
        for ev in ctx.framework_evidence:
            lines.append(f"  - {ev}")

        lines.append("WM_GETOBJECT 探针：")
        for hit in ctx.probes:
            if hit.accessible_hr is not None:
                hr = f"  AccessibleObjectFromWindow HRESULT=0x{hit.accessible_hr & 0xFFFFFFFF:X}"
            else:
                hr = "  （该对象 ID 不适用于 AccessibleObjectFromWindow）"
            lines.append(f"  {hit.name:<16} objid={hit.objid:<4} lresult=0x{hit.lresult & 0xFFFFFFFFFFFFFFFF:X}{hr}")

        lines.append(
            "UIA 节点数：{n}（backend={b}{trunc}）".format(
                n=ctx.node_count.count,
                b=ctx.node_count.backend,
                trunc="，已截断" if ctx.node_count.truncated else "",
            )
        )
        if ctx.node_count.control_types:
            top = sorted(ctx.node_count.control_types.items(), key=lambda kv: -kv[1])[:6]
            lines.append("  ControlType：" + ", ".join(f"{k}={v}" for k, v in top))
        if ctx.node_count.error:
            lines.append(f"  节点计数异常：{ctx.node_count.error}")

        lines.append("provider 识别：")
        for p, s in self.scores:
            # 置信度为 0 的 provider 只是"没匹配到"，显示它声明的 kind 更有参考价值，
            # 否则会出现"Qt 明明没装却显示暂不支持"这种误导。
            shown_kind = p.kind if s < 0.05 else p.kind_for(ctx)
            lines.append(
                f"  {p.id:<18} {s:4.2f}  {KIND_LABELS.get(shown_kind, shown_kind)}"
            )
        if registry.LOAD_ERRORS:
            lines.append("  （有 entry point 加载失败，见 `uiaunlock list`）")

        lines.append("")
        lines.append(f"结论：{self.verdict.get('summary')}")
        lines.append(f"置信度：{self.verdict.get('confidence')}（{self.verdict.get('evidence_level')}）")
        for step in self.verdict.get("next_steps", []) or []:
            lines.append(f"下一步：{step}")
        if ctx.notes:
            lines.append("注意：")
            for note in ctx.notes:
                lines.append(f"  - {note}")
        return lines


def _build(pid=None, exe=None, hwnd=None, depth: int = 6, with_probe: bool = True) -> TargetContext:
    resolved_pid, resolved_hwnd = resolve_target(pid=pid, exe=exe, hwnd=hwnd)
    return build_context(resolved_pid, resolved_hwnd, depth=depth, with_probe=with_probe)


def scan(
    pid: Optional[int] = None,
    exe: Optional[str] = None,
    hwnd: Optional[int] = None,
    depth: int = 6,
) -> ScanResult:
    """只读扫描：框架识别 + 三种探针 + 节点数 + 结论。

    **不会修改目标进程**（唯一副作用是把最小化窗口还原以便正确计数）。
    """
    ctx = _build(pid=pid, exe=exe, hwnd=hwnd, depth=depth)
    scores = registry.detect(ctx)
    verdict = report_mod.build_verdict(ctx, scores)
    return ScanResult(ctx=ctx, scores=scores, verdict=verdict)


def diagnose(
    pid: Optional[int] = None,
    exe: Optional[str] = None,
    hwnd: Optional[int] = None,
    depth: int = 6,
    out: Optional[str] = None,
) -> Tuple[Dict[str, object], str]:
    """scan + 写出结构化 JSON 报告，返回 ``(report, 实际路径)``。"""
    result = scan(pid=pid, exe=exe, hwnd=hwnd, depth=depth)
    report = report_mod.build_report(result.ctx, result.scores)
    path = report_mod.write_report(report, out)
    return report, path


def make_plan(
    pid: Optional[int] = None,
    exe: Optional[str] = None,
    hwnd: Optional[int] = None,
    provider: Optional[str] = None,
    depth: int = 6,
) -> Tuple[TargetContext, Provider, float, Plan]:
    """构造执行计划（纯预览，不产生任何副作用）。

    CLI 的 ``unlock --dry-run`` 与"执行前打印计划"都走这里。
    """
    ctx = _build(pid=pid, exe=exe, hwnd=hwnd, depth=depth)
    chosen, score = registry.best(ctx, provider)
    return ctx, chosen, score, chosen.plan(ctx)


def unlock(
    pid: Optional[int] = None,
    exe: Optional[str] = None,
    hwnd: Optional[int] = None,
    provider: Optional[str] = None,
    dry_run: bool = False,
    depth: int = 6,
) -> UnlockResult:
    """执行解锁。

    安全闸门（按顺序检查，任何一条不满足都返回 ok=False）：
    1. provider 必须被识别（未知 provider 直接拒绝）；
    2. ``plan.allowed`` 必须为 True（导出缺失/版本不支持则拒绝）；
    3. provider 的生效 kind 必须是 ``in_process``（startup/unsupported 绝不注入）；
    4. ``dry_run=True`` 时只返回计划。

    成功后会用同一窗口的节点数前后对比来判定 ``ok``，不把"调用没报错"当成功。
    """
    started = time.time()
    ctx, chosen, score, plan = make_plan(
        pid=pid, exe=exe, hwnd=hwnd, provider=provider, depth=depth
    )
    kind = chosen.kind_for(ctx)

    def refuse(message: str) -> UnlockResult:
        return UnlockResult(
            provider_id=chosen.id, ok=False, pid=ctx.pid, message=message,
            before_nodes=ctx.node_total, after_nodes=ctx.node_total,
            evidence={"plan": plan.as_dict(), "provider_confidence": round(score, 2)},
            duration_ms=int((time.time() - started) * 1000),
        )

    if not plan.allowed:
        return refuse(f"拒绝执行：{plan.reason}")
    if kind != KIND_IN_PROCESS:
        return refuse(
            f"拒绝执行：provider {chosen.id} 的 kind={kind}（{KIND_LABELS.get(kind, kind)}）。"
            "本库只会对 in_process 方案执行远程调用；请按计划使用启动期开关"
        )
    if dry_run:
        return refuse("dry-run：只打印计划，未执行任何远程调用")

    result = chosen.unlock(ctx)
    result.duration_ms = result.duration_ms or int((time.time() - started) * 1000)
    result.evidence.setdefault("provider_confidence", round(score, 2))
    return result


def verify(
    pid: Optional[int] = None,
    exe: Optional[str] = None,
    hwnd: Optional[int] = None,
    provider: Optional[str] = None,
    depth: int = 6,
) -> VerifyResult:
    """验证解锁方案是否真的"可逆"（A/B 对照）。

    对企业微信 provider：关→开→关（或开→关→开）都会测量节点数，
    只有两个方向都出现明显跳变才算通过，并且会恢复到原始状态。
    """
    ctx = _build(pid=pid, exe=exe, hwnd=hwnd, depth=depth)
    chosen, _score = registry.best(ctx, provider)
    return chosen.verify(ctx)
