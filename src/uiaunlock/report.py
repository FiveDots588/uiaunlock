"""uiaunlock.report —— 结构化报告与人类可读摘要。

报告是"证据"，不是"日志"：它必须能回答

- 目标是谁（exe/版本/pid/位数/窗口类）
- 加载了哪些 GUI 框架模块
- 三种 WM_GETOBJECT 的结果
- 解锁前后节点数（以及 backend：uia 还是 msaa）
- 结论与置信度，以及哪些是实测、哪些是推断
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .context import TargetContext
from .providers.base import KIND_IN_PROCESS, KIND_LABELS, KIND_STARTUP, KIND_UNSUPPORTED

SCHEMA = "uiaunlock/report/v1"

# 只有 uiautomation 后端统计出的节点数才能直接对应"用户能用 uiautomation 操作"
TRUSTED_BACKENDS = ("uia",)


def build_verdict(ctx: TargetContext, scores: List[Tuple[object, float]]) -> Dict[str, object]:
    """根据节点数 + 探针 + provider 置信度给出结论。

    等级划分（节点数是唯一硬指标）：
    - ``>= 10``：UIA 树可用；
    - ``3 ~ 9``：部分可用（常见于 Qt5 的 MSAA 桥接、或只有部分控件暴露）；
    - ``<= 2``：不可用（只有根节点，通常意味着特性开关关着）。
    """
    nodes = ctx.node_total
    backend = ctx.node_count.backend
    top = scores[0] if scores else None
    top_provider = top[0] if top else None
    top_score = float(top[1]) if top else 0.0
    kind = top_provider.kind_for(ctx) if top_provider is not None else KIND_UNSUPPORTED

    if nodes >= 10:
        available = True
        if backend in TRUSTED_BACKENDS:
            summary = f"UIA 树可用：当前 {nodes} 个节点（backend={backend}）"
        else:
            summary = (
                f"MSAA 层可遍历到 {nodes} 个节点，但未能用 uiautomation 复核"
                "（建议安装 uia 额外依赖后再测）"
            )
    elif nodes >= 3:
        available = False
        summary = (
            f"部分可用：只有 {nodes} 个节点。可能只暴露了原生边框，"
            "或框架仅提供 MSAA 桥接（Qt5 常见）"
        )
    else:
        available = False
        summary = (
            f"UIA 树不可用：仅 {nodes} 个节点。窗口很可能只提供了一个空的根对象，"
            "典型原因是无障碍特性开关（feature gate）关闭"
        )

    # 置信度：provider 分越高、能拿到 AccessibleObjectFromWindow 的成功 HRESULT，越可信
    confidence = min(0.98, 0.45 + top_score * 0.5)
    client_hit = ctx.probe_hit("OBJID_CLIENT")
    if client_hit and client_hit.accessible_ok:
        confidence = min(0.98, confidence + 0.05)

    next_steps: List[str] = []
    if top_provider is None or top_score < 0.5:
        next_steps.append("未识别出可信 provider：先看 scan 里的模块列表，按 docs/VERIFICATION_PROTOCOL.md 排查")
    elif kind == KIND_IN_PROCESS:
        if available:
            next_steps.append("树已可用，无需解锁；如需复核可运行 `uiaunlock verify --pid <pid>`")
        else:
            next_steps.append(f"运行 `uiaunlock unlock --pid {ctx.pid}` 尝试进程内解锁")
    elif kind == KIND_STARTUP:
        next_steps.append("该框架必须在启动前设置开关：运行 `uiaunlock diagnose --pid %d` 查看 plan 里的启动命令" % ctx.pid)
    else:
        next_steps.append("当前目标没有已知可行方案：按 docs/VERIFICATION_PROTOCOL.md 采集证据后再决定")

    evidence_level = "measured" if (ctx.probes and backend != "none") else "inferred"

    # 没装 uiautomation 时只有 MSAA 后端，节点数会严重偏低（DuiLib 只会数到 1）。
    # 这种情况必须显式提示，否则用户会误以为"解锁失败"。
    if backend not in TRUSTED_BACKENDS:
        next_steps.insert(
            0,
            "当前节点计数后端不是 uia（未安装 uiautomation），节点数仅供参考；"
            "请先执行 `pip install \"uiaunlock[uia]\"` 再重新 scan/unlock",
        )

    return {
        "available": available,
        "nodes": nodes,
        "backend": backend,
        "summary": summary,
        "confidence": round(confidence, 2),
        "kind": kind,
        "kind_label": KIND_LABELS.get(kind, kind),
        "provider": getattr(top_provider, "id", None),
        "provider_confidence": round(top_score, 2),
        "next_steps": next_steps,
        "evidence_level": evidence_level,
    }


def build_report(
    ctx: TargetContext,
    scores: List[Tuple[object, float]],
    *,
    plan=None,
    unlock=None,
    verify=None,
) -> Dict[str, object]:
    """把上下文、provider 评分、执行结果合成一个可落盘的 JSON 结构。"""
    now = datetime.now().astimezone()
    verdict = build_verdict(ctx, scores)

    exports_found: Dict[str, Dict[str, int]] = {}
    plan_actions_ids: List[str] = []
    if plan is not None and getattr(plan, "actions", None):
        for action in plan.actions:
            exports_found.setdefault(action.module, {})[
                action.export
            ] = action.rva
            plan_actions_ids.append(action.export)

    report = {
        "schema": SCHEMA,
        "generated_at": now.isoformat(timespec="seconds"),
        "host": {
            "python_bits": ctx.host_bitness,
            "is_admin": ctx.is_admin,
            "screen_reader": ctx.screen_reader,
            "uiautomation_available": ctx.uia_available,
        },
        "target": ctx.to_dict(),
        "providers": [
            {
                "id": p.id,
                "display_name": p.display_name,
                "declared_kind": p.kind,
                "effective_kind": p.kind_for(ctx),
                "confidence": round(float(s), 3),
            }
            for p, s in scores
        ],
        "exports": exports_found,
        "plan": plan.as_dict() if plan is not None else None,
        "unlock": unlock.as_dict() if unlock is not None else None,
        "verify": verify.as_dict() if verify is not None else None,
        "verdict": verdict,
    }
    return report


def human_summary(report: Dict[str, object]) -> str:
    """把报告渲染成一段中文摘要（直接打印给用户看）。"""
    target = report.get("target", {}) or {}
    verdict = report.get("verdict", {}) or {}
    host = report.get("host", {}) or {}
    window = target.get("window", {}) or {}
    framework = target.get("framework", {}) or {}
    nodes = target.get("nodes", {}) or {}

    lines: List[str] = []
    lines.append("== uiaunlock 诊断摘要 ==")
    lines.append(f"时间：{report.get('generated_at')}")
    lines.append(
        "目标：pid={pid} {name} {ver}  {bits} 位".format(
            pid=target.get("pid"),
            name=target.get("process_name") or "(未知进程名)",
            ver=("v" + target.get("exe_version", "")) if target.get("exe_version") else "",
            bits=target.get("bitness"),
        )
    )
    if target.get("exe_path"):
        lines.append(f"路径：{target.get('exe_path')}")
    lines.append(
        "窗口：hwnd={hwnd} class={cls!r} title={title!r} visible={vis} iconic={ico}".format(
            hwnd=window.get("hwnd_hex"),
            cls=window.get("class"),
            title=window.get("title"),
            vis=window.get("visible"),
            ico=window.get("iconic"),
        )
    )
    lines.append(f"框架：{framework.get('label')}（{framework.get('id')}）")
    for ev in framework.get("evidence", []) or []:
        lines.append(f"  - {ev}")

    lines.append("探针：")
    for hit in target.get("probes", []) or []:
        if hit.get("accessible_hr_hex") is not None:
            hr = f" AccessibleObjectFromWindow={hit['accessible_hr_hex']}"
        else:
            hr = ""
        lines.append(
            f"  {hit['name']}({hit['objid']}): lresult={hit['lresult_hex']}{hr}"
        )

    lines.append(
        "节点：{n}（backend={b}）".format(n=nodes.get("count"), b=nodes.get("backend"))
    )
    types = nodes.get("control_types") or {}
    if types:
        top = sorted(types.items(), key=lambda kv: -kv[1])[:5]
        lines.append("  ControlType Top5：" + ", ".join(f"{k}={v}" for k, v in top))

    lines.append(f"主机：admin={host.get('is_admin')} screenreader={host.get('screen_reader')} "
                 f"uiautomation={host.get('uiautomation_available')}")
    lines.append("")
    lines.append(f"结论：{verdict.get('summary')}")
    lines.append(f"置信度：{verdict.get('confidence')}（{verdict.get('evidence_level')}）")
    for step in verdict.get("next_steps", []) or []:
        lines.append(f"下一步：{step}")

    if report.get("unlock"):
        unlock = report["unlock"]
        lines.append(
            "解锁：{ok} 节点 {a} -> {b}；{msg}".format(
                ok="成功" if unlock.get("ok") else "失败",
                a=unlock.get("before_nodes"), b=unlock.get("after_nodes"),
                msg=unlock.get("message"),
            )
        )
    if report.get("verify"):
        verify = report["verify"]
        lines.append(
            "验证：{ok} reversible={rev}；{msg}".format(
                ok="通过" if verify.get("ok") else "未通过",
                rev=verify.get("reversible"),
                msg=verify.get("message"),
            )
        )
    return "\n".join(lines)


def reports_dir() -> Path:
    """默认报告目录：当前工作目录下的 ``uiaunlock_reports``。"""
    return Path(os.getcwd()) / "uiaunlock_reports"


def write_report(report: Dict[str, object], path: Optional[str] = None) -> str:
    """写 JSON 报告，返回实际写入的路径。"""
    if path:
        out = Path(path)
    else:
        out = reports_dir() / f"uiaunlock-{datetime.now():%Y%m%d-%H%M%S}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return str(out)
