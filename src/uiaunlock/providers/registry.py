"""uiaunlock.providers.registry —— provider 注册与选择。

两种注册方式：

1. **内置**：本包自带的四个 provider（见 ``_BUILTINS``）。
2. **entry_points**：第三方 pip 包只要在自己的 ``pyproject.toml`` 里声明

       [project.entry-points."uiaunlock.providers"]
       myapp = "my_pkg.provider:MyProvider"

   本库就会自动发现，无需修改源码。加载失败的 entry point 不会让整个库崩，
   而是记录在 :data:`LOAD_ERRORS` 里，由 ``uiaunlock list`` / ``doctor`` 显示。
"""
from __future__ import annotations

import importlib.metadata as md
from typing import Dict, List, Optional, Tuple

from .base import KIND_IN_PROCESS, KIND_STARTUP, KIND_UNSUPPORTED, Provider
from .cef_electron import CefElectronProvider
from .generic import GenericProvider
from .qt_startup import QtStartupProvider
from .wxwork_duilib import WxWorkDuiLibProvider

ENTRY_POINT_GROUP = "uiaunlock.providers"

# 每次进程启动时重新实例化，provider 实例可以安全地持有缓存（如导出表）
_BUILTINS: List[Provider] = [
    WxWorkDuiLibProvider(),
    QtStartupProvider(),
    CefElectronProvider(),
    GenericProvider(),
]

# entry point 加载错误：{entry_point_name: 错误文本}
LOAD_ERRORS: Dict[str, str] = {}


def _load_entry_points() -> List[Provider]:
    """读取 ``uiaunlock.providers`` entry points。

    Python 3.9 的 importlib.metadata 没有 ``entry_points(group=...)`` 的
    统一行为，这里做兼容分支，避免在 3.9 上拿不到第三方 provider。
    """
    out: List[Provider] = []
    try:
        eps = md.entry_points()
        if hasattr(eps, "select"):
            selected = eps.select(group=ENTRY_POINT_GROUP)
        else:  # Python 3.9
            selected = eps.get(ENTRY_POINT_GROUP, [])  # type: ignore[arg-type]
    except Exception as exc:  # pragma: no cover - 环境异常
        LOAD_ERRORS["<discovery>"] = str(exc)
        return out

    for ep in selected:
        try:
            obj = ep.load()
            provider = obj() if isinstance(obj, type) else obj
            if not isinstance(provider, Provider):
                raise TypeError(f"不是 Provider 子类：{type(provider)!r}")
            if not provider.id:
                provider.id = ep.name
            out.append(provider)
        except Exception as exc:
            LOAD_ERRORS[ep.name] = f"{type(exc).__name__}: {exc}"
    return out


def get_providers(include_entry_points: bool = True) -> List[Provider]:
    """返回全部 provider（内置 + 第三方），按 priority 从高到低。"""
    providers = list(_BUILTINS)
    if include_entry_points:
        providers.extend(_load_entry_points())
    providers.sort(key=lambda p: (-p.priority, p.id))
    return providers


def detect(ctx, providers: Optional[List[Provider]] = None) -> List[Tuple[Provider, float]]:
    """对所有 provider 跑 ``detect``，按置信度降序返回 ``[(provider, 0..1)]``。

    detect 抛异常的 provider 会被当作 0 分（并保留在列表末尾供排查），
    这样"某个第三方 provider 写坏了"不会让 scan 整体失败。
    """
    if providers is None:
        providers = get_providers()
    scores: List[Tuple[Provider, float]] = []
    for p in providers:
        try:
            score = float(p.detect(ctx))
        except Exception:
            score = 0.0
        scores.append((p, max(0.0, min(1.0, score))))
    scores.sort(key=lambda item: (-item[1], -item[0].priority, item[0].id))
    return scores


def best(ctx, provider_id: Optional[str] = None) -> Tuple[Provider, float]:
    """选择要使用的 provider。

    - 指定 ``provider_id`` 时：找不到直接抛 :class:`LookupError`（CLI 会拒绝执行）；
    - 未指定时：取置信度最高者，但要求 >= 0.5，否则视为"未知 provider"。
    """
    scores = detect(ctx)
    if provider_id:
        for p, s in scores:
            if p.id.lower() == provider_id.lower():
                return p, s
        known = ", ".join(p.id for p, _ in scores)
        raise LookupError(f"未知 provider {provider_id!r}；可用：{known}")
    if not scores or scores[0][1] < 0.5:
        top = scores[0] if scores else None
        raise LookupError(
            "没有识别出可信的 provider"
            + (f"（最高分 {top[0].id}={top[1]:.2f}）" if top else "")
            + "。请先运行 `uiaunlock scan` 查看框架识别结果；"
            "如需强制执行，请显式指定 --provider generic"
        )
    return scores[0]


def by_kind(providers: List[Provider], ctx=None) -> Dict[str, List[Provider]]:
    """按 kind 分组，``list`` 命令用。"""
    groups: Dict[str, List[Provider]] = {
        KIND_IN_PROCESS: [], KIND_STARTUP: [], KIND_UNSUPPORTED: [],
    }
    for p in providers:
        kind = p.kind_for(ctx) if ctx is not None else p.kind
        groups.setdefault(kind, []).append(p)
    return groups
