"""uiaunlock.providers.base —— provider 协议与结果类型。

一个 provider 代表"针对某一类 UI 框架的解锁方案"，它必须回答五个问题：

- ``detect(ctx)``：这个目标是不是我管的？给 0~1 的置信度。
- ``kind``：我的方案属于哪一类？
  - ``in_process``：可以在不重启的情况下，在目标进程内调用函数打开开关；
  - ``startup``：只能通过环境变量/命令行/注册表在**启动前**决定，必须重启；
  - ``unsupported``：当前目标无解（或只有实验方向），本库不会做任何侵入操作。
- ``plan(ctx)``：如果要动手，具体调用什么（模块/导出名/RVA/地址/参数），
  以及有哪些风险。**这一步必须能纯打印，不产生副作用。**
- ``unlock(ctx)``：真正执行，并做前后节点数对比。
- ``verify(ctx)``：证明"可逆"——关→开→关（或开→关→开）节点数出现跳变。

约定：``unlock`` 只允许 in_process 的 provider 实现真正的动作；
startup/unsupported 的 ``unlock`` 返回 ``ok=False`` + 明确指引，绝不偷偷注入。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

KIND_IN_PROCESS = "in_process"
KIND_STARTUP = "startup"
KIND_UNSUPPORTED = "unsupported"

KIND_LABELS = {
    KIND_IN_PROCESS: "进程内可热开",
    KIND_STARTUP: "仅启动期开关（需重启）",
    KIND_UNSUPPORTED: "暂不支持 / 仅建议",
}


class ProviderError(RuntimeError):
    """provider 执行失败（找不到导出、权限不足、目标版本不支持等）。"""


@dataclass
class PlannedAction:
    """一次计划中的远程调用。"""

    module: str
    export: str
    rva: int
    address: int
    arg: int
    note: str = ""

    def describe(self) -> str:
        arg_text = "bool(true)" if self.arg and self.export.endswith("SAX_N@Z") else str(self.arg)
        return (
            f"  {self.module}!{self.export}\n"
            f"    RVA=0x{self.rva:X}  地址=0x{self.address:X}  参数={arg_text}"
            + (f"\n    说明：{self.note}" if self.note else "")
        )

    def as_dict(self) -> dict:
        return {
            "module": self.module,
            "export": self.export,
            "rva": self.rva,
            "rva_hex": f"0x{self.rva:X}",
            "address": self.address,
            "address_hex": f"0x{self.address:X}",
            "arg": self.arg,
            "note": self.note,
        }


@dataclass
class Plan:
    """执行计划。CLI 在真正动手前会完整打印它。"""

    provider_id: str
    display_name: str
    kind: str
    pid: int
    bitness: int
    allowed: bool
    reason: str = ""
    actions: List[PlannedAction] = field(default_factory=list)
    steps: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    startup: List[str] = field(default_factory=list)

    def describe(self) -> str:
        lines = [
            f"方案：{self.display_name} ({self.provider_id})",
            f"类型：{KIND_LABELS.get(self.kind, self.kind)}   目标 pid={self.pid} "
            f"（{self.bitness} 位）",
        ]
        if self.steps:
            lines.append("步骤：")
            lines.extend(f"  {i + 1}. {s}" for i, s in enumerate(self.steps))
        if self.actions:
            lines.append(f"将执行 {len(self.actions)} 次远程调用：")
            lines.extend(a.describe() for a in self.actions)
        if self.startup:
            lines.append("启动期做法（需要重启目标程序）：")
            lines.extend(f"  {s}" for s in self.startup)
        if self.warnings:
            lines.append("风险提示：")
            lines.extend(f"  - {w}" for w in self.warnings)
        if not self.allowed:
            lines.append(f"拒绝执行：{self.reason}")
        return "\n".join(lines)

    def as_dict(self) -> dict:
        return {
            "provider_id": self.provider_id,
            "display_name": self.display_name,
            "kind": self.kind,
            "pid": self.pid,
            "bitness": self.bitness,
            "allowed": self.allowed,
            "reason": self.reason,
            "actions": [a.as_dict() for a in self.actions],
            "steps": self.steps,
            "warnings": self.warnings,
            "startup": self.startup,
        }


@dataclass
class UnlockResult:
    """unlock 的执行结果。

    ``ok`` 的判定标准不是"函数调用没报错"，而是"节点数确实变多了"。
    这一点很关键：调用成功但树没出来 = 失败。
    """

    provider_id: str
    ok: bool
    pid: int
    message: str
    before_nodes: Optional[int] = None
    after_nodes: Optional[int] = None
    actions: List[Dict[str, Any]] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0

    def as_dict(self) -> dict:
        return {
            "provider_id": self.provider_id,
            "ok": self.ok,
            "pid": self.pid,
            "message": self.message,
            "before_nodes": self.before_nodes,
            "after_nodes": self.after_nodes,
            "actions": self.actions,
            "evidence": self.evidence,
            "duration_ms": self.duration_ms,
        }


@dataclass
class VerifyResult:
    """verify 的结果：重点看 ``reversible``，而不是只看一次跳变。"""

    provider_id: str
    ok: bool
    pid: int
    message: str
    reversible: bool = False
    evidence: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "provider_id": self.provider_id,
            "ok": self.ok,
            "pid": self.pid,
            "message": self.message,
            "reversible": self.reversible,
            "evidence": self.evidence,
        }


class Provider:
    """provider 基类。第三方扩展只需要继承它并实现 detect/plan（可选 unlock/verify）。"""

    id: str = ""
    display_name: str = ""
    kind: str = KIND_UNSUPPORTED
    priority: int = 50
    notes: str = ""

    # ------------------------------------------------------------ 识别

    def detect(self, ctx) -> float:
        """返回 0~1 的置信度。0 表示"明确不是我的目标"。"""
        return 0.0

    def kind_for(self, ctx) -> str:
        """实际生效的 kind。

        有些 provider 声明是 startup，但对"只有原生边框节点"的目标应降级为
        unsupported（例如 Qt 应用只给了一个空窗口，说明它压根没有可访问控件）。
        """
        return self.kind

    # ------------------------------------------------------------ 计划

    def plan(self, ctx) -> Plan:
        raise NotImplementedError

    # ------------------------------------------------------------ 执行

    def unlock(self, ctx) -> UnlockResult:
        """默认实现：明确拒绝。

        为什么默认拒绝而不是默认空操作：库的定位是"安全第一"，
        没有实现动作的 provider 绝不能悄悄返回成功。
        """
        plan = self.plan(ctx)
        return UnlockResult(
            provider_id=self.id,
            ok=False,
            pid=ctx.pid,
            message=f"{self.display_name} 不支持进程内解锁：{plan.reason or '属于启动期开关'}",
            before_nodes=ctx.node_total,
            after_nodes=ctx.node_total,
            evidence={"kind": plan.kind, "startup": plan.startup},
        )

    def verify(self, ctx) -> VerifyResult:
        return VerifyResult(
            provider_id=self.id,
            ok=False,
            pid=ctx.pid,
            message="该方案无法做可逆跳变验证（不支持进程内开关）",
            evidence={"kind": self.kind_for(ctx), "nodes": ctx.node_total},
        )

    # ------------------------------------------------------------ 描述

    def describe(self, ctx=None) -> str:
        kind = self.kind_for(ctx) if ctx is not None else self.kind
        return f"{self.id:<18} {KIND_LABELS.get(kind, kind):<18} {self.display_name}"
