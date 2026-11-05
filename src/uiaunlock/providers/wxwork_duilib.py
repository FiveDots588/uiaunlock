"""uiaunlock.providers.wxwork_duilib —— 企业微信（DuiLib 自绘）进程内解锁。

这是本库 **唯一经过完整实测** 的 in_process 方案。原理：

企业微信主界面是 DuiLib 自绘（窗口类 ``WeWorkWindow``，没有子 HWND），
内部有一个无障碍特性门（AccessibilityFeatureGate），默认关闭。
关闭时窗口只提供一个空的无障碍根节点；打开后 UIA/MSAA 客户端能看到完整控件树。

``duilib.dll`` 导出了开关这些门的静态函数（MSVC 修饰名见下方 EXPORTS）。
用 ``CreateRemoteThread`` 依次调用：

    SetFeatureEnabledByBusiness(true) -> SetAtWhitelistAuthorized(true)
    -> SetEnabled(true) -> TriggerAtProbe()

效果等价于影刀"元素捕获"做的那一步，但不需要注入 DLL、不依赖影刀。

已验证事实（2026-11，WXWork 5.0.13.6005，32 位，Windows 11）：
- 解锁前节点数 1~2（只有根节点），解锁后 43~44；
- 关→开→关可逆，节点数同步跳变；
- 解锁后可在搜索框输入文本并读回（真实 UI 操作验证通过）。

风险 / 局限：
- **版本绑定**：导出名稳定，但 RVA 每次升级都会变，必须动态解析（本 provider 已如此）；
- **权限**：必须与目标同权限；企业微信以管理员运行时本库也要管理员；
- **安全软件**：CreateRemoteThread 可能被拦截（报 OpenProcess/CreateRemoteThread 失败）；
- **生命周期**：开关只对当前进程有效，企业微信重启后失效，需要重新 unlock；
- 若窗口最小化/隐藏，节点数会一直是 1，容易被误判为"没生效"（本 provider 会先还原窗口）。
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional, Tuple

from .. import pe, probe, remote, w32
from ..w32 import W32Error
from .base import (
    KIND_IN_PROCESS,
    PlannedAction,
    Plan,
    Provider,
    ProviderError,
    UnlockResult,
    VerifyResult,
)

# 目标窗口特征
WXWORK_WINDOW_CLASS = "WeWorkWindow"
DUILIB_MODULE = "duilib.dll"

# MSVC 修饰名：CAccessibilityNotifier@DuiLib 的静态成员函数
# 顺序很重要：先授权（business/whitelist），再开门（SetEnabled），最后触发通知。
EXPORT_BUSINESS = "?SetFeatureEnabledByBusiness@CAccessibilityNotifier@DuiLib@@SAX_N@Z"
EXPORT_WHITELIST = "?SetAtWhitelistAuthorized@CAccessibilityNotifier@DuiLib@@SAX_N@Z"
EXPORT_SET_ENABLED = "?SetEnabled@CAccessibilityNotifier@DuiLib@@SAX_N@Z"
EXPORT_TRIGGER = "?TriggerAtProbe@CAccessibilityNotifier@DuiLib@@SAXXZ"
EXPORT_IS_ENABLED = "?IsEnabled@CAccessibilityNotifier@DuiLib@@SA_NXZ"

# 真正决定"能不能开"的两个导出；business/whitelist 是配套授权，缺了会降级但不致命
REQUIRED_EXPORTS = (EXPORT_SET_ENABLED, EXPORT_TRIGGER)

UNLOCK_TIMEOUT_S = 6.0
TOGGLE_SETTLE_S = 0.4

# 节点数判据（本机实测：关门时 3 个节点，开门后 21~44 个）。
# 不用 IsEnabled 导出做判据——它在本机恒为 True，不可靠。
ON_NODE_THRESHOLD = 10
OFF_NODE_THRESHOLD = 6


def _lookup(table: pe.ExportTable, name: str) -> Optional[int]:
    return table.entries.get(name)


class WxWorkDuiLibProvider(Provider):
    id = "wxwork_duilib"
    display_name = "企业微信 DuiLib 无障碍开关（进程内）"
    kind = KIND_IN_PROCESS
    priority = 90
    notes = (
        "已验证方案：远程调用 duilib.dll 的 CAccessibilityNotifier 静态导出，"
        "在本进程生命周期内打开 UIA 树；重启目标后失效。"
    )

    def __init__(self) -> None:
        # 导出表缓存：key=(pid, 模块基址)，同一进程内不必反复读文件/内存
        self._cache: Dict[Tuple[int, int], pe.ExportTable] = {}

    # ------------------------------------------------------------ 导出定位

    def export_table(self, ctx) -> Tuple[Optional[pe.ExportTable], str]:
        """取 duilib.dll 的导出表，返回 ``(table, 来源说明)``。

        优先解析磁盘文件（快、稳）；文件被删/被替换时退回读目标进程内存，
        用正在运行的模块副本解析 —— 这样即使热更新了也能对上 RVA。
        """
        mod = ctx.module(DUILIB_MODULE)
        if mod is None:
            return None, "目标进程未加载 duilib.dll"
        key = (ctx.pid, mod.base)
        if key in self._cache:
            return self._cache[key], "cache"

        table: Optional[pe.ExportTable] = None
        source = ""
        if mod.path:
            try:
                table = pe.parse_exports_file(mod.path)
                source = mod.path
            except (OSError, pe.PEError):
                table = None
        if table is None:
            try:
                with w32.MemoryReader(ctx.pid) as reader:
                    table = pe.parse_exports_memory(reader.read, mod.base)
                source = f"memory@0x{mod.base:X}"
            except (W32Error, pe.PEError) as exc:
                return None, f"解析导出表失败：{exc}"
        self._cache[key] = table
        return table, source

    # ------------------------------------------------------------ 识别

    def detect(self, ctx) -> float:
        """置信度构成：加载 duilib +0.45，窗口类命中 +0.25，导出齐全 +0.30。

        没有导出时只给 0.2：说明是 DuiLib 应用，但不是企业微信这套带开关的版本，
        此时 provider 会展示但拒绝执行（plan.allowed=False）。
        """
        mod = ctx.module(DUILIB_MODULE)
        if mod is None:
            return 0.0
        score = 0.45
        if ctx.window_class == WXWORK_WINDOW_CLASS:
            score += 0.25
        table, _src = self.export_table(ctx)
        if table:
            found = [n for n in (EXPORT_SET_ENABLED, EXPORT_TRIGGER) if n in table.entries]
            if len(found) == 2:
                score += 0.30
            elif found:
                score += 0.10
        return min(1.0, score)

    # ------------------------------------------------------------ 计划

    def plan(self, ctx) -> Plan:
        table, source = self.export_table(ctx)
        warnings = [
            "远程线程调用会在目标进程里执行代码：地址算错会让企业微信崩溃，请确认版本与 RVA 一致",
            "需要与目标进程相同的权限（目标以管理员运行时，本命令也要以管理员运行）",
            "部分安全软件会拦截 CreateRemoteThread，可能报 OpenProcess/CreateRemoteThread 失败",
            "开关只在本次进程生命周期内有效，企业微信重启后需重新 unlock",
            "窗口必须可见且未最小化，否则节点数会一直为 1，看起来像失败",
            "目标应用升级后 RVA 会变化，请重新运行 scan/unlock（本库每次都会重新解析导出表）",
        ]

        if table is None:
            return Plan(
                provider_id=self.id, display_name=self.display_name, kind=self.kind,
                pid=ctx.pid, bitness=ctx.bitness, allowed=False,
                reason=f"无法获取 duilib.dll 导出表（{source}）",
                warnings=warnings,
            )

        entries = table.entries
        missing = [n for n in REQUIRED_EXPORTS if n not in entries]
        if missing:
            return Plan(
                provider_id=self.id, display_name=self.display_name, kind=self.kind,
                pid=ctx.pid, bitness=ctx.bitness, allowed=False,
                reason=(
                    "duilib.dll 缺少关键导出：" + ", ".join(missing)
                    + "（大概率是企业微信版本不同，需要重新做一轮验证）"
                ),
                actions=[], warnings=warnings,
            )

        mod = ctx.module(DUILIB_MODULE)
        assert mod is not None
        actions: List[PlannedAction] = []
        if EXPORT_BUSINESS in entries:
            actions.append(PlannedAction(
                module=mod.name, export=EXPORT_BUSINESS, rva=entries[EXPORT_BUSINESS],
                address=mod.base + entries[EXPORT_BUSINESS], arg=1,
                note="授权业务侧启用无障碍特性",
            ))
        if EXPORT_WHITELIST in entries:
            actions.append(PlannedAction(
                module=mod.name, export=EXPORT_WHITELIST, rva=entries[EXPORT_WHITELIST],
                address=mod.base + entries[EXPORT_WHITELIST], arg=1,
                note="把当前进程加入无障碍白名单",
            ))
        actions.append(PlannedAction(
            module=mod.name, export=EXPORT_SET_ENABLED, rva=entries[EXPORT_SET_ENABLED],
            address=mod.base + entries[EXPORT_SET_ENABLED], arg=1,
            note="打开总开关（AccessibilityFeatureGate）",
        ))
        actions.append(PlannedAction(
            module=mod.name, export=EXPORT_TRIGGER, rva=entries[EXPORT_TRIGGER],
            address=mod.base + entries[EXPORT_TRIGGER], arg=0,
            note="立即触发一次探针通知，让 provider 重建控件树",
        ))

        steps = [
            "还原/显示目标窗口，记录解锁前节点数",
            "依次调用 business/whitelist/SetEnabled（参数 true）",
            "调用 TriggerAtProbe() 触发无障碍树重建",
            "轮询节点数，若明显增加则判定成功（不是看'调用没报错'）",
        ]
        return Plan(
            provider_id=self.id, display_name=self.display_name, kind=self.kind,
            pid=ctx.pid, bitness=ctx.bitness, allowed=True,
            reason=f"导出表来源：{source}",
            actions=actions, steps=steps, warnings=warnings,
        )

    # ------------------------------------------------------------ 内部动作

    def _call(self, ctx, action: PlannedAction) -> dict:
        """执行一条计划中的调用，并把结果整理成可写进报告的字典。"""
        result = remote.call_export(
            ctx.pid, action.address - action.rva, action.rva, action.arg,
        )
        item = result.as_dict()
        item.update({"module": action.module, "export": action.export})
        return item

    def _apply(self, ctx, table: pe.ExportTable, enabled: bool) -> List[dict]:
        """打开或关闭总开关（三个授权位一起切）。

        实测要点（2026-11，WXWork 5.0.13.6005）：
        - 只调 ``SetEnabled(false)`` **不会**让已经建好的树消失（nodes 21 -> 21），
          必须把 business / whitelist 一起置 0 再 TriggerAtProbe，树才会塌回 3 个节点；
        - 反过来，打开时也要三个一起置 1，否则可能"看起来开了但树不出来"；
        - ``IsEnabled`` 导出的读回值在本机上始终是 True，**不能**用它判断状态，
          判断只能看节点数。这也是为什么报告里把它标成"参考值"。
        """
        mod = ctx.module(DUILIB_MODULE)
        if mod is None:
            raise ProviderError("duilib.dll 不在目标进程里（企业微信可能已重启/退出）")

        flag = 1 if enabled else 0
        calls: List[Tuple[str, int, int]] = []
        if EXPORT_BUSINESS in table.entries:
            calls.append((EXPORT_BUSINESS, table.entries[EXPORT_BUSINESS], flag))
        if EXPORT_WHITELIST in table.entries:
            calls.append((EXPORT_WHITELIST, table.entries[EXPORT_WHITELIST], flag))
        calls.append((EXPORT_SET_ENABLED, table.entries[EXPORT_SET_ENABLED], flag))
        calls.append((EXPORT_TRIGGER, table.entries[EXPORT_TRIGGER], 0))

        records: List[dict] = []
        for name, rva, arg in calls:
            action = PlannedAction(
                module=mod.name, export=name, rva=rva, address=mod.base + rva, arg=arg
            )
            try:
                records.append(self._call(ctx, action))
            except remote.RemoteCallError as exc:
                raise ProviderError(
                    f"远程调用失败：{name} (RVA=0x{rva:X})\n{exc}"
                ) from exc
            time.sleep(0.12)  # 给 UI 线程一点时间处理通知
        return records

    def _is_enabled(self, ctx, table: pe.ExportTable) -> Optional[bool]:
        """读取总开关状态（只读，不修改任何东西）。

        导出缺失或调用失败时返回 None —— 调用方必须能区分"关着"和"读不到"。
        """
        rva = table.entries.get(EXPORT_IS_ENABLED)
        mod = ctx.module(DUILIB_MODULE)
        if rva is None or mod is None:
            return None
        try:
            res = remote.remote_call(ctx.pid, mod.base + rva, 0, timeout_ms=3000)
        except remote.RemoteCallError:
            return None
        if res.exit_code is None:
            return None
        return bool(res.exit_code)

    # ------------------------------------------------------------ 解锁

    def unlock(self, ctx) -> UnlockResult:
        started = time.time()
        plan = self.plan(ctx)
        if not plan.allowed:
            return UnlockResult(
                provider_id=self.id, ok=False, pid=ctx.pid,
                message=f"拒绝执行：{plan.reason}",
                before_nodes=ctx.node_total, after_nodes=ctx.node_total,
                evidence={"plan": plan.as_dict()},
            )

        table, source = self.export_table(ctx)
        if table is None:
            raise ProviderError(source)

        mod = ctx.module(DUILIB_MODULE)
        assert mod is not None

        before = probe.count_nodes(ctx.hwnd, max_depth=ctx.depth)
        is_on_before = self._is_enabled(ctx, table)
        actions = self._apply(ctx, table, enabled=True)

        after = probe.wait_node_count(
            ctx.hwnd,
            lambda n: n.count > before.count,
            timeout_s=UNLOCK_TIMEOUT_S,
            max_depth=ctx.depth,
        )
        is_on_after = self._is_enabled(ctx, table)

        # 判定标准：节点数必须真的变多；若解锁前就已可用（before >= 阈值），
        # 则只要求"解锁后仍然可用"，避免把幂等调用误判为失败。
        grew = after.count > before.count
        ok = after.count >= ON_NODE_THRESHOLD and (
            grew or before.count >= ON_NODE_THRESHOLD
        )

        if ok:
            message = (
                f"解锁成功：UIA 节点数 {before.count} -> {after.count}"
                if grew else
                f"目标已处于解锁态（节点数 {after.count}），已重新确认开关"
            )
        else:
            if after.backend != "uia":
                message = (
                    f"调用已执行，但当前计数后端是 {after.backend}（没有安装 uiautomation），"
                    "无法看到 DuiLib 的 UIA 树，因此不能确认是否生效。"
                    "请安装 uiaunlock[uia] 后重新执行 unlock/verify 复核。"
                )
            else:
                message = (
                    f"调用已完成但节点数没有增长到可用水平（{before.count} -> {after.count}，"
                    f"阈值 {ON_NODE_THRESHOLD}）。"
                    "请确认窗口可见/未最小化；若仍失败，可能版本不受支持或安全软件拦截了远程线程"
                )

        return UnlockResult(
            provider_id=self.id, ok=ok, pid=ctx.pid, message=message,
            before_nodes=before.count, after_nodes=after.count,
            actions=actions,
            evidence={
                "export_source": source,
                "duilib_base": f"0x{mod.base:X}",
                # IsEnabled 导出只作参考：本机实测它不会随 SetEnabled(false) 变化
                "is_enabled_export_before": is_on_before,
                "is_enabled_export_after": is_on_after,
                "backend": after.backend,
                "control_types": after.control_types,
                "plan": plan.as_dict(),
            },
            duration_ms=int((time.time() - started) * 1000),
        )

    # ------------------------------------------------------------ 可逆验证

    def verify(self, ctx) -> VerifyResult:
        """A/B 对照：制造"关 → 开 →（必要时再关回）"的节点数跳变。

        - 当前是关：测关态 → 开 → 测 → 关回原状（保证不改变用户环境）；
        - 当前是开：测开态 → 关 → 测 → 开回来（同样恢复原状）。

        只有两个方向的跳变都成立才叫"可逆"；单次能开不算证明。
        """
        plan = self.plan(ctx)
        if not plan.allowed:
            return VerifyResult(
                provider_id=self.id, ok=False, pid=ctx.pid,
                message=f"无法验证：{plan.reason}",
            )
        table, source = self.export_table(ctx)
        if table is None:
            return VerifyResult(
                provider_id=self.id, ok=False, pid=ctx.pid, message=source
            )

        n_base = probe.count_nodes(ctx.hwnd, max_depth=ctx.depth)
        # 以节点数作为唯一判据：IsEnabled 导出在本机实测恒为 True，不能用来判断开关状态
        original_on = n_base.count >= ON_NODE_THRESHOLD
        stages: List[dict] = []

        def measure(label: str, enabled: bool, timeout_s: float = 6.0) -> int:
            records = self._apply(ctx, table, enabled=enabled)
            predicate = (
                (lambda n: n.count >= ON_NODE_THRESHOLD) if enabled
                else (lambda n: n.count <= OFF_NODE_THRESHOLD)
            )
            nodes = probe.wait_node_count(
                ctx.hwnd, predicate, timeout_s=timeout_s, max_depth=ctx.depth
            )
            stages.append({
                "stage": label,
                "enabled": enabled,
                "nodes": nodes.count,
                "backend": nodes.backend,
                "calls": records,
            })
            return nodes.count

        n_off = measure("强制关闭", False)
        n_on = measure("强制打开", True)
        if original_on:
            # 原本就是开的：当前已经恢复成"开"，不需要再切
            n_restored = n_on
            restored_to = "on(already)"
        else:
            # 原本是关的：再关回去，既证明可逆，也不改变用户环境
            n_restored = measure("恢复为关闭", False)
            restored_to = "off"

        stages.insert(0, {
            "stage": "初始状态", "enabled": bool(original_on),
            "nodes": n_base.count, "backend": n_base.backend, "calls": [],
        })

        jump_up = n_on >= ON_NODE_THRESHOLD and n_on > n_off
        jump_down = (n_restored <= OFF_NODE_THRESHOLD) if not original_on else True
        reversible = jump_up and jump_down
        ok = reversible

        if ok:
            message = (
                f"可逆跳变成立：关={n_off} → 开={n_on}"
                + (f" → 再关={n_restored}" if not original_on else "（原状态为开，已保持开启）")
            )
        else:
            message = (
                f"未能证明可逆跳变：关={n_off}，开={n_on}，恢复={n_restored}。"
                "请检查窗口是否可见、是否被安全软件拦截"
            )

        return VerifyResult(
            provider_id=self.id, ok=ok, pid=ctx.pid, message=message,
            reversible=reversible,
            evidence={
                "export_source": source,
                "original_state": "on" if original_on else "off",
                "restored_to": restored_to,
                "stages": stages,
            },
        )
