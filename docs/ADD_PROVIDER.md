# 验证成功后：把方案作为一个 provider 加进库

前提：你已经按 [VERIFICATION_PROTOCOL.md](VERIFICATION_PROTOCOL.md) 跑完了验收三件套
（同进程可逆跳变、探针变化、真实 UI 操作），并且有 JSON 证据。

一个 provider 就是"某类框架 → 一套解锁方案"的封装。它需要回答 5 个问题：

| 方法 | 返回 | 要点 |
|---|---|---|
| `id` | str | 唯一 id，CLI 用 `--provider <id>` 指定 |
| `display_name` | str | 给人看的名字 |
| `kind` | `in_process` / `startup` / `unsupported` | 决定库允不允许动手 |
| `detect(ctx)` | 0~1 | 置信度，`>=0.5` 才会被自动选中 |
| `kind_for(ctx)` | kind | 可选的"降级"逻辑（例如只有原生边框 → unsupported） |
| `plan(ctx)` | `Plan` | 要调用什么、风险、启动期做法；**纯打印、无副作用** |
| `unlock(ctx)` | `UnlockResult` | 执行 + 前后节点数对比，`ok` 以节点数为准 |
| `verify(ctx)` | `VerifyResult` | 制造可逆跳变，恢复原状 |
| `notes` | str | 风险与前置条件 |

---

## 0. 先看两个现成范例

- 进程内（已验证）：[`src/uiaunlock/providers/wxwork_duilib.py`](../src/uiaunlock/providers/wxwork_duilib.py)
- 启动期（不注入）：[`src/uiaunlock/providers/qt_startup.py`](../src/uiaunlock/providers/qt_startup.py)

---

## 1. 判断该做 in_process 还是 startup

**只有同时满足以下全部条件，才做 `in_process`：**

1. 能找到**静态无参/单 bool 参数**的导出函数（如 `?SetEnabled@CAccessibilityNotifier@...@@SAX_N@Z`）；
2. 该函数在**运行中调用**后，节点数确实变化（不是只有调用没崩）；
3. 变化**可逆**（能关能开）；
4. 关闭状态是**可制造**的（否则无法证明是你这一下造成的）；
5. 目标进程**没有自我保护**（反作弊/完整性校验会拦截 `CreateRemoteThread`）。

**以下情况做 `startup`，不要做注入：**

- 开关只在初始化时读一次（Qt 的 `QT_ACCESSIBILITY`、Chromium 的
  `--force-renderer-accessibility`）；
- 进程内调用实测无效（Qt：`QAccessible::setActive(true)` 后 7→7）；
- 只有注册表/配置文件开关，且必须重启才生效；
- 目标有反调试/反注入保护（做也白做，还可能崩溃）。

**以下情况声明 `unsupported`：**

- 框架确实不暴露任何可访问对象（Unity 默认、部分 Flutter 配置）；
- 只有原生边框节点，且没有任何导出可用；
- 需要应用厂商改代码才能解决。

---

## 2. 可复制模板（`in_process`）

新建 `src/uiaunlock/providers/myapp_xxx.py`：

```python
"""uiaunlock.providers.myapp_xxx —— <应用名> 的 <框架> 进程内解锁。

实测结论（<日期>，<应用版本>，<位数>，<Windows 版本>）：
- 解锁前节点数 <N>；解锁后 <M>；
- 关→开→关可逆，节点数同步跳变；
- 解锁后能在 <控件> 上输入文本并读回（真实 UI 操作验证通过）。

原理：
<一句话说明开关在哪、为什么要调这几个函数>
"""
from __future__ import annotations

import time
from typing import List, Optional, Tuple

from .. import pe, probe, remote
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

# ---- 目标特征（detect 用；变量名/导出名保持英文原文）---------------------
WINDOW_CLASS = "<目标窗口类>"
MODULE_NAME = "<框架 DLL，如 duilib.dll>"

# ---- 导出名：用导出表里的**原始名字**，不要翻译 ----------------------------
EXPORT_ENABLE = "?EnableAccessibility@...@...@@SAX_N@Z"
EXPORT_TRIGGER = "?TriggerAtProbe@...@...@@SAXXZ"
EXPORT_IS_ON = "?IsEnabled@...@...@@SA_NXZ"          # 可选，仅作参考

REQUIRED_EXPORTS = (EXPORT_ENABLE, EXPORT_TRIGGER)   # 缺一个就拒绝执行

# ---- 判据阈值：用你实测的数字，不要拍脑袋 ---------------------------------
ON_NODE_THRESHOLD = 10     # >= 这个数认为"树可用"
OFF_NODE_THRESHOLD = 6     # <= 这个数认为"树是空的"
UNLOCK_TIMEOUT_S = 6.0


class MyAppXxxProvider(Provider):
    id = "myapp_xxx"
    display_name = "<应用名> <框架> 无障碍开关（进程内）"
    kind = KIND_IN_PROCESS
    priority = 80                      # 0~100，越大越优先
    notes = "已验证方案：远程调用 <DLL> 的静态导出；仅当前进程生命周期有效。"

    def __init__(self) -> None:
        # 导出表缓存：key=(pid, 模块基址)。同一进程内不重复读文件/内存。
        self._cache: dict = {}

    # ---------------------------------------------------------- 导出定位
    def export_table(self, ctx) -> Tuple[Optional[pe.ExportTable], str]:
        """优先解析磁盘 DLL；失败则读目标进程内存里的模块副本。

        为什么要有内存兜底：应用可能热更新/删除磁盘文件，
        而运行中的模块才是真正被执行的那一份，RVA 必须和它对齐。
        """
        mod = ctx.module(MODULE_NAME)
        if mod is None:
            return None, f"目标进程未加载 {MODULE_NAME}"
        key = (ctx.pid, mod.base)
        if key in self._cache:
            return self._cache[key], "cache"

        table = None
        source = ""
        if mod.path:
            try:
                table = pe.parse_exports_file(mod.path)
                source = mod.path
            except (OSError, pe.PEError):
                table = None
        if table is None:
            try:
                from .. import w32
                with w32.MemoryReader(ctx.pid) as reader:
                    table = pe.parse_exports_memory(reader.read, mod.base)
                source = f"memory@0x{mod.base:X}"
            except (W32Error, pe.PEError) as exc:
                return None, f"解析导出表失败：{exc}"
        self._cache[key] = table
        return table, source

    # ---------------------------------------------------------- 识别
    def detect(self, ctx) -> float:
        """0~1 置信度。建议按"证据强度"累加：

        - 加载了目标 DLL：+0.45（最可靠）
        - 窗口类命中：+0.25
        - 关键导出齐全：+0.30（能直接执行）
        缺导出时只给 0.2：让它在列表里可见，但 plan 会拒绝执行。
        """
        mod = ctx.module(MODULE_NAME)
        if mod is None:
            return 0.0
        score = 0.45
        if ctx.window_class == WINDOW_CLASS:
            score += 0.25
        table, _ = self.export_table(ctx)
        if table:
            found = [n for n in REQUIRED_EXPORTS if n in table.entries]
            score += 0.30 if len(found) == len(REQUIRED_EXPORTS) else 0.10
        return min(1.0, score)

    # ---------------------------------------------------------- 计划
    def plan(self, ctx) -> Plan:
        """只描述、不执行。CLI 在动任何东西之前会完整打印它。"""
        table, source = self.export_table(ctx)
        warnings = [
            "远程线程调用会在目标进程里执行代码：地址算错会让目标崩溃",
            "需要与目标进程相同的权限",
            "部分安全软件会拦截 CreateRemoteThread",
            "开关只在本次进程生命周期内有效，目标重启后需重新 unlock",
            "窗口必须可见且未最小化，否则节点数会一直为 1",
            "目标升级后 RVA 会变，每次都要重新解析导出表",
        ]
        if table is None:
            return Plan(
                provider_id=self.id, display_name=self.display_name, kind=self.kind,
                pid=ctx.pid, bitness=ctx.bitness, allowed=False,
                reason=f"无法获取导出表（{source}）", warnings=warnings,
            )
        missing = [n for n in REQUIRED_EXPORTS if n not in table.entries]
        if missing:
            return Plan(
                provider_id=self.id, display_name=self.display_name, kind=self.kind,
                pid=ctx.pid, bitness=ctx.bitness, allowed=False,
                reason="缺少关键导出：" + ", ".join(missing), warnings=warnings,
            )

        mod = ctx.module(MODULE_NAME)
        assert mod is not None
        actions: List[PlannedAction] = []
        actions.append(PlannedAction(
            module=mod.name, export=EXPORT_ENABLE,
            rva=table.entries[EXPORT_ENABLE],
            address=mod.base + table.entries[EXPORT_ENABLE],
            arg=1, note="打开无障碍开关",
        ))
        actions.append(PlannedAction(
            module=mod.name, export=EXPORT_TRIGGER,
            rva=table.entries[EXPORT_TRIGGER],
            address=mod.base + table.entries[EXPORT_TRIGGER],
            arg=0, note="触发一次通知，让控件树重建",
        ))
        return Plan(
            provider_id=self.id, display_name=self.display_name, kind=self.kind,
            pid=ctx.pid, bitness=ctx.bitness, allowed=True,
            reason=f"导出表来源：{source}",
            actions=actions,
            steps=[
                "还原/显示目标窗口，记录解锁前节点数",
                "调用 EnableAccessibility(true)",
                "调用 TriggerAtProbe() 触发重建",
                "轮询节点数，明显增加才算成功（不是看'调用没报错'）",
            ],
            warnings=warnings,
        )

    # ---------------------------------------------------------- 执行
    def _call(self, ctx, action: PlannedAction) -> dict:
        """一次远程调用：CreateRemoteThread 到 base+rva，等待并读回 exit code。"""
        result = remote.call_export(
            ctx.pid, action.address - action.rva, action.rva, action.arg,
        )
        item = result.as_dict()
        item.update({"module": action.module, "export": action.export})
        return item

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

        before = probe.count_nodes(ctx.hwnd, max_depth=ctx.depth)
        records = [self._call(ctx, a) for a in plan.actions]
        after = probe.wait_node_count(
            ctx.hwnd,
            lambda n: n.count > before.count,
            timeout_s=UNLOCK_TIMEOUT_S,
            max_depth=ctx.depth,
        )

        grew = after.count > before.count
        ok = after.count >= ON_NODE_THRESHOLD and (grew or before.count >= ON_NODE_THRESHOLD)
        message = (
            f"解锁成功：UIA 节点数 {before.count} -> {after.count}"
            if ok else
            f"调用完成但节点数未达阈值（{before.count} -> {after.count}，阈值 {ON_NODE_THRESHOLD}）；"
            "检查窗口是否可见、版本是否支持、安全软件是否拦截"
        )
        return UnlockResult(
            provider_id=self.id, ok=ok, pid=ctx.pid, message=message,
            before_nodes=before.count, after_nodes=after.count, actions=records,
            evidence={"export_source": source, "backend": after.backend,
                      "control_types": after.control_types, "plan": plan.as_dict()},
            duration_ms=int((time.time() - started) * 1000),
        )

    # ---------------------------------------------------------- 可逆验证
    def verify(self, ctx) -> VerifyResult:
        """关键是"可逆"：关→开→（原状态关则关回）。

        只做一次"能打开"不叫验证；必须两个方向都跳变，并且恢复用户原状态。
        """
        plan = self.plan(ctx)
        if not plan.allowed:
            return VerifyResult(provider_id=self.id, ok=False, pid=ctx.pid,
                                message=f"无法验证：{plan.reason}")
        table, _ = self.export_table(ctx)
        if table is None:
            return VerifyResult(provider_id=self.id, ok=False, pid=ctx.pid,
                                message="导出表不可用")

        n_base = probe.count_nodes(ctx.hwnd, max_depth=ctx.depth)
        original_on = n_base.count >= ON_NODE_THRESHOLD
        stages = []

        def measure(label: str, enabled: bool) -> int:
            # 注意：关闭时如果只关总开关不够，要把所有授权位一起置 0（踩过的坑）
            mod = ctx.module(MODULE_NAME)
            assert mod is not None
            calls = []
            for export, arg in ((EXPORT_ENABLE, 1 if enabled else 0),
                                (EXPORT_TRIGGER, 0)):
                action = PlannedAction(
                    module=mod.name, export=export,
                    rva=table.entries[export],
                    address=mod.base + table.entries[export], arg=arg,
                )
                calls.append(self._call(ctx, action))
                time.sleep(0.12)
            pred = (lambda n: n.count >= ON_NODE_THRESHOLD) if enabled \
                else (lambda n: n.count <= OFF_NODE_THRESHOLD)
            nodes = probe.wait_node_count(ctx.hwnd, pred, timeout_s=6.0,
                                          max_depth=ctx.depth)
            stages.append({"stage": label, "enabled": enabled,
                           "nodes": nodes.count, "backend": nodes.backend, "calls": calls})
            return nodes.count

        n_off = measure("强制关闭", False)
        n_on = measure("强制打开", True)
        if original_on:
            n_restored, restored_to = n_on, "on(already)"
        else:
            n_restored = measure("恢复为关闭", False)
            restored_to = "off"
        stages.insert(0, {"stage": "初始状态", "enabled": original_on,
                          "nodes": n_base.count, "backend": n_base.backend, "calls": []})

        reversible = n_on >= ON_NODE_THRESHOLD and n_on > n_off
        if not original_on:
            reversible = reversible and n_restored <= OFF_NODE_THRESHOLD
        return VerifyResult(
            provider_id=self.id, ok=reversible, pid=ctx.pid,
            message=(f"可逆跳变成立：关={n_off} → 开={n_on}" if reversible
                     else f"未能证明可逆：关={n_off}，开={n_on}，恢复={n_restored}"),
            reversible=reversible,
            evidence={"original_state": "on" if original_on else "off",
                      "restored_to": restored_to, "stages": stages},
        )
```

要点：

- **`plan()` 必须是纯的**（不执行、不写任何东西）；
- **`ok` 以节点数为准**，不要用"函数返回 True"或 `IsEnabled` 导出（企业微信实测它恒为 True）；
- **`verify()` 必须恢复原状**：原本关就关回去，原本开就保持开；
- 阈值用你实测的数字（如 `ON=10 / OFF=6`），并写进注释说明来源。

---

## 3. 可复制模板（`startup`）

```python
"""uiaunlock.providers.myapp_startup —— <应用名> 的启动期无障碍开关（不注入）。"""
from __future__ import annotations

from .base import KIND_STARTUP, Plan, Provider, UnlockResult, VerifyResult


class MyAppStartupProvider(Provider):
    id = "myapp_startup"
    display_name = "<应用名> 启动期无障碍"
    kind = KIND_STARTUP          # 关键：库不会对它执行远程调用
    priority = 70
    notes = "只能在启动前设置环境变量/命令行；本 provider 不做任何注入。"

    def detect(self, ctx) -> float:
        if ctx.framework == "<框架 id>":
            return 0.95
        if ctx.has_module("<框架 dll>"):
            return 0.85
        return 0.0

    def kind_for(self, ctx) -> str:
        """只有原生边框节点时降级为 unsupported，避免给用户虚假希望。"""
        from .base import KIND_UNSUPPORTED
        if ctx.node_total <= 10 and ctx.node_count.control_types:
            shell = {"WindowControl", "PaneControl", "TitleBarControl",
                     "MenuBarControl", "ScrollBarControl", "Unknown", "CustomControl"}
            if set(ctx.node_count.control_types) <= shell:
                return KIND_UNSUPPORTED
        return self.kind

    def plan(self, ctx) -> Plan:
        exe = ctx.exe_path or "<目标程序路径>"
        return Plan(
            provider_id=self.id, display_name=self.display_name,
            kind=self.kind_for(ctx), pid=ctx.pid, bitness=ctx.bitness,
            allowed=False,                     # startup 永远不允许"执行"
            reason="启动期开关：需要带环境变量重启目标程序",
            steps=[
                "完全退出目标程序（包括托盘/子进程）",
                "启动前设置环境变量（见 startup 命令）",
                "重新启动并等待主窗口出现",
                "用 `uiaunlock scan --exe <路径>` 对比节点数",
            ],
            warnings=[
                "环境变量只在启动时读取，热改无效",
                "若机器屏幕阅读器标志为 TRUE，应用可能默认已开启，需记录/还原该标志",
                "目标升级后开关名可能变化，需重测",
            ],
            startup=[
                "# PowerShell（仅本次启动生效）",
                f'$env:<VAR> = "1"; & "{exe}"',
                "",
                "# cmd.exe",
                f'set <VAR>=1 && "{exe}"',
            ],
        )

    def unlock(self, ctx) -> UnlockResult:
        return UnlockResult(
            provider_id=self.id, ok=ctx.node_total >= 10, pid=ctx.pid,
            message="启动期方案：请按 plan 里的命令重启目标程序后再执行 unlock/scan",
            before_nodes=ctx.node_total, after_nodes=ctx.node_total,
            evidence={"plan": self.plan(ctx).as_dict()},
        )

    def verify(self, ctx) -> VerifyResult:
        return VerifyResult(
            provider_id=self.id, ok=False, pid=ctx.pid,
            message=("启动期开关无法做进程内可逆跳变；"
                     "验证方式：带/不带 <VAR> 分别启动，比较节点数"),
            evidence={"nodes": ctx.node_total, "screen_reader": ctx.screen_reader},
        )
```

---

## 4. 注册到库

### 方式 A：内置（改本仓库，需要发版）

1. 把新文件放到 `src/uiaunlock/providers/`；
2. 在 `registry.py` 里 import 并加入 `_BUILTINS`：

```python
from .myapp_xxx import MyAppXxxProvider

_BUILTINS: List[Provider] = [
    WxWorkDuiLibProvider(),
    MyAppXxxProvider(),          # 新加的
    QtStartupProvider(),
    CefElectronProvider(),
    GenericProvider(),
]
```

3. `uiaunlock list` 能看到它，`scan` 会自动给它打分。

### 方式 B：独立 pip 包（用户不需要改本库，推荐第三方扩展）

在你的包里放 provider 类，然后声明 entry point：

```toml
# 你的包的 pyproject.toml
[project.entry-points."uiaunlock.providers"]
myapp_xxx = "my_pkg.provider:MyAppXxxProvider"
```

安装你的包后，`uiaunlock list` 会自动发现（每次进程启动重新扫描）。
加载失败不会让库崩，而是记录在 `registry.LOAD_ERRORS`，由 `uiaunlock list` / `doctor` 显示。

---

## 5. 测试怎么写（参考 `tests/test_providers.py`）

```python
from conftest import FakeContext
from uiaunlock.providers.myapp_xxx import MyAppXxxProvider, EXPORT_ENABLE


def test_detect_without_module_is_zero():
    # 没加载目标 DLL → 明确不是我的目标
    assert MyAppXxxProvider().detect(FakeContext(modules=[])) == 0.0


def test_detect_with_module_and_class():
    ctx = FakeContext(modules=[("duilib.dll", 0x10000000)], window_class="WeWorkWindow")
    score = MyAppXxxProvider().detect(ctx)
    assert 0.5 <= score <= 1.0        # 有模块+窗口类命中，应超过自动选择阈值


def test_plan_never_executes():
    p = MyAppXxxProvider()
    plan = p.plan(FakeContext(...))
    # 计划里的地址必须等于 base + RVA，且 allowed=False 时不能有动作
    for a in plan.actions:
        assert a.address >= 0x10000000


def test_unlock_refuses_when_export_missing():
    ...  # 结果 ok=False，message 里应包含"拒绝执行"
```

要点：

- 测试**不需要真的启动目标应用**（用 `FakeContext`）；
- 反例比正例更重要：缺模块、缺导出、窗口不可见，都必须返回 `ok=False`；
- `plan()` 单测要断言"没有任何副作用"（纯函数、只读数据）。

---

## 6. 提交前自检清单

- [ ] `detect()` 在"目标不存在"时返回 0，而不是靠异常；
- [ ] `plan()` 在缺导出时 `allowed=False` 且给出明确 reason；
- [ ] `plan()` 打印的地址 = `module_base + RVA`（跟着版本动态解析，不写死）；
- [ ] `unlock()` 成功判据是**节点数**，不是"调用没报错"；
- [ ] `unlock()` 失败时的 message 能指导用户下一步；
- [ ] `verify()` 会恢复原始状态（原本关就关回去）；
- [ ] 有中文 docstring/注释说明"为什么这么做、坑在哪"；
- [ ] 所有 Win32 调用有显式 `argtypes/restype`，句柄用 `c_void_p`；
- [ ] `pytest` 通过（无目标应用的机器上也能跑，缺依赖时 `skip` 而不是 `fail`）；
- [ ] 文档里记录了实测版本号 + 证据路径（JSON/截图）。
