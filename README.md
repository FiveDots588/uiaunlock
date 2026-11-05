# uiaunlock

诊断并解锁 Windows 自绘 UI 框架（DuiLib / Qt / CEF / Electron …）的 **UIA 无障碍树**。

适用场景：某个应用用 UIAutomation / `uiautomation` / 影刀等工具只能看到 1~2 个节点（或只有一圈原生边框），
但它其实是 DuiLib、Qt、Chromium 这类"自绘"界面 —— 控件都在进程内自己画，默认不向无障碍客户端暴露。

本库把事情分成三类：

| kind | 含义 | 能否不重启就生效 |
|---|---|---|
| `in_process` | 进程内远程调用开关函数 | 可以（企业微信属于这一类） |
| `startup` | 只能启动前设环境变量 / 命令行参数 | 不行，必须重启目标程序 |
| `unsupported` | 当前目标无解，只给诊断与建议 | —— |

**只读优先**：`scan` / `diagnose` / `doctor` 不会修改目标进程；只有 `unlock` 会执行远程调用，且执行前一定先打印完整计划。

---

## 1. 安装

要求：**Windows** + Python 3.9+。核心只依赖标准库与 `ctypes`。

```powershell
# 在源码目录内（开发/本机验证）
pip install -e .

# 需要更准确的节点计数（强烈建议）
pip install -e ".[uia]"

# 从 wheel 安装
pip install .\dist\uiaunlock-0.1.0-py3-none-any.whl
pip install "uiaunlock[uia]"
```

`uiautomation` 是可选依赖：

- 装了 → 节点计数走 UIA 后端（能数到 DuiLib / Qt 的控件，`unlock` 才能自动判定成功）；
- 没装 → 降级为 MSAA 计数，只能数到 Win32 子窗口级，DuiLib 应用会一直显示 1~2 个节点。

安装后得到两个入口：`uiaunlock` 命令，以及 `python -m uiaunlock.cli`。

---

## 2. 五个命令（最小用法）

```powershell
uiaunlock list                                  # 有哪些 provider，各自 kind
uiaunlock scan    --exe "<WXWORK_EXE>"          # 只读诊断（换成你的目标 exe 路径）
uiaunlock diagnose --pid 95344 --out report.json                     # 只读 + 写 JSON 报告
uiaunlock unlock  --pid 95344 --dry-run         # 只打印计划（推荐第一次这样跑）
uiaunlock unlock  --pid 95344 --yes             # 真正执行
uiaunlock verify  --pid 95344                   # A/B 可逆验证
uiaunlock doctor                                # 环境自检
```

目标定位三选一：`--pid` / `--exe <路径或进程名>` / `--hwnd 0x...`（优先级 hwnd > pid > exe）。

退出码：`0` 成功，`1` 参数/定位失败，`2` 拒绝执行（未知 provider / 导出缺失 / 非 in_process），`3` 执行了但没效果。

---

## 3. 真实输出（本机实测，Windows 11 + 企业微信 5.0.13.6005）

### 3.1 `uiaunlock doctor`

```text
== uiaunlock doctor ==
版本：uiaunlock 0.1.0   Python 3.14.0  (64 位)
管理员：否（普通用户通常够用；目标以管理员运行时需要提权）
uiautomation：已安装（节点计数用 UIA 后端）
SPI_GETSCREENREADER：True（TRUE 时 Qt/Chromium 可能默认已开无障碍，做 A/B 前要记录）
provider：内置 + entry points 共 4 个
企业微信安装路径：
  <WXWORK_EXE>  v5.0.13.6005
企业微信进程：5 个 -> [95344, 88184, 52892, 112408, 116964]
  主窗口：pid=95344 hwnd=0x2506D8 title='企业微信'
  位数：32
  ...
```

看点：Python 位数、是否管理员、`uiautomation` 是否在、屏幕阅读器标志、目标进程位数。

### 3.2 `uiaunlock list`

```text
uiaunlock 0.1.0  共 4 个 provider（含第三方 entry points）

ID                  KIND                      PRIORITY  名称
------------------------------------------------------------------------------------------------
wxwork_duilib       进程内可热开                  90        企业微信 DuiLib 无障碍开关（进程内）
cef_electron        仅启动期开关（需重启）            75        Chromium / CEF / Electron 启动期无障碍
qt_startup          仅启动期开关（需重启）            70        Qt 5/6 启动期无障碍（QT_ACCESSIBILITY=1）
generic             暂不支持 / 仅建议              10        通用只读探查（不执行任何操作）

说明：in_process = 可在运行中通过远程调用打开；startup = 必须在启动前设置（需重启）；unsupported = 只给建议，不做操作
```

### 3.3 `uiaunlock scan`（关态 baseline）

```text
目标：pid=95344 WXWork.exe v5.0.13.6005  32 位   管理员=否
路径：<WXWORK_EXE>
窗口：hwnd=0x2506D8 class='WeWorkWindow' title='企业微信' visible=True iconic=False size=1182x822
框架：DuiLib 自绘（DirectUI）（duilib）
  - 已加载 duilib.dll（DuiLib 自绘库）
  - 窗口类 'WeWorkWindow' 是企业微信主窗口
WM_GETOBJECT 探针：
  OBJID_CLIENT     objid=-4   lresult=0x0   AccessibleObjectFromWindow HRESULT=0x0
  OBJID_WINDOW     objid=0    lresult=0x0   AccessibleObjectFromWindow HRESULT=0x0
  UiaRootObjectId  objid=-25  lresult=0x0   （该对象 ID 不适用于 AccessibleObjectFromWindow）
UIA 节点数：2（backend=uia）
  ControlType：WindowControl=1, PaneControl=1
provider 识别：
  wxwork_duilib      1.00  进程内可热开
  generic            0.05  暂不支持 / 仅建议
  cef_electron       0.00  仅启动期开关（需重启）
  qt_startup         0.00  仅启动期开关（需重启）

结论：UIA 树不可用：仅 2 个节点。窗口很可能只提供了一个空的根对象，典型原因是无障碍特性开关（feature gate）关闭
置信度：0.98（measured）
下一步：运行 `uiaunlock unlock --pid 95344` 尝试进程内解锁
```

### 3.4 `uiaunlock scan`（开态，同一进程）

```text
WM_GETOBJECT 探针：
  OBJID_CLIENT     objid=-4   lresult=0xC13F  AccessibleObjectFromWindow HRESULT=0x0
  OBJID_WINDOW     objid=0    lresult=0x0     AccessibleObjectFromWindow HRESULT=0x0
  UiaRootObjectId  objid=-25  lresult=0x0     （该对象 ID 不适用于 AccessibleObjectFromWindow）
UIA 节点数：20（backend=uia）
  ControlType：GroupControl=15, WindowControl=1, PaneControl=1, ToolBarControl=1, ButtonControl=1, CustomControl=1
...
结论：UIA 树可用：当前 20 个节点（backend=uia）
```

**这就是最有价值的差分证据**：开关关闭时 `WM_GETOBJECT(OBJID_CLIENT)` 返回 `0x0`，
打开后返回一个非零的 LRESULT（本次 `0xC13F`，具体值每次不同，是进程内的对象地址）。

### 3.5 `uiaunlock unlock --pid 95344 --dry-run`

```text
方案：企业微信 DuiLib 无障碍开关（进程内） (wxwork_duilib)
类型：进程内可热开   目标 pid=95344 （32 位）
步骤：
  1. 还原/显示目标窗口，记录解锁前节点数
  2. 依次调用 business/whitelist/SetEnabled（参数 true）
  3. 调用 TriggerAtProbe() 触发无障碍树重建
  4. 轮询节点数，若明显增加则判定成功（不是看'调用没报错'）
将执行 4 次远程调用：
  DuiLib.dll!?SetFeatureEnabledByBusiness@CAccessibilityNotifier@DuiLib@@SAX_N@Z
    RVA=0x31CC0  地址=0x711A1CC0  参数=bool(true)
    说明：授权业务侧启用无障碍特性
  DuiLib.dll!?SetAtWhitelistAuthorized@CAccessibilityNotifier@DuiLib@@SAX_N@Z
    RVA=0x31D00  地址=0x711A1D00  参数=bool(true)
    说明：把当前进程加入无障碍白名单
  DuiLib.dll!?SetEnabled@CAccessibilityNotifier@DuiLib@@SAX_N@Z
    RVA=0x31D90  地址=0x711A1D90  参数=bool(true)
    说明：打开总开关（AccessibilityFeatureGate）
  DuiLib.dll!?TriggerAtProbe@CAccessibilityNotifier@DuiLib@@SAXXZ
    RVA=0x31D70  地址=0x711A1D70  参数=0
    说明：立即触发一次探针通知，让 provider 重建控件树
风险提示：
  - 远程线程调用会在目标进程里执行代码：地址算错会让企业微信崩溃，请确认版本与 RVA 一致
  - 需要与目标进程相同的权限（目标以管理员运行时，本命令也要以管理员运行）
  - 部分安全软件会拦截 CreateRemoteThread，可能报 OpenProcess/CreateRemoteThread 失败
  - 开关只在本次进程生命周期内有效，企业微信重启后需重新 unlock
  - 窗口必须可见且未最小化，否则节点数会一直为 1，看起来像失败
  - 目标应用升级后 RVA 会变化，请重新运行 scan/unlock（本库每次都会重新解析导出表）

provider 置信度：1.00

[dry-run] 未执行任何远程调用。
```

### 3.6 `uiaunlock unlock --pid 95344 --yes`（关态 → 开态）

```text
结果：成功
节点数：2 -> 20
耗时：568 ms
说明：解锁成功：UIA 节点数 2 -> 20
复核：当前节点数 20（backend=uia）
      ControlType：GroupControl=15, WindowControl=1, PaneControl=1, ToolBarControl=1, ButtonControl=1
```

### 3.7 `uiaunlock verify --pid 95344`（可逆跳变）

```text
provider：wxwork_duilib（置信度 1.00，进程内可热开）
目标：pid=95344，窗口 class='WeWorkWindow'

可逆跳变成立：关=2 → 开=20（原状态为开，已保持开启）

阶段              开关      节点数     backend
初始状态            True    20      uia
强制关闭            False   2       uia
强制打开            True    20      uia

原始状态：on  恢复为：on(already)

结论：可逆验证通过
```

### 3.8 真实 UI 操作验证（解锁后才做得到）

解锁后，用 UIA 找到搜索框并输入文本、读回值（验证完已清空，没有发任何消息）：

```text
edit: '搜索' EditControl (430,168,569,190)[139x22]
name= '搜索' value= 'aaa'
name= '搜索' value= 'aaaaaa'
value= '空白'          # 退格清空后回到占位文字
```

> 输入方式说明：企业微信的搜索框是 DuiLib 自绘控件，没有自己的 HWND。
> `uiautomation.SendKeys` 在本机没有把字符送进去（焦点/前台策略所致），
> 改为向主窗口 `HWND` 发送 `WM_CHAR(0x0102)` 才生效，读回 `ValuePattern.Value` 得到 `aaa`。
> 这说明"树出来了"和"控件真的可读可写"是两件事，验收必须做后者。

---

## 4. 从安装到跑通的完整流程（以企业微信为例）

```powershell
# 0) 前置：目标程序已启动并显示主窗口；当前终端与目标同权限（都用普通用户或都用管理员）
cd uiaunlock          # 进入本仓库目录
pip install -e ".[uia]"

# 1) 环境自检：看位数、管理员、uiautomation、屏幕阅读器标志
uiaunlock doctor

# 2) 只读诊断：能不能识别框架、当前节点数多少、推荐哪个 provider
uiaunlock scan --exe "<WXWORK_EXE>"

# 3) 先看计划，不执行
uiaunlock unlock --exe "<WXWORK_EXE>" --dry-run

# 4) 真正执行（会打印计划 -> 执行 -> 复核节点数）
uiaunlock unlock --pid 95344 --yes

# 5) 证明可逆（关→开→恢复），这一步才是"验收"
uiaunlock verify --pid 95344

# 6) 需要留档时写 JSON 报告
uiaunlock diagnose --pid 95344 --out .\docs\sample_report.json
```

判断"真的成功"的三个条件（缺一不可）：

1. `unlock` 报告 `节点数：N -> M`，且 `M >= 10`，`M` 明显大于 `N`；
2. `verify` 报告两个方向都能跳变（关得住、开得回来）；
3. 能用 UIA **操作**一个控件并读回结果（例如输入文本后 `ValuePattern.Value` 等于输入内容）。

---

## 5. 在脚本里调用库

```python
"""把 uiaunlock 当成普通库用：诊断 -> 计划 -> 解锁 -> 验证 -> 真实操作。"""
import os

import uiaunlock
from uiaunlock import providers

# 先设置环境变量再运行，避免把本机路径写死：
#   PowerShell: $env:WXWORK_EXE = "<WXWORK_EXE>"
EXE = os.environ["WXWORK_EXE"]

# 1) 只读扫描（不修改目标进程）
result = uiaunlock.scan(exe=EXE)
print(result.ctx.brief())
print("结论：", result.verdict["summary"])
print("节点数：", result.ctx.node_total, "backend=", result.ctx.node_count.backend)
for provider, score in result.scores:
    print(f"  {provider.id:20s} {score:.2f}  {provider.kind_for(result.ctx)}")

# 2) 拿计划（纯预览）
ctx, provider, score, plan = uiaunlock.make_plan(exe=EXE)
print(plan.describe())
if not plan.allowed:
    raise SystemExit("方案被拒绝：" + plan.reason)

# 3) 执行解锁（默认 dry_run=False；建议先 dry_run=True 预览一次）
res = uiaunlock.unlock(exe=EXE)
print(res.ok, res.before_nodes, "->", res.after_nodes, res.message)

# 4) 可逆验证
v = uiaunlock.verify(exe=EXE)
print(v.ok, v.reversible, v.message)

# 5) 解锁后做真实 UI 操作（需要 uiautomation）
import ctypes, time, uiautomation as auto

hwnd = ctx.hwnd
w = auto.ControlFromHandle(hwnd)
edit = w.EditControl(searchDepth=16)          # 企业微信左上角搜索框
print("找到控件：", edit.Name, edit.ControlTypeName)

# 说明：DuiLib 自绘编辑框没有独立 HWND，键盘输入要发给主窗口
user32 = ctypes.windll.user32
user32.SendMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint,
                                ctypes.c_void_p, ctypes.c_void_p]
edit.Click()
for ch in "aaa":
    user32.SendMessageW(hwnd, 0x0102, ctypes.c_void_p(ord(ch)), 0)  # WM_CHAR
    time.sleep(0.05)
time.sleep(0.6)
print("读回：", edit.GetValuePattern().Value)  # -> 'aaa'

# 清理：退格清空，不要留下文字
for _ in range(6):
    user32.SendMessageW(hwnd, 0x0100, ctypes.c_void_p(0x08), 0)                  # WM_KEYDOWN VK_BACK
    user32.SendMessageW(hwnd, 0x0101, ctypes.c_void_p(0x08), ctypes.c_void_p(0xC0000001))
print("清理后：", edit.GetValuePattern().Value)  # -> '空白'（占位文字）
```

只想按 provider 名字精确调用时：

```python
from uiaunlock.providers.registry import best
ctx, score, plan = None, None, None
p, s = best(ctx, "wxwork_duilib")   # 指定 id；不存在会抛 LookupError
```

查看所有 provider：

```python
for p in providers.get_providers():
    print(p.id, p.kind, p.priority, p.display_name)
```

---

## 6. 能力边界

- **只支持 Windows**。UIA / MSAA / `WM_GETOBJECT` / `CreateRemoteThread` 都是 Win32 概念。
- **必须与目标同权限**。目标以管理员运行时，本库也要以管理员运行，否则 `OpenProcess` 会报拒绝访问。
- **位数不需要一致，但地址要按目标位数处理**：64 位宿主可以枚举 32 位进程的模块（`LIST_MODULES_ALL`），
  远程线程地址必须落在目标进程地址空间（32 位目标地址 `< 0x7FFF0000`）。
- **`in_process` 只对"当前进程生命周期"有效**。目标重启后要重新 `unlock`。
- **`startup` 永远不能热开**。Qt 实测进程内调 `QAccessible::setActive(true)` 无效（节点 7→7）。
- **窗口必须可见且未最小化**。最小化时所有应用都只有 1 个节点，别把这个当成"没解锁"。
- **RVA 与版本绑定**。每次运行都会重新解析目标的导出表，但导出名/行为本身随版本可能变化；
  升级后请重跑 `scan` 与 `verify`。
- 不认识的目标：`generic` provider 只做只读探查（列模块、查导出关键字），**绝不调用任何函数**。

---

## 7. 常见报错与处理

| 报错 / 现象 | 原因 | 处理 |
|---|---|---|
| `OpenProcess ... err=5` | 权限不足（目标以管理员运行） | 用管理员终端重跑；企业微信是普通权限时不要提权 |
| `CreateRemoteThread ... err=5` | 安全软件拦截 / 权限不足 | 换普通用户或加白；先 `--dry-run` 确认地址正确 |
| `OpenProcess ... err=87` | 进程已退出 / pid 错误 | 重新 `doctor` 拿新 pid |
| `无法枚举 pid=... 的模块` | 位数/权限问题 | 确认用 `LIST_MODULES_ALL`（库已固定）；确认同权限 |
| `目标进程未加载 duilib.dll` | 企业微信版本不同 / 不是主进程 | 用 `--exe` 让库自动挑"有主窗口的进程" |
| `duilib.dll 缺少关键导出` | 版本不受支持 | 重新走一遍 `docs/VERIFICATION_PROTOCOL.md`，或先提 issue |
| `没有识别出可信的 provider（最高分 ...）` | 框架未知 | `scan` 看模块列表；确需尝试时显式 `--provider generic`（仍不会执行） |
| `节点数：N -> 1` / 一直 1 | 窗口被最小化或隐藏 | 恢复窗口；确认 `visible=True iconic=False` |
| 节点数涨了但控件仍抓不到 | 只开了半数开关 | 三件套一起切（business / whitelist / SetEnabled），再 `TriggerAtProbe` |
| `pid=... 没有可用的顶层窗口` | 选到了后台/托盘进程 | 用 `--exe`；或先打开主界面 |
| `uiautomation` 未安装导致"无法确认" | 计数降级为 MSAA | `pip install "uiaunlock[uia]"` |
| `SetEnabled(false)` 后树还在 | 只关总开关不够 | 本库已把 business/whitelist 一起置 0（实测必须这样） |
| `UiaRootObjectId(-25)=0` 但能看到控件 | Qt5 只提供 MSAA | 正常现象，不要据此判定"不支持" |

---

## 8. 风险与安全

- `unlock` 会在目标进程里创建远程线程执行代码。**地址算错 = 目标崩溃**。
  所以本库每次都重新解析导出表，并在执行前打印模块/导出名/RVA/绝对地址/参数。
- 库不修改影刀目录、不写注册表、不改系统全局配置。
  唯一的全局性建议（`setx QT_ACCESSIBILITY 1`）只出现在 `startup` 计划的文字里，需要用户自己执行。
- 被调试/被保护的目标（反作弊、部分安全软件）请不要使用。
- 用完后可以用 `verify` 的"恢复到原始状态"逻辑把开关切回去；`unlock` 本身是幂等的。

---

## 9. 目录与文档

```text
uiaunlock/
├─ pyproject.toml
├─ README.md
├─ LICENSE                       # MIT
├─ docs/
│  ├─ VERIFICATION_PROTOCOL.md   # 新应用怎么验证解锁方法（可执行清单）
│  ├─ ADD_PROVIDER.md            # 验证成功后怎么加进库（可复制模板）
│  ├─ CASE_WXWORK.md             # 企业微信案例的记录
│  └─ sample_report.json         # diagnose 产出的真实报告样例（关态）
├─ src/uiaunlock/
│  ├─ __init__.py      # 公共 API：scan / diagnose / unlock / verify / providers / UnlockResult
│  ├─ api.py           # 上面这些函数的具体实现与安全闸门
│  ├─ w32.py           # 进程/窗口/模块/消息 薄封装（句柄全部 c_void_p）
│  ├─ pe.py            # 纯标准库 PE 导出表解析（磁盘文件 / 内存镜像）
│  ├─ remote.py        # CreateRemoteThread + 超时 + 读回返回值
│  ├─ probe.py         # WM_GETOBJECT 三种 objid、AccessibleObjectFromWindow、节点计数
│  ├─ context.py       # TargetContext：框架识别 + 一次采集的全部观测值
│  ├─ report.py        # 结构化 JSON 报告 + 中文摘要 + 结论
│  ├─ cli.py           # list/scan/diagnose/unlock/verify/doctor
│  └─ providers/
│     ├─ base.py       # Provider 协议、Plan / UnlockResult / VerifyResult
│     ├─ registry.py   # 内置 + entry_points 自动发现
│     ├─ wxwork_duilib.py   # 已验证：企业微信 DuiLib 进程内解锁
│     ├─ qt_startup.py      # Qt 5/6：只给启动期建议
│     ├─ cef_electron.py    # Chromium/CEF/Electron：只给启动期建议
│     └─ generic.py         # 兜底只读探查
└─ tests/              # pytest：PE 解析、provider 注册/选择、plan 文案、CLI 参数
```

下一步：

- 新应用怎么验证 → [docs/VERIFICATION_PROTOCOL.md](docs/VERIFICATION_PROTOCOL.md)
- 验证成功后怎么加 provider → [docs/ADD_PROVIDER.md](docs/ADD_PROVIDER.md)

---

## 10. 许可证

MIT License，见仓库根目录 [LICENSE](LICENSE)。可自由修改、商用、再发布，保留版权与许可声明即可。
