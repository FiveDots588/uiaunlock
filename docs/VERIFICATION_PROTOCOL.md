# 新应用如何验证"解锁 UIA 树"的方法

目标：面对一个"UIA 只能看到 1~2 个节点 / 只有一圈原生边框"的新应用，
用最短路径判断它属于哪一类问题、有没有可用的解锁方法，并产出**可复核的证据**。

本文所有命令都可直接复制执行；把 `<EXE>` 换成目标程序路径。

---

## 0. 准备与铁律

```powershell
uiaunlock doctor
uiaunlock scan --exe "<EXE>"
```

铁律：

1. **先造出"失败态"再谈成功**。没有关态的对照，任何"解锁成功"都不算证据。
2. **窗口必须可见、未最小化**。最小化时所有应用都只有 1 个节点。
3. **同一进程才有意义**。两次测量必须落在同一个 pid / 同一个 hwnd 上。
4. **记录版本号**。目标升级后 RVA、导出名、行为都可能变，结论要重测。

---

## 1. 建立失败态基线（只读）

要求：目标主窗口已显示（`visible=True`、`iconic=False`）。

```powershell
uiaunlock scan --exe "<EXE>" --depth 8
uiaunlock diagnose --exe "<EXE>" --out baseline.json
```

必须记录以下几项（`scan` / `diagnose` 已自动包含，JSON 里在 `target` 下）：

| 字段 | 为什么要记 |
|---|---|
| `nodes.count` + `nodes.backend` | 基线节点数；backend 必须是 `uia`，否则结论不可信 |
| `nodes.control_types` | ControlType 分布：只有一个 Window/Pane 说明树是空的 |
| `probes[OBJID_CLIENT].lresult` | 通常为 `0x0`（关）或非零对象指针（开） |
| `probes[OBJID_WINDOW].lresult` | `WM_GETOBJECT(0)` 的返回值 |
| `probes[UiaRootObjectId].lresult` | `-25`；Qt5 恒为 0 属正常 |
| `probes[*].accessible_hr` | `AccessibleObjectFromWindow` 的 HRESULT，`0x80004002`(E_NOINTERFACE) 表示该 objid 不给 MSAA 接口 |
| `window.class` / `exe_version` | 证据的一部分，换版本要重测 |
| `host.screen_reader` | 屏幕阅读器标志，影响 Qt/Chromium 的默认行为 |

判定：

- `count <= 2` → **空树**，几乎一定是特性开关（feature gate）关闭；
- `count` 在 3~9 → **只有框架壳**（标题栏/边框/滚动条），自绘控件未暴露；
- `count >= 10` 且能看到 `Button/Edit/List/Tree` → 树本来可用，不要继续"解锁"。

---

## 2. 识别框架

来源优先级：**模块名 > 窗口类名 > 字符串/导出表 > 人工判断**。

```powershell
uiaunlock scan --exe "<EXE>" --json | findstr /i "modules framework"
```

对照表：

| 现象 | 框架 | 典型判据 |
|---|---|---|
| 加载 `duilib.dll`；窗口类 `WeWorkWindow` | DuiLib（DirectUI） | 企业微信等 |
| 加载 `Qt5Core.dll` / `Qt6Core.dll`；窗口类以 `Qt` 开头 | Qt 5 / 6 | `Qt51517QWindowToolSaveBits` |
| 加载 `libcef.dll` / `chrome_elf.dll`；窗口类 `Chrome_WidgetWin_*` | CEF / Electron | 钉钉旧版、VSCode |
| 加载 `jvm.dll` | Java（Swing/SWT） | 需要 Java Access Bridge |
| 加载 `flutter_windows.dll` | Flutter | 需 `SemanticsBinding` |
| 加载 `UnityPlayer.dll` | Unity | 通常无解 |
| 只有系统 DLL + 标准类名 | Win32 原生 | 树本来就有，别乱动 |

补充手段（只读）：

```powershell
# 看进程加载的全部模块（含 32 位，需要 LIST_MODULES_ALL；库已处理）
uiaunlock scan --exe "<EXE>" --json | more
```

如果模块名被改名/加密，再考虑：
- 窗口类名（`GetClassName`）；
- 进程目录下的 DLL 文件名；
- `strings` 搜 `Accessibility` / `ScreenReader` / `UIA`；
- 解析候选模块导出表（`generic` provider 已做，见 `uiaunlock scan` 的 provider 列表）。

---

## 3. 判断症状层级（决定走哪条路）

| 层级 | 表现 | 走哪条 |
|---|---|---|
| a. 空树（1~2 节点） | 只有 `WindowControl`+`PaneControl` | 特性开关关闭 → 先试启动期，再试进程内 |
| b. 只有框架壳（3~9 节点） | 有 `TitleBar/MenuBar/ScrollBar`，没有业务控件 | 同上；多半是自绘控件没注册 provider |
| c. 能看到部分控件 | 有 `Button/Edit` 但缺一块 | 可能是虚拟化/懒加载 → 滚动/展开后再测，不一定要"解锁" |

对应 provider 类型：

- a/b 且框架是 **DuiLib** → 很可能有进程内静态开关（`in_process`）；
- a/b 且框架是 **Qt** → 只能启动期（`startup`），实测热调 `QAccessible::setActive(true)` 无效；
- a/b 且框架是 **CEF/Electron** → 启动期（`--force-renderer-accessibility` 或 CDP）；
- c → 先别解锁，先确认是不是懒加载。

---

## 4. 先试启动期开关（成本最低、最安全）

思路：用环境变量 / 命令行 / 注册表让程序"从一开始就以无障碍模式启动"。

```powershell
# Qt 例子：带环境变量重启，观察节点数是否变化
$env:QT_ACCESSIBILITY = "1"
& "<EXE>"
# 另开一个终端
uiaunlock scan --exe "<EXE>"
```

```powershell
# Chromium/Electron 例子
& "<EXE>" --force-renderer-accessibility
# 或开 CDP：--remote-debugging-port=9222 然后 Accessibility.enable
```

**验收关键：必须先能造出"关态"。**

- 能关（不带变量启动 → 节点少）再能开（带变量启动 → 节点多）→ **差分成立**；
- 如果关不掉（不带变量也一样多）→ **只能标记"未能差分"**，不要写"已验证"。
  常见原因：机器 `SPI_GETSCREENREADER=TRUE`、注册表已全局打开、应用自身默认开启。

记录：两次启动的 pid、节点数、`WM_GETOBJECT` lresult、ControlType 分布，全部写进 JSON。

---

## 5. 再试进程内调用（只对"有静态开关导出"的框架）

前提：导出表里能找到形如
`?SetEnabled@CAccessibilityNotifier@...@@SAX_N@Z` / `?EnableXXX@@SAXXZ` 的静态函数。

步骤：

```powershell
# 1) 先确认导出存在（只读）
uiaunlock scan --exe "<EXE>"
# generic provider 会把候选模块的可疑导出列出来

# 2) 生成计划，看清要调用什么（不执行）
uiaunlock unlock --exe "<EXE>" --provider generic --dry-run
# 专用 provider 写好后则是：
uiaunlock unlock --exe "<EXE>" --dry-run

# 3) 真正执行
uiaunlock unlock --pid <PID> --yes

# 4) 立刻复核（不要只看"没报错"）
uiaunlock scan --pid <PID>
```

自己写实验代码时，关键点：

- `CreateRemoteThread(addr = module_base + RVA, lpParameter = arg)`；
- bool 参数按 1 字节传（x86 调用约定下 `SetEnabled(true)` 就是传 `1`）；
- 地址必须在目标进程地址空间内（32 位目标 `< 0x7FFF0000`）；
- 调用后必须 `TriggerAtProbe()`（或等价"通知"函数），否则树可能不会重建；
- **关闭往往要关多个位**：企业微信实测只 `SetEnabled(false)` 树不塌，必须把
  `SetFeatureEnabledByBusiness(false)` / `SetAtWhitelistAuthorized(false)` 一起置 0。

---

## 6. 验收三件套（缺一不可）

1. **同一进程 A/B 可逆跳变**
   ```powershell
   uiaunlock verify --pid <PID>
   ```
   期望：`关=2 → 开=20 → （原状态关则再关=2）`，且报告 `reversible=true`。

2. **探针层面的变化**
   `WM_GETOBJECT(OBJID_CLIENT)` 的 lresult 从 `0x0` 变成非零（本次实测 `0xC13F`），
   或 `AccessibleObjectFromWindow` 的 HRESULT 从 `0x80004002` 变为 `0x0`。

3. **真实 UI 操作**
   不是"树里有 Edit 就算"，而是能输入并读回：
   ```text
   找到 '搜索' EditControl -> 输入 aaa -> ValuePattern.Value == 'aaa' -> 清空
   ```
   注意 DuiLib 的编辑框没有独立 HWND，键盘事件要发给**主窗口**
   （`SendMessage(hwnd, WM_CHAR, ...)`）；清空后确认值回到占位文字。

---

## 7. 记录证据

```powershell
uiaunlock diagnose --pid <PID> --out .\evidence\<app>-<version>-on.json
uiaunlock diagnose --pid <PID> --out .\evidence\<app>-<version>-off.json   # 关态
```

一份合格记录包含：

- 时间、exe 路径、版本号、pid、位数、窗口类/标题、窗口尺寸；
- 加载的 GUI 框架模块（名字 + 基址 + 路径）；
- 三种 `WM_GETOBJECT` 的 lresult + `AccessibleObjectFromWindow` 的 HRESULT；
- 节点数前后对比 + ControlType 分布；
- 结论与置信度，且每条结论注明 **实测 / 推断**；
- 截图（开/关各一张）与执行日志；
- 复现命令（能照着重新跑一遍）。

---

## 8. 常见假阳性（务必排除）

| 假象 | 真相 |
|---|---|
| 窗口最小化/隐藏时节点数为 1 | 所有应用都这样，与无障碍开关无关 |
| `UiaRootObjectId(-25)` 返回 0 | Qt5 只提供 MSAA，这是正常的，不代表"不支持" |
| "远程调用没崩" 就宣布成功 | 调用成功 ≠ 树出来，必须看节点数 |
| 只测一次就下结论 | 没有关态对照，无法排除"本来就能用" |
| 节点数涨了但控件抓不到 | 可能只开了部分开关，或树没重建（缺 Trigger） |
| `IsEnabled` 导出读回 True 就认为已开 | 企业微信实测它恒为 True，不可靠，只能看节点数 |
| 换了个 pid 测"前后" | 不同进程的树完全不同，必须同 pid/同 hwnd |
| 屏幕阅读器标志为 TRUE 的机器上测 Qt | Qt 可能默认已激活，测不出差异；先记录并还原该标志 |

---

## 最短路径总结

```text
doctor -> scan（记基线 + 认框架）
      -> 试 startup（能造出关态才算证明）
      -> 有静态开关导出 -> plan(dry-run) -> unlock -> verify
      -> 三件套通过 -> diagnose 出 JSON -> 写 provider（见 ADD_PROVIDER.md）
```
