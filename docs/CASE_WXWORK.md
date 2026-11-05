# 案例：企业微信（DuiLib）进程内解锁

本案例是库中 `wxwork_duilib` provider 的来源。所有数字均为本机实测。

## 环境

| 项 | 值 |
|---|---|
| 系统 | Windows 11 |
| 宿主 Python | 3.14.0，64 位 |
| 目标 | 企业微信 `5.0.13.6005`，`<WXWORK_EXE>`（默认安装路径因机器而异） |
| 目标位数 | 32 位 |
| 窗口 | `hwnd` 随启动变化（本次 `0x2506D8`），`class='WeWorkWindow'`，`title='企业微信'` |
| 权限 | 普通用户（非管理员） |
| `SPI_GETSCREENREADER` | True |
| 关键模块 | `duilib.dll`，本次基址 `0x71170000` |

## 症状

解锁前（同一进程、窗口已显示）：

```text
UIA 节点数：2（backend=uia）
  ControlType：WindowControl=1, PaneControl=1
WM_GETOBJECT(OBJID_CLIENT, -4) -> lresult=0x0
WM_GETOBJECT(OBJID_WINDOW,   0) -> lresult=0x0
WM_GETOBJECT(UiaRootObjectId, -25) -> lresult=0x0
AccessibleObjectFromWindow(OBJID_CLIENT) -> HRESULT=0x0（但没有可用的树）
```

结论：窗口只提供了一个空的根对象，业务控件全部不可见。

## 框架判定

- 加载 `duilib.dll` → DuiLib（DirectUI 自绘）；
- 窗口类 `WeWorkWindow` → 企业微信主窗口；
- 主界面无子 HWND，控件全部由 DuiLib 自绘。

## 开关在哪

`duilib.dll` 导出 `CAccessibilityNotifier` 的静态成员（MSVC 修饰名）：

| 导出 | RVA（本版本） | 作用 |
|---|---|---|
| `?SetFeatureEnabledByBusiness@CAccessibilityNotifier@DuiLib@@SAX_N@Z` | `0x31CC0` | 业务侧授权 |
| `?SetAtWhitelistAuthorized@CAccessibilityNotifier@DuiLib@@SAX_N@Z` | `0x31D00` | 白名单授权 |
| `?SetEnabled@CAccessibilityNotifier@DuiLib@@SAX_N@Z` | `0x31D90` | 总开关（AccessibilityFeatureGate） |
| `?TriggerAtProbe@CAccessibilityNotifier@DuiLib@@SAXXZ` | `0x31D70` | 立即触发探针通知 |
| `?IsEnabled@CAccessibilityNotifier@DuiLib@@SA_NXZ` | —— | 读回开关状态（**不可靠**） |

执行方式：`CreateRemoteThread(module_base + RVA, arg)`，参数 `true` 传 `1`，`Trigger` 传 `0`。

## 踩过的坑（重要）

1. **只调 `SetEnabled(false)` 树不会消失**（21 → 21）。
   关闭时必须把 `business` / `whitelist` 一起置 0，再 `TriggerAtProbe`，才会塌回 2~3 个节点。
2. **`IsEnabled` 导出恒为 `True`**，无法用它判断状态；判据只能是节点数。
3. **窗口最小化/隐藏时节点数是 1**，会被误判成"解锁失败"，必须先还原窗口。
4. **`AccessibleObjectFromWindow` 成功（HRESULT=0）也只是拿到了一个空对象**，
   不代表树可用；要看节点数与 `WM_GETOBJECT` 的 lresult。
5. DuiLib 编辑框没有独立 HWND，`SendKeys` 可能送不进去；本机改为向主窗口发 `WM_CHAR` 才生效。

## 验收证据

### A/B 可逆（`uiaunlock verify`）

```text
阶段              开关      节点数     backend
初始状态            True    20      uia
强制关闭            False   2       uia
强制打开            True    20      uia

结论：可逆验证通过
```

### 节点数与探针差分

| | 关态 | 开态 |
|---|---|---|
| UIA 节点数 | 2 | 20 |
| `WM_GETOBJECT(OBJID_CLIENT)` lresult | `0x0` | `0xC13F`（非零对象指针，每次不同） |
| ControlType | Window, Pane | Group×15, Window, Pane, ToolBar, Button, Custom |

### 真实 UI 操作

```text
edit: '搜索' EditControl (430,168,569,190)[139x22]
输入 aaa -> ValuePattern.Value == 'aaa'      # 读回成功
退格清空 -> '空白'                            # 恢复占位文字，没有发送任何消息
```

## 复现命令

```powershell
uiaunlock doctor
uiaunlock scan    --exe "<WXWORK_EXE>"
uiaunlock unlock  --pid <pid> --dry-run
uiaunlock unlock  --pid <pid> --yes
uiaunlock verify  --pid <pid>
uiaunlock diagnose --pid <pid> --out .\docs\sample_report.json
```

## 适用边界

- 仅对**当前进程生命周期**有效，企业微信重启后需重新 `unlock`；
- 版本升级后 RVA 会变 —— 本库每次都重新解析导出表，但导出名/行为仍可能变化，需重跑 `verify`；
- 目标以管理员运行时，本命令也需管理员；
- 部分安全软件会拦截 `CreateRemoteThread`。
