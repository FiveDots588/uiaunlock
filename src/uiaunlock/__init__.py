"""uiaunlock —— 诊断并解锁 Windows 自绘 UI 框架的 UIA 无障碍树。

最常用的四个入口：

    from uiaunlock import scan, diagnose, unlock, verify

    r = scan(exe=r"<WXWORK_EXE>")   # 换成目标 exe 的实际路径
    print(r.verdict["summary"])

    res = unlock(pid=95344)          # 只对 in_process provider 生效
    print(res.ok, res.before_nodes, res.after_nodes)

命令行用法见 ``README.md``，或直接运行 ``uiaunlock --help``。
"""
from __future__ import annotations

from .api import ScanResult, diagnose, make_plan, scan, unlock, verify
from .context import TargetContext, TargetError, resolve_target
from .providers import Provider, registry
from .providers.base import (
    KIND_IN_PROCESS,
    KIND_LABELS,
    KIND_STARTUP,
    KIND_UNSUPPORTED,
    Plan,
    ProviderError,
    UnlockResult,
    VerifyResult,
)

__version__ = "0.1.0"

__all__ = [
    # 公共 API
    "scan",
    "diagnose",
    "unlock",
    "verify",
    "make_plan",
    "providers",
    # 结果类型
    "ScanResult",
    "TargetContext",
    "Plan",
    "UnlockResult",
    "VerifyResult",
    # 异常
    "TargetError",
    "ProviderError",
    # 常量
    "KIND_IN_PROCESS",
    "KIND_STARTUP",
    "KIND_UNSUPPORTED",
    "KIND_LABELS",
    "Provider",
    "registry",
    "resolve_target",
    "__version__",
]

# ``uiaunlock.providers`` 既是子包，也是"provider 注册表"的入口。
# 这里显式导出子包模块，方便 `from uiaunlock import providers; providers.get_providers()`。
from . import providers  # noqa: E402  (放在末尾避免循环导入)
