"""pytest 共享夹具：一个不依赖真实进程的最小上下文对象。

provider 的 detect/plan 只读 ctx 的少数字段（模块列表、窗口类、节点数），
所以测试里不需要真的启动企业微信/Qt 程序。
"""
from __future__ import annotations

import os
import sys
from typing import List, Optional

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from uiaunlock import w32  # noqa: E402
from uiaunlock.probe import NodeCount  # noqa: E402
from uiaunlock.w32 import ModuleInfo  # noqa: E402


def candidate_wxwork_dirs() -> List[str]:
    """运行时探测企业微信安装目录，避免把本机绝对路径写死进仓库。

    顺序：
    1. ``WXWORK_HOME`` 环境变量（CI/自定义安装位置时手动指定）；
    2. ``%ProgramFiles(x86)%\\WXWork`` / ``%ProgramFiles%\\WXWork``（默认安装位置）；
    3. 正在运行的 ``WXWork.exe`` 所在目录（最可靠，但要求进程在跑）。
    """
    roots: List[str] = []
    home = os.environ.get("WXWORK_HOME")
    if home:
        roots.append(home)
    for env in ("ProgramFiles(x86)", "ProgramFiles"):
        base = os.environ.get(env)
        if base:
            roots.append(os.path.join(base, "WXWork"))
    try:
        for pid in w32.find_pids_by_exe("WXWork.exe"):
            try:
                path = w32.process_image_path(pid)
            except Exception:
                path = ""
            if path:
                roots.append(os.path.dirname(path))
                break
    except Exception:
        pass
    return list(dict.fromkeys(roots))


class FakeContext:
    """最小可用的 TargetContext 替身。"""

    def __init__(
        self,
        modules: Optional[List[ModuleInfo]] = None,
        window_class: str = "",
        framework: str = "unknown",
        nodes: int = 0,
        control_types: Optional[dict] = None,
        bitness: int = 64,
    ) -> None:
        self.pid = os.getpid()  # 仅用于格式化，tests 不会真的远程调用
        self.hwnd = 0
        self.exe_path = ""
        self.exe_version = ""
        self.process_name = "python.exe"
        self.modules = modules or []
        self.window_class = window_class
        self.window = {"class": window_class, "title": "", "visible": True, "iconic": False}
        self.framework = framework
        self.bitness = bitness
        self.host_bitness = 64
        self.depth = 6
        self.node_count = NodeCount(
            count=nodes, backend="uia", control_types=control_types or {}
        )
        self.probes = []
        self.is_admin = False
        self.screen_reader = False
        self.uia_available = True
        self.notes: List[str] = []

    # 与 TargetContext 对齐的查询方法
    def module(self, name: str) -> Optional[ModuleInfo]:
        for m in self.modules:
            if m.name.lower() == name.lower():
                return m
        return None

    def modules_with_prefix(self, *prefixes: str) -> List[ModuleInfo]:
        return [
            m for m in self.modules
            if any(m.name.lower().startswith(p.lower()) for p in prefixes)
        ]

    def has_module(self, *names: str) -> bool:
        return any(self.module(n) is not None for n in names)

    @property
    def node_total(self) -> int:
        return self.node_count.count

    @property
    def framework_label(self) -> str:
        return self.framework

    @property
    def window_title(self) -> str:
        return ""

    def probe_hit(self, name: str):
        return None


@pytest.fixture
def fake_ctx():
    return FakeContext()
