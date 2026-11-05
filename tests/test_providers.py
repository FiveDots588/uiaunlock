"""provider 注册、识别与计划文案测试（不需要真实目标进程）。"""
from __future__ import annotations

import os

import pytest

from uiaunlock.providers import registry
from uiaunlock.providers.base import KIND_IN_PROCESS, KIND_STARTUP, KIND_UNSUPPORTED
from uiaunlock.w32 import ModuleInfo

from conftest import FakeContext, candidate_wxwork_dirs


DUILIB_EXPORTS = [
    "?SetFeatureEnabledByBusiness@CAccessibilityNotifier@DuiLib@@SAX_N@Z",
    "?SetAtWhitelistAuthorized@CAccessibilityNotifier@DuiLib@@SAX_N@Z",
    "?SetEnabled@CAccessibilityNotifier@DuiLib@@SAX_N@Z",
    "?TriggerAtProbe@CAccessibilityNotifier@DuiLib@@SAXXZ",
]


def _find_duilib() -> str:
    """在常见安装路径下找 duilib.dll；找不到返回空字符串（相关测试 skip）。"""
    for root in candidate_wxwork_dirs():
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                if name.lower() == "duilib.dll":
                    return os.path.join(dirpath, name)
    return ""


def test_builtin_registry():
    providers = registry.get_providers()
    ids = [p.id for p in providers]
    assert "wxwork_duilib" in ids
    assert "qt_startup" in ids
    assert "cef_electron" in ids
    assert "generic" in ids
    # priority 降序：wxwork_duilib 应该在最前面
    assert providers[0].id == "wxwork_duilib"
    assert not registry.LOAD_ERRORS


def test_kinds():
    by_id = {p.id: p for p in registry.get_providers()}
    assert by_id["wxwork_duilib"].kind == KIND_IN_PROCESS
    assert by_id["qt_startup"].kind == KIND_STARTUP
    assert by_id["cef_electron"].kind == KIND_STARTUP
    assert by_id["generic"].kind == KIND_UNSUPPORTED


def test_wxwork_detect_without_duilib():
    ctx = FakeContext()
    by_id = {p.id: p for p in registry.get_providers()}
    assert by_id["wxwork_duilib"].detect(ctx) == 0.0


def test_wxwork_detect_with_duilib_module():
    ctx = FakeContext(
        modules=[ModuleInfo(name="duilib.dll", path="", base=0x10000000)],
        window_class="WeWorkWindow",
    )
    by_id = {p.id: p for p in registry.get_providers()}
    score = by_id["wxwork_duilib"].detect(ctx)
    # 只加载了 duilib + 窗口类命中（导出不可读）：0.45 + 0.25
    assert 0.6 <= score <= 0.8


def test_wxwork_plan_and_exports():
    path = _find_duilib()
    if not path:
        pytest.skip("本机没有企业微信 duilib.dll")
    ctx = FakeContext(
        modules=[ModuleInfo(name="duilib.dll", path=path, base=0x71100000)],
        window_class="WeWorkWindow",
        nodes=3,
    )
    by_id = {p.id: p for p in registry.get_providers()}
    provider = by_id["wxwork_duilib"]
    assert provider.detect(ctx) > 0.9

    plan = provider.plan(ctx)
    assert plan.allowed, plan.reason
    assert len(plan.actions) == 4
    names = [a.export for a in plan.actions]
    for name in DUILIB_EXPORTS:
        assert name in names
    # 地址必须等于 基址 + RVA
    for action in plan.actions:
        assert action.address == 0x71100000 + action.rva
    text = plan.describe()
    assert "远程调用" in text
    assert "0x711" in text.lower()


def test_qt_kind_downgrade():
    from uiaunlock.providers.qt_startup import QtStartupProvider

    provider = QtStartupProvider()
    ctx = FakeContext(
        modules=[ModuleInfo(name="Qt5Core.dll", path="", base=0x10000000)],
        window_class="Qt5QWindowIcon",
        framework="qt5",
        nodes=7,
        control_types={"WindowControl": 1, "PaneControl": 6},
    )
    assert provider.detect(ctx) > 0.8
    assert provider.kind_for(ctx) == KIND_UNSUPPORTED

    ctx.node_count.control_types = {"ButtonControl": 40, "EditControl": 5}
    ctx.node_count.count = 51
    assert provider.kind_for(ctx) == KIND_STARTUP
    plan = provider.plan(ctx)
    assert "QT_ACCESSIBILITY" in "\n".join(plan.startup)
    assert not plan.allowed  # 启动期方案不允许 unlock 执行


def test_cef_detect_and_plan():
    from uiaunlock.providers.cef_electron import CefElectronProvider

    provider = CefElectronProvider()
    ctx = FakeContext(
        modules=[ModuleInfo(name="libcef.dll", path="", base=0x10000000)],
        window_class="Chrome_WidgetWin_1",
        framework="cef",
    )
    assert provider.detect(ctx) > 0.9
    plan = provider.plan(ctx)
    assert "--force-renderer-accessibility" in "\n".join(plan.startup)
    assert not plan.allowed


def test_generic_is_read_only():
    from uiaunlock.providers.generic import GenericProvider

    provider = GenericProvider()
    ctx = FakeContext(framework="unknown", nodes=1)
    assert provider.detect(ctx) == pytest.approx(0.35)
    plan = provider.plan(ctx)
    assert plan.kind == KIND_UNSUPPORTED
    assert not plan.allowed
    assert not plan.actions
    assert "docs/ADD_PROVIDER.md" in "\n".join(plan.steps)


def test_best_prefers_wxwork():
    path = _find_duilib()
    ctx = FakeContext(
        modules=[ModuleInfo(name="duilib.dll", path=path, base=0x71100000)],
        window_class="WeWorkWindow",
        nodes=3,
    )
    chosen, score = registry.best(ctx)
    assert chosen.id == "wxwork_duilib"
    assert score >= 0.9


def test_best_unknown_raises():
    ctx = FakeContext(framework="unknown", nodes=1)
    with pytest.raises(LookupError):
        registry.best(ctx)
