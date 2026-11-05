"""uiaunlock.providers —— 内置 provider 与注册表。

导入本包即可拿到 :func:`get_providers` / :func:`detect` / :func:`best`。
"""
from . import registry
from .base import (
    KIND_IN_PROCESS,
    KIND_LABELS,
    KIND_STARTUP,
    KIND_UNSUPPORTED,
    Plan,
    PlannedAction,
    Provider,
    ProviderError,
    UnlockResult,
    VerifyResult,
)
from .cef_electron import CefElectronProvider
from .generic import GenericProvider
from .qt_startup import QtStartupProvider
from .wxwork_duilib import WxWorkDuiLibProvider

__all__ = [
    "registry",
    "Provider",
    "Plan",
    "PlannedAction",
    "UnlockResult",
    "VerifyResult",
    "ProviderError",
    "KIND_IN_PROCESS",
    "KIND_STARTUP",
    "KIND_UNSUPPORTED",
    "KIND_LABELS",
    "WxWorkDuiLibProvider",
    "QtStartupProvider",
    "CefElectronProvider",
    "GenericProvider",
    "get_providers",
    "detect",
    "best",
]

get_providers = registry.get_providers
detect = registry.detect
best = registry.best
