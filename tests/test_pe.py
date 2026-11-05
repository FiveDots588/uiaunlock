"""PE 导出解析测试（离线，用系统 DLL 作为 fixture）。"""
from __future__ import annotations

import os

import pytest

from uiaunlock import pe

from conftest import candidate_wxwork_dirs


KERNEL32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "kernel32.dll")


@pytest.mark.skipif(not os.path.exists(KERNEL32), reason="找不到 System32/kernel32.dll")
def test_parse_exports_kernel32():
    table = pe.parse_exports_file(KERNEL32)
    assert table.machine_name in ("x64", "x86", "arm64")
    assert len(table.entries) > 100, "kernel32 导出表应该有大量符号"
    # 这些是 kernel32 长期稳定的导出
    assert "CreateFileW" in table.entries
    assert "GetLastError" in table.entries
    # RVA 应该在镜像范围内且非 0
    assert all(rva > 0 for rva in table.entries.values())


@pytest.mark.skipif(not os.path.exists(KERNEL32), reason="找不到 System32/kernel32.dll")
def test_select_and_keywords():
    table = pe.parse_exports_file(KERNEL32)
    selected = table.select(["CreateFileW", "NotExistSymbol"])
    assert list(selected.keys()) == ["CreateFileW"]
    hits = pe.find_matching_exports(table, ["file"])
    assert any("File" in name for name in hits)


@pytest.mark.skipif(not os.path.exists(KERNEL32), reason="找不到 System32/kernel32.dll")
def test_image_metadata():
    meta = pe.parse_image_metadata_file(KERNEL32)
    assert meta["machine"] in (pe.MACHINE_X86, pe.MACHINE_X64, pe.MACHINE_ARM64)
    assert meta["is_64"] in (True, False)


def test_not_a_pe(tmp_path):
    bad = tmp_path / "bad.dll"
    bad.write_bytes(b"this is not a PE file")
    with pytest.raises(pe.PEError):
        pe.parse_exports_file(str(bad))


def test_duilib_exports_if_present():
    """如果本机装了企业微信，顺带验证目标 DLL 的导出能被解析出来。"""
    found = []
    for root in candidate_wxwork_dirs():
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                if name.lower() == "duilib.dll":
                    found.append(os.path.join(dirpath, name))
    if not found:
        pytest.skip("本机没有企业微信的 duilib.dll")
    table = pe.parse_exports_file(found[0])
    names = [
        "?SetEnabled@CAccessibilityNotifier@DuiLib@@SAX_N@Z",
        "?TriggerAtProbe@CAccessibilityNotifier@DuiLib@@SAXXZ",
    ]
    hit = table.select(names)
    assert hit, f"未在 {found[0]} 中找到 CAccessibilityNotifier 导出"
