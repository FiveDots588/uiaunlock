"""探针与 CLI 参数解析测试。"""
from __future__ import annotations

import ctypes

import pytest

from uiaunlock import cli, probe
from uiaunlock.remote import RemoteCallError, validate_address


def test_probe_constants():
    assert probe.OBJID_CLIENT == -4
    assert probe.OBJID_WINDOW == 0
    assert probe.UIA_ROOT_OBJECT_ID == -25
    assert probe.WM_GETOBJECT == 0x003D


def test_variant_size_matches_host():
    """VARIANT 大小必须与平台一致，否则 AccessibleChildren 会写坏内存。"""
    expected = 24 if ctypes.sizeof(ctypes.c_void_p) == 8 else 16
    assert ctypes.sizeof(probe.VARIANT) == expected


def test_validate_address_rejects_null():
    import os
    pid = os.getpid()
    with pytest.raises(RemoteCallError) as exc:
        validate_address(pid, 0)
    assert "空指针" in str(exc.value) or "太小" in str(exc.value)


def test_validate_address_accepts_normal():
    import os
    pid = os.getpid()
    validate_address(pid, 0x10000000)  # 不抛异常即可


def test_parser_scan_args():
    parser = cli.build_parser()
    args = parser.parse_args(["scan", "--exe", r"C:\Tools\WXWork.exe", "--depth", "8"])
    assert args.command == "scan"
    assert args.exe.endswith("WXWork.exe")
    assert args.depth == 8
    assert args.json is False


def test_parser_hwnd_hex():
    parser = cli.build_parser()
    args = parser.parse_args(["scan", "--hwnd", "0x2506D8"])
    assert args.hwnd == 0x2506D8


def test_parser_unlock_defaults():
    parser = cli.build_parser()
    args = parser.parse_args(["unlock", "--pid", "95344"])
    assert args.dry_run is False
    assert args.yes is False
    assert args.provider is None


def test_help_exits_zero():
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0


def test_list_command(capsys):
    code = cli.main(["list"])
    out = capsys.readouterr().out
    assert code == 0
    assert "wxwork_duilib" in out
    assert "qt_startup" in out
    assert "in_process" in out


def test_scan_rejects_missing_target(capsys):
    """不给目标时必须是参数错误，而不是随便猜一个进程。"""
    code = cli.main(["scan"])
    assert code == 1
    assert "[错误]" in capsys.readouterr().err
