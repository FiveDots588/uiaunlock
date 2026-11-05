"""uiaunlock.cli —— 命令行入口。

五个命令：``list`` / ``scan`` / ``diagnose`` / ``unlock`` / ``verify``，外加 ``doctor``。

退出码约定（方便脚本化）：
- 0：成功（scan 总是 0；unlock 节点数确实增长；verify 可逆成立）
- 1：参数错误 / 用户取消 / 目标定位失败
- 2：拒绝执行（未知 provider、导出缺失、非 in_process 方案）
- 3：执行了但没达到效果（节点数没涨、可逆验证不成立）
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import unicodedata
from typing import List, Optional

from . import __version__, api, report as report_mod, w32
from . import probe as probe_mod
from .providers import registry
from .providers.base import KIND_IN_PROCESS, KIND_LABELS


def _add_target_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--pid", type=int, help="目标进程 PID")
    p.add_argument("--exe", help="目标可执行文件路径或文件名（自动挑选有主窗口的进程）")
    p.add_argument(
        "--hwnd", type=lambda s: int(s, 0),
        help="目标窗口句柄（支持 0x 十六进制），优先级最高",
    )
    p.add_argument("--depth", type=int, default=6, help="UIA 遍历深度（默认 6）")


def _print_json(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def _pad(text: str, width: int) -> str:
    """按“显示宽度”补空格。

    坑：中文在等宽终端里占 2 列，直接用 f-string 的 ``:<20`` 会算成 1 列，
    导致表格错位。这里用 East Asian Width 估算真实列宽。
    """
    cells = sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in text)
    return text + " " * max(0, width - cells)


# ---------------------------------------------------------------- list


def cmd_list(args) -> int:
    providers = registry.get_providers()
    print(f"uiaunlock {__version__}  共 {len(providers)} 个 provider（含第三方 entry points）")
    print()
    print(_pad("ID", 20) + _pad("KIND", 26) + _pad("PRIORITY", 10) + "名称")
    print("-" * 96)
    for p in providers:
        kind = KIND_LABELS.get(p.kind, p.kind)
        print(_pad(p.id, 20) + _pad(kind, 26) + _pad(str(p.priority), 10) + p.display_name)
    print()
    print("说明：in_process = 可在运行中通过远程调用打开；"
          "startup = 必须在启动前设置（需重启）；unsupported = 只给建议，不做操作")
    if registry.LOAD_ERRORS:
        print()
        print("entry point 加载失败：")
        for name, err in registry.LOAD_ERRORS.items():
            print(f"  {name}: {err}")
    return 0


# ---------------------------------------------------------------- scan


def cmd_scan(args) -> int:
    try:
        result = api.scan(pid=args.pid, exe=args.exe, hwnd=args.hwnd, depth=args.depth)
    except Exception as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return 1

    if args.json:
        _print_json(result.to_dict())
        return 0
    print("\n".join(result.summary_lines()))
    return 0


# ---------------------------------------------------------------- diagnose


def cmd_diagnose(args) -> int:
    try:
        result = api.scan(pid=args.pid, exe=args.exe, hwnd=args.hwnd, depth=args.depth)
        report = report_mod.build_report(result.ctx, result.scores)
        path = report_mod.write_report(report, args.out)
    except Exception as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return 1

    if args.json:
        _print_json(report)
    else:
        print("\n".join(result.summary_lines()))
    print()
    print(f"报告已写入：{path}")
    print()
    print(report_mod.human_summary(report))
    return 0


# ---------------------------------------------------------------- unlock


def cmd_unlock(args) -> int:
    try:
        ctx, provider, score, plan = api.make_plan(
            pid=args.pid, exe=args.exe, hwnd=args.hwnd,
            provider=args.provider, depth=args.depth,
        )
    except LookupError as exc:
        print(f"[拒绝] {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return 1

    print(plan.describe())
    print()
    print(f"provider 置信度：{score:.2f}")

    if not plan.allowed:
        print("\n[拒绝] 计划不允许执行（见上方原因）", file=sys.stderr)
        return 2
    if provider.kind_for(ctx) != KIND_IN_PROCESS:
        print(
            f"\n[拒绝] provider {provider.id} 是 "
            f"{KIND_LABELS.get(provider.kind_for(ctx), provider.kind_for(ctx))}，"
            "本库不会对它执行远程调用；请按上面的启动期步骤操作。",
            file=sys.stderr,
        )
        return 2
    if args.dry_run:
        print("\n[dry-run] 未执行任何远程调用。")
        return 0

    if not args.yes:
        try:
            answer = input("确认执行以上远程调用？[y/N] ").strip().lower()
        except EOFError:
            answer = ""
        if answer not in ("y", "yes"):
            print("[取消] 未执行。")
            return 1

    result = provider.unlock(ctx)
    print()
    if args.json:
        _print_json(result.as_dict())
    else:
        print(f"结果：{'成功' if result.ok else '失败'}")
        print(f"节点数：{result.before_nodes} -> {result.after_nodes}")
        print(f"耗时：{result.duration_ms} ms")
        print(f"说明：{result.message}")

    # 解锁后立刻再做一次复核（独立于 provider 的 before/after）
    nodes = probe_mod.count_nodes(ctx.hwnd, max_depth=args.depth)
    if not args.json:
        print(f"复核：当前节点数 {nodes.count}（backend={nodes.backend}）")
        if nodes.control_types:
            top = sorted(nodes.control_types.items(), key=lambda kv: -kv[1])[:5]
            print("      ControlType：" + ", ".join(f"{k}={v}" for k, v in top))
    return 0 if result.ok else 3


# ---------------------------------------------------------------- verify


def cmd_verify(args) -> int:
    try:
        ctx, provider, score, plan = api.make_plan(
            pid=args.pid, exe=args.exe, hwnd=args.hwnd,
            provider=args.provider, depth=args.depth,
        )
    except LookupError as exc:
        print(f"[拒绝] {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return 1

    print(f"provider：{provider.id}（置信度 {score:.2f}，{KIND_LABELS.get(provider.kind_for(ctx))}）")
    print(f"目标：pid={ctx.pid}，窗口 class={ctx.window_class!r}")
    print()

    result = provider.verify(ctx)
    if args.json:
        _print_json(result.as_dict())
    else:
        print(result.message)
        stages = (result.evidence or {}).get("stages") or []
        if stages:
            print()
            print(f"{'阶段':<16}{'开关':<8}{'节点数':<8}backend")
            for st in stages:
                print(
                    f"{st.get('stage', ''):<16}"
                    f"{str(st.get('enabled')):<8}"
                    f"{st.get('nodes'):<8}"
                    f"{st.get('backend', '')}"
                )
            print()
            print(f"原始状态：{(result.evidence or {}).get('original_state')}  "
                  f"恢复为：{(result.evidence or {}).get('restored_to')}")
        print(f"\n结论：{'可逆验证通过' if result.ok else '可逆验证未通过'}")
    return 0 if result.ok else 3


# ---------------------------------------------------------------- doctor


def cmd_doctor(args) -> int:
    print("== uiaunlock doctor ==")
    print(f"版本：uiaunlock {__version__}   Python {sys.version.split()[0]}  "
          f"({w32.host_bitness()} 位)")
    print(f"管理员：{'是' if w32.is_admin() else '否（普通用户通常够用；目标以管理员运行时需要提权）'}")
    uia_ok = probe_mod.uiautomation_available()
    uia_text = "已安装（节点计数用 UIA 后端）" if uia_ok else "未安装（降级为 MSAA 计数，可 pip install uiaunlock[uia]）"
    print(f"uiautomation：{uia_text}")
    print(f"SPI_GETSCREENREADER：{w32.screen_reader_enabled()}（TRUE 时 Qt/Chromium 可能默认已开无障碍，做 A/B 前要记录）")

    providers = registry.get_providers()
    print(f"provider：内置 + entry points 共 {len(providers)} 个")
    if registry.LOAD_ERRORS:
        for name, err in registry.LOAD_ERRORS.items():
            print(f"  [entry point 失败] {name}: {err}")

    # 企业微信安装位置：全部走运行时探测，不把任何本机路径写死
    #   1) WXWORK_HOME 环境变量（自定义安装/绿色版）
    #   2) %ProgramFiles(x86)% / %ProgramFiles% 下的默认目录
    #   3) 正在运行的 WXWork.exe 的真实镜像路径（最可靠）
    pids = w32.find_pids_by_exe("WXWork.exe")
    guesses = []
    home = os.environ.get("WXWORK_HOME")
    if home:
        guesses.append(os.path.join(home, "WXWork.exe"))
    for env in ("ProgramFiles(x86)", "ProgramFiles"):
        base = os.environ.get(env)
        if base:
            guesses.append(os.path.join(base, "WXWork", "WXWork.exe"))
            guesses.append(os.path.join(base, "Tencent", "WXWork", "WXWork.exe"))
    for pid in pids:
        try:
            image = w32.process_image_path(pid)
        except Exception:
            image = ""
        if image:
            guesses.append(image)
    found = list(dict.fromkeys(p for p in guesses if os.path.exists(p)))
    if found:
        print("企业微信安装路径：")
        for p in found:
            print(f"  {p}  v{w32.file_version(p)}")
    if pids:
        print(f"企业微信进程：{len(pids)} 个 -> {pids}")
        for pid in pids:
            hwnd = w32.find_main_window(pid)
            if hwnd:
                print(f"  主窗口：pid={pid} hwnd=0x{hwnd:X} title={w32.get_window_text(hwnd)!r}")
                try:
                    print(f"  位数：{w32.process_bitness(pid)}")
                except Exception as exc:
                    print(f"  位数读取失败：{exc}")
    else:
        print("企业微信进程：未运行")

    if args.pid or args.exe or args.hwnd:
        try:
            pid, hwnd = api.resolve_target(pid=args.pid, exe=args.exe, hwnd=args.hwnd)
            print(f"目标检查：pid={pid} hwnd=0x{hwnd:X} 位数={w32.process_bitness(pid)} "
                  f"class={w32.get_class_name(hwnd)!r}")
            print(f"  位数是否匹配宿主：{'是' if w32.process_bitness(pid) == w32.host_bitness() else '否（跨位数调用是允许的，但要注意模块地址范围）'}")
        except Exception as exc:
            print(f"[错误] {exc}", file=sys.stderr)
            return 1
    return 0


# ---------------------------------------------------------------- 参数解析


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="uiaunlock",
        description="诊断并解锁 Windows 自绘 UI 框架的 UIA 无障碍树（只读优先，解锁前必打印计划）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例：\n"
            "  uiaunlock list\n"
            "  uiaunlock scan --exe \"<WXWORK_EXE>\"\n"
            "  uiaunlock scan --pid 95344\n"
            "  uiaunlock diagnose --pid 95344 --out report.json\n"
            "  uiaunlock unlock --pid 95344 --dry-run\n"
            "  uiaunlock unlock --pid 95344 --yes\n"
            "  uiaunlock verify --pid 95344\n"
            "  uiaunlock doctor\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"uiaunlock {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p_list = sub.add_parser("list", help="列出 provider 及其 kind")
    p_list.set_defaults(func=cmd_list)

    p_scan = sub.add_parser("scan", help="只读扫描：框架识别 + 探针 + 节点数")
    _add_target_args(p_scan)
    p_scan.add_argument("--json", action="store_true", help="输出 JSON")
    p_scan.set_defaults(func=cmd_scan)

    p_diag = sub.add_parser("diagnose", help="scan + 写 JSON 报告")
    _add_target_args(p_diag)
    p_diag.add_argument("--out", help="报告输出路径（默认 ./uiaunlock_reports/）")
    p_diag.add_argument("--json", action="store_true", help="把完整报告打到标准输出")
    p_diag.set_defaults(func=cmd_diagnose)

    p_unlock = sub.add_parser("unlock", help="执行解锁（先打印计划，默认需要确认）")
    _add_target_args(p_unlock)
    p_unlock.add_argument("--provider", help="指定 provider id（默认自动选择最高置信度）")
    p_unlock.add_argument("--dry-run", action="store_true", help="只打印计划，不执行")
    p_unlock.add_argument("--yes", action="store_true", help="跳过交互确认")
    p_unlock.add_argument("--json", action="store_true", help="输出 JSON 结果")
    p_unlock.set_defaults(func=cmd_unlock)

    p_verify = sub.add_parser("verify", help="A/B 对照验证（关→开→关，证明可逆）")
    _add_target_args(p_verify)
    p_verify.add_argument("--provider", help="指定 provider id")
    p_verify.add_argument("--json", action="store_true", help="输出 JSON 结果")
    p_verify.set_defaults(func=cmd_verify)

    p_doc = sub.add_parser("doctor", help="环境自检")
    p_doc.add_argument("--pid", type=int, help="可选：检查指定进程")
    p_doc.add_argument("--exe", help="可选：检查指定程序的运行进程")
    p_doc.add_argument("--hwnd", type=lambda s: int(s, 0), help="可选：检查指定窗口")
    p_doc.set_defaults(func=cmd_doctor)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
