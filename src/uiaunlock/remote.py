"""uiaunlock.remote —— 在目标进程里执行一个"无参/单参函数"的远程调用。

用途：某些自绘框架把"打开无障碍"做成 DLL 里的静态导出函数，
没有命令行开关，也不能靠发消息触发。此时唯一不改文件的办法是：

    CreateRemoteThread(目标进程, 入口地址 = 模块基址 + 导出 RVA, 参数)

本模块只负责"调用"这一件事，不做"该不该调用"的判断（那是 provider 的事）。

为什么参数可以直接当 lpParameter 传：
- x86 上导出函数是 ``__cdecl``/``__stdcall`` + 1 个参数，参数在栈上，
  线程入口约定也把 lpParameter 放在栈上同样的位置，所以"恰好"能对上；
- x64 上第一个参数走 RCX，CreateRemoteThread 传入的 lpParameter 也在 RCX，
  同样能对上；
- ``bool`` 参数在 MSVC ABI 下只读低 1 字节，传 0/1 即可；
- 返回值会进 eax/rax，CreateRemoteThread 结束后可用 GetExitCodeThread 读到
  （DWORD 截断，只适合 bool/int 这种小返回值）。

风险（必须让调用方知道）：
- 函数地址错了 = 目标进程直接崩，且没有恢复机会；
- 目标进程可能需要先初始化 COM/UI 线程，远程线程里没有这些状态；
- 安全软件可能拦截 CreateRemoteThread（尤其对"非调试器"场景）。

所有调用都带超时；超时不会强杀目标线程（做不到，也不该做），
只返回"可能仍在执行"的状态，由上层决定是否继续轮询节点数。
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import time
from dataclasses import dataclass
from typing import Optional

from . import w32
from .w32 import W32Error

kernel32 = w32.kernel32

kernel32.CreateRemoteThread.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
    ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD),
]
kernel32.CreateRemoteThread.restype = ctypes.c_void_p
kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, wt.DWORD]
kernel32.WaitForSingleObject.restype = wt.DWORD
kernel32.GetExitCodeThread.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.DWORD)]
kernel32.GetExitCodeThread.restype = wt.BOOL

WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
WAIT_FAILED = 0xFFFFFFFF

# 远程线程需要的最小权限集合。
# PROCESS_VM_OPERATION 严格来说不是 CreateRemoteThread 必需，但很多安全软件
# 会对"只带 CREATE_THREAD"的请求额外拦截；带上它反而更容易成功。
REMOTE_ACCESS = (
    w32.PROCESS_CREATE_THREAD
    | w32.PROCESS_QUERY_INFORMATION
    | w32.PROCESS_VM_OPERATION
    | w32.PROCESS_SYNCHRONIZE
)


class RemoteCallError(RuntimeError):
    """远程调用失败，带可诊断信息。

    字段：
    - ``code``：Win32 错误码（可能为 None）
    - ``hint``：给人类看的处理建议
    - ``stage``：失败发生在哪个阶段（open/validate/create/wait/read）
    """

    def __init__(
        self, message: str, *, code: Optional[int] = None, hint: str = "", stage: str = ""
    ) -> None:
        self.code = code
        self.hint = hint
        self.stage = stage
        text = message
        if code is not None:
            text += f" (WinError {code})"
        if hint:
            text += f"；提示：{hint}"
        super().__init__(text)


@dataclass
class RemoteCallResult:
    """一次远程调用的结果。"""

    pid: int
    address: int
    arg: int
    ok: bool
    thread_id: int = 0
    exit_code: Optional[int] = None
    duration_ms: int = 0
    timed_out: bool = False
    message: str = ""

    def as_dict(self) -> dict:
        return {
            "pid": self.pid,
            "address": f"0x{self.address:X}",
            "arg": self.arg,
            "ok": self.ok,
            "thread_id": self.thread_id,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "timed_out": self.timed_out,
            "message": self.message,
        }


def validate_address(pid: int, address: int) -> None:
    """在创建线程前做地址合理性检查，避免"地址错了把目标进程搞崩"。

    检查项：
    1. 地址不能为 0 / 过小（空指针区）；
    2. 32 位目标不能用超过 4GB 的地址（典型错误：拿 64 位的模块基址去调 32 位进程）；
    3. 目标位宽与宿主位宽不同是允许的（远程线程由内核创建，不需要同位数）。
    """
    if address <= 0x10000:
        raise RemoteCallError(
            f"拒绝执行：目标地址 0x{address:X} 太小，疑似空指针/导出解析失败",
            hint="检查模块基址是否取到、导出 RVA 是否为 0",
            stage="validate",
        )
    bits = w32.process_bitness(pid)
    if bits == 32 and address > 0xFFFFFFFF:
        raise RemoteCallError(
            f"拒绝执行：目标是 32 位进程，但地址 0x{address:X} 超出 4GB 地址空间",
            hint="多半是枚举到了 64 位模块（需要 LIST_MODULES_ALL），或把宿主位宽当成了目标位宽",
            stage="validate",
        )


def remote_call(
    pid: int,
    address: int,
    arg: int = 0,
    timeout_ms: int = 5000,
    *,
    wait: bool = True,
) -> RemoteCallResult:
    """在 pid 中执行 ``((void(*)(int))address)(arg)``。

    参数：
    - ``arg``：0/1 表示 bool；如果是整数常量也按指针宽度传（x64 下 8 字节）。
      注意：本库不负责在目标进程里分配内存，所以不支持"传字符串/结构体指针"的场景。
    - ``timeout_ms``：等待线程结束的超时。超时不代表失败，只是"还没返回"。
    - ``wait=False``：只创建线程立即返回（用于必须连续调多个函数、不想被卡住的场景）。

    返回 :class:`RemoteCallResult`；硬失败抛 :class:`RemoteCallError`。
    """
    validate_address(pid, address)
    started = time.perf_counter()

    try:
        handle = w32.open_process(pid, REMOTE_ACCESS)
    except W32Error as exc:
        hint = exc.hint or "以管理员身份重试，或检查安全软件是否拦截了远程线程"
        raise RemoteCallError(
            f"OpenProcess(pid={pid}, CREATE_THREAD) 失败",
            code=exc.code, hint=hint, stage="open",
        ) from exc

    try:
        tid = wt.DWORD(0)
        thread = kernel32.CreateRemoteThread(
            ctypes.c_void_p(handle),
            None,
            0,
            ctypes.c_void_p(int(address)),
            ctypes.c_void_p(int(arg) & 0xFFFFFFFFFFFFFFFF),  # 按指针宽度传参
            0,
            ctypes.byref(tid),
        )
        if not thread:
            code = ctypes.get_last_error()
            hint = ""
            if code == 5:
                hint = "权限不足：目标进程可能是管理员权限，或被杀软拦截"
            elif code == 87:
                hint = "参数错误：address 是否在当前进程地址空间？字节序/位宽是否对上？"
            raise RemoteCallError(
                f"CreateRemoteThread(pid={pid}, addr=0x{address:X}) 失败",
                code=code, hint=hint, stage="create",
            )

        result = RemoteCallResult(
            pid=pid, address=address, arg=int(arg), ok=True,
            thread_id=int(tid.value),
        )

        if not wait:
            result.duration_ms = int((time.perf_counter() - started) * 1000)
            kernel32.CloseHandle(ctypes.c_void_p(int(thread)))
            return result

        wait_ret = kernel32.WaitForSingleObject(
            ctypes.c_void_p(int(thread)), wt.DWORD(int(timeout_ms))
        )
        if wait_ret == WAIT_TIMEOUT:
            result.timed_out = True
            result.ok = False
            result.message = (
                f"等待 {timeout_ms}ms 超时，线程可能仍在执行（常见于目标 UI 线程繁忙）；"
                "不要重复调用同一函数，改为轮询节点数"
            )
        elif wait_ret == WAIT_FAILED:
            code = ctypes.get_last_error()
            result.ok = False
            result.message = f"WaitForSingleObject 失败（WinError {code}）"
        else:
            code = wt.DWORD(0)
            if kernel32.GetExitCodeThread(
                ctypes.c_void_p(int(thread)), ctypes.byref(code)
            ):
                result.exit_code = int(code.value)

        result.duration_ms = int((time.perf_counter() - started) * 1000)
        kernel32.CloseHandle(ctypes.c_void_p(int(thread)))
        return result
    finally:
        w32.close_handle(handle)


def call_export(
    pid: int,
    module_base: int,
    rva: int,
    arg: int = 0,
    timeout_ms: int = 5000,
) -> RemoteCallResult:
    """``remote_call`` 的语法糖：地址 = 模块基址 + RVA。"""
    return remote_call(pid, int(module_base) + int(rva), arg, timeout_ms)
