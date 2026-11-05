"""uiaunlock.pe —— 纯标准库实现的 PE 导出表解析。

为什么不用 pefile：
- 本库要求核心依赖只有标准库 + ctypes，装 pefile 会给用户增加负担；
- 我们只需要"导出名 -> RVA"这一件事，手工解析 3 个结构就够；
- 内存镜像（已加载模块）与磁盘文件两种来源都要支持，
  自己解析反而更容易统一处理。

关键概念（看懂这三个就懂本文件）：
- **RVA**：相对虚拟地址。导出表里存的是 RVA，不是文件偏移，也不是运行时地址。
- **运行地址 = 模块加载基址 + RVA**。远程线程调用时传的就是这个地址。
- **文件偏移 = 所在节的 PointerToRawData + (RVA - 节的 VirtualAddress)**。
  磁盘文件和内存镜像的映射规则不同，这是本文件要处理的核心差异。

导出表结构（IMAGE_EXPORT_DIRECTORY）本身也是一段 RVA，字段顺序：
    Characteristics, TimeDateStamp, MajorVersion, MinorVersion,
    Name(RVA), Base, NumberOfFunctions, NumberOfNames,
    AddressOfFunctions(RVA), AddressOfNames(RVA), AddressOfNameOrdinals(RVA)
其中 AddressOfNames 是"名称 RVA 数组"，AddressOfNameOrdinals 是"名称对应的
函数序号数组"，用序号再去 AddressOfFunctions 取真正的函数 RVA。
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

# PE 头里的 machine 字段
MACHINE_X86 = 0x014C
MACHINE_X64 = 0x8664
MACHINE_ARM64 = 0xAA64

PE32_MAGIC = 0x010B
PE32_PLUS_MAGIC = 0x020B


class PEError(ValueError):
    """PE 解析失败（文件不是 PE、导出表损坏、RVA 越界等）。"""


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int

    def contains(self, rva: int) -> bool:
        span = max(self.virtual_size, self.raw_size)
        return self.virtual_address <= rva < self.virtual_address + span


@dataclass
class ExportTable:
    """导出表解析结果。

    ``entries`` 只保存"名称 -> RVA"；``ordinal_only`` 是只有序号没有名字的导出，
    对定位静态函数没用，但计数时会带上，便于诊断。
    """

    entries: Dict[str, int] = field(default_factory=dict)
    dll_name: str = ""
    timestamp: int = 0
    machine: int = 0
    is_64: bool = False
    source: str = ""
    ordinal_only: int = 0

    def get(self, name: str) -> Optional[int]:
        return self.entries.get(name)

    def select(self, names: List[str]) -> Dict[str, int]:
        return {n: self.entries[n] for n in names if n in self.entries}

    @property
    def machine_name(self) -> str:
        return {
            MACHINE_X86: "x86",
            MACHINE_X64: "x64",
            MACHINE_ARM64: "arm64",
        }.get(self.machine, f"0x{self.machine:04X}")


class _FileAccessor:
    """按"镜像偏移"读取磁盘 PE 文件。

    故意不把整个文件读进内存：libcef.dll 动辄 200MB+，
    按需 seek/read 更省内存，也不会因为大文件把 scan 拖慢。
    """

    def __init__(self, path: str):
        self.path = path
        self._f = open(path, "rb")
        self.size = os.path.getsize(path)

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or offset >= self.size:
            raise PEError(f"读取 {self.path} 越界：offset=0x{offset:X}")
        self._f.seek(offset)
        data = self._f.read(size)
        if len(data) < size:
            # 文件被截断时返回实际读到的部分，由调用方按 len() 判断
            return data
        return data

    def close(self) -> None:
        try:
            self._f.close()
        except Exception:
            pass


class _MemoryAccessor:
    """按"内存绝对地址"读取已加载模块。

    reader 的签名是 ``(address, size) -> bytes``，由 w32.MemoryReader 提供。
    """

    def __init__(self, reader: Callable[[int, int], bytes], base: int):
        self.reader = reader
        self.base = base

    def read(self, offset: int, size: int) -> bytes:
        return self.reader(self.base + offset, size)

    def close(self) -> None:
        pass


def _parse_headers(accessor, is_memory: bool) -> Tuple[int, int, List[Section], int, int, int]:
    """解析 DOS/NT 头与节表。

    返回 (e_lfanew, machine, sections, timestamp, export_rva, is_64)。

    读取策略：先读 0x1000 字节（够覆盖 DOS 头 + NT 头 + 大多数节表），
    根据 NumberOfSections 再补读一次节表 —— 而不是假设固定 0x400，避免
    节表特别多的小概率失败。
    """
    head = accessor.read(0, 0x1000)
    if len(head) < 0x40 or head[:2] != b"MZ":
        raise PEError("不是有效的 PE 文件（缺少 MZ 头）")
    e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
    if e_lfanew + 24 > len(head):
        raise PEError("e_lfanew 越界，文件可能被截断")
    if head[e_lfanew: e_lfanew + 4] != b"PE\x00\x00":
        raise PEError("缺少 PE 签名")
    machine = struct.unpack_from("<H", head, e_lfanew + 4)[0]
    nsect = struct.unpack_from("<H", head, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", head, e_lfanew + 20)[0]
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", head, opt)[0] if opt + 2 <= len(head) else 0
    is_64 = magic == PE32_PLUS_MAGIC
    if magic not in (PE32_MAGIC, PE32_PLUS_MAGIC):
        raise PEError(f"未知的可选头 magic=0x{magic:04X}")

    timestamp = struct.unpack_from("<I", head, e_lfanew + 8)[0]

    # 数据目录起始位置：PE32 是可选头 +96，PE32+ 是 +112
    dd_off = opt + (112 if is_64 else 96)
    export_rva = 0
    if dd_off + 8 <= len(head):
        export_rva = struct.unpack_from("<I", head, dd_off)[0]

    sect_off = opt + opt_size
    want = sect_off + 40 * nsect
    if want > len(head):
        head += accessor.read(len(head), want - len(head))
    sections: List[Section] = []
    for i in range(nsect):
        o = sect_off + 40 * i
        raw_name, vsize, vaddr, rsize, raddr = struct.unpack_from("<8sIIII", head, o)
        sections.append(
            Section(
                name=raw_name.decode("ascii", "ignore").strip("\x00"),
                virtual_address=vaddr,
                virtual_size=vsize,
                raw_offset=raddr,
                raw_size=rsize,
            )
        )
    return e_lfanew, machine, sections, timestamp, export_rva, is_64


def _rva_to_pos(rva: int, sections: List[Section], is_memory: bool, image_size: int) -> int:
    """RVA -> 读取位置。

    - 内存镜像：已按节对齐加载，位置就是 RVA 本身。
    - 磁盘文件：需要查节表换成文件偏移；落在头部（不在任何节）时，RVA 就是偏移。
    """
    if is_memory:
        if image_size and rva >= image_size:
            raise PEError(f"RVA 0x{rva:X} 超出镜像大小 0x{image_size:X}")
        return rva
    for s in sections:
        if s.contains(rva):
            return s.raw_offset + (rva - s.virtual_address)
    if rva < 0x1000:
        return rva  # 头部区域，RVA 即文件偏移
    raise PEError(f"RVA 0x{rva:X} 不在任何节内（文件可能被打包/加密）")


def _read_export_table(
    accessor, sections: List[Section], is_memory: bool, export_rva: int,
    timestamp: int, machine: int, is_64: bool, source: str,
) -> ExportTable:
    """真正解析 IMAGE_EXPORT_DIRECTORY。"""
    if export_rva == 0:
        return ExportTable(timestamp=timestamp, machine=machine, is_64=is_64, source=source)

    d = accessor.read(_rva_to_pos(export_rva, sections, is_memory, 0), 40)
    if len(d) < 40:
        raise PEError("导出目录读取失败（长度不足 40 字节）")
    (
        _chars, _ts, _major, _minor, name_rva, base_ord,
        num_funcs, num_names, funcs_rva, names_rva, ords_rva,
    ) = struct.unpack_from("<IIHHIIIIIII", d, 0)

    if num_names > 65535 or num_funcs > 1_000_000:
        raise PEError(
            f"导出表字段异常（num_names={num_names}, num_funcs={num_funcs}），"
            "可能不是正常 PE 或已加壳"
        )

    table = ExportTable(
        timestamp=timestamp, machine=machine, is_64=is_64, source=source
    )

    if name_rva:
        try:
            raw = accessor.read(_rva_to_pos(name_rva, sections, is_memory, 0), 512)
            table.dll_name = raw.split(b"\x00", 1)[0].decode("ascii", "ignore")
        except PEError:
            table.dll_name = ""

    name_pos = _rva_to_pos(names_rva, sections, is_memory, 0)
    ord_pos = _rva_to_pos(ords_rva, sections, is_memory, 0)
    func_pos = _rva_to_pos(funcs_rva, sections, is_memory, 0)

    # 先一次性把三张表读进来（名称 RVA 数组 / 序号数组 / 函数 RVA 数组），
    # 再逐个读名称字符串。这样只需 num_names 次小读取，而不是 3*num_names 次。
    names_data = accessor.read(name_pos, 4 * num_names) if num_names else b""
    ords_data = accessor.read(ord_pos, 2 * num_names) if num_names else b""
    funcs_data = accessor.read(func_pos, 4 * max(num_funcs, 1)) if num_funcs else b""

    for i in range(num_names):
        if 4 * i + 4 > len(names_data):
            break
        name_ptr = struct.unpack_from("<I", names_data, 4 * i)[0]
        try:
            name_raw = accessor.read(_rva_to_pos(name_ptr, sections, is_memory, 0), 256)
            nm = name_raw.split(b"\x00", 1)[0].decode("ascii", "ignore")
        except PEError:
            continue
        if not nm:
            continue
        try:
            ordinal = struct.unpack_from("<H", ords_data, 2 * i)[0]
            fn_rva = struct.unpack_from("<I", funcs_data, 4 * ordinal)[0]
        except (struct.error, IndexError):
            continue
        table.entries[nm] = fn_rva

    table.ordinal_only = max(0, num_funcs - len(table.entries))
    return table


def parse_exports_file(path: str) -> ExportTable:
    """解析磁盘 PE 文件的导出表，返回 {导出名: RVA}。

    对 duilib.dll / Qt5Core.dll 这类"静态函数入口"的定位都走这里。
    注意：磁盘文件可能和"正在运行的模块"版本不同（热更新场景），
    如果 RVA 在目标进程里调用失败，应改用 :func:`parse_exports_memory`。
    """
    accessor = _FileAccessor(path)
    try:
        _e, machine, sections, timestamp, export_rva, is_64 = _parse_headers(accessor, False)
        return _read_export_table(
            accessor, sections, False, export_rva, timestamp, machine, is_64,
            source=path,
        )
    finally:
        accessor.close()


def parse_exports_memory(reader: Callable[[int, int], bytes], base: int) -> ExportTable:
    """解析"已加载到内存"的模块导出表。

    ``reader`` 由 :class:`uiaunlock.w32.MemoryReader` 提供（签名 ``(addr, size)``），
    ``base`` 是模块加载基址。适用于：磁盘文件被删/被替换，但进程里还有副本。
    """
    accessor = _MemoryAccessor(reader, int(base))
    try:
        _e, machine, sections, timestamp, export_rva, is_64 = _parse_headers(accessor, True)
        table = _read_export_table(
            accessor, sections, True, export_rva, timestamp, machine, is_64,
            source=f"memory@0x{int(base):X}",
        )
        return table
    finally:
        accessor.close()


def parse_image_metadata_file(path: str) -> Dict[str, object]:
    """只读 PE 头，返回机器类型/位数等元信息（doctor 与 report 用）。"""
    accessor = _FileAccessor(path)
    try:
        _e, machine, _sections, timestamp, _exp, is_64 = _parse_headers(accessor, False)
        return {
            "machine": machine,
            "machine_name": {
                MACHINE_X86: "x86",
                MACHINE_X64: "x64",
                MACHINE_ARM64: "arm64",
            }.get(machine, f"0x{machine:04X}"),
            "is_64": is_64,
            "timestamp": timestamp,
            "path": path,
        }
    finally:
        accessor.close()


def find_matching_exports(table: ExportTable, keywords: List[str]) -> Dict[str, int]:
    """按关键字（不区分大小写）筛选导出名，用于 generic provider 的探查。

    例：``keywords=["Accessibility", "ScreenReader", "UIA"]``
    """
    lows = [k.lower() for k in keywords]
    return {
        name: rva for name, rva in table.entries.items()
        if any(k in name.lower() for k in lows)
    }
