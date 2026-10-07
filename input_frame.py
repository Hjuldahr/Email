from __future__ import annotations
import asyncio
from enum import IntEnum
import struct
from typing import Iterator, Sequence
import zlib

class Operations(IntEnum):
    PING = 0x000
    REQ = 0x001
    HELLO = 0x002
    REGISTER = 0x004
    LOGIN = 0x005
    LOGOUT = 0x006
    DC = 0x003
    
    ADDR_REQ = 0x102
    ADDR_REL = 0x103 
    ADDR = 0x101
    LIST_ADDR = 0x100
    
    LIST_FEATURE = 0x301 
    FEATURE = 0x302
    VIEWONLY = 0x303
    NOTIFY = 0x304
    
    DETACH = 0x403
    MOVE = 0x404
    FORWARD = 0x405
    SEEN = 0x406
    LIST = 0x400
    LIST_THREAD = 0x401
    FETCH = 0x407
    DELETE = 0x408
    RESTORE = 0x409
    ARCH = 0x40A
    FLAG = 0x40B
    TAG = 0x40C
    LIST_TAG = 0x402
    
    DRAFT = 0x501
    EDIT_ADDR = 0x502
    EDIT_THREAD = 0x503
    EDIT_SUBJ = 0x504
    EDIT_BODY = 0x505
    SEND = 0x506
    
    LIST_ATTACH = 0x600
    DOWNLOAD = 0x601
    UPLOAD = 0x602
    
    MIRROR = 0x700
    
    ACT = 0x801
    LIST_ACT = 0x800
    
    BLOCK = 0x901
    LIST_BLOCK = 0x900
    
    CONTACT_ADD = 0xA02
    CONTACT_REM = 0xA03
    LIST_CONTACT = 0xA00
    CONTACT = 0xA01
    
    STATUS = 0x300
    
    @classmethod
    def from_op_code(cls, status_code: int) -> Operations | None:
        return cls._value2member_map_.get(status_code, None)
    
class InputFrame:
    __slots__ = ('version', 'operation', 'arguments')

    MAGIC_PREFIX = b'PRLSCNT'
    OUTER_HEADER = struct.Struct("!7sBI")
    INNER_HEADER = struct.Struct("!HB")
    INNER_TRAILER = struct.Struct("!I")
    ARG_PREFIX = struct.Struct("!H")

    def __init__(self, version: int, operation: Operations, arguments: Sequence[str] | None = None):
        self.version = version
        self.operation = operation
        self.arguments = arguments or []

    def __int__(self) -> int:
        return self.operation.value

    def __str__(self) -> str:
        return f'[{self.operation.name}: {", ".join(self.arguments)}]'

    def __repr__(self) -> str:
        return f'InputFrame(version={self.version}, operation={self.operation!r}, arguments={self.arguments!r})'

    def __bytes__(self) -> bytes:
        return self.pack()

    def __iter__(self) -> Iterator[Operations | str]:
        yield self.operation
        yield from self.arguments

    def __len__(self) -> int:
        return len(self.arguments) + 1

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, InputFrame):
            return NotImplemented
        return self.version == value.version and self.operation == value.operation and self.arguments == value.arguments

    def __hash__(self):
        return hash((self.version, self.operation, *self.arguments))

    @classmethod
    async def from_wire(cls, reader: asyncio.StreamReader) -> InputFrame | None:
        try:
            raw_outer_header = await reader.readexactly(cls.OUTER_HEADER.size)
            magic, version, inner_frame_size = cls.OUTER_HEADER.unpack(raw_outer_header)

            if magic != cls.MAGIC_PREFIX:
                return None

            raw_inner_frame = await reader.readexactly(inner_frame_size)
            view = memoryview(raw_inner_frame)

            op_code, arg_count = cls.INNER_HEADER.unpack_from(view)
            
            if (operation := Operations.from_op_code(op_code)) is None:
                return None
            
            offset = cls.INNER_HEADER.size
            args = []

            for _ in range(arg_count):
                arg_size, = cls.ARG_PREFIX.unpack_from(view, offset)
                offset += cls.ARG_PREFIX.size

                if offset + arg_size > inner_frame_size:
                    return None

                args.append(str(view[offset:offset + arg_size], 'utf-8'))
                offset += arg_size

            if offset + cls.INNER_TRAILER.size != inner_frame_size:
                return None

            computed_checksum = zlib.crc32(view[:offset])
            expected_checksum, = cls.INNER_TRAILER.unpack_from(view, offset)

            if computed_checksum != expected_checksum:
                return None

            return InputFrame(version, operation, args)
        except struct.error:
            return None
    
    def pack(self) -> bytes:
        frame_body = b''.join(self.ARG_PREFIX.pack(len(arg)) + arg for arg in map(str.encode, self.arguments))
                
        inner_frame_size = self.INNER_HEADER.size + len(frame_body) + self.INNER_TRAILER.size
        
        outer_header = self.OUTER_HEADER.pack(self.MAGIC_PREFIX, self.version, inner_frame_size)
        inner_header = self.INNER_HEADER.pack(self.operation.value, len(self.arguments))
        inner_trailer = self.INNER_TRAILER.pack(zlib.crc32(inner_header + frame_body))
        
        return outer_header + inner_header + frame_body + inner_trailer
    
    async def to_wire(self, writer: asyncio.StreamWriter) -> None:
        writer.write(self.pack())
        await writer.drain()