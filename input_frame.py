from __future__ import annotations
from enum import IntEnum
import struct
from typing import Iterator
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
    def from_opcode(cls, opcode: int) -> Operations | None:
        return next(member for member in cls if member.value == opcode)

class InputFrame:
    __slots__ = ('operation', 'arguments')

    MAGIC_PREFIX = b'PRLSCNT'
    FRAME_HEADER = struct.Struct("!7sBB")
    FRAME_TRAILER = struct.Struct("!I")
    ARG_HEADER = struct.Struct("!I")

    def __init__(self, operation: Operations, arguments: list[str] | None):
        self.operation = operation
        self.arguments = arguments or []

    def __int__(self) -> int:
        return self.operation.value

    def __str__(self) -> str:
        return f'[{self.operation.name}: {", ".join(self.arguments)}]'

    def __repr__(self) -> str:
        return f'InputFrame(operation={self.operation!r}, arguments={self.arguments!r})'

    def __bytes__(self) -> bytes:
        return self.serialize()

    def __iter__(self) -> Iterator[Operations | str]:
        yield self.operation
        yield from self.arguments

    def __len__(self) -> int:
        return len(self.arguments) + 1

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, InputFrame):
            return NotImplemented
        return self.operation == value.operation and self.arguments == value.arguments

    def __getitem__(self, idx: int) -> Operations | str:
        if idx < 0:
            idx += len(self)
        if idx == 0:
            return self.operation
        return self.arguments[idx - 1]

    def __setitem__(self, idx: int, value: Operations | str) -> None:
        if idx < 0:
            idx += len(self)
        if idx == 0:
            self.operation = value
        else:
            self.arguments[idx - 1] = value

    @classmethod
    def deserialize(cls, data: bytes, initial_offset: int = 0) -> InputFrame | None:
        view = memoryview(data)
        args = []
        offset = initial_offset

        prefix, op_code, arg_count = cls.FRAME_HEADER.unpack_from(view, offset)
        if prefix != cls.MAGIC_PREFIX:
            return None
        offset += cls.FRAME_HEADER.size
        
        for _ in range(arg_count):
            arg_size, = cls.ARG_HEADER.unpack_from(view, offset)
            offset += cls.ARG_HEADER.size

            args.append(str(view[offset:offset + arg_size], 'utf-8'))
            offset += arg_size

        computed_checksum = zlib.crc32(view[initial_offset:offset])

        expected_checksum, = cls.FRAME_TRAILER.unpack_from(view, offset)

        if computed_checksum != expected_checksum:
            return None

        return InputFrame(Operations.from_opcode(op_code), args)

    def serialize(self) -> bytes:
        header = self.FRAME_HEADER.pack(self.MAGIC_PREFIX, self.user_uid.bytes, self.operation.value, len(self.arguments))

        body = bytearray()
        for arg in self.arguments:
            arg_bytes = arg.encode('utf-8')
            body.extend(self.ARG_HEADER.pack(len(arg_bytes)))
            body.extend(arg_bytes)

        payload = header + bytes(body)
            
        return payload + self.FRAME_TRAILER.pack(zlib.crc32(payload))