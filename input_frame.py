from __future__ import annotations
from enum import IntEnum
import struct
from typing import Iterator
import zlib

class Operations(IntEnum):
    PING = 0
    REQ = 1
    HELLO = 2
    REGISTER = 100
    LOGIN = 101
    LOGOUT = 102
    DC = 3
    ADDR_REQ = 202
    ADDR_REL = 203
    ADDR = 201
    ADDR_ON = 204
    ADDR_OFF = 205
    LIST_ADDR = 200
    LIST_FEATURE = 300
    FEATURE = 301
    FEATURE_ON = 302
    FEATURE_OFF = 303
    VIEWONLY = 400
    VIEWONLY_ON = 401
    VIEWONLY_OFF = 402
    
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