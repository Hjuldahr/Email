from __future__ import annotations
import asyncio
from enum import IntEnum
import struct
from typing import Iterator, Sequence
import zlib

class Status(IntEnum):
    SYNC = 0x0
    OK = 0x1
    INFO = 0x2
    WARN = 0x3
    ERR = 0x4
    
    @classmethod
    def from_status_code(cls, status_code: int) -> Status | None:
        return cls._value2member_map_.get(status_code, None)
    
class OutputFrame:
    __slots__ = ('version', 'status', 'entries')

    MAGIC_PREFIX = b'TNCSLRP' # Differentiate from input frames
    OUTER_HEADER = struct.Struct("!7sBI")
    INNER_HEADER = struct.Struct("!BH")
    INNER_TRAILER = struct.Struct("!I")
    ENTRY_PREFIX = struct.Struct("!H")

    def __init__(self, version: int, status: Status, entries: Sequence[str] | None = None):
        self.version = version
        self.status = status
        self.entries = entries or []

    def __int__(self) -> int:
        return self.status.value

    def __str__(self) -> str:
        return f'[{self.status.name}: {", ".join(self.entries)}]'

    def __repr__(self) -> str:
        return f'OutputFrame(version={self.version}, status={self.status!r}, entries={self.entries!r})'

    def __bytes__(self) -> bytes:
        return self.pack()

    def __iter__(self) -> Iterator[Status | str]:
        yield self.status
        yield from self.entries

    def __len__(self) -> int:
        return len(self.entries) + 1

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, OutputFrame):
            return NotImplemented
        return self.version == value.version and self.status == value.status and self.entries == value.entries

    @classmethod
    async def from_wire(cls, reader: asyncio.StreamReader) -> OutputFrame | None:
        try:
            raw_outer_header = await reader.readexactly(cls.OUTER_HEADER.size)
            magic, version, inner_frame_size = cls.OUTER_HEADER.unpack(raw_outer_header)

            if magic != cls.MAGIC_PREFIX:
                return None

            raw_inner_frame = await reader.readexactly(inner_frame_size)
            view = memoryview(raw_inner_frame)

            status_code, entry_count = cls.INNER_HEADER.unpack_from(view)
            
            if (status := Status.from_status_code(status_code)) is None:
                return None
            
            offset = cls.INNER_HEADER.size
            entries = []

            for _ in range(entry_count):
                entry_size, = cls.ENTRY_PREFIX.unpack_from(view, offset)
                offset += cls.ENTRY_PREFIX.size

                if offset + entry_size > inner_frame_size:
                    return None

                entries.append(str(view[offset:offset + entry_size], 'utf-8'))
                offset += entry_size

            if offset + cls.INNER_TRAILER.size != inner_frame_size:
                return None

            computed_checksum = zlib.crc32(view[:offset])
            expected_checksum, = cls.INNER_TRAILER.unpack_from(view, offset)

            if computed_checksum != expected_checksum:
                return None

            return OutputFrame(version, status, entries)
        except struct.error:
            return None

    def pack(self) -> bytes:
        frame_body = b''.join(self.ENTRY_PREFIX.pack(len(entry)) + entry for entry in map(str.encode, self.entries))
                
        inner_frame_size = self.INNER_HEADER.size + len(frame_body) + self.INNER_TRAILER.size
        
        outer_header = self.OUTER_HEADER.pack(self.MAGIC_PREFIX, self.version, inner_frame_size)
        inner_header = self.INNER_HEADER.pack(self.status.value, len(self.entries))
        inner_trailer = self.INNER_TRAILER.pack(zlib.crc32(inner_header + frame_body))
        
        return outer_header + inner_header + frame_body + inner_trailer

    async def to_wire(self, writer: asyncio.StreamWriter) -> None:
        writer.write(self.pack())
        await writer.drain()