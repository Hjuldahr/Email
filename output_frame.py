from __future__ import annotations
from enum import IntEnum
import struct
from typing import Iterator
import zlib

class Status(IntEnum):
    PING = 0
    
    @classmethod
    def from_status_code(cls, status_code: int) -> Status | None:
        return next(member for member in cls if member.value == status_code)
    
class OutputFrame:
    __slots__ = ('status', 'entries')

    MAGIC_PREFIX = b'TNCSLRP' # Using new prefix, to differentiate from input frames
    FRAME_HEADER = struct.Struct("!7sHB")
    FRAME_TRAILER = struct.Struct("!I")
    ENTRY_HEADER = struct.Struct("!I")

    def __init__(self, status: Status, entries: list[str] | None):
        self.status = status
        self.entries = entries or []

    def __int__(self) -> int:
        return self.status.value

    def __str__(self) -> str:
        return f'[{self.status.name}: {", ".join(self.entries)}]'

    def __repr__(self) -> str:
        return f'OutputFrame(status={self.status!r}, entries={self.entries!r})'

    def __bytes__(self) -> bytes:
        return self.serialize()

    def __iter__(self) -> Iterator[Status | str]:
        yield self.status
        yield from self.entries

    def __len__(self) -> int:
        return len(self.entries) + 1

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, OutputFrame):
            return NotImplemented
        return self.status == value.status and self.entries == value.entries
    
    def __getitem__(self, idx: int) -> Status | str:
        if idx < 0:
            idx += len(self)
        if idx == 0:
            return self.status
        return self.entries[idx - 1]

    def __setitem__(self, idx: int, value: Status | str) -> None:
        if idx < 0:
            idx += len(self)
        if idx == 0:
            self.status = value
        else:
            self.entries[idx - 1] = value

    @classmethod
    def deserialize(cls, data: bytes, initial_offset: int = 0) -> OutputFrame | None:
        view = memoryview(data)
        entries = []
        offset = initial_offset

        prefix, status_code, entry_count = cls.FRAME_HEADER.unpack_from(view, offset)
        if prefix != cls.MAGIC_PREFIX:
            return None
        offset += cls.FRAME_HEADER.size

        for _ in range(entry_count):
            entry_size, = cls.ENTRY_HEADER.unpack_from(view, offset)
            offset += cls.ENTRY_HEADER.size

            entries.append(str(view[offset:offset + entry_size], 'utf-8'))
            offset += entry_size

        computed_checksum = zlib.crc32(view[initial_offset:offset])

        expected_checksum, = cls.FRAME_TRAILER.unpack_from(view, offset)

        if computed_checksum != expected_checksum:
            return None

        return cls(Status.from_status_code(status_code), entries)

    def serialize(self) -> bytes:
        header = self.FRAME_HEADER.pack(self.MAGIC_PREFIX, self.status.value, len(self.entries))

        body = bytearray()
        for entry in self.entries:
            entry_bytes = entry.encode('utf-8')
            body.extend(self.ENTRY_HEADER.pack(len(entry_bytes)))
            body.extend(entry_bytes)

        payload = header + bytes(body)
            
        return payload + self.FRAME_TRAILER.pack(zlib.crc32(payload))