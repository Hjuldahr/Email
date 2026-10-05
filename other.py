from __future__ import annotations
import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum, StrEnum, auto
import struct
import aiomysql

from input_frame import InputFrame
from output_frame import OutputFrame, Status

@dataclass(slots=True)
class User:
    user_id: int
    username: str
    created_on: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_accessed_on: datetime | None = None

class Folder(StrEnum):
    INBOX = 'INBOX'
    DRAFTS = 'DRAFTS'
    OUTBOX = 'OUTBOX'
    SENT = 'SENT'
    ARCHIVE = 'ARCHIVE'
    JUNK = 'JUNK'
    TRASH = 'TRASH'
    MERC = 'MERC'
    
    @classmethod
    def from_string(cls, name: str, default: Folder | None=None) -> Folder | None:
        return cls._member_map_.get(name.strip(), default)
    
class SessionMode(IntEnum):
    CONNECTED = auto()
    AUTHENTICATED = auto()
    VALIDATING_JOINING = auto()
    MESSAGE_VIEWING = auto()
    MESSAGE_COMPOSING = auto()

@dataclass(slots=True)
class SessionCoordinator:
    version: int
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    pool: aiomysql.Pool
    conn: aiomysql.connection.Connection
    user: User | None = None
    cwd: Folder | None = None
    mode: SessionMode = SessionMode.CONNECTED
    input_frame: InputFrame | None = None

    def purge_auth(self):
        self.user = None
        self.cwd = None
        self.mode = SessionMode.CONNECTED

    def open_auth(self, user: User):
        self.user = user
        self.cwd = Folder.INBOX
        self.mode = SessionMode.AUTHENTICATED

    async def cleanup(self):
        try:
            self.writer.close()
            await self.writer.wait_closed()
        finally:
            try:
                self.pool.release(self.conn)
            except Exception:
                pass
            
    async def read(self):
        self.input_frame = await InputFrame.from_wire(self.reader)
        
    async def write(self, status: Status, *entries: str):
        await OutputFrame(self.version, status, entries).to_wire(self.writer)