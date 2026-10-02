from __future__ import annotations
import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum, StrEnum, auto
import aiomysql

@dataclass(slots=True)
class User:
    user_id: int
    username: str
    created_on: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_accessed_on: datetime | None = None

@dataclass(slots=True)
class TransientUser:
    username: str
    password_hash: bytes | None = None
    created_on: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

class Folder(StrEnum):
    INBOX = 'Inbox'
    DRAFT = 'Draft'
    OUTBOX = 'Outbox'
    SENT = 'Sent'
    ARCHIVE = 'Archive'
    
    SPAM = 'Spam'
    JUNK = 'Junk'
    ASAP = 'ASAP'
    TODO = 'ToDo'
    TBC = 'TBC'
    TBD = 'TBD'
    MEMO = 'Memo'
    MISC = 'Misc'
    
    @classmethod
    def from_string(cls, value: str, default: Folder | None=None) -> Folder | None:
        clean = value.strip().upper()
        return next((member for member in cls if member.name == clean), default)
    
class Mode(IntEnum):
    WAITING = auto()
    AUTHENTICATED = auto()
    VALIDATING_JOINING = auto()
    MESSAGE_VIEWING = auto()
    MESSAGE_COMPOSING = auto()

@dataclass(slots=True)
class Context:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    pool: aiomysql.Pool
    conn: aiomysql.connection.Connection
    user: User | None = None
    trans_user: TransientUser | None = None
    cwd: Folder | None = None
    mode: Mode = Mode.WAITING

    def purge_auth(self):
        self.trans_user = None
        self.user = None
        self.cwd = None
        self.mode = Mode.WAITING

    def purge_join(self):
        self.trans_user = None
        if self.user is None:
            self.cwd = None
            self.mode = Mode.WAITING
        else:
            self.mode = Mode.AUTHENTICATED

    def promote_join(self, user_id: int):
        self.user = User(user_id, self.trans_user.username, self.trans_user.created_on)
        self.trans_user = None
        self.cwd = Folder.INBOX
        self.mode = Mode.AUTHENTICATED

    async def cleanup(self):
        try:
            self.writer.close()
            await self.writer.wait_closed()
        finally:
            try:
                self.pool.release(self.conn)
            except Exception:
                pass