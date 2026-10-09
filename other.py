from __future__ import annotations
import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum, StrEnum, auto
from typing import NamedTuple
import uuid
import aiomysql

from input_frame import InputFrame
from output_frame import OutputFrame, Status

class Direction(StrEnum):
    INBOUND = "INBOUND" 
    OUTBOUND = "OUTBOUND"

class MessageFolder(NamedTuple):
    current_folder: Folder
    direction: Direction

@dataclass(slots=True)
class User:
    user_id: int
    username: str
    created_on: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_accessed_on: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

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

class SessionCoordinator:
    # Swap 'session_uid' for '_session_uid' to protect the hash base
    __slots__ = (
        'version', 'reader', 'writer', 'pool', 
        'conn', 'input_frame', 'view_only', 'notify', 'contact_alias', 
        'is_eof', 'mirror_address', 'notification_queue', '_session_uid',
        'user', 'mode'
    )
    
    def __init__(self,
        version: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        pool: aiomysql.Pool,
        conn: aiomysql.connection.Connection
    ):
        # Application level
        self.version = version
        self.reader = reader
        self.writer = writer
        self.pool = pool
        
        # Session level
        self._session_uid = uuid.uuid7()
        self.conn = conn
        self.mode: SessionMode = SessionMode.CONNECTED
        self.input_frame: InputFrame | None = None
        self.view_only = False
        self.notify = True
        self.contact_alias = True
        self.is_eof = False
        self.mirror_address: str | None = None
        self.notification_queue = asyncio.Queue()
        
        # Auth level
        self.user: User | None = None

    @property
    def session_uid(self) -> uuid.UUID:
        """Expose read-only UUID to keep the hash stable for collections."""
        return self._session_uid
        
    def __hash__(self) -> int:
        return hash(self._session_uid)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SessionCoordinator):
            return False
        return self._session_uid == other._session_uid 

    def open_auth(self, user: User):
        self.user = user
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
        try:
            self.input_frame = await InputFrame.from_wire(self.reader)
        finally:
            if self.input_frame is None and self.reader.at_eof():
                self.is_eof = True
        
    async def write(self, status: Status, *entries: str):
        await OutputFrame(self.version, status, *entries).to_wire(self.writer)
    
    async def auth_check(self):
        if self.mode != SessionMode.AUTHENTICATED:
            await self.write(Status.ERR, 'You must be authenticated to use this operation.')
            return False
        return True
    
    async def modify_check(self):
        if self.view_only:
            await self.write(Status.ERR, 'You must have viewonly set to OFF to use this operation.')
            return False
        return True