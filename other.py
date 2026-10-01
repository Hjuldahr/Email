from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum, auto


@dataclass(slots=True)
class User:
    user_id: int
    username: str
    created_on: datetime = field(default_factory=lambda _: datetime.now(timezone.utc))
    last_accessed_on: datetime | None = None

@dataclass(slots=True)
class TransientUser:
    username: str
    password_hash: bytes | None = None
    created_on: datetime = field(default_factory=lambda _: datetime.now(timezone.utc))

@dataclass(slots=True)
class Folder:
    folder_id: int
    folder_name: str
    created_on: datetime

class Mode(IntEnum):
    WAITING = auto()
    AUTHENTICATED = auto()
    VALIDATING_JOINING = auto()
    MESSAGE_VIEWING = auto()
    MESSAGE_COMPOSING = auto()

@dataclass(slots=True)
class Context:
    conn = None
    user: User | None = None
    trans_user: TransientUser | None = None
    cwd: Folder | None = None
    mode: Mode = Mode.WAITING
    
    def purge(self):
        self.trans_user = None
        self.user = None
        self.cwd = None
        self.mode = Mode.WAITING
    
    def purge_transient_user(self):
        self.trans_user = None
        self.mode = Mode.WAITING if self.user is None else Mode.AUTHENTICATED
        
    def fold(self, user_id: int):
        self.user = User(user_id, self.trans_user.username, self.trans_user.created_on)
        self.trans_user = None
        self.cwd = None
        self.mode = Mode.AUTHENTICATED