# WILL BE LEFT UNFINISHED AS POP3 WAS DEEMED TERMINALLY DEPRECATED FOR THE PROJECT

import asyncio
import contextvars
from dataclasses import dataclass, field
import datetime
from enum import IntEnum, StrEnum
import os
import ssl
from typing import Sequence
import uuid

import aiomysql

from database import Database

class POP3State(IntEnum):
    AUTHORIZATION = field()
    TRANSACTION = field()
    UPDATE = field()

class POP3Status(StrEnum):
    OK = "+OK"
    ERR = "-ERR"

@dataclass(slots=True)
class User:
    account_uid: int
    account_address: str
    created_at: datetime
    updated_at: datetime

class POP3Session:
    __slot__ = ('_uid', 'reader', 'writer', 'state')
    
    def __init__(self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        pool
    ):
        self._uid = uuid.uuid7()
        self.reader = reader
        self.writer = writer
        self.state = POP3State.AUTHORIZATION
        self.pool = pool
        
        self.flagged_messages: set[int] = set()
        self.uidl_mode = False
        self.user: User | None = None

    @property
    def uid(self) -> uuid.UUID:
        return self._uid
    
    def __hash__(self):
        return hash(self._uid)

    def __eq__(self, other: object):
        if not isinstance(object, POP3Session):
            return False
        return self._uid == other._uid

    def write_text(self, text: str):
        self.writer.write(text.encode())

    def write_raw(self, text: bytes):
        self.writer.write(text)

    async def drain(self):
        await self.writer.drain()
        
    async def close(self):
        self.writer.close()
        await self.writer.wait_closed()

class POP3Database:
    def __init__(self):
        self._pool: aiomysql.Pool | None = None
        self._task_connection = contextvars.ContextVar("task_connection")

    async def create_pool(self) -> None:
        if self._pool is None or self._pool.closed:
            self._pool = await aiomysql.create_pool(
                host=os.environ["POP3_MySQL_HOST"],
                user=os.environ["POP3_MySQL_USER"],
                password=os.environ["POP3_MySQL_PASSWORD"],
                db=os.environ["POP3_MySQL_DB"],
            )

    async def test_conn(self) -> bool:
        try:
            async with self._pool.acquire() as conn, conn.cursor() as cursor:
                await cursor.execute("SELECT VERSION();")
                ver, = await cursor.fetchone()
                print(f"Connected to MySQL version: {ver}")
                return True
        except Exception as e:
            print(f"Failed to connect to MySQL: {e}")
            return False

    async def close_pool(self) -> None:
        if self._pool is None:
            return
        self._pool.close()
        await self._pool.wait_closed()
        self._pool = None

class POP3Server:
    SAFE_CIPHERS = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
    SSL_OPTIONS = ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_CIPHER_SERVER_PREFERENCE | ssl.OP_NO_RENEGOTIATION
    
    MYSQL_CONN = {
        'host':os.environ["POP3_MySQL_HOST"],
        'user':os.environ["POP3_MySQL_USER"],
        'password':os.environ["POP3_MySQL_PASSWORD"],
        'db':os.environ["POP3_MySQL_DB"]
    }
    
    def __init__(self, 
        host: str = "localhost", 
        standard_port: int = 110, 
        secure_port: int = 995, 
        *, 
        ip_blacklist: Sequence[int] | None = None
    ):
        self.host = host
        self.standard_port = standard_port
        self.secure_port = secure_port
        
        self.unsecure_socket: None | asyncio.Server = None
        self.secure_socket: None | asyncio.Server = None
        
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.ssl_context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
        
        self.is_running = False
        self.is_serving = False
        
        self.pool = None
        
        self.ip_blacklist = set(ip_blacklist) if ip_blacklist else set()
        
        self.sessions = set()
    
    async def start(self):
        if not self.is_running:
            self.unsecure_socket = await asyncio.start_server(self._listen, self.host, self.standard_port)
            self.secure_socket = await asyncio.start_server(self._listen, self.host, self.secure_port, ssl=self.ssl_context)
            self.is_running = True
    
    async def serve(self):
        if not self.is_serving:
            await asyncio.gather(
                self.unsecure_sock.serve_forever(), 
                self.secure_sock.serve_forever()
            )
            self.is_serving = True
    
    async def _listen(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peername = writer.get_extra_info("peername")
        if peername and peername[0] in self.ip_blacklist:
            writer.close()
            await writer.wait_closed()
            return
        
        writer.write(b"")
        
        async with aiomysql.create_pool(**self.MYSQL_CONN) as pool:
            session = POP3Session(reader, writer, pool)
            self.sessions.add(session)
            
            
    
    async def _quit_command(self, session: POP3Session):
        if session.state == POP3State.AUTHORIZATION:
            session.write_raw(b"+OK Pearlescence server signing off\r\n")

        elif session.state == POP3State.UPDATE:
            n_flagged = len(session.flagged_messages)
            affected = 0

            if n_flagged > 0:
                async with session.pool.acquire() as conn:
                    async with conn.cursor() as cur:
                        placeholders = ', '.join(['%s'] * n_flagged)
                        
                        await cur.execute(
                            f"DELETE FROM message WHERE message_uid IN ({placeholders})", 
                            tuple(session.flagged_messages)
                        )
                        
                        affected = cur.rowcount
                        
                        await conn.commit()

            if affected == n_flagged:
                session.write_raw(b"+OK Pearlescence server signing off\r\n")
            else:
                session.write_text(f"-ERR {affected}/{n_flagged} messages were deleted\r\n")

        else:
            session.write_raw(b"-ERR quit must be used during AUTHORIZATION or UPDATE\r\n")
        
        await session.drain()
        
    async def _stat_command(self, session: POP3Session):
        if session.state == POP3State.TRANSACTION:
            async with session.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        """SELECT COUNT(*), COALESCE(SUM(m.byte_count), 0) FROM message as m
                        INNER JOIN message_recipient as mr ON m.message_uid = mr.message_uid
                        WHERE recipient_address = %s;""", 
                        (session.user.account_address)
                    )

                    row = await cur.fetchone()
            
            session.write_text(f"+OK {row[0]} {row[1]}\r\n")
                
        else:
            session.write_raw(b"-ERR state must be used during TRANSACTION\r\n")
                
        await session.drain()    
        
    async def _list_command(self, session: POP3Session, args: list[str]):
        if session.state == POP3State.TRANSACTION:
            if not args:
                async with session.pool.acquire() as conn:
                    async with conn.cursor() as cur:
                        n_flagged = len(session.flagged_messages)
                        placeholders = ', '.join(['%s'] * n_flagged)
                        
                        await cur.execute(
                            f"""SELECT m.byte_count FROM message as m
                            INNER JOIN message_recipient as mr ON m.message_uid = mr.message_uid
                            WHERE recipient_address = %s AND message_uid NOT IN ({placeholders});""", 
                            (session.user.account_address, *session.flagged_messages)
                        )
                        
                        rows = await cur.fetchall()
                        
                session.write_text(f"+OK {len(rows)} messages ({sum(row[0] for row in rows)} bytes)\r\n")
                for i, row in enumerate(row, 1):
                    session.write_text(f"{i} {row}\r\n")
                session.write_raw(b".\r\n")
                    
            else:
                target = int(args[0])
                
                async with session.pool.acquire() as conn:
                    async with conn.cursor() as cur:
                        if session.uidl_mode:
                            if target not in session.flagged_messages:
                                await cur.execute(
                                    """SELECT byte_count.m FROM message as m 
                                    INNER JOIN message_recipient as mr ON m.message_uid = mr.message_uid
                                    WHERE recipient_address = %s AND message_uid = %s;""",
                                    (session.user.account_address, target)
                                )
                                row = await cur.fetchone()
                            else:
                                row = None
                        else:
                            await cur.execute(
                                f"""SELECT byte_count FROM (
                                        SELECT m.byte_count, ROW_NUMBER() OVER (ORDER BY m.message_uid) as row_num
                                        FROM message as m
                                        INNER JOIN message_recipient as mr ON m.message_uid = mr.message_uid
                                        WHERE recipient_address = %s AND m.message_uid NOT IN ({placeholders})
                                    ) as numbered
                                    WHERE row_num = %s;""",
                                (session.user.account_address, *session.flagged_messages, target)
                            )
                            row = await cur.fetchone()
                if row:
                    session.write_text(f"+OK {target} {row[0]}\r\n")
                else:
                    session.write_text(f"+ERR {target} is not available\r\n")
        
        else:
            session.write_raw(b"-ERR list must be used during TRANSACTION\r\n")
                    
        await session.drain()               
        
    async def _retr_command(self, session: POP3Session, args: list[str]):
        if session.state == POP3State.TRANSACTION:
            target = int(args[0])
            
            async with session.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    if session.uidl_mode:
                        if target not in session.flagged_messages:
                            await cur.execute(
                                """SELECT m.byte_count, m.return_path, m.sender_address, m.subject, m.mime_version, m.content_type, m.content_boundary, m.body 
                                FROM message as m 
                                INNER JOIN message_recipient as mr ON m.message_uid = mr.message_uid
                                WHERE recipient_address = %s AND message_uid = %s;""",
                                (session.user.account_address, target)
                            )
                            email = await cur.fetchone()
                            
                        else: # Cater to outdated clients for protocol compliance
                            n_flagged = len(session.flagged_messages)
                            placeholders = ', '.join(['%s'] * n_flagged)
                            
                            await cur.execute(
                                f"""SELECT byte_count, return_path, sender_address, subject, mime_version, content_type, content_boundary, body 
                                FROM (
                                    SELECT m.byte_count, m.return_path, m.sender_address, m.subject, m.mime_version, m.content_type, m.content_boundary, m.body, ROW_NUMBER() OVER (ORDER BY m.message_uid) as row_num
                                    FROM message as m
                                    INNER JOIN message_recipient as mr ON m.message_uid = mr.message_uid
                                    WHERE recipient_address = %s AND m.message_uid NOT IN ({placeholders})
                                ) as numbered
                                WHERE row_num = %s;""",
                                (session.user.account_address, *session.flagged_messages, target)
                            )
                            email = await cur.fetchone()
                            
                        await cur.execute(
                            """SELECT recipient_address, type 
                            FROM message_recipient
                            WHERE message_uid = %s AND type != 'BCC';""",
                            (target,)
                        )
                        recipients = await cur.fetchall()
                            
            session.write_text(f"+OK {email[0]} bytes follow\r\n")
            
        
    def _dele_command(self):
        ...
        
    def _noop_command(self):
        ...
        
    def _rset_command(self):
        ...
        
    def _top_command(self):
        ...
        
    def _uidl_command(self):
        ...
        
    def _user_command(self):
        ...
        
    def _pass_command(self):
        ...
        
    def _apop_command(self):
        ...