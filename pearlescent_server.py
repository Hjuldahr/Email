import asyncio
import os
from typing import NamedTuple
import uuid

import aiomysql
import bcrypt

class User(NamedTuple):
    user_id: int
    username: str
    password_hash: bytes | None

class PearlescentServer:
    HOST = "127.0.0.1"
    MY_PORT = 25
    POP3_PORT = 110

    NAMESPACE = uuid.UUID('99b00d33-11b3-4f37-bd46-18a624fcfe74')

    def __init__(self):
        self.pool: aiomysql.Pool | None = None
        self.sock: asyncio.Server | None = None

    async def start(self):
        if self.pool is None or self.pool.closed:
            self.pool = await aiomysql.create_pool(
                host=os.environ["SQL_HOST"],
                user=os.environ["SQL_USER"],
                password=os.environ["SQL_PASSWORD"],
                db=os.environ["SQL_DB"],
            )

            async with self.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute("SELECT VERSION();")
                    ver, = await cur.fetchone()
                    print(f"Connected to MySQL version: {ver}")
                    
        if self.sock is None:
            self.sock = await asyncio.start_server(
                self.listen,
                self.HOST,
                self.MY_PORT,
            )
            
    async def serve(self):
        async with self.sock:
            await asyncio.gather(
                self.sock.serve_forever()
            )
    
    @staticmethod
    async def read_frame(reader: asyncio.StreamReader) -> list[bytes]:
        data = await reader.readuntil(b'\v')
        return data.removesuffix(b'\v').split(b'\t')
    
    async def listen(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        # format 'CMD\tmy data\tmultiline\ntext\v'
        user: User | None = None

        writer.write(b'+OK pearlescence service ready\v')
        await writer.drain()

        try:
            async with self.pool.acquire() as conn:
                while True:
                    cmd_seq = await self.read_frame(reader)

                    match cmd_seq[0]:
                        case b'AUTH':
                            user, msg = await self.auth_cmd(conn, cmd_seq)

                        case b'JOIN':
                            user, msg = await self.join_cmd(conn, cmd_seq)
                            writer.write(msg)
                            await writer.drain()

                            if user is not None:
                                cmd_seq = await self.read_frame(reader)
                                user, msg = await self.verify_join_cmd(conn, user, cmd_seq)

                        case b'DROP':
                            user, msg = await self.drop_user_cmd(conn, user, cmd_seq)

                        case b'EXIT':
                            if user is not None:
                                msg = f'+OK Goodbye {user.user_name}!\nYou have been logged out.\v'.encode('ascii')
                            else:
                                msg = b'+OK You are already logged out.\v'
                            user = None

                        case b'DC':
                            writer.write(f'+OK Goodbye {user.user_name}!\nYou have been {"logged out and " if user is not None else ""}disconnected.\v'.encode('ascii'))
                            await writer.drain()
                            break

                        case _:
                            msg = b'-ERR Unknown Command\v'

                    writer.write(msg)
                    await writer.drain()

        except asyncio.IncompleteReadError as e:
            print(f"Connection ended: {e.partial!r}")
        except Exception as e:
            print(f"Invalid state: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def auth_cmd(self, conn, cmd_seq: list[bytes]) -> tuple[User | None, bytes]:
        if len(cmd_seq) != 3:
            return None, b'-ERR Invalid Arguments\v'
        
        username = cmd_seq[1].decode('ascii')
        password = cmd_seq[2]
        
        async with conn.cursor() as cur:
            await cur.execute(
                '''
                SELECT last_accessed_on, user_id, user_password_hash
                FROM user_accounts
                WHERE user_name = %s;
                ''',
                (username,),
            )

            row = await cur.fetchone()

            if row is None:
                return None, b'-ERR authentication failed\v'
            
            last_login, user_id, password_hash = row
            
            if not bcrypt.checkpw(password, password_hash):
                return None, b'-ERR authentication failed\v'
            
            await cur.execute(
                '''
                SELECT COUNT(*)
                FROM messages
                WHERE user_id = %s
                AND is_unread;
                ''',
                (user_id,),
            )
            unread, = await cur.fetchone()
            
            await cur.execute(
                '''
                UPDATE user_accounts SET last_accessed_on = CURRENT_TIMESTAMP
                WHERE user_id = %s;
                ''',
                (user_id,),
            )
            await conn.commit()
        
        user = User(user_id, username, None)
        return user, f'+OK Welcome {username} (#{user_id})!\nYou have {unread} unread messages.\nYour last login was on {last_login}\v'.encode('ascii')
    
    async def join_cmd(self, conn, cmd_seq: list[bytes]) -> tuple[User | None, bytes]:
        if len(cmd_seq) != 3:
            return None, b'-ERR Invalid Arguments\v'

        username = cmd_seq[1].decode('ascii')
        password = cmd_seq[2]

        async with conn.cursor() as cur:
            await cur.execute(
                '''
                SELECT EXISTS (
                    SELECT 1
                    FROM user_accounts
                    WHERE user_name = %s
                );
                ''',
                (username,),
            )

            exists, = await cur.fetchone()

        if exists:
            return None, f'-ERR Sorry, but the username {username} was already taken!\nPlease be more creative next time.\v'.encode('ascii')

        salt = bcrypt.gensalt(12)
        password_hash = bcrypt.hashpw(password, salt)
                
        user = User(-1, username, password_hash)
        return user, b'+OK Please verify your password\v'
        
    async def verify_join_cmd(self, conn, user: User, cmd_seq: list[bytes]) -> tuple[User | None, bytes]:
        if user is None:
            return None, b'-ERR Partial authentication required\v'
        
        if len(cmd_seq) != 1:
            return None, b'-ERR Invalid Arguments\v'

        password = cmd_seq[0]

        if not bcrypt.checkpw(password, user.password_hash):
            return None, b'-ERR authentication failed\v'
        
        async with conn.cursor() as cur:
            await cur.execute(
                '''
                INSERT INTO user_accounts(user_name, user_password_hash)
                VALUES(%s, %s);
                ''',
                (user.username, user.password_hash),
            )

            user.user_id = cur.lastrowid
            await conn.commit()
        
        user.password_hash = None
        return user, f'+OK Welcome {user.username} (#{user.user_id})!\nYou have zero unread messages.\nYour last login was never\v'.encode('ascii')
    
    async def drop_user_cmd(
        self,
        conn,
        user: User | None,
        cmd_seq: list[bytes],
    ) -> tuple[User | None, bytes]:
        if user is None:
            return user, b'-ERR Authentication required\v'

        if len(cmd_seq) != 1:
            return user, b'-ERR Invalid Arguments\v'

        password = cmd_seq[0]

        async with conn.cursor() as cur:
            await cur.execute(
                '''
                SELECT user_password_hash
                FROM user_accounts
                WHERE user_id = %s;
                ''',
                (user.user_id,),
            )

            row = await cur.fetchone()

            if row is None:
                return None, b'-ERR Account no longer exists\v'

            password_hash, = row

            if not bcrypt.checkpw(password, password_hash):
                return user, b'-ERR authentication failed\v'

            await cur.execute(
                '''
                DELETE FROM user_accounts
                WHERE user_id = %s;
                ''',
                (user.user_id,),
            )

            await conn.commit()

        username = user.username
        return None, f'+OK Goodbye {username}!\nPlease come again in the future.\v'.encode('ascii')