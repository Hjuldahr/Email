import asyncio
from datetime import datetime
import uuid
import bcrypt

from database import Database
from other import Context, Folder, Mode, TransientUser, User

class PearlescentServer:
    HOST = "127.0.0.1"
    MY_PORT = 25
    POP3_PORT = 110

    NAMESPACE = uuid.UUID('99b00d33-11b3-4f37-bd46-18a624fcfe74')

    def __init__(self):
        self.db = Database()
        self.sock: asyncio.Server | None = None

    async def start(self):
        await self.db.open()
                    
        if self.sock is None:
            self.sock = await asyncio.start_server(
                self._listen,
                self.HOST,
                self.MY_PORT,
            )
            
        async with self.sock:
            await asyncio.gather(
                self.sock.serve_forever()
            )
            
    async def stop(self):
        self.sock.close()
        self.sock.close_clients()
        await self.sock.wait_closed()
        
        await self.db.close()
    
    @staticmethod
    async def _read_frame(reader: asyncio.StreamReader) -> list[bytes]:
        data = await reader.readuntil(b'\v')
        return data.removesuffix(b'\v').split(b'\t')
    
    async def _listen(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        # format 'CMD\tmy data\tmultiline\ntext\v'
        ctx = Context()

        writer.write(b'+OK pearlescence service ready\v')
        await writer.drain()

        try:
            async with self.db.pool.acquire() as conn:
                ctx.conn = conn
                
                while True:
                    cmd_seq = await self._read_frame(reader)

                    match cmd_seq[0]:
                        case b'AUTH':
                            user, msg = await self.auth_cmd(conn, cmd_seq)
                            ctx.user = user

                        case b'JOIN':
                            msg = await self.join_cmd(conn, cmd_seq)
                            
                            writer.write(msg)
                            await writer.drain()

                            if ctx.user is not None:
                                cmd_seq = await self._read_frame(reader)
                                msg = await self.verify_join_cmd(ctx, cmd_seq)

                        case b'DROP':
                            msg = await self.drop_user_cmd(ctx, cmd_seq)

                        case b'EXIT':
                            if ctx.user is not None:
                                msg = f'+OK Goodbye {ctx.user.user_name}!\nYou have been logged out.\v'.encode('ascii')
                            else:
                                msg = b'+OK You are already logged out.\v'
                            ctx.user = None

                        case b'DC':
                            writer.write(f'+OK Goodbye {ctx.user.user_name}!\nYou have been {"logged out and " if ctx.user is not None else ""}disconnected.\v'.encode('ascii'))
                            await writer.drain()
                            break
                        
                        case b'USE':
                            msg = await self.use_folder_cmd(ctx, cmd_seq)

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


    async def auth_cmd(self, ctx: Context, cmd_seq: list[bytes]) -> bytes:
        if len(cmd_seq) != 3:
            return b'-ERR Invalid Arguments\v'
        
        username = cmd_seq[1].decode('ascii')
        password = cmd_seq[2]
        
        async with ctx.conn.cursor() as cur:
            await cur.execute(
                '''
                SELECT user_id, user_password_hash, created_on, last_accessed_on
                FROM user_accounts
                WHERE user_name = %s;
                ''',
                (username,),
            )

            row = await cur.fetchone()

            if row is None:
                return b'-ERR authentication failed\v'
            
            user_id, password_hash, created_on, last_login = row
            
            if not bcrypt.checkpw(password, password_hash):
                return b'-ERR authentication failed\v'
            
            await cur.execute(
                '''
                SELECT COUNT(*)
                FROM messages
                WHERE user_id = %s AND 
                folder = 'Inbox' AND 
                is_unread
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
            await ctx.conn.commit()
        
        ctx.user = User(user_id, username, created_on, last_login)
        ctx.mode = Mode.AUTHENTICATED
        
        return f'+OK Welcome {username} (#{user_id})!\nYou have {unread} unread messages in your Inbox.\nYour last login was on {last_login}\v'.encode('ascii')

    
    async def join_cmd(self, ctx: Context, cmd_seq: list[bytes]) -> bytes:
        if len(cmd_seq) != 3:
            return b'-ERR Invalid Arguments\v'

        username = cmd_seq[1].decode('ascii')
        password = cmd_seq[2]

        async with ctx.conn.cursor() as cur:
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
                
        ctx.trans_user = TransientUser(
            username, 
            bcrypt.hashpw(password, bcrypt.gensalt(12))
        )
        ctx.mode = Mode.VALIDATING_JOINING
        
        return b'+OK Please verify your password\v'
        
    async def verify_join_cmd(self, ctx: Context, cmd_seq: list[bytes]) -> bytes:
        if ctx.mode != Mode.VALIDATING_JOINING:
            ctx.purge_transient_user()
            return b'-ERR Invalid mode\v'
        
        if len(cmd_seq) != 1:
            ctx.purge_transient_user()
            return b'-ERR Invalid Arguments\v'

        password = cmd_seq[0]

        if not bcrypt.checkpw(password, ctx.trans_user.password_hash):
            return b'-ERR authentication failed\v'
        
        async with ctx.conn.cursor() as cur:
            await cur.execute(
                '''
                INSERT INTO user_accounts(user_name, user_password_hash)
                VALUES(%s, %s);
                ''',
                (ctx.trans_user.username, ctx.trans_user.password_hash),
            )

            user_id = cur.lastrowid
            await ctx.conn.commit()
            
        ctx.fold(user_id)
        
        return f'+OK Welcome {ctx.user.username} (#{user_id})!\nYou have zero unread messages.\nYour last login was never\v'.encode('ascii')
    
    async def drop_user_cmd(
        self,
        ctx: Context,
        cmd_seq: list[bytes],
    ) -> bytes:
        if ctx.mode != Mode.AUTHENTICATED:
            return b'-ERR Authentication required\v'

        if len(cmd_seq) != 1:
            return b'-ERR Invalid Arguments\v'

        password = cmd_seq[0]

        async with ctx.conn.cursor() as cur:
            await cur.execute(
                '''
                SELECT user_password_hash
                FROM user_accounts
                WHERE user_id = %s;
                ''',
                (ctx.user.user_id,),
            )

            row = await cur.fetchone()

            if row is None:
                return b'-ERR Account no longer exists\v'

            if not bcrypt.checkpw(password, row[0]):
                return b'-ERR authentication failed\v'

            await cur.execute(
                '''
                DELETE FROM user_accounts
                WHERE user_id = %s;
                ''',
                (ctx.user.user_id,),
            )

            await ctx.conn.commit()

        ctx.purge()
        return f'+OK Goodbye {ctx.user.username}!\nPlease come again in the future.\v'.encode('ascii')
    
    async def use_folder_cmd(
        self,
        ctx: Context,
        cmd_seq: list[bytes],
    ) -> bytes:
        if ctx.mode != Mode.AUTHENTICATED:
            return b'-ERR Authentication required\v'

        if len(cmd_seq) != 2:
            return b'-ERR Invalid Arguments\v'
        
        folder_name = cmd_seq[1].decode('ascii')
        
        async with ctx.conn.cursor() as cur:
            await cur.execute(
                '''
                SELECT folder_id, created_on
                FROM folders
                WHERE user_id = %s AND folder_name = %s;
                ''',
                (ctx.user.user_id, folder_name),
            )
            
            row = await cur.fetchone()
            
            if row is None:
                return f'-ERR The folder {folder_name} does not exist\v'.encode('ascii')
            
            folder_id, created_on = row
            
        ctx.cwd = Folder(
            folder_id,
            folder_name,
            created_on
        )
        
        return f'+OK The folder {folder_name} is now open\v'