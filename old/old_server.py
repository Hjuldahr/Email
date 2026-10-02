import asyncio
import os
import uuid
import aiomysql
import bcrypt

class EmailServer:
    HOST = "127.0.0.1"
    SMTP_PORT = 25
    POP3_PORT = 110

    NAMESPACE = uuid.UUID('99b00d33-11b3-4f37-bd46-18a624fcfe74')

    def __init__(self):
        self.pool: aiomysql.Pool | None = None
        self.smtp: asyncio.Server | None = None
        self.pop3: asyncio.Server | None = None

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
                    
        if self.smtp is None:
            self.smtp = await asyncio.start_server(
                self.handle_smtp,
                self.HOST,
                self.SMTP_PORT,
            )
            
        if self.pop3 is None:
            self.pop3 = await asyncio.start_server(
                self.handle_pop3,
                self.HOST,
                self.POP3_PORT,
            )
            
    async def serve(self):
        async with self.smtp, self.pop3:
            await asyncio.gather(
                self.smtp.serve_forever(),
                self.pop3.serve_forever(),
            )
        
    async def handle_smtp(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        ...

    async def handle_pop3(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        state = 'AUTHORIZATION'
        user_id: int | None = None
        username: str | None = None
        message_ids: list[int] = []
        deleted: set[int] = set()

        writer.write(b'+OK pearlescence POP3 service ready\r\n')
        await writer.drain()

        async with self.pool.acquire() as conn:
            async with conn.cursor() as cur:
                while True:
                    line = await reader.readuntil(b'\r\n')
                    parts = line[:-2].split(b' ', 1)
                    command = parts[0]
                    args = parts[1] if len(parts) > 1 else b''

                    match command:
                        case b'QUIT':
                            if state == 'TRANSACTION':
                                for message_number in deleted:
                                    message_id = message_ids[message_number - 1]
                                    await cur.execute(
                                        '''
                                        DELETE FROM messages
                                        WHERE message_id = %s
                                        AND user_id = %s;
                                        ''',
                                        (message_id, user_id),
                                    )

                            await conn.commit()
                            writer.write(
                                b'+OK pearlescence session terminating\r\n'
                            )
                            await writer.drain()
                            break

                        case b'USER':
                            if state != 'AUTHORIZATION':
                                writer.write(b'-ERR already authenticated\r\n')
                                continue

                            username = args.decode()
                            writer.write(b'+OK\r\n')

                        case b'PASS':
                            if state != 'AUTHORIZATION':
                                writer.write(b'-ERR already authenticated\r\n')
                                continue

                            if username is None:
                                writer.write(b'-ERR USER required\r\n')
                                continue

                            await cur.execute(
                                '''
                                SELECT user_id, user_password_hash
                                FROM user_accounts
                                WHERE user_name = %s;
                                ''',
                                (username,),
                            )

                            row = await cur.fetchone()

                            if row is None:
                                writer.write(b'-ERR authentication failed\r\n')
                                continue

                            user_id, password_hash = row

                            if not bcrypt.checkpw(args, password_hash):
                                user_id = None
                                writer.write(b'-ERR authentication failed\r\n')
                                continue

                            await cur.execute(
                                '''
                                SELECT message_id
                                FROM messages
                                WHERE user_id = %s
                                ORDER BY message_id;
                                ''',
                                (user_id,),
                            )

                            message_ids = [
                                message_id
                                for message_id, in await cur.fetchall()
                            ]

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
                            state = 'TRANSACTION'

                            writer.write(
                                f'+OK welcome {username}. '
                                f'You have {unread} unread messages.\r\n'
                                .encode('ascii')
                            )

                        case b'STAT':
                            if state != 'TRANSACTION':
                                writer.write(b'-ERR authentication required\r\n')
                                continue

                            await cur.execute(
                                '''
                                SELECT COUNT(*), COALESCE(SUM(body_size), 0)
                                FROM messages
                                WHERE user_id = %s;
                                ''',
                                (user_id,),
                            )

                            quantity, size = await cur.fetchone()

                            writer.write(
                                f'+OK {quantity} {size}\r\n'.encode('ascii')
                            )

                        case b'LIST':
                            if state != 'TRANSACTION':
                                writer.write(b'-ERR not authenticated\r\n')
                                continue

                            if args:
                                try:
                                    message_number = int(args)
                                except ValueError:
                                    writer.write(b'-ERR invalid message number\r\n')
                                    continue

                                if not 1 <= message_number <= len(message_ids):
                                    writer.write(b'-ERR no such message\r\n')
                                    continue

                                message_id = message_ids[message_number - 1]

                                await cur.execute(
                                    '''
                                    SELECT body_size
                                    FROM messages
                                    WHERE message_id = %s
                                    AND user_id = %s;
                                    ''',
                                    (message_id, user_id),
                                )

                                row = await cur.fetchone()

                                if row is None:
                                    writer.write(b'-ERR no such message\r\n')
                                    continue

                                size, = row

                                writer.write(
                                    f'+OK {message_number} {size}\r\n'
                                    .encode('ascii')
                                )
                            else:
                                await cur.execute(
                                    '''
                                    SELECT message_id, body_size
                                    FROM messages
                                    WHERE user_id = %s
                                    ORDER BY message_id;
                                    ''',
                                    (user_id,),
                                )

                                rows = await cur.fetchall()

                                writer.write(
                                    f'+OK {len(rows)} messages\r\n'
                                    .encode('ascii')
                                )

                                writer.writelines(
                                    f'{i} {size}\r\n'.encode('ascii')
                                    for i, (_, size) in enumerate(rows, 1)
                                )

                                writer.write(b'.\r\n')

                        case b'RETR':
                            if state != 'TRANSACTION':
                                writer.write(b'-ERR not authenticated\r\n')
                                continue

                            try:
                                message_number = int(args)
                            except ValueError:
                                writer.write(b'-ERR invalid message number\r\n')
                                continue

                            if not 1 <= message_number <= len(message_ids):
                                writer.write(b'-ERR no such message\r\n')
                                continue

                            message_id = message_ids[message_number - 1]

                            await cur.execute(
                                '''
                                SELECT body
                                FROM messages
                                WHERE message_id = %s
                                AND user_id = %s;
                                ''',
                                (message_id, user_id),
                            )

                            row = await cur.fetchone()

                            if row is None:
                                writer.write(b'-ERR no such message\r\n')
                                continue

                            body, = row

                            writer.write(b'+OK message follows\r\n')
                            writer.write(body)
                            writer.write(b'\r\n.\r\n')

                        case b'DELE':
                            if state != 'TRANSACTION':
                                writer.write(b'-ERR not authenticated\r\n')
                                continue

                            try:
                                message_number = int(args)
                            except ValueError:
                                writer.write(b'-ERR invalid message number\r\n')
                                continue

                            if not 1 <= message_number <= len(message_ids):
                                writer.write(b'-ERR no such message\r\n')
                                continue

                            if message_number in deleted:
                                writer.write(b'-ERR message already deleted\r\n')
                                continue

                            deleted.add(message_number)

                            writer.write(
                                f'+OK message {message_number} marked for deletion\r\n'
                                .encode('ascii')
                            )

                        case b'NOOP':
                            writer.write(b'+OK\r\n')

                        case b'RSET':
                            if state != 'TRANSACTION':
                                writer.write(b'-ERR not authenticated\r\n')
                                continue

                            deleted.clear()
                            writer.write(b'+OK\r\n')

                        case b'TOP':
                            if state != 'TRANSACTION':
                                writer.write(b'-ERR not authenticated\r\n')
                                continue

                            try:
                                message_number, line_count = args.split(b' ', 1)
                                message_number = int(message_number)
                                line_count = int(line_count)
                            except (ValueError, TypeError):
                                writer.write(b'-ERR invalid arguments\r\n')
                                continue

                            if not 1 <= message_number <= len(message_ids):
                                writer.write(b'-ERR no such message\r\n')
                                continue

                            message_id = message_ids[message_number - 1]

                            await cur.execute(
                                '''
                                SELECT body
                                FROM messages
                                WHERE message_id = %s
                                AND user_id = %s;
                                ''',
                                (message_id, user_id),
                            )

                            row = await cur.fetchone()

                            if row is None:
                                writer.write(b'-ERR no such message\r\n')
                                continue

                            body, = row

                            # TODO: separate headers from body.
                            headers, _, body = body.partition(b'\r\n\r\n')
                            body_lines = body.splitlines()[:line_count]

                            writer.write(b'+OK top of message follows\r\n')
                            writer.write(headers)
                            writer.write(b'\r\n\r\n')

                            for line in body_lines:
                                writer.write(line + b'\r\n')

                            writer.write(b'.\r\n')

                        case b'UIDL':
                            if state != 'TRANSACTION':
                                writer.write(b'-ERR not authenticated\r\n')
                                continue

                            if args:
                                try:
                                    message_number = int(args)
                                except ValueError:
                                    writer.write(b'-ERR invalid message number\r\n')
                                    continue

                                if not 1 <= message_number <= len(message_ids):
                                    writer.write(b'-ERR no such message\r\n')
                                    continue

                                message_id = message_ids[message_number - 1]
                                uid = uuid.uuid5(
                                    self.NAMESPACE,
                                    str(message_id),
                                ).hex

                                writer.write(
                                    f'+OK {message_number} {uid}\r\n'
                                    .encode('ascii')
                                )
                            else:
                                writer.write(
                                    b'+OK unique-id listing follows\r\n'
                                )

                                for number, message_id in enumerate(
                                    message_ids,
                                    1,
                                ):
                                    uid = uuid.uuid5(
                                        self.NAMESPACE,
                                        str(message_id),
                                    ).hex

                                    writer.write(
                                        f'{number} {uid}\r\n'.encode('ascii')
                                    )

                                writer.write(b'.\r\n')

                        case b'CAPA':
                            writer.write(
                                b'+OK Capability list follows\r\n'
                                b'USER\r\n'
                                b'PASS\r\n'
                                b'QUIT\r\n'
                                b'STAT\r\n'
                                b'LIST\r\n'
                                b'RETR\r\n'
                                b'DELE\r\n'
                                b'TOP\r\n'
                                b'RSET\r\n'
                                b'UIDL\r\n'
                                b'CAPA\r\n'
                                b'.\r\n'
                            )

                        case _:
                            writer.write(b'-ERR unknown command\r\n')

                    await writer.drain()

    async def close(self):
        if self.smtp is not None and self.smtp.is_serving():
            self.smtp.close()
            await self.smtp.wait_closed()
            self.smtp = None
            
        if self.pop3 is not None and self.pop3.is_serving():
            self.pop3.close()
            await self.pop3.wait_closed()
            self.pop3 = None
            
        if self.pool is not None and not self.pool.closed:
            self.pool.close()
            await self.pool.wait_closed()
            self.pool = None
            
async def main():
    server = EmailServer()

    try:
        await server.start()
        await server.serve()
    finally:
        print("\nStopping server...")
        await server.stop()
        print("Stopped server...")

if __name__ == "__main__":
    asyncio.run(main())