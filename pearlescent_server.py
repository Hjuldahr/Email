import asyncio
import datetime
from enum import IntEnum, auto
import math
import re
import uuid
from database import Database
from input_frame import InputFrame, Operations
from other import SessionCoordinator, SessionMode, User
from output_frame import OutputFrame, Status
import aiobcrypt

class ProtocolError(Exception): ...

class ServerStatus(IntEnum):
    OFFLINE = auto()
    ONLINE = auto()
    CYCLING = auto()
    MALFUNCTIONING = auto()

class PearlescentServer:
    HOST = "127.0.0.1"
    UNSECURE_PORT = 25
    SECURE_PORT = 25
    POP3_PORT = 110

    PROTO_VERSION = 1
    NAMESPACE = uuid.UUID("99b00d33-11b3-4f37-bd46-18a624fcfe74")
    
    TIMEOUT = 300
    
    DESTINATION_TRANSITIONS = {
        'OUTBOX': {'DRAFTS', 'TRASH', 'ARCHIVE'},
        'DRAFTS': {'OUTBOX', 'TRASH', 'ARCHIVE'},
        'MERC': {'INBOX', 'JUNK', 'TRASH', 'ARCHIVE'},
        'INBOX': {'JUNK', 'TRASH', 'ARCHIVE'},
        'SENT': {'TRASH', 'ARCHIVE'},
        'JUNK': {'INBOX', 'ARCHIVE', 'TRASH'},
        'ARCHIVE': {'INBOX', 'JUNK', 'SENT', 'DRAFTS', 'TRASH'},
        'TRASH': {'INBOX', 'JUNK', 'SENT', 'DRAFTS'},
    }

    def __init__(self):
        self.db = Database()
        self.unsecure_sock: asyncio.Server | None = None
        self.secure_sock: asyncio.Server | None = None
        
        # Store raw bytes to avoid repeated packing
        self.out_greeting = OutputFrame(self.PROTO_VERSION, Status.INFO, ["Pearlescence service ready."]).pack()
        self.out_ping = OutputFrame.MAGIC_PREFIX + self.PROTO_VERSION.to_bytes(1)
        self.out_secure_params = OutputFrame(self.PROTO_VERSION, Status.INFO, ["Placeholder secure connection estabalishment params.", "A", "B", "C"]).pack()
        self.out_invalid_cmd = OutputFrame(self.PROTO_VERSION, Status.WARN, ["Invalid operation."]).pack()
        
        self.blocked_ips = set()
        self.sessions: set[SessionCoordinator] = set()
        
        self.status = ServerStatus.OFFLINE

    async def start(self):
        if self.status != ServerStatus.OFFLINE:
            return
        self.status = ServerStatus.CYCLING

        try:
            await self.db.open()

            if self.unsecure_sock is None:
                self.unsecure_sock = await asyncio.start_server(
                    self._unsecure_listen, self.HOST, self.UNSECURE_PORT
                )
                
            if self.secure_sock is None:
                self.secure_sock = await asyncio.start_server(
                    self._secure_listen, self.HOST, self.SECURE_PORT
                )

            self.status = ServerStatus.ONLINE

            async with self.unsecure_sock, self.secure_sock:
                await asyncio.gather(
                    self.unsecure_sock.serve_forever(),
                    self.secure_sock.serve_forever()
                )
        except Exception:
            self.status = ServerStatus.MALFUNCTIONING
            raise

    async def stop(self, reason: str, grace_period: float = 0):
        if self.status != ServerStatus.ONLINE:
            return
        self.status = ServerStatus.CYCLING
        
        try:
            # Stop accepting new connections
            self.unsecure_sock.close()
            self.secure_sock.close()
            
            # Close urchin connections
            self.unsecure_sock.close_clients()
            await self.unsecure_sock.wait_closed()
            
            # Grace period for active clients
            remaining = grace_period
            
            while remaining > 0:
                await self.broadcast(
                    Status.INFO,
                    f"The server is shutting down in {str(datetime.timedelta(seconds=math.ceil(remaining)))} for {reason}.\n", "Please disconnect when it is most convenient."
                )
                
                if remaining <= 60:
                    delay = remaining
                else:
                    delay = remaining / 2
                if delay > 0:
                    await asyncio.sleep(delay)
                remaining -= delay

            await self.broadcast(Status.WARN, f"The server is shutting down now for {reason}.")

            # Close client connections
            self.secure_sock.close_clients()
            await self.secure_sock.wait_closed()

            await self.db.close()
            
            self.unsecure_sock = None
            self.secure_sock = None
            
            self.sessions = set()
            
            self.status = ServerStatus.OFFLINE
        except Exception:
            self.status = ServerStatus.MALFUNCTIONING
            raise
        
    async def broadcast(self, status: Status, *entries: str):
        # exclusive to secure sessions
        await asyncio.gather(
            *(ses.write(status, *entries) for ses in tuple(self.sessions))
        )
        
    async def repair(self, reboot: bool = True):
        if self.status != ServerStatus.MALFUNCTIONING:
            return
        self.status = ServerStatus.CYCLING
        
        # Clean up Unsecure Socket
        if self.unsecure_sock is not None:
            print("Attempting to fix unsecure port")
            try:
                self.unsecure_sock.close()
            except Exception as e:
                print(f"Error calling close on unsecure socket: {e}")
            try:
                self.unsecure_sock.close_clients()
            except Exception as e:
                print(f"Error closing unsecure clients: {e}")
            try:
                await self.unsecure_sock.wait_closed()
            except Exception as e:
                print(f"Issue occurred during unsecure port wait_closed: {e}")
            finally:
                print("Reset unsecure port")
                self.unsecure_sock = None

        # Clean up Secure Socket
        if self.secure_sock is not None:
            print("Attempting to fix secure port")
            try:
                self.secure_sock.close()
            except Exception as e:
                print(f"Error calling close on secure socket: {e}")
            try:
                self.secure_sock.close_clients()
            except Exception as e:
                print(f"Error closing secure clients: {e}")
            try:
                await self.secure_sock.wait_closed()
            except Exception as e:
                print(f"Issue occurred during secure port wait_closed: {e}")
            finally:
                print("Reset secure port")
                self.secure_sock = None

        # Clean up Session Pool
        if self.sessions is None:
            print("Cached session coordinator pool is unset")
        elif not isinstance(self.sessions, set):
            print("Cached session coordinator pool is not a Set")
        else:
            error = 0
            invalid = 0
            print(f"{len(self.sessions)} elements found in sessions")
            for e in tuple(self.sessions):
                if e is not None and isinstance(e, SessionCoordinator):
                    try:
                        await e.cleanup()
                    except Exception as err:
                        error += 1
                        print(f"Failed to close session element: {err}")
                else:
                    invalid += 1
                    print(f"{e} is not a SessionCoordinator")
                    
            print(f"{invalid} elements were not SessionCoordinatoors. {error} SessionCoordinatoors failed to close.")

        self.sessions = set()
        print("Cleared cached session coordinator pool")

        # Clean up Database Context
        if self.db is not None:
            print("Attempting to fix DB")
            try:
                if await self.db.test(): 
                    print("Can connect to DB currently")
                else:
                    print("Cannot connect to DB currently")
            except Exception as e:
                print(f"DB connectivity check threw an error: {e}")

            try:
                await self.db.close()
            except Exception as e:
                print(f"Issue occurred during database close: {e}")
                
        print("Reset DB")
        self.db = Database()
        
        # 5. Guarded Reboot Routine
        self.status = ServerStatus.OFFLINE
        if reboot:
            print("Initiating server reboot sequence...")
            try:
                await self.start()
            except Exception as e:
                self.status = ServerStatus.MALFUNCTIONING
                print(f"Failed to reboot: {e}. Server remains MALFUNCTIONING.")
        else:
            print("Server OFFLINE.")
            
    @staticmethod
    async def _write_raw(writer: asyncio.StreamWriter, data: bytes) -> None:
        writer.write(data)
        await writer.drain()

    async def _unsecure_listen(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peername = writer.get_extra_info("peername")
        if peername and peername[0] in self.blocked_ips:
            writer.close()
            await writer.wait_closed()
            return

        try:
            input_frame = await InputFrame.from_wire(reader)

            if input_frame is None:
                raise ProtocolError("Input frame failed to deserialize.")

            match input_frame.operation:
                case Operations.PING:
                    await self._write_raw(writer, self.out_ping)
                case Operations.REQ:
                    await self._write_raw(writer, self.out_secure_params)
                case _:
                    await self._write_raw(writer, self.out_invalid_cmd)

        except ProtocolError as e:
            print(f"Invalid protocol frame: {e}")
        except (asyncio.IncompleteReadError, ConnectionResetError) as e:
            print(f"Connection closed during unsecure stream: {e}")
        except Exception as e:
            print(f"Error handling unsecure stream: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def _secure_listen(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peername = writer.get_extra_info("peername")
        if peername and peername[0] in self.blocked_ips:
            writer.close()
            await writer.wait_closed()
            return
        
        ses = None
        try:
            conn = await self.db.pool.acquire()
            ses = SessionCoordinator(self.PROTO_VERSION, reader, writer, self.db.pool, conn)
            self.sessions.add(ses)
            
            await self._write_raw(writer, self.out_greeting)
            
            while True:
                await asyncio.wait_for(ses.read(), timeout=self.TIMEOUT)
                
                if ses.input_frame is None:
                    await ses.write(Status.ERR, "Malformed input frame received")
                    continue

                match ses.input_frame.operation:
                    case Operations.PING:
                        await self._write_raw(writer, self.out_ping)
                    
                    case Operations.REGISTER:
                        await self.register_op(ses)
                        
                    case Operations.LOGIN:
                        await self.login_op(ses)
                        
                    case Operations.LOGOUT:
                        await self.logout_op(ses)
                        
                    case Operations.DC:
                        break
                    
                    case Operations.ADDR_REQ:
                        await self.request_address_op(ses)
                        
                    case Operations.ADDR:
                        await self.address_op(ses)
                        
                    case Operations.LIST_ADDR:
                        await self.list_address_op(ses)
                        
                    case Operations.VIEWONLY:
                        await self.viewonly_op(ses)
                        
                    case Operations.NOTIFY:
                        await self.notify_op(ses)
                        
                    case Operations.DETACH:
                        await self.detach_op(ses)  
                        
                    case Operations.MOVE:
                        await self.move_op(ses)  
                        
                    case _:
                        await self._write_raw(writer, self.out_invalid_cmd)

        except asyncio.TimeoutError:
            print(f"Connection timed out after {self.TIMEOUT}s.")
            await ses.write(Status.WARN, f"Connection timed out after {self.TIMEOUT}s. Executing {Operations.DC}")
            
        except asyncio.IncompleteReadError as e:
            print(f"Connection ended: {e.partial!r}")
            
        except asyncio.InvalidStateError as e:
            print(f"Invalid state: {e}")
            
        finally:
            if ses is not None:
                await self.dc_op(ses)
            else:
                writer.close()
                await writer.wait_closed()
            
    async def register_op(self, ses: SessionCoordinator) -> None:
        username, password = ses.input_frame.arguments
        password_hash = await aiobcrypt.hashpw_with_salt(password.encode())

        async with ses.conn.cursor() as cursor:
            await cursor.execute(
                "INSERT IGNORE INTO account (username, password_hash) VALUES (%s, %s);",
                (username, password_hash)
            )

            await ses.conn.commit()
            affected = cursor.rowcount

            if affected == 0:
                await ses.write(Status.ERR, "Username already taken.")
                return

            ses.open_auth(User(cursor.lastrowid, username))
            await ses.write(Status.OK, "User created.\nAccount opened.")
            
    async def login_op(self, ses: SessionCoordinator) -> None:
        username, password = ses.input_frame.arguments

        async with ses.conn.cursor() as cursor:
            await cursor.execute(
                "SELECT account_id, password_hash, created_at, last_login_at FROM account WHERE username = %s;",
                (username,)
            )

            row = await cursor.fetchone()

            if not row:
                await ses.write(Status.ERR, "Login unsuccessful.")
                return

            account_id, password_hash, created_at, last_login_at = row

            if not await aiobcrypt.checkpw(password.encode(), password_hash):
                await ses.write(Status.ERR, "Login unsuccessful.")
                return

            await cursor.execute(
                "UPDATE account SET last_login_at = CURRENT_TIMESTAMP(6) WHERE account_id = %s;",
                (account_id,)
            )
            await ses.conn.commit()

            await cursor.execute(
                """SELECT COUNT(*) FROM message
                INNER JOIN address ON message.address = address.address
                WHERE address.account_id = %s AND message.folder = 'INBOX' AND NOT message.seen;""",
                (account_id,)
            )

            unread_messages, = await cursor.fetchone()

        ses.open_auth(User(account_id, username, created_at, last_login_at))
        await ses.write(
            Status.OK,
            "Login successful.\n",
            f"{unread_messages} new messages.\n",
            f"Last login at {last_login_at}."
        )
        
    async def logout_op(self, ses: SessionCoordinator, suppress_output: bool = False) -> None:
        if ses.user is not None:
            await ses.write(Status.OK, "Logout successful.")
            ses.purge_auth()
        else:
            await ses.write(Status.INFO, "Not currently logged in.")
        
    async def dc_op(self, ses: SessionCoordinator) -> None:
        if ses.user is not None:
            await ses.write(Status.OK, "Logged out and disconnected.")
            ses.purge_auth()
        else:
            await ses.write(Status.OK, "Disconnected.")
        await ses.cleanup()
        self.sessions.discard(ses)
        ses = None
        
    async def request_address_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return
        
        address, = ses.input_frame.arguments

        if not (16 <= len(address) <= 254):
            await ses.write(Status.ERR, "Address is not between 16 and 254 characters.")
            return

        plus = address.count("+")
        
        if plus > 1:
            await ses.write(Status.ERR, "Address cannot contain more than 1 '+' symbol.")
            return

        if plus == 1:
            address = re.sub(r"\+[^@]*@", "@", address)

        if not re.search(r"^[^@\s,\\\"]{1,237}@pearlescent\.[a-zA-Z]{2,3}$", address, re.I):
            await ses.write(Status.ERR, "Cannot register another domains address from the server.")
            return

        async with ses.conn.cursor() as cursor:
            await cursor.execute(
                """SELECT account_id FROM address_reservation 
                WHERE LOWER(address) = LOWER(%s) AND reserved_until >= CURRENT_TIMESTAMP(6);""",
                (address,),
            )
            row = await cursor.fetchone()
            account_id = row[0] if row else None

            if account_id is not None and account_id != ses.user.user_id:
                await ses.write(Status.ERR, "Address is not available for request.")
                return
                
            await cursor.execute(
                """INSERT IGNORE INTO address (account_id, address)
                VALUES (%s, %s);""",
                (ses.user.user_id, address),
            )
            
            affected = cursor.rowcount
            await ses.conn.commit()
            
        if affected == 0:
            await ses.write(Status.WARN, "Address is not available for request.")
            return
        
        await ses.write(Status.OK, "Address has been assigned to your account.")
        
    async def release_address_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return
        
        address, = ses.input_frame.arguments

        async with ses.conn.cursor() as cursor:
            await cursor.execute(
                """DELETE FROM address
                WHERE account_id = %s AND address = %s;""",
                (ses.user.user_id, address),
            )
            if cursor.rowcount == 0:
                await ses.write(Status.ERR, "Address is not available for release.")
                return

            await cursor.execute(
                """INSERT INTO address_reservation (account_id, address)
                VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE
                    released_at = CURRENT_TIMESTAMP(6),
                    reserved_until = CURRENT_TIMESTAMP(6) + INTERVAL 1 WEEK;""",
                (ses.user.user_id, address),
            )

            await ses.conn.commit()

        await ses.write(Status.OK, "Address has been released from your account.")
        
    async def address_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return
        
        args = ses.input_frame.arguments

        async with ses.conn.cursor() as cursor:
            if len(args) == 1:
                address, = args

                await cursor.execute(
                    """SELECT enabled FROM address
                    WHERE account_id = %s AND address = %s;""",
                    (ses.user.user_id, address),
                )
                row = await cursor.fetchone()

                if row is None:
                    await ses.write(Status.ERR, "Address does not exist")
                else:
                    await ses.write(Status.OK, "ON" if row[0] else "OFF")
                return

            enabled, address = args
            enabled = enabled == "ON"

            await cursor.execute(
                """UPDATE address SET enabled = %s
                WHERE account_id = %s AND address = %s;""",
                (enabled, ses.user.user_id, address),
            )
            affected = cursor.rowcount
            await ses.conn.commit()

        if affected == 0:
            await ses.write(Status.ERR, "Address does not exist or already set to this state")
            return

        await ses.write(Status.OK, "Enabled address" if enabled else "Disabled address")
        
    async def list_address_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check():
            return
        
        async with ses.conn.cursor() as cursor:
            await cursor.execute(
                """SELECT a.address, a.enabled, COALESCE(SUM(mr.current_folder = 'INBOX' AND NOT mr.seen), 0) AS unread_count FROM address AS a
                LEFT JOIN message_recipient AS mr ON a.account_id = mr.account_id AND a.address = mr.address
                WHERE a.account_id = %s
                GROUP BY a.address, a.enabled;""",
                (ses.user.user_id,),
            )
            rows = await cursor.fetchall()
            
            if not rows:
                await ses.write(Status.WARN, f'You have zero addresses registered.')
                return
                
            await ses.write(Status.OK, f'You have {len(rows)} addresses registered.', *[f'{row[0]} {"ON" if row[1] else "OFF"} {row[2]}' for row in rows])
            
    async def viewonly_op(self, ses: SessionCoordinator) -> None:
        args = ses.input_frame.arguments

        if len(args) == 0:
            await ses.write(Status.OK, "Viewonly mode is ON" if ses.view_only else "Viewonly mode is OFF")
            return

        enabled, = args
        ses.view_only = enabled == "ON"

        await ses.write(Status.OK, "Viewonly mode set to ON" if ses.view_only else "Viewonly mode set to OFF")
        
    async def notify_op(self, ses: SessionCoordinator) -> None:
        if not await ses.modify_check():
            return
        
        args = ses.input_frame.arguments

        if len(args) == 0:
            await ses.write(Status.OK, "Notify mode is ON" if ses.view_only else "Notify mode is OFF")
            return

        enabled, = args
        ses.notify = enabled == "ON"

        await ses.write(Status.OK, "Notify mode is set to ON" if ses.notify else "Notify mode is set to OFF")
        
    async def detach_op(self, ses: SessionCoordinator) -> None:
        ...
        
    async def move_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        destination_folder, *message_uids = ses.input_frame.arguments
        message_uids = list(map(int, message_uids))

        placeholders = ', '.join(['%s'] * len(message_uids))

        async with ses.conn.cursor() as cursor:
            # Check folder regardless of if you were sent it or received it.
            await cursor.execute(
                f"""SELECT m.message_id, m.current_folder, mr.current_folder FROM message AS m
                LEFT JOIN message_recipient AS mr ON m.message_id = mr.message_id AND mr.account_id = %s
                WHERE (m.account_id = %s OR mr.account_id IS NOT NULL) AND m.message_id IN ({placeholders});""",
                (ses.user.user_id, ses.user.user_id, *message_uids),
            )

            rows = await cursor.fetchall()

            if not rows:
                await ses.write(Status.ERR, "Message not found")
                return

            message_ids = []
            recipient_ids = []

            for message_id, sender_folder, recipient_folder in rows:
                if recipient_folder is not None:
                    current_folder = recipient_folder
                else:
                    current_folder = sender_folder

                if current_folder == destination_folder:
                    continue

                if destination_folder not in self.DESTINATION_TRANSITIONS[current_folder]:
                    continue

                if recipient_folder is not None:
                    recipient_ids.append(message_id)
                else:
                    message_ids.append(message_id)

            if not message_ids and not recipient_ids:
                await ses.write(Status.ERR, "No messages can be moved")
                return

            if message_ids:
                placeholders = ', '.join(['%s'] * len(message_ids))
                await cursor.execute(
                    f"""UPDATE message SET current_folder = %s
                    WHERE message_id IN ({placeholders}) AND account_id = %s;""",
                    (destination_folder, *message_ids, ses.user.user_id),
                )

            if recipient_ids:
                placeholders = ', '.join(['%s'] * len(recipient_ids))
                await cursor.execute(
                    f"""UPDATE message_recipient SET current_folder = %s
                    WHERE message_id IN ({placeholders}) AND account_id = %s;""",
                    (destination_folder, *recipient_ids, ses.user.user_id),
                )

            await ses.conn.commit()

        await ses.write(Status.OK, f"Moved {len(message_ids) + len(recipient_ids)} message(s) to {destination_folder}")
        
    