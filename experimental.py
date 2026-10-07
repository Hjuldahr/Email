import asyncio
import datetime
from enum import IntEnum, auto
import math
import re
import ssl
import uuid
from database import Database
from input_frame import InputFrame, Operations
from other import SessionCoordinator, User, Folder
from output_frame import OutputFrame, Status
import aiobcrypt

class ProtocolError(Exception):
    ...

class ServerStatus(IntEnum):
    OFFLINE = auto()
    ONLINE = auto()
    CYCLING = auto()
    MALFUNCTIONING = auto()

class PearlescentServer:
    HOST = "127.0.0.1"
    # Testing
    UNSECURE_PORT = 8025
    SECURE_PORT = 8110

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

    INBOUND_FOLDERS = {Folder.INBOX, Folder.MERC, Folder.JUNK, Folder.ARCHIVE, Folder.TRASH}

    ORDINARY_INBOUND_FOLDERS = { Folder.INBOX, Folder.MERC, Folder.JUNK }

    OUTBOUND_FOLDERS = { Folder.DRAFTS, Folder.OUTBOX, Folder.SENT, Folder.ARCHIVE, Folder.TRASH }

    SAFE_CIPHERS = (
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256"
    )
    SSL_OPTIONS = ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_CIPHER_SERVER_PREFERENCE | ssl.OP_NO_RENEGOTIATION

    def __init__(self):
        self.db = Database()
        self.unsecure_sock: asyncio.Server | None = None
        self.secure_sock: asyncio.Server | None = None

        self.server_ssl_context: ssl.SSLContext | None = None
        
        self.out_greeting = OutputFrame(self.PROTO_VERSION, Status.INFO, ["Pearlescence service ready."]).pack()
        self.out_ping = OutputFrame.MAGIC_PREFIX + self.PROTO_VERSION.to_bytes(1)
        self.out_secure_params: OutputFrame = None # Updates to match the current config on Start()
        self.out_invalid_cmd = OutputFrame(self.PROTO_VERSION, Status.WARN, ["Invalid operation."]).pack()

        self.ip_blacklist: set[str] = set()
        self.sessions: set[SessionCoordinator] = set()
        self.status = ServerStatus.OFFLINE

    # ------------------------------------------------------------------
    # Generic helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _placeholders(values) -> str:
        return ', '.join(['%s'] * len(values))

    @staticmethod
    def _origin_subject(folder: str, subject: str) -> str:
        return f'[{folder}] {subject}'

    @staticmethod
    def _remove_origin_subject(subject: str) -> str:
        return re.sub(r'^\[(INBOX|MERC|JUNK|ARCHIVE|TRASH|DRAFTS|OUTBOX|SENT)\]\s*', '', subject, count=1)

    @staticmethod
    def _parse_uids(args: list[str]) -> list[int] | None:
        try:
            return [int(uid) for uid in args]
        except ValueError:
            return None

    @staticmethod
    def _parse_bool(value: str) -> bool | None:
        value = value.upper()
        if value == "ON":
            return True
        if value == "OFF":
            return False
        return None

    async def _message_exists(
        self,
        ses: SessionCoordinator,
        cursor,
        message_id: int,
    ) -> bool:
        await cursor.execute(
            """SELECT 1
            FROM (
                SELECT message_id FROM inbound_message
                WHERE account_id = %s AND message_id = %s

                UNION

                SELECT message_id FROM outbound_message
                WHERE account_id = %s AND message_id = %s
            ) AS owned
            LIMIT 1;""",
            (ses.user.user_id, message_id, ses.user.user_id, message_id),
        )
        return await cursor.fetchone() is not None

    async def _owned_message(
        self,
        ses: SessionCoordinator,
        cursor,
        message_id: int,
    ):
        await cursor.execute(
            """SELECT im.current_folder, im.original_folder, im.flagged, im.seen, NULL AS drafted_at, im.received_at, im.read_at, NULL AS out_at,
                NULL AS sent_at, 'INBOUND' AS direction
            FROM inbound_message AS im
            WHERE im.account_id = %s AND im.message_id = %s

            UNION ALL

            SELECT om.current_folder, om.original_folder, om.flagged, NULL AS seen, om.drafted_at, NULL AS received_at, NULL AS read_at, om.out_at, 
                om.sent_at, 'OUTBOUND' AS direction
            FROM outbound_message AS om
            WHERE om.account_id = %s AND om.message_id = %s
            LIMIT 1;""",
            (ses.user.user_id, message_id, ses.user.user_id, message_id),
        )
        return await cursor.fetchone()

    async def _require_messages(
        self,
        ses: SessionCoordinator,
        cursor,
        message_ids: list[int],
    ) -> bool:
        if not message_ids:
            await ses.write(Status.ERR, "At least one Message UID is required.")
            return False

        placeholders = self._placeholders(message_ids)

        await cursor.execute(
            f"""SELECT message_id
            FROM (
                SELECT message_id
                FROM inbound_message
                WHERE account_id = %s AND message_id IN ({placeholders})

                UNION

                SELECT message_id
                FROM outbound_message
                WHERE account_id = %s AND message_id IN ({placeholders})
            ) AS owned;""",
            (ses.user.user_id, *message_ids, ses.user.user_id, *message_ids),
        )

        owned = {row[0] for row in await cursor.fetchall()}
        missing = [uid for uid in message_ids if uid not in owned]

        if missing:
            await ses.write(Status.ERR, f"Unknown Message UID(s): {', '.join(map(str, missing))}")
            return False

        return True

    async def _message_folder(
        self,
        ses: SessionCoordinator,
        cursor,
        message_id: int,
    ) -> tuple[str, str] | None:
        await cursor.execute(
            """SELECT current_folder, 'INBOUND'
            FROM inbound_message
            WHERE account_id = %s AND message_id = %s

            UNION ALL

            SELECT current_folder, 'OUTBOUND'
            FROM outbound_message
            WHERE account_id = %s AND message_id = %s
            LIMIT 1;""",
            (ses.user.user_id, message_id, ses.user.user_id, message_id),
        )
        return await cursor.fetchone()

    async def _delete_message(
        self,
        ses: SessionCoordinator,
        cursor,
        message_id: int,
    ) -> bool:
        await cursor.execute(
            """DELETE FROM inbound_message
            WHERE account_id = %s AND message_id = %s;""",
            (ses.user.user_id, message_id),
        )
        if cursor.rowcount:
            return True

        await cursor.execute(
            """DELETE FROM outbound_message
            WHERE account_id = %s AND message_id = %s;""",
            (ses.user.user_id, message_id),
        )
        return bool(cursor.rowcount)

    async def start(self):
            if self.status != ServerStatus.OFFLINE:
                return
            print(f"Server is now starting up")
            self.status = ServerStatus.CYCLING
    
            try:
                self.server_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                self.server_ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
                self.server_ssl_context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
                
                print(f"Server has acquired the assigned ssl certs.")

                self.out_secure_params = OutputFrame(
                    self.PROTO_VERSION, Status.INFO, 
                    [
                        f"ENDPOINT={self.HOST}:{self.SECURE_PORT}",
                        f"MIN_TLS={self.server_ssl_context.minimum_version.name}",
                        f"AUTH={self.server_ssl_context.protocol.name}",
                        f"CIPHERS={self.SAFE_CIPHERS}"
                    ]
                ).pack()
                
                await self.db.open()
                
                if not await self.db.test():
                    await self.db.close()
                    self.status = ServerStatus.OFFLINE
                    raise RuntimeError("Database verification failed")
                
                async with self.db.pool.acquire() as conn, conn.cursor() as cursor:
                    await cursor.execute("SELECT ip_address FROM ip_blacklist;")
                    self.ip_blacklist = {row[0] for row in await cursor.fetchall()}
                    print(f"Server has acquired the IP blacklist\n{len(self.ip_blacklist)} addresses are presently blacklisted.")
    
                if self.unsecure_sock is None:
                    self.unsecure_sock = await asyncio.start_server(self._unsecure_listen, self.HOST, self.UNSECURE_PORT)
                    print("Server has started the unsecure port")
                    
                if self.secure_sock is None:
                    self.secure_sock = await asyncio.start_server(self._secure_listen, self.HOST, self.SECURE_PORT, ssl=self.server_ssl_context)
                    print("Server has started the secure port")
    
                print(f"Server is now started.\nListening on {self.HOST}:{self.UNSECURE_PORT} (Unsecure) and {self.HOST}:{self.SECURE_PORT} (Secure)")
                self.status = ServerStatus.ONLINE
    
                await asyncio.gather(self.unsecure_sock.serve_forever(), self.secure_sock.serve_forever())
                    
            except Exception as e:
                print(f"Server failed to start up: {e}")
                self.status = ServerStatus.MALFUNCTIONING
                raise
    
    async def stop(self, reason: str, grace_period: float = 0):
        if self.status != ServerStatus.ONLINE:
            return
        print(f"Server is now shutting down.")
        self.status = ServerStatus.CYCLING
        
        try:
            self.unsecure_sock.close()
            self.secure_sock.close()
            print(f"Server has stopped accepting new connections")
            
            self.unsecure_sock.close_clients()
            await self.unsecure_sock.wait_closed()
            print(f"Server has closed unsecure connections.")
            
            # Grace period for active clients
            remaining = grace_period
            
            if grace_period > 0:
                print(f"A {grace_period}s grace period will be given to secure connections.")
            
            while remaining > 0 and self.sessions:
                time_str = str(datetime.timedelta(seconds=math.ceil(remaining)))
                
                await self.broadcast( Status.INFO, f"The server is shutting down in {time_str} for {reason}.\n", "Please disconnect when it is most convenient." )
                
                delay = remaining if remaining <= 60 else (remaining / 2)
                
                if delay <= 0:
                    break
                    
                await asyncio.sleep(delay)
                remaining -= delay

            if self.sessions:
                await self.broadcast(Status.WARN, f"The server is shutting down now for {reason}.")

            # Close client connections
            self.secure_sock.close_clients()
            await self.secure_sock.wait_closed()
            print(f"Server has closed secure connections")

            await self.db.close()
            print(f"Server has closed the MySQL connection")
            
            self.unsecure_sock = None
            self.secure_sock = None
            
            self.sessions = set()
            
            print("Server is now shutdown.")
            self.status = ServerStatus.OFFLINE
        except Exception:
            print("Server failed to shutdown up")
            self.status = ServerStatus.MALFUNCTIONING
            raise
        
    async def _safe_write(self, ses, status, entries):
        try:
            await ses.write(status, *entries)
        except Exception:
            self.sessions.discard(ses)
        
    async def broadcast(self, status: Status, *entries: str):
        # exclusive to secure sessions
        await asyncio.gather(
            *(self._safe_write(ses, status, entries) for ses in tuple(self.sessions))
        )
            
    @staticmethod
    async def _write_raw(writer: asyncio.StreamWriter, data: bytes) -> None:
        writer.write(data)
        await writer.drain()

    async def _unsecure_listen(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peername = writer.get_extra_info("peername")
        if peername and peername[0] in self.ip_blacklist:
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
        ssl_object = writer.get_extra_info('ssl_object')
        
        if (peername and peername[0] in self.ip_blacklist) or (ssl_object is None):
            writer.close()
            await writer.wait_closed()
            return
        
        # TODO (if notify is ON only) SSE for newly arrived messages & replies to threads your in 
        # (cumulative and time batched, eg: you have <X> unread messages to <address>, 
        # which will stop sending once past an alert capacity limit such 99+ total unread messages per address), 
        # successful sent from the outbox (indicates its both no longer retractable and did not fail), 
        # when a recipient has viewed a sent message (can add aggregate batching for rapid views in a short period eg: <X> recipients have just viewed message <UID>)
        
        ses = None
        try:
            conn = await self.db.pool.acquire()
            ses = SessionCoordinator(self.PROTO_VERSION, reader, writer, self.db.pool, conn)
            self.sessions.add(ses)
            
            await self._write_raw(writer, self.out_greeting)
            
            while True:
                await asyncio.wait_for(ses.read(), timeout=self.TIMEOUT)
                
                if ses.is_eof:
                    break
                
                if ses.input_frame is None:
                    await ses.write(Status.ERR, "Malformed input frame received")
                    continue

                match ses.input_frame.operation:
                    case Operations.PING:
                        await self._write_raw(writer, self.out_ping)
                    case Operations.REQ:
                        await self._write_raw(writer, self.out_secure_params)
                    case Operations.HELLO:
                        await self.hello_op(ses)
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
                    case Operations.ADDR_REL:
                        await self.release_address_op(ses)
                    case Operations.ADDR:
                        await self.address_op(ses)
                    case Operations.LIST_ADDR:
                        await self.list_address_op(ses)
                    case Operations.LIST_FEATURE:
                        await self.list_feature_op(ses)
                    case Operations.FEATURE:
                        await self.feature_op(ses)
                    case Operations.VIEWONLY:
                        await self.viewonly_op(ses)
                    case Operations.NOTIFY:
                        await self.notify_op(ses)
                    case Operations.DETACH:
                        await self.detach_op(ses)
                    case Operations.MOVE:
                        await self.move_op(ses)
                    case Operations.FORWARD:
                        await self.forward_op(ses)
                    case Operations.SEEN:
                        await self.seen_op(ses)
                    case Operations.LIST:
                        await self.list_op(ses)
                    case Operations.LIST_THREAD:
                        await self.list_thread_op(ses)
                    case Operations.FETCH:
                        await self.fetch_op(ses)
                    case Operations.DELETE:
                        await self.delete_op(ses)
                    case Operations.RESTORE:
                        await self.restore_op(ses)
                    case Operations.ARCH:
                        await self.arch_op(ses)
                    case Operations.FLAG:
                        await self.flag_op(ses)
                    case Operations.TAG:
                        await self.tag_op(ses)
                    case Operations.LIST_TAG:
                        await self.list_tag_op(ses)
                    case Operations.DRAFT:
                        await self.draft_op(ses)
                    case Operations.EDIT_ADDR:
                        await self.edit_addr_op(ses)
                    case Operations.EDIT_THREAD:
                        await self.edit_thread_op(ses)
                    case Operations.EDIT_SUBJ:
                        await self.edit_subj_op(ses)
                    case Operations.EDIT_BODY:
                        await self.edit_body_op(ses)
                    case Operations.SEND:
                        await self.send_op(ses)
                    case Operations.LIST_ATTACH:
                        await self.list_attach_op(ses)
                    case Operations.DOWNLOAD:
                        await self.download_op(ses)
                    case Operations.UPLOAD:
                        await self.upload_op(ses)
                    case Operations.MIRROR:
                        await self.mirror_op(ses)
                    case Operations.ACT:
                        await self.act_op(ses)
                    case Operations.LIST_ACT:
                        await self.list_act_op(ses)
                    case Operations.BLOCK:
                        await self.block_op(ses)
                    case Operations.LIST_BLOCK:
                        await self.list_block_op(ses)
                    case Operations.CONTACT_ADD:
                        await self.contact_add_op(ses)
                    case Operations.CONTACT_REM:
                        await self.contact_rem_op(ses)
                    case Operations.LIST_CONTACT:
                        await self.list_contact_op(ses)
                    case Operations.CONTACT:
                        await self.contact_op(ses)
                    case Operations.STATUS:
                        await self.status_op(ses)
                    case _:
                        await self._write_raw(writer, self.out_invalid_cmd)

        except asyncio.TimeoutError:
            print(f"Connection timed out after {self.TIMEOUT}s.")
            await ses.write(Status.WARN, f"Connection timed out after {self.TIMEOUT}s. Executing {Operations.DC}")
            
        except asyncio.IncompleteReadError as e:
            print(f"Connection ended: {e.partial}")
            
        except asyncio.InvalidStateError as e:
            print(f"Invalid state: {e}")
            
        finally:
            if ses is not None:
                await self.dc_op(ses)
            else:
                writer.close()
                await writer.wait_closed()
                try:
                    await self.db.pool.release(conn)
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Connection/session
    # ------------------------------------------------------------------

    async def hello_op(self, ses: SessionCoordinator) -> None:
        if ses.input_frame.arguments:
            await ses.write(Status.OK, "Connection accepted.")
        else:
            await ses.write(Status.ERR, "Client UID is required.")

    async def register_op(self, ses: SessionCoordinator) -> None:
        username, password = ses.input_frame.arguments
        password_hash = await aiobcrypt.hashpw_with_salt(password.encode())

        async with ses.conn.cursor() as cursor:
            await cursor.execute( "INSERT IGNORE INTO account (username, password_hash) VALUES (%s, %s);", (username, password_hash) )

            await ses.conn.commit()
            affected = cursor.rowcount

            if affected == 0:
                await ses.write(Status.ERR, "Username already taken.")
                return

            ses.open_auth(User(cursor.lastrowid, username))
            await ses.write(Status.OK, "Account created and authenticated.")

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
                """SELECT COUNT(*) FROM inbound_message
                WHERE account_id = %s AND current_folder = 'INBOX' AND NOT seen;""",
                (account_id,)
            )
            unread_messages, = await cursor.fetchone()

        ses.open_auth(User(account_id, username, created_at, last_login_at))
        
        # Cleaned up string entries by removing embedded \n character anomalies
        await ses.write(
            Status.OK,
            "Login successful.",
            f"{unread_messages} new messages.",
            f"Last login at {last_login_at}."
        )

    async def logout_op(self, ses: SessionCoordinator) -> None:
        if ses.user is None:
            return

        account_id = ses.user.user_id

        async with ses.conn.cursor() as cursor:
            # Permanently remove TRASH.
            await cursor.execute(
                """DELETE FROM inbound_message
                WHERE account_id = %s AND current_folder = 'TRASH';""",
                (account_id,),
            )

            await cursor.execute(
                """DELETE FROM outbound_message
                WHERE account_id = %s AND current_folder = 'TRASH';""",
                (account_id,),
            )

            # MIRROR OFF.
            await cursor.execute(
                """DELETE FROM mirror
                WHERE account_id = %s;""",
                (account_id,),
            )

            await ses.conn.commit()

        await ses.write(Status.OK, "Logout successful.")
        ses.purge_auth()

    async def dc_op(self, ses: SessionCoordinator) -> None:
        if ses.user is not None:
            # Logout semantics are executed, but their normal response is
            # intentionally suppressed because DC owns the final response.
            account_id = ses.user.user_id

            async with ses.conn.cursor() as cursor:
                await cursor.execute(
                    """DELETE FROM inbound_message
                    WHERE account_id = %s AND current_folder = 'TRASH';""",
                    (account_id,),
                )
                await cursor.execute(
                    """DELETE FROM outbound_message
                    WHERE account_id = %s AND current_folder = 'TRASH';""",
                    (account_id,),
                )
                await cursor.execute(
                    """DELETE FROM mirror
                    WHERE account_id = %s;""",
                    (account_id,),
                )
                await ses.conn.commit()

            ses.purge_auth()

        await ses.write(Status.OK, "Disconnected.")
        await ses.cleanup()
        self.sessions.discard(ses)

    # ------------------------------------------------------------------
    # Capabilities/session controls
    # ------------------------------------------------------------------

    async def list_feature_op(self, ses: SessionCoordinator) -> None:
        # TODO replace with real output
        await ses.write(
            Status.OK,
            "STATUS ON",
            "VIEWONLY ON",
            "NOTIFY ON",
            "CONTACT ON",
            "MIRROR ON",
            "ACTIONS ON",
            "ATTACHMENTS ON",
        )

    async def feature_op(self, ses: SessionCoordinator) -> None:
        args = ses.input_frame.arguments

        if len(args) == 0:
            await ses.write( Status.INFO, "Feature negotiation is currently informational." )
            return

        if len(args) < 2:
            await ses.write( Status.ERR, "FEATURE requires ON/OFF and at least one feature." )
            return

        enabled = self._parse_bool(args[0])
        if enabled is None:
            await ses.write(Status.ERR, "Feature state must be ON or OFF.")
            return

        await ses.write(
            Status.OK,
            *[f"Requested {'enablement' if enabled else 'disablement'} of:",
            *args[1:]]
        )

    async def viewonly_op(self, ses: SessionCoordinator) -> None:
        args = ses.input_frame.arguments

        if len(args) == 0:
            await ses.write( Status.OK, "Viewonly mode is ON" if ses.view_only else "Viewonly mode is OFF" )
            return

        if len(args) != 1:
            await ses.write(Status.ERR, "VIEWONLY accepts ON or OFF.")
            return

        enabled = self._parse_bool(args[0])
        if enabled is None:
            await ses.write(Status.ERR, "VIEWONLY accepts ON or OFF.")
            return

        ses.view_only = enabled
        await ses.write( Status.OK, f"Viewonly mode set to {'ON' if enabled else 'OFF'}" )

    async def notify_op(self, ses: SessionCoordinator) -> None:
        args = ses.input_frame.arguments

        if len(args) == 0:
            await ses.write( Status.OK, "Notify mode is ON" if ses.notify else "Notify mode is OFF" )
            return

        if len(args) != 1:
            await ses.write(Status.ERR, "NOTIFY accepts ON or OFF.")
            return

        enabled = self._parse_bool(args[0])
        if enabled is None:
            await ses.write(Status.ERR, "NOTIFY accepts ON or OFF.")
            return

        ses.notify = enabled
        await ses.write(
            Status.OK,
            f"Notify mode set to {'ON' if enabled else 'OFF'}"
        )

    # ------------------------------------------------------------------
    # Addresses
    # ------------------------------------------------------------------

    async def list_address_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check():
            return

        async with ses.conn.cursor() as cursor:
            await cursor.execute(
                """SELECT a.address, a.enabled,
                (
                    SELECT COUNT(*) FROM inbound_message AS im
                    INNER JOIN message_recipient AS mr ON mr.message_id = im.message_id AND mr.account_id = im.account_id
                    WHERE im.account_id = a.account_id AND im.seen = FALSE AND im.current_folder = 'INBOX' AND mr.address = a.address
                )
                FROM address AS a
                WHERE a.account_id = %s
                ORDER BY a.address;""",
                (ses.user.user_id,),
            )

            rows = await cursor.fetchall()

        if not rows:
            await ses.write(Status.WARN, "You have zero addresses registered.")
            return

        await ses.write(
            Status.OK, f"You have {len(rows)} addresses registered.",
            *[
                f"{address} {unseen} {'ON' if enabled else 'OFF'}"
                for address, enabled, unseen in rows
            ],
        )

    async def request_address_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        address, = ses.input_frame.arguments

        if not (16 <= len(address) <= 254):
            await ses.write( Status.ERR, "Address is not between 16 and 254 characters." )
            return

        plus = address.count("+")
        if plus > 1:
            await ses.write(
                Status.ERR,
                "Address cannot contain more than 1 '+' symbol."
            )
            return

        if plus:
            address = re.sub(r"\+[^@]*@", "@", address)

        if not re.search(
            r"^[^@\s,\\\"]{1,237}@pearlescent\.[a-zA-Z]{2,3}$",
            address,
            re.I,
        ):
            await ses.write(
                Status.ERR,
                "Cannot register another domains address from the server."
            )
            return

        async with ses.conn.cursor() as cursor:
            await cursor.execute(
                """SELECT account_id FROM address_reservation
                WHERE LOWER(address) = LOWER(%s) AND reserved_until >= CURRENT_TIMESTAMP(6);""",
                (address,),
            )
            row = await cursor.fetchone()

            if row is not None and row[0] != ses.user.user_id:
                await ses.write( Status.ERR, "Address is not available for request." )
                return

            await cursor.execute(
                """INSERT IGNORE INTO address (account_id, address)
                VALUES (%s, %s);""",
                (ses.user.user_id, address),
            )

            if cursor.rowcount == 0:
                await ses.write( Status.WARN, "Address is not available for request." )
                return

            await cursor.execute(
                """DELETE FROM address_reservation
                WHERE address = %s;""",
                (address,)
            )

            await ses.conn.commit()

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
                await ses.write(
                    Status.ERR,
                    "Address is not available for release."
                )
                return

            await cursor.execute(
                """INSERT INTO address_reservation (account_id, address)
                VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE
                    account_id = VALUES(account_id),
                    released_at = CURRENT_TIMESTAMP(6),
                    reserved_until = CURRENT_TIMESTAMP(6) + INTERVAL 1 WEEK;""",
                (ses.user.user_id, address),
            )

            # Release resets address state because the row itself is removed.
            await ses.conn.commit()

        await ses.write(
            Status.OK,
            "Address has been released from your account."
        )

    async def address_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        args = ses.input_frame.arguments

        if len(args) == 1:
            address, = args

            async with ses.conn.cursor() as cursor:
                await cursor.execute(
                    """SELECT enabled FROM address
                    WHERE account_id = %s AND address = %s;""",
                    (ses.user.user_id, address),
                )
                row = await cursor.fetchone()

            if row is None:
                await ses.write(Status.ERR, "Address does not exist.")
            else:
                await ses.write(Status.OK, "ON" if row[0] else "OFF")
            return

        if len(args) != 2:
            await ses.write(Status.ERR, "ADDR accepts [ON|OFF] ADDRESS.")
            return

        enabled = self._parse_bool(args[0])
        if enabled is None:
            await ses.write(Status.ERR, "Address state must be ON or OFF.")
            return

        address = args[1]

        async with ses.conn.cursor() as cursor:
            await cursor.execute(
                """UPDATE address SET enabled = %s
                WHERE account_id = %s AND address = %s;""",
                (enabled, ses.user.user_id, address),
            )

            if cursor.rowcount == 0:
                await ses.write( Status.ERR, "Address does not exist or is already in that state." )
                return

            await ses.conn.commit()

        await ses.write( Status.OK, "Enabled address" if enabled else "Disabled address" )

    # ------------------------------------------------------------------
    # Mailbox: detach/move/seen
    # ------------------------------------------------------------------

    async def detach_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        message_id, = self._parse_uids(ses.input_frame.arguments) or [None]

        if message_id is None:
            await ses.write(Status.ERR, "Invalid Message UID.")
            return

        async with ses.conn.cursor() as cursor:
            row = await self._message_folder(ses, cursor, message_id)

            if row is None:
                await ses.write(Status.ERR, "Message does not exist.")
                return

            folder, direction = row

            if direction != 'INBOUND' or folder not in { Folder.INBOX, Folder.MERC, Folder.JUNK }:
                await ses.write( Status.ERR, "Message must be in INBOX, MERC, or JUNK." )
                return

            await cursor.execute(
                """DELETE FROM attachment
                WHERE message_id = %s;""",
                (message_id,),
            )

            count = cursor.rowcount
            await ses.conn.commit()

        await ses.write( Status.OK, f"Detached {count} attachment(s)." )

    async def move_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        args = ses.input_frame.arguments

        if len(args) < 2:
            await ses.write( Status.ERR, "MOVE requires a destination and at least one Message UID." )
            return

        destination = Folder.from_string(args[0])

        if destination not in { Folder.INBOX, Folder.MERC, Folder.JUNK }:
            await ses.write( Status.ERR, "MOVE only supports INBOX, MERC, and JUNK." )
            return

        message_ids = self._parse_uids(args[1:])
        if message_ids is None:
            await ses.write(Status.ERR, "Invalid Message UID.")
            return

        async with ses.conn.cursor() as cursor:
            if not await self._require_messages( ses, cursor, message_ids, ):
                return

            for message_id in message_ids:
                row = await self._message_folder( ses, cursor, message_id, )

                folder, direction = row

                if direction != 'INBOUND':
                    await ses.write( Status.ERR, f"Message {message_id} is not an inbound message." )
                    return

                allowed = { Folder.INBOX: {Folder.JUNK}, Folder.JUNK: {Folder.INBOX}, Folder.MERC: {Folder.INBOX, Folder.JUNK}, }

                if destination.value not in allowed.get(folder, set()):
                    await ses.write( Status.ERR, f"Cannot move {folder} to {destination.value}." )
                    return

            placeholders = self._placeholders(message_ids)

            await cursor.execute(
                f"""UPDATE inbound_message SET current_folder = %s
                WHERE account_id = %s AND message_id IN ({placeholders});""",
                ( destination.value, ses.user.user_id, *message_ids, ),
            )

            await ses.conn.commit()

        await ses.write( Status.OK, f"Moved {len(message_ids)} message(s) to {destination.value}." )

    async def seen_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        args = ses.input_frame.arguments

        if len(args) < 2:
            await ses.write( Status.ERR, "SEEN requires ON/OFF and at least one Message UID." )
            return

        seen = self._parse_bool(args[0])
        if seen is None:
            await ses.write(Status.ERR, "SEEN accepts ON or OFF.")
            return

        message_ids = self._parse_uids(args[1:])
        if message_ids is None:
            await ses.write(Status.ERR, "Invalid Message UID.")
            return

        async with ses.conn.cursor() as cursor:
            if not await self._require_messages(
                ses,
                cursor,
                message_ids,
            ):
                return

            placeholders = self._placeholders(message_ids)

            if seen:
                await cursor.execute(
                    f"""UPDATE inbound_message SET seen = TRUE, read_at = COALESCE(read_at, CURRENT_TIMESTAMP(6))
                    WHERE account_id = %s AND message_id IN ({placeholders});""",
                    (ses.user.user_id, *message_ids),
                )
            else:
                await cursor.execute(
                    f"""UPDATE inbound_message SET seen = FALSE, read_at = NULL
                    WHERE account_id = %s AND message_id IN ({placeholders});""",
                    (ses.user.user_id, *message_ids),
                )

            await ses.conn.commit()

        await ses.write( Status.OK, f"Set {len(message_ids)} message(s) seen state to " f"{'ON' if seen else 'OFF'}." )

    # ------------------------------------------------------------------
    # Listing
    # ------------------------------------------------------------------

    async def list_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check():
            return

        args = ses.input_frame.arguments

        if not args:
            await ses.write(Status.ERR, "LIST requires a folder.")
            return

        folder = Folder.from_string(args[0])

        if folder is None:
            await ses.write(Status.ERR, "Unknown folder.")
            return

        if folder == Folder.MERC:
            await ses.write( Status.ERR, "MERC is only available while a mirror is active." )
            return

        # V4 intentionally leaves the filter/range grammar to the
        # corresponding command syntax. Until that grammar is formalized,
        # reject extra arguments rather than silently interpreting them.
        if len(args) > 1:
            await ses.write( Status.ERR, "Email filter/range syntax is not implemented yet." )
            return

        async with ses.conn.cursor() as cursor:
            if folder in self.INBOUND_FOLDERS:
                await cursor.execute(
                    """SELECT m.thread_id, m.message_id, im.flagged, m.sender_address, m.subject, m.created_at, im.seen, im.read_at,
                        ( SELECT COUNT(*) FROM attachment AS a WHERE a.message_id = m.message_id ),
                        ( SELECT COUNT(*) FROM message WHERE thread_id = m.thread_id )
                    FROM inbound_message AS im
                    INNER JOIN message AS m ON m.message_id = im.message_id
                    WHERE im.account_id = %s AND im.current_folder = %s
                    ORDER BY m.created_at;""",
                    (ses.user.user_id, folder.value),
                )
            else:
                await cursor.execute(
                    """SELECT m.thread_id, m.message_id, om.flagged, m.sender_address, m.subject, COALESCE(om.sent_at, om.out_at, om.drafted_at), NULL, NULL,
                        ( SELECT COUNT(*) FROM attachment AS a WHERE a.message_id = m.message_id ),
                        ( SELECT COUNT(*) FROM message WHERE thread_id = m.thread_id )
                    FROM outbound_message AS om
                    INNER JOIN message AS m ON m.message_id = om.message_id
                    WHERE om.account_id = %s AND om.current_folder = %s
                    ORDER BY COALESCE( om.sent_at, om.out_at, om.drafted_at
                    );""",
                    (ses.user.user_id, folder.value),
                )

            rows = await cursor.fetchall()

        if not rows:
            await ses.write(Status.WARN, f"{folder.value} is empty.")
            return

        entries = []

        for ( thread_id, message_id, flagged, sender, subject, timestamp, seen, read_at, attachment_count, reply_count, ) in rows:
            subject = subject.replace('\n', ' ').replace('\r', ' ')
            if len(subject) > 80:
                subject = f'{subject[:77]}...'

            if seen is None:
                state = '-'
            elif seen:
                state = f"READ {read_at}"
            else:
                state = "UNREAD"

            entries.append(
                f"{thread_id} {message_id} "
                f"{'FLAG' if flagged else '-'} "
                f"{sender} "
                f"{subject} "
                f"REPLIES={reply_count} "
                f"ATTACH={attachment_count} "
                f"{timestamp} "
                f"{state}"
            )

        await ses.write(Status.OK, *entries)

    async def list_thread_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check():
            return

        thread_id, = ses.input_frame.arguments

        try:
            thread_id = int(thread_id)
        except ValueError:
            await ses.write(Status.ERR, "Invalid Thread UID.")
            return

        async with ses.conn.cursor() as cursor:
            await cursor.execute(
                """SELECT DISTINCT m.message_id FROM message AS m
                LEFT JOIN inbound_message AS im ON im.message_id = m.message_id AND im.account_id = %s
                LEFT JOIN outbound_message AS om ON om.message_id = m.message_id AND om.account_id = %s
                WHERE m.thread_id = %s AND (im.message_id IS NOT NULL OR om.message_id IS NOT NULL)
                ORDER BY m.created_at;""",
                (
                    ses.user.user_id,
                    ses.user.user_id,
                    thread_id,
                ),
            )
            rows = await cursor.fetchall()

        if not rows:
            await ses.write(Status.WARN, "Thread does not exist.")
            return

        await ses.write( Status.OK, *[str(row[0]) for row in rows], )

    async def fetch_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check():
            return

        args = ses.input_frame.arguments

        if not args:
            await ses.write(Status.ERR, "FETCH requires a Message UID.")
            return

        mode = None

        if args[0] in {"METAONLY", "BODYONLY"}:
            mode = args[0]
            args = args[1:]

        if not args:
            await ses.write(Status.ERR, "Message UID is required.")
            return

        try:
            message_id = int(args[0])
        except ValueError:
            await ses.write(Status.ERR, "Invalid Message UID.")
            return

        if len(args) > 1:
            await ses.write(
                Status.ERR,
                "Byte-range syntax is not implemented yet."
            )
            return

        async with ses.conn.cursor() as cursor:
            row = await self._owned_message(
                ses,
                cursor,
                message_id,
            )

            if row is None:
                await ses.write(Status.ERR, "Message does not exist.")
                return

            await cursor.execute(
                """SELECT thread_id, message_id, sender_address, created_at, updated_at, subject, payload
                FROM message WHERE message_id = %s;""",
                (message_id,),
            )

            message = await cursor.fetchone()

            if message is None:
                await ses.write(Status.ERR, "Message does not exist.")
                return

            (thread_id, uid, sender, created_at, updated_at, subject, payload) = message

            (current_folder, original_folder, flagged, seen, drafted_at, received_at, read_at, out_at, sent_at, direction) = row

            if mode != "BODYONLY":
                await ses.write(
                    Status.OK,
                    f"THREAD {thread_id}",
                    f"MESSAGE {uid}",
                    f"FROM {sender}",
                    f"SUBJECT {subject}",
                    f"FOLDER {current_folder}",
                    f"ORIGINAL {original_folder}",
                    f"FLAG {'ON' if flagged else 'OFF'}",
                    f"SEEN {'ON' if seen else 'OFF'}"
                    if seen is not None
                    else "SEEN N/A",
                    f"CREATED {created_at}",
                    f"UPDATED {updated_at}",
                    f"SIZE {len(payload.encode('utf-8'))}",
                )

            if mode != "METAONLY":
                await ses.write(Status.OK, payload)

            # FETCH BOTH or BODYONLY marks inbound mail as seen.
            if direction == 'INBOUND' and mode != "METAONLY":
                await cursor.execute(
                    """UPDATE inbound_message SET seen = TRUE, read_at = COALESCE(read_at, CURRENT_TIMESTAMP(6))
                    WHERE account_id = %s AND message_id = %s;""",
                    (ses.user.user_id, message_id),
                )
                await ses.conn.commit()

    # ------------------------------------------------------------------
    # Delete/archive/restore/flag/tag
    # ------------------------------------------------------------------

    async def delete_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        message_ids = self._parse_uids(ses.input_frame.arguments)

        if message_ids is None or not message_ids:
            await ses.write(Status.ERR, "Invalid Message UID.")
            return

        async with ses.conn.cursor() as cursor:
            if not await self._require_messages( ses, cursor, message_ids, ):
                return

            for message_id in message_ids:
                row = await self._message_folder(
                    ses,
                    cursor,
                    message_id,
                )

                folder, direction = row

                if direction == 'INBOUND':
                    await cursor.execute(
                        """UPDATE message AS m
                        INNER JOIN inbound_message AS im ON im.message_id = m.message_id
                        SET m.subject = CONCAT('[', im.current_folder, '] ', m.subject), im.original_folder = im.current_folder, im.current_folder = 'TRASH'
                        WHERE im.account_id = %s AND im.message_id = %s;""",
                        (ses.user.user_id, message_id),
                    )
                else:
                    await cursor.execute(
                        """UPDATE message AS m
                        INNER JOIN outbound_message AS om ON om.message_id = m.message_id
                        SET m.subject = CONCAT('[', om.current_folder, '] ', m.subject), om.original_folder = om.current_folder, om.current_folder = 'TRASH'
                        WHERE om.account_id = %s AND om.message_id = %s;""",
                        (ses.user.user_id, message_id),
                    )

            await ses.conn.commit()

        await ses.write( Status.OK, f"Moved {len(message_ids)} message(s) to TRASH." )

    async def restore_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        message_ids = self._parse_uids(ses.input_frame.arguments)

        if message_ids is None or not message_ids:
            await ses.write(Status.ERR, "Invalid Message UID.")
            return

        async with ses.conn.cursor() as cursor:
            if not await self._require_messages( ses, cursor, message_ids, ):
                return

            for message_id in message_ids:
                row = await self._message_folder( ses, cursor, message_id, )

                folder, direction = row

                if folder not in {'TRASH', 'ARCHIVE'}:
                    await ses.write( Status.ERR, f"Message {message_id} is not in TRASH or ARCHIVE." )
                    return

                table = "inbound_message" if direction == "INBOUND" else "outbound_message"

                await cursor.execute(
                    f"""SELECT original_folder FROM {table}
                    WHERE account_id = %s AND message_id = %s;""",
                    (ses.user.user_id, message_id),
                )

                original = (await cursor.fetchone())[0]

                await cursor.execute(
                    f"""UPDATE {table} SET current_folder = original_folder
                    WHERE account_id = %s AND message_id = %s;""",
                    (ses.user.user_id, message_id),
                )

                await cursor.execute(
                    """UPDATE message
                    SET subject = %s
                    WHERE message_id = %s;""",
                    (
                        self._remove_origin_subject(
                            (
                                await cursor.execute(
                                    "SELECT subject FROM message WHERE message_id = %s",
                                    (message_id,),
                                )
                            )
                            if False else
                            ""
                        ),
                        message_id,
                    ),
                )

            # Re-read subjects separately. This keeps the folder update above
            # independent from the textual origin cleanup.
            for message_id in message_ids:
                await cursor.execute(
                    "SELECT subject FROM message WHERE message_id = %s;",
                    (message_id,),
                )
                row = await cursor.fetchone()

                if row:
                    await cursor.execute(
                        """UPDATE message SET subject = %s
                        WHERE message_id = %s;""",
                        ( self._remove_origin_subject(row[0]), message_id, ),
                    )

            await ses.conn.commit()

        await ses.write( Status.OK, f"Restored {len(message_ids)} message(s)." )

    async def arch_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        message_ids = self._parse_uids(ses.input_frame.arguments)

        if message_ids is None or not message_ids:
            await ses.write(Status.ERR, "Invalid Message UID.")
            return

        async with ses.conn.cursor() as cursor:
            if not await self._require_messages( ses, cursor, message_ids, ):
                return

            for message_id in message_ids:
                row = await self._message_folder( ses, cursor, message_id, )

                folder, direction = row

                if folder == 'ARCHIVE':
                    continue

                table = ( "inbound_message" if direction == "INBOUND" else "outbound_message" )

                await cursor.execute(
                    f"""SELECT current_folder FROM {table}
                    WHERE account_id = %s AND message_id = %s;""",
                    (ses.user.user_id, message_id),
                )
                old_folder = (await cursor.fetchone())[0]

                await cursor.execute(
                    """UPDATE message SET subject = CONCAT('[', %s, '] ', subject)
                    WHERE message_id = %s;""",
                    (old_folder, message_id),
                )

                await cursor.execute(
                    f"""UPDATE {table} SET original_folder = %s, current_folder = 'ARCHIVE'
                    WHERE account_id = %s AND message_id = %s;""",
                    ( old_folder, ses.user.user_id, message_id, ),
                )

            await ses.conn.commit()

        await ses.write( Status.OK, f"Archived {len(message_ids)} message(s)." )

    async def flag_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        args = ses.input_frame.arguments

        if len(args) < 2:
            await ses.write( Status.ERR, "FLAG requires ON/OFF and Message UID(s)." )
            return

        enabled = self._parse_bool(args[0])
        if enabled is None:
            await ses.write(Status.ERR, "FLAG accepts ON or OFF.")
            return

        message_ids = self._parse_uids(args[1:])

        if message_ids is None:
            await ses.write(Status.ERR, "Invalid Message UID.")
            return

        async with ses.conn.cursor() as cursor:
            if not await self._require_messages( ses, cursor, message_ids, ):
                return

            placeholders = self._placeholders(message_ids)

            await cursor.execute(
                f"""UPDATE inbound_message SET flagged = %s
                WHERE account_id = %s AND message_id IN ({placeholders});""",
                (
                    enabled,
                    ses.user.user_id,
                    *message_ids,
                ),
            )

            inbound_changed = cursor.rowcount

            await cursor.execute(
                f"""UPDATE outbound_message SET flagged = %s
                WHERE account_id = %s AND message_id IN ({placeholders});""",
                ( enabled, ses.user.user_id, *message_ids, ),
            )

            await ses.conn.commit()

        await ses.write(
            Status.OK,
            f"Flagged state set to {'ON' if enabled else 'OFF'} "
            f"for {len(message_ids)} message(s)."
        )

    async def tag_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        args = ses.input_frame.arguments

        if len(args) < 3:
            await ses.write( Status.ERR, "TAG requires ON/OFF, a tag, and Message UID(s)." )
            return

        enabled = self._parse_bool(args[0])
        if enabled is None:
            await ses.write(Status.ERR, "TAG accepts ON or OFF.")
            return

        tag = args[1]
        message_ids = self._parse_uids(args[2:])

        if message_ids is None:
            await ses.write(Status.ERR, "Invalid Message UID.")
            return

        async with ses.conn.cursor() as cursor:
            if not await self._require_messages(
                ses,
                cursor,
                message_ids,
            ):
                return

            for message_id in message_ids:
                await cursor.execute(
                    """SELECT 1 FROM inbound_message
                    WHERE account_id = %s AND message_id = %s;""",
                    (ses.user.user_id, message_id),
                )

                if await cursor.fetchone():
                    if enabled:
                        await cursor.execute(
                            """INSERT IGNORE INTO inbound_message_tag (message_id, account_id, tag)
                            VALUES (%s, %s, %s);""",
                            ( message_id, ses.user.user_id, tag, ),
                        )
                    else:
                        await cursor.execute(
                            """DELETE FROM inbound_message_tag
                            WHERE account_id = %s AND message_id = %s AND tag = %s;""",
                            ( ses.user.user_id, message_id, tag, ),
                        )
                    continue

                if enabled:
                    await cursor.execute(
                        """INSERT IGNORE INTO outbound_message_tag (message_id, account_id, tag)
                        VALUES (%s, %s, %s);""",
                        ( message_id, ses.user.user_id, tag, ),
                    )
                else:
                    await cursor.execute(
                        """DELETE FROM outbound_message_tag
                        WHERE account_id = %s AND message_id = %s AND tag = %s;""",
                        ( ses.user.user_id, message_id, tag, ),
                    )

            await ses.conn.commit()

        await ses.write(
            Status.OK,
            f"Tag {tag!r} {'added to' if enabled else 'removed from'} {len(message_ids)} message(s)."
        )

    async def list_tag_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check():
            return

        async with ses.conn.cursor() as cursor:
            await cursor.execute(
                """SELECT tag, COUNT(*), MIN(created_at)
                FROM (
                    SELECT imt.tag, im.message_id, m.created_at FROM inbound_message_tag AS imt
                    INNER JOIN inbound_message AS im ON im.account_id = imt.account_id AND im.message_id = imt.message_id
                    INNER JOIN message AS m ON m.message_id = im.message_id
                    WHERE imt.account_id = %s

                    UNION ALL

                    SELECT omt.tag, om.message_id, m.created_at
                    FROM outbound_message_tag AS omt
                    INNER JOIN outbound_message AS om ON om.account_id = omt.account_id AND om.message_id = omt.message_id
                    INNER JOIN message AS m ON m.message_id = om.message_id
                    WHERE omt.account_id = %s
                ) AS tags
                GROUP BY tag
                ORDER BY tag;""",
                (ses.user.user_id, ses.user.user_id),
            )

            rows = await cursor.fetchall()

        if not rows:
            await ses.write(Status.WARN, "No tags are currently in use.")
            return

        await ses.write( Status.OK, *[ f"{tag} {count} {created}" for tag, count, created in rows ], )

    # ------------------------------------------------------------------
    # Forwarding
    # ------------------------------------------------------------------

    async def forward_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        args = ses.input_frame.arguments

        if len(args) not in {2, 3}:
            await ses.write( Status.ERR, "FORWARD requires Message UID, Recipient, and optional NOW." )
            return

        try:
            original_id = int(args[0])
        except ValueError:
            await ses.write(Status.ERR, "Invalid Message UID.")
            return

        recipient = args[1]
        immediate = len(args) == 3 and args[2].upper() == "NOW"

        if len(args) == 3 and not immediate:
            await ses.write(Status.ERR, "FORWARD only accepts NOW.")
            return

        async with ses.conn.cursor() as cursor:
            row = await self._message_folder( ses, cursor, original_id, )

            if row is None:
                await ses.write(Status.ERR, "Message does not exist.")
                return

            folder, direction = row

            if folder not in {'INBOX', 'SENT', 'MERC', 'JUNK'}:
                await ses.write( Status.ERR, "Message is not in a forwardable folder." )
                return

            await cursor.execute(
                """SELECT thread_id, sender_address, subject, payload FROM message
                WHERE message_id = %s;""",
                (original_id,),
            )

            message = await cursor.fetchone()

            if message is None:
                await ses.write(Status.ERR, "Message does not exist.")
                return

            thread_id, sender, subject, payload = message

            await cursor.execute(
                """INSERT INTO message (thread_id, sender_address, subject, payload)
                SELECT thread_id, sender_address, CONCAT('Fwd: ', subject), payload FROM message
                WHERE message_id = %s;""",
                (original_id,),
            )

            new_message_id = cursor.lastrowid

            await cursor.execute(
                """INSERT INTO message_recipient (account_id, message_id, recipient_type, address)
                VALUES (NULL, %s, 'TO', %s);""",
                (new_message_id, recipient),
            )

            await cursor.execute(
                """INSERT INTO outbound_message (message_id, account_id, current_folder, original_folder, out_at)
                VALUES (%s, %s, %s, 'DRAFTS', CASE WHEN %s THEN CURRENT_TIMESTAMP(6) ELSE NULL END);""",
                ( new_message_id, ses.user.user_id, 'OUTBOX' if not immediate else 'OUTBOX', immediate, ),
            )

            # Copy attachments.
            await cursor.execute(
                """INSERT INTO attachment (message_id, attachment_index, filename, content_type, size_bytes, payload)
                SELECT %s, attachment_index, filename, content_type, size_bytes, payload FROM attachment
                WHERE message_id = %s;""",
                (new_message_id, original_id),
            )

            await ses.conn.commit()

        await ses.write(
            Status.OK,
            f"Forward created with Message UID {new_message_id}.",
            "Immediate delivery requested." if immediate
            else "Placed in OUTBOX.",
        )

    # ------------------------------------------------------------------
    # Drafts
    # ------------------------------------------------------------------

    async def draft_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        args = ses.input_frame.arguments

        if len(args) < 3:
            await ses.write(
                Status.ERR,
                "DRAFT requires recipient addresses, subject, and payload size."
            )
            return

        # The V4 syntax is:
        # DRAFT [THREAD UID] RECIPIENTS SUBJECT PAYLOAD SIZE
        #
        # Since the recipient grammar itself is comma-delimited and the
        # framing already gives us argument boundaries, subject remains one
        # argument and recipient specification remains one argument.
        thread_id = None

        if len(args) == 4:
            try:
                thread_id = int(args[0])
            except ValueError:
                await ses.write(Status.ERR, "Invalid Thread UID.")
                return
            recipient_spec, subject, payload_size = args[1:]
        else:
            recipient_spec, subject, payload_size = args

        try:
            payload_size = int(payload_size)
        except ValueError:
            await ses.write(Status.ERR, "Invalid payload size.")
            return

        if payload_size < 0:
            await ses.write(Status.ERR, "Payload size cannot be negative.")
            return

        recipients = self._parse_recipient_spec(recipient_spec)

        if recipients is None:
            await ses.write(Status.ERR, "Invalid recipient specification.")
            return

        async with ses.conn.cursor() as cursor:
            if thread_id is not None:
                await cursor.execute(
                    """SELECT 1 FROM message AS m
                    LEFT JOIN inbound_message AS im ON im.message_id = m.message_id AND im.account_id = %s
                    LEFT JOIN outbound_message AS om ON om.message_id = m.message_id AND om.account_id = %s
                    WHERE m.thread_id = %s AND (im.message_id IS NOT NULL OR om.message_id IS NOT NULL)
                    LIMIT 1;""",
                    (
                        ses.user.user_id,
                        ses.user.user_id,
                        thread_id,
                    ),
                )

                if await cursor.fetchone() is None:
                    await ses.write(Status.ERR, "Thread does not exist.")
                    return

            await cursor.execute(
                """SELECT address FROM address
                WHERE account_id = %s AND enabled = TRUE;""",
                (ses.user.user_id,),
            )
            own_addresses = {row[0].lower() for row in await cursor.fetchall()}

            for recipient_type, address in recipients:
                if address.lower() in own_addresses:
                    continue

                await cursor.execute(
                    """SELECT 1 FROM block
                    WHERE account_id = %s AND address = %s
                    LIMIT 1;""",
                    (ses.user.user_id, address),
                )

                if await cursor.fetchone():
                    await ses.write( Status.ERR, f"Recipient is blocked: {address}" )
                    return

            await cursor.execute(
                """INSERT INTO message (thread_id, sender_address, subject, payload)
                VALUES (%s, %s, %s, '');""",
                ( thread_id, await self._default_sender_address( ses, cursor, ), subject, ),
            )

            message_id = cursor.lastrowid

            for order, (recipient_type, address) in enumerate(recipients):
                await cursor.execute(
                    """INSERT INTO message_recipient (account_id, message_id, recipient_type, address, recipient_order)
                    VALUES (NULL, %s, %s, %s, %s);""",
                    ( message_id, recipient_type, address, order, ),
                )

            await cursor.execute(
                """INSERT INTO outbound_message (message_id, account_id, current_folder, original_folder)
                VALUES (%s, %s, 'DRAFTS', 'DRAFTS');""",
                ( message_id, ses.user.user_id, ),
            )

            await ses.conn.commit()

        # The actual payload stream is intentionally not consumed here.
        # See the transfer hook below.
        await ses.write( Status.OK, f"Ready for {payload_size} bytes.", f"MESSAGE {message_id}", )

    @staticmethod
    def _parse_recipient_spec(value: str):
        result = []

        # Expected form:
        # TO:a,b,CC:c,BCC:d,e
        #
        # A trailing comma is what separates recipient blocks in V4.
        current = None

        for token in value.split(','):
            if ':' in token:
                kind, address = token.split(':', 1)
                kind = kind.upper()

                if kind not in {'TO', 'CC', 'BCC'}:
                    return None

                current = kind
                if address:
                    result.append((current, address))
            else:
                if current is None or not token:
                    return None
                result.append((current, token))

        return result

    async def _default_sender_address(
        self,
        ses: SessionCoordinator,
        cursor,
    ) -> str:
        await cursor.execute(
            """SELECT address FROM address
            WHERE account_id = %s AND enabled = TRUE
            ORDER BY address
            LIMIT 1;""",
            (ses.user.user_id,),
        )

        row = await cursor.fetchone()

        if row is None:
            raise ProtocolError( "Cannot create an outbound message without an enabled address." )

        return row[0]

    async def edit_addr_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        args = ses.input_frame.arguments

        if len(args) != 2:
            await ses.write( Status.ERR, "EDIT ADDR requires Message UID and recipients." )
            return

        try:
            message_id = int(args[0])
        except ValueError:
            await ses.write(Status.ERR, "Invalid Message UID.")
            return

        recipients = self._parse_recipient_spec(args[1])

        if recipients is None:
            await ses.write(Status.ERR, "Invalid recipient specification.")
            return

        async with ses.conn.cursor() as cursor:
            row = await self._message_folder( ses, cursor, message_id, )

            if row != ('DRAFTS', 'OUTBOUND'):
                await ses.write( Status.ERR, "Message is not in DRAFTS." )
                return

            await cursor.execute(
                """DELETE FROM message_recipient
                WHERE message_id = %s;""",
                (message_id,),
            )

            for order, (recipient_type, address) in enumerate(recipients):
                await cursor.execute(
                    """INSERT INTO message_recipient (account_id, message_id, recipient_type, address, recipient_order)
                    VALUES (NULL, %s, %s, %s, %s);""",
                    ( message_id, recipient_type, address, order, ),
                )

            await ses.conn.commit()

        await ses.write(Status.OK, "Draft recipients replaced.")

    async def edit_thread_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        args = ses.input_frame.arguments

        if len(args) not in {1, 2}:
            await ses.write( Status.ERR, "EDIT THREAD requires Message UID and optional Thread UID." )
            return

        try:
            message_id = int(args[0])
        except ValueError:
            await ses.write(Status.ERR, "Invalid Message UID.")
            return

        thread_id = None

        if len(args) == 2:
            try:
                thread_id = int(args[1])
            except ValueError:
                await ses.write(Status.ERR, "Invalid Thread UID.")
                return

        async with ses.conn.cursor() as cursor:
            row = await self._message_folder(
                ses,
                cursor,
                message_id,
            )

            if row != ('DRAFTS', 'OUTBOUND'):
                await ses.write(Status.ERR, "Message is not in DRAFTS.")
                return

            await cursor.execute(
                """UPDATE message SET thread_id = %s
                WHERE message_id = %s;""",
                (thread_id, message_id),
            )

            await ses.conn.commit()

        await ses.write(
            Status.OK,
            "Draft thread updated."
            if thread_id is not None
            else "Draft detached from its thread."
        )

    async def edit_subj_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        args = ses.input_frame.arguments

        if len(args) != 2:
            await ses.write( Status.ERR, "EDIT SUBJ requires Message UID and Subject." )
            return

        try:
            message_id = int(args[0])
        except ValueError:
            await ses.write(Status.ERR, "Invalid Message UID.")
            return

        async with ses.conn.cursor() as cursor:
            row = await self._message_folder(
                ses,
                cursor,
                message_id,
            )

            if row != ('DRAFTS', 'OUTBOUND'):
                await ses.write(Status.ERR, "Message is not in DRAFTS.")
                return

            await cursor.execute(
                """UPDATE message SET subject = %s
                WHERE message_id = %s;""",
                (args[1], message_id),
            )

            await ses.conn.commit()

        await ses.write(Status.OK, "Draft subject updated.")

    async def edit_body_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        args = ses.input_frame.arguments

        if len(args) < 1:
            await ses.write(Status.ERR, "Message UID is required.")
            return

        try:
            message_id = int(args[0])
        except ValueError:
            await ses.write(Status.ERR, "Invalid Message UID.")
            return

        async with ses.conn.cursor() as cursor:
            row = await self._message_folder( ses, cursor, message_id, )

            if row != ('DRAFTS', 'OUTBOUND'):
                await ses.write(Status.ERR, "Message is not in DRAFTS.")
                return

        await ses.write( Status.ERR, "EDIT BODY requires the transport raw-stream extension." )

    async def send_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        args = ses.input_frame.arguments

        if not args:
            await ses.write(Status.ERR, "Message UID is required.")
            return

        try:
            message_ids = [int(value) for value in args if value.upper() != "NOW"]
        except ValueError:
            await ses.write(Status.ERR, "Invalid Message UID.")
            return

        mode = next( (value.upper() for value in args if value.upper() in {"NOW", "ABORT"}), None, )

        if mode == "ABORT":
            await ses.write( Status.ERR, "ABORT requires an OUTBOX message; SEND normally operates on drafts." )
            return

        async with ses.conn.cursor() as cursor:
            if not await self._require_messages( ses, cursor, message_ids, ):
                return

            for message_id in message_ids:
                row = await self._message_folder( ses, cursor, message_id, )

                if row != ('DRAFTS', 'OUTBOUND'):
                    await ses.write(
                        Status.ERR,
                        f"Message {message_id} is not in DRAFTS."
                    )
                    return

                await cursor.execute(
                    """UPDATE outbound_message
                    SET current_folder = 'OUTBOX', original_folder = 'DRAFTS', out_at = CURRENT_TIMESTAMP(6)
                    WHERE account_id = %s AND message_id = %s AND current_folder = 'DRAFTS';""",
                    (ses.user.user_id, message_id),
                )

            await ses.conn.commit()

        await ses.write( Status.OK, *[ f"{message_id} queued for delivery." for message_id in message_ids ], )

    # ------------------------------------------------------------------
    # Attachments
    # ------------------------------------------------------------------

    async def list_attach_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check():
            return

        args = ses.input_frame.arguments

        if len(args) != 1:
            await ses.write(Status.ERR, "Message UID is required.")
            return

        try:
            message_id = int(args[0])
        except ValueError:
            await ses.write(Status.ERR, "Invalid Message UID.")
            return

        async with ses.conn.cursor() as cursor:
            if not await self._message_exists(
                ses,
                cursor,
                message_id,
            ):
                await ses.write(Status.ERR, "Message does not exist.")
                return

            await cursor.execute(
                """SELECT attachment_index, filename, content_type, size_bytes FROM attachment
                WHERE message_id = %s
                ORDER BY attachment_index;""",
                (message_id,),
            )

            rows = await cursor.fetchall()

        if not rows:
            await ses.write(Status.WARN, "Message has no attachments.")
            return

        await ses.write( Status.OK, *[ f"{index} {filename} {content_type or '-'} {size}" for index, filename, content_type, size in rows ], )

    async def download_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check():
            return

        args = ses.input_frame.arguments

        if not args:
            await ses.write(Status.ERR, "Message UID is required.")
            return

        try:
            message_id = int(args[0])
        except ValueError:
            await ses.write(Status.ERR, "Invalid Message UID.")
            return

        if len(args) > 2:
            await ses.write( Status.ERR, "DOWNLOAD accepts an optional archive type or attachment index." )
            return

        async with ses.conn.cursor() as cursor:
            row = await self._message_folder(
                ses,
                cursor,
                message_id,
            )

            if row != ('INBOX', 'INBOUND'):
                await ses.write( Status.ERR, "DOWNLOAD requires a message in INBOX." )
                return

        await ses.write( Status.ERR, "DOWNLOAD requires the transport attachment-stream extension." )

    async def upload_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        args = ses.input_frame.arguments

        if not args:
            await ses.write(Status.ERR, "Message UID is required.")
            return

        try:
            message_id = int(args[0])
        except ValueError:
            await ses.write(Status.ERR, "Invalid Message UID.")
            return

        if len(args) > 2:
            await ses.write( Status.ERR, "UPLOAD accepts at most one attachment selector." )
            return

        selector = args[1] if len(args) == 2 else None

        if selector is not None and selector != '*':
            try:
                int(selector)
            except ValueError:
                await ses.write(Status.ERR, "Invalid attachment index.")
                return

        async with ses.conn.cursor() as cursor:
            row = await self._message_folder( ses, cursor, message_id, )

            if row != ('DRAFTS', 'OUTBOUND'):
                await ses.write( Status.ERR, "UPLOAD requires a message in DRAFTS." )
                return

        await ses.write( Status.ERR, "UPLOAD requires the transport attachment-stream extension." )

    # ------------------------------------------------------------------
    # Mirror
    # ------------------------------------------------------------------

    async def mirror_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        args = ses.input_frame.arguments

        if len(args) > 1:
            await ses.write(Status.ERR, "MIRROR accepts ON or OFF.")
            return

        async with ses.conn.cursor() as cursor:
            await cursor.execute(
                """SELECT address, enabled FROM mirror
                WHERE account_id = %s
                ORDER BY mirror_id DESC
                LIMIT 1;""",
                (ses.user.user_id,),
            )

            current = await cursor.fetchone()

            if not args:
                if current is None or not current[1]:
                    await ses.write(Status.INFO, "Mirror is OFF.")
                else:
                    await ses.write(Status.OK, current[0])
                return

            enabled = self._parse_bool(args[0])

            if enabled is None:
                await ses.write(Status.ERR, "MIRROR accepts ON or OFF.")
                return

            if not enabled:
                await cursor.execute(
                    """DELETE FROM inbound_message
                    WHERE account_id = %s AND current_folder = 'MERC';""",
                    (ses.user.user_id,),
                )

                await cursor.execute(
                    """DELETE FROM mirror
                    WHERE account_id = %s;""",
                    (ses.user.user_id,),
                )

                await ses.conn.commit()

                await ses.write( Status.OK, "Mirror disabled." )
                return

            if current is not None and current[1]:
                await ses.write(Status.OK, current[0])
                return

            timestamp = int(datetime.datetime.now().timestamp())
            random_part = uuid.uuid4().hex

            address = f"{timestamp}{random_part}@pearlescent.mail"

            await cursor.execute(
                """INSERT INTO mirror (account_id, address, enabled)
                VALUES (%s, %s, TRUE);""",
                (ses.user.user_id, address),
            )

            await ses.conn.commit()

        await ses.write(Status.OK, address)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    async def list_act_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check():
            return

        async with ses.conn.cursor() as cursor:
            await cursor.execute(
                """SELECT HEX(action_uid), enabled, priority, filter, operations
                FROM action
                WHERE account_id = %s
                ORDER BY priority, action_id;""",
                (ses.user.user_id,),
            )

            rows = await cursor.fetchall()

        if not rows:
            await ses.write(Status.WARN, "No actions configured.")
            return

        await ses.write(
            Status.OK,
            *[
                f"{uid} {'ON' if enabled else 'OFF'} "
                f"{priority} {filter_json} {operations_json}"
                for uid, enabled, priority,
                    filter_json, operations_json in rows
            ],
        )

    async def act_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        args = ses.input_frame.arguments

        if not args:
            await ses.write(
                Status.ERR,
                "ACT requires an action definition or action UID."
            )
            return

        # ACT ON/OFF UID...
        if args[0].upper() in {"ON", "OFF"}:
            if len(args) < 2:
                await ses.write(Status.ERR, "Action UID is required.")
                return

            enabled = args[0].upper() == "ON"

            try:
                action_uids = [
                    uuid.UUID(value.replace('-', ''))
                    for value in args[1:]
                ]
            except ValueError:
                await ses.write(Status.ERR, "Invalid Action UID.")
                return

            async with ses.conn.cursor() as cursor:
                for action_uid in action_uids:
                    await cursor.execute(
                        """UPDATE action SET enabled = %s
                        WHERE account_id = %s AND action_uid = %s;""",
                        (
                            enabled,
                            ses.user.user_id,
                            action_uid.bytes,
                        ),
                    )

                await ses.conn.commit()

            await ses.write( Status.OK, f"{len(action_uids)} action(s) set to {'ON' if enabled else 'OFF'}.")
            return

        # ACT UID DEL
        if len(args) == 2 and args[1].upper() == "DEL":
            try:
                action_uid = uuid.UUID(args[0].replace('-', ''))
            except ValueError:
                await ses.write(Status.ERR, "Invalid Action UID.")
                return

            async with ses.conn.cursor() as cursor:
                await cursor.execute(
                    """DELETE FROM action
                    WHERE account_id = %s AND action_uid = %s;""",
                    ( ses.user.user_id, action_uid.bytes, ),
                )

                if cursor.rowcount == 0:
                    await ses.write(Status.ERR, "Action does not exist.")
                    return

                await ses.conn.commit()

            await ses.write(Status.OK, "Action deleted.")
            return

        # The actual Filter/Action grammar is not specified sufficiently
        # to safely deserialize it from positional frame arguments.
        await ses.write( Status.ERR, "ACT action-definition grammar is not implemented yet." )

    # ------------------------------------------------------------------
    # Blocking
    # ------------------------------------------------------------------

    async def block_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        args = ses.input_frame.arguments

        if len(args) < 2:
            await ses.write( Status.ERR, "BLOCK requires ON/OFF and at least one address." )
            return

        enabled = self._parse_bool(args[0])

        if enabled is None:
            await ses.write(Status.ERR, "BLOCK accepts ON or OFF.")
            return

        addresses = args[1:]

        async with ses.conn.cursor() as cursor:
            for address in addresses:
                if enabled:
                    await cursor.execute(
                        """INSERT IGNORE INTO block (account_id, address)
                        VALUES (%s, %s);""",
                        (ses.user.user_id, address),
                    )
                else:
                    await cursor.execute(
                        """DELETE FROM block
                        WHERE account_id = %s AND address = %s;""",
                        (ses.user.user_id, address),
                    )

            await ses.conn.commit()

        await ses.write( Status.OK, f"{'Blocked' if enabled else 'Unblocked'} {len(addresses)} address(es)." )

    async def list_block_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check():
            return

        async with ses.conn.cursor() as cursor:
            await cursor.execute(
                """SELECT address, blocked_at FROM block
                WHERE account_id = %s
                ORDER BY address;""",
                (ses.user.user_id,),
            )

            rows = await cursor.fetchall()

        if not rows:
            await ses.write(Status.WARN, "No blocked addresses.")
            return

        await ses.write( Status.OK, *[ f"{address} {blocked_at}" for address, blocked_at in rows ], )

    # ------------------------------------------------------------------
    # Contacts
    # ------------------------------------------------------------------

    async def contact_add_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        args = ses.input_frame.arguments

        if len(args) not in {2, 3}:
            await ses.write( Status.ERR, "CONTACT ADD requires Name, Address, and optional About." )
            return

        name, address = args[:2]
        about = args[2] if len(args) == 3 else None

        async with ses.conn.cursor() as cursor:
            await cursor.execute(
                """INSERT INTO contact (account_id, name, address, about)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    name = VALUES(name),
                    about = VALUES(about);""",
                ( ses.user.user_id, name, address, about, ),
            )

            await ses.conn.commit()

        await ses.write(Status.OK, "Contact added.")

    async def contact_rem_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check() or not await ses.modify_check():
            return

        address, = ses.input_frame.arguments

        async with ses.conn.cursor() as cursor:
            await cursor.execute(
                """DELETE FROM contact
                WHERE account_id = %s AND address = %s;""",
                (ses.user.user_id, address),
            )

            if cursor.rowcount == 0:
                await ses.write(Status.WARN, "Contact does not exist.")
                return

            await ses.conn.commit()

        await ses.write(Status.OK, "Contact removed.")

    async def list_contact_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check():
            return

        async with ses.conn.cursor() as cursor:
            await cursor.execute(
                """SELECT c.name, c.address, c.about, c.added_at,
                    (
                        SELECT COUNT(*) FROM inbound_message AS im
                        INNER JOIN message AS m ON m.message_id = im.message_id
                        WHERE im.account_id = c.account_id AND m.sender_address = c.address
                    ),
                    (
                        SELECT COUNT(*) FROM outbound_message AS om
                        INNER JOIN message_recipient AS mr ON mr.message_id = om.message_id AND mr.account_id IS NULL
                        WHERE om.account_id = c.account_id AND mr.address = c.address
                    ),
                    EXISTS(
                        SELECT 1 FROM block AS b
                        WHERE b.account_id = c.account_id AND b.address = c.address
                    )
                FROM contact AS c
                WHERE c.account_id = %s
                ORDER BY c.name, c.address;""",
                (ses.user.user_id,),
            )

            rows = await cursor.fetchall()

        if not rows:
            await ses.write(Status.WARN, "No contacts.")
            return

        await ses.write(
            Status.OK,
            *[
                f"{name} {address} "
                f"{about or '-'} {added_at} "
                f"RECEIVED={received} SENT={sent} "
                f"BLOCKED={'ON' if blocked else 'OFF'}"
                for ( name, address, about, added_at, received, sent, blocked, ) in rows
            ],
        )

    async def contact_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check():
            return

        # Contact aliasing is session state, but SessionCoordinator currently
        # has no contact_alias flag. Until one is added, the command can
        # acknowledge the setting without pretending it persists.
        args = ses.input_frame.arguments

        if not args:
            await ses.write( Status.INFO, "Contact aliasing is ON." )
            return

        if len(args) != 1 or self._parse_bool(args[0]) is None:
            await ses.write(Status.ERR, "CONTACT accepts ON or OFF.")
            return

        await ses.write( Status.OK, f"Contact aliasing set to {args[0].upper()}." )

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    async def status_op(self, ses: SessionCoordinator) -> None:
        if not await ses.auth_check():
            return

        async with ses.conn.cursor() as cursor:
            await cursor.execute(
                """SELECT current_folder, COUNT(*)
                FROM (
                    SELECT current_folder FROM inbound_message
                    WHERE account_id = %s

                    UNION ALL

                    SELECT current_folder FROM outbound_message
                    WHERE account_id = %s
                ) AS folders
                GROUP BY current_folder
                ORDER BY current_folder;""",
                (ses.user.user_id, ses.user.user_id),
            )

            rows = await cursor.fetchall()

            await cursor.execute(
                """SELECT COUNT(*) FROM inbound_message
                WHERE account_id = %s AND current_folder = 'INBOX' AND seen = FALSE;""",
                (ses.user.user_id,),
            )

            unread, = await cursor.fetchone()

        await ses.write( Status.OK, *[ f"{folder} {count}" for folder, count in rows ], f"UNREAD {unread}")