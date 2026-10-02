import asyncio
from enum import Enum
import uuid
import bcrypt
from database import Database
from other import Context, Folder, Mode, TransientUser, User

class Status(Enum):
    OK = "+OK"
    INFO = "+INFO"
    WARN = "+WARN"
    ERR = "-ERR"

type Result = tuple[Status, str]

class PearlescentServer:
    HOST = "127.0.0.1"
    MY_PORT = 25
    POP3_PORT = 110

    NAMESPACE = uuid.UUID("99b00d33-11b3-4f37-bd46-18a624fcfe74")

    def __init__(self):
        self.db = Database()
        self.sock: asyncio.Server | None = None

    async def start(self):
        await self.db.open()

        if self.sock is None:
            self.sock = await asyncio.start_server(
                self._listen, self.HOST, self.MY_PORT
            )

        async with self.sock:
            await asyncio.gather(self.sock.serve_forever())

    async def stop(self):
        self.sock.close()
        self.sock.close_clients()
        await self.sock.wait_closed()

        await self.db.close()

    @staticmethod
    async def _read_frame(reader: asyncio.StreamReader) -> list[str]:
        data = await reader.readuntil(b"\v")
        return data[:-1].decode('ascii').split("\t")
    
    @staticmethod
    async def _write_res(writer: asyncio.StreamWriter, res: Result) -> None:
        writer.write((f'{res[0].value}\t{res[1]}\v').encode('ascii'))
        await writer.drain()
        
    @staticmethod
    async def _write_raw(writer: asyncio.StreamWriter, data: bytes) -> None:
        writer.write(data)
        await writer.drain()

    async def _listen(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        # format 'CMD\tmy data\tmultiline\ntext\v'
        conn = await self.db.pool.acquire()
        ctx = Context(reader, writer, conn)
        
        await self._write_raw(writer, Status.OK, "pearlescence service ready\v")

        try:
            while True:
                cmd_seq = await self._read_frame(reader)

                match cmd_seq[0]:
                    case "AUTH":
                        user, msg = await self.auth_cmd(conn, cmd_seq)
                        ctx.user = user

                    case "JOIN":
                        msg = await self.join_cmd(conn, cmd_seq)

                        writer.write(msg)
                        await writer.drain()

                        if ctx.user is not None:
                            cmd_seq = await self._read_frame(reader)
                            msg = await self.verify_join_cmd(ctx, cmd_seq)

                    case "EXIT":
                        if ctx.user is not None:
                            msg = Status.OK, f"Goodbye {ctx.user.user_name}!\nYou have been logged out."
                        else:
                            msg = Status.OK, "You are already logged out."
                        ctx.user = None

                    case "DC":
                        # Call write directly, otherwise  it will get bypassed by loop termination
                        await self._write_msg(writer, Status.OK, f"Goodbye {ctx.user.user_name}!\nYou have been {'logged out and ' if ctx.user is not None else ''}disconnected.")
                        break

                    case "USE":
                        msg = await self.use_folder_cmd(ctx, cmd_seq)

                    case "TAG":
                        msg = await self.tag_cmd(ctx, cmd_seq)

                    case "DEL":
                        match cmd_seq[1]:
                            case "ACCOUNT":
                                msg = await self.del_account_cmd(ctx, cmd_seq)

                    case "LIST":
                        match cmd_seq[1]:
                            case "TAG":
                                msg = await self.list_tag_cmd(ctx, cmd_seq)

                    case _:
                        msg = Status.ERR, "Unknown Command"

                await self._write_msg(writer, msg)

        except asyncio.IncompleteReadError as e:
            print(f"Connection ended: {e.partial!r}")
        except asyncio.InvalidStateError as e:
            print(f"Invalid state: {e}")
        finally:
            await ctx.cleanup()

    async def auth_cmd(self, ctx: Context, cmd_seq: list[str]) -> Result:
        if len(cmd_seq) != 3:
            return Status.ERR, "Invalid Arguments"

        username = cmd_seq[1].decode("ascii")
        password = cmd_seq[2]

        async with ctx.conn.cursor() as cur:
            await cur.execute(
                """SELECT user_id, user_password_hash, created_on, last_accessed_on FROM user_accounts
                WHERE user_name = %s;""",
                (username,),
            )

            row = await cur.fetchone()

            if row is None:
                return Status.ERR, "authentication failed"

            user_id, password_hash, created_on, last_login = row

            if not bcrypt.checkpw(password, password_hash):
                return Status.ERR, "authentication failed"

            await cur.execute(
                """SELECT COUNT(*) FROM messages as m
                INNER JOIN message_recipients as mr
                INNER JOIN user_addresses as ua
                WHERE ua.recipient_address = mr. AND folder = 'Inbox' AND is_unread""",
                (user_id,),
            )
            (unread,) = await cur.fetchone()

            await cur.execute(
                """UPDATE user_accounts SET last_accessed_on = CURRENT_TIMESTAMP
                WHERE user_id = %s;""",
                (user_id,),
            )
            await ctx.conn.commit()

        ctx.user = User(user_id, username, created_on, last_login)
        ctx.mode = Mode.AUTHENTICATED

        return Status.OK, f"Welcome {username} (#{user_id})!\nYou have {unread} unread messages in your Inbox.\nYour last login was on {last_login}"

    async def join_cmd(self, ctx: Context, cmd_seq: list[str]) -> Result:
        if len(cmd_seq) != 3:
            await Status.ERR, "Invalid Arguments"

        username = cmd_seq[1].decode("ascii")
        password = cmd_seq[2]

        async with ctx.conn.cursor() as cur:
            await cur.execute(
                """SELECT EXISTS (
                    SELECT 1 FROM user_accounts
                    WHERE user_name = %s
                );""",
                (username,),
            )

            (exists,) = await cur.fetchone()

        if exists:
            return Status.ERR, f"Sorry, but the username {username} was already taken!\nPlease be more creative next time."

        ctx.trans_user = TransientUser(
            username, bcrypt.hashpw(password, bcrypt.gensalt(12))
        )
        ctx.mode = Mode.VALIDATING_JOINING

        return Status.OK, "Please verify your password"

    async def verify_join_cmd(self, ctx: Context, cmd_seq: list[str]) -> Result:
        if ctx.mode != Mode.VALIDATING_JOINING:
            ctx.purge_join()
            return Status.ERR, "Invalid mode"

        if len(cmd_seq) != 1:
            ctx.purge_join()
            return Status.ERR, "Invalid Arguments"

        password = cmd_seq[0]

        if not bcrypt.checkpw(password, ctx.trans_user.password_hash):
            return Status.ERR, "authentication failed"

        async with ctx.conn.cursor() as cur:
            await cur.execute(
                """INSERT INTO user_accounts(user_name, user_password_hash)
                VALUES(%s, %s);""",
                (ctx.trans_user.username, ctx.trans_user.password_hash),
            )

            user_id = cur.lastrowid
            await ctx.conn.commit()

        ctx.promote_join(user_id)

        return Status.OK, f"Welcome {ctx.user.username} (#{user_id})!\nYou have zero unread messages.\nYour last login was never"

    async def del_account_cmd(self, ctx: Context, cmd_seq: list[str]) -> Result:
        if ctx.mode != Mode.AUTHENTICATED:
            return Status.ERR, "Authentication required"

        if len(cmd_seq) != 3:
            return Status.ERR, "Invalid Arguments"

        password = cmd_seq[2]

        async with ctx.conn.cursor() as cur:
            await cur.execute(
                """SELECT user_password_hash
                FROM user_accounts
                WHERE user_id = %s;""",
                (ctx.user.user_id,),
            )

            row = await cur.fetchone()

            if row is None:
                return Status.ERR, "Account no longer exists"

            if not bcrypt.checkpw(password, row[0]):
                return Status.ERR, "authentication failed"

            await cur.execute(
                """DELETE FROM user_accounts
                WHERE user_id = %s;""",
                (ctx.user.user_id,),
            )

            await ctx.conn.commit()

        ctx.purge_auth()
        return Status.OK, f"Goodbye {ctx.user.username}!\nPlease come again in the future."

    async def list_tag_cmd(self, ctx: Context, cmd_seq: list[str]):
        if ctx.mode != Mode.AUTHENTICATED:
            return Status.ERR, "Authentication required"

        if len(cmd_seq) != 3:
            return Status.ERR, "Invalid Arguments"

        async with ctx.conn.cursor() as cur:
            await cur.execute(
                """SELECT tag_id, tag_name FROM tags
                WHERE user_id = %s
                ORDER BY tag_name;""",
                (ctx.user.user_id,),
            )

            rows = await cur.fetchall()

        if not rows:
            return Status.OK, "You have no tags created. Use `NEW TAG` or `TAG` to create tags"

        return Status.OK, f"You have the following tags:{''.join(f'\n{row[0]} {row[1]}' for row in rows)}"

    async def tag_cmd(self, ctx: Context, cmd_seq: list[str]):
        if ctx.mode != Mode.AUTHENTICATED:
            return Status.ERR, "Authentication required"

        try:
            i = cmd_seq.index("TO", 2)
        except ValueError:
            return Status.ERR, "Invalid Arguments"

        if i == 2 or i + 1 == len(cmd_seq):
            return Status.ERR, "Invalid Arguments"

        tags = [tag_raw.decode("ascii") for tag_raw in cmd_seq[1:i]]
        msg_ids = [int(msg_id_raw) for msg_id_raw in cmd_seq[i + 1 :]]

        tag_placeholders = ", ".join(["%s"] * len(tags))

        async with ctx.conn.cursor() as cur:
            await cur.executemany(
                """INSERT IGNORE INTO tags (user_id, tag_name)
                VALUES (%s, %s);""",
                [(ctx.user.user_id, tag) for tag in tags],
            )

            await cur.execute(
                f"""
                SELECT tag_id FROM tags
                WHERE user_id = %s
                AND tag_name IN ({tag_placeholders});
                """,
                (ctx.user.user_id, *tags),
            )

            tag_ids = await cur.fetchall()

            await cur.executemany(
                """INSERT IGNORE INTO message_tags (tag_id, message_id)
                VALUES (%s, %s);""",
                [(tag_id, msg_id) for (tag_id,) in tag_ids for msg_id in msg_ids],
            )

            affected = cur.rowcount

            await ctx.conn.commit()

        if affected == 0:
            return Status.OK, "No tag associations were added."
        return Status.OK, f"{affected} tag associations applied."

    async def untag_cmd(self, ctx: Context, cmd_seq: list[str]):
        if ctx.mode != Mode.AUTHENTICATED:
            return Status.ERR, "Authentication required"

        try:
            i = cmd_seq.index("FROM", 2)
        except ValueError:
            return Status.ERR, "Invalid Arguments"

        if i == 2 or i + 1 == len(cmd_seq):
            return Status.ERR, "Invalid Arguments"

        tags = [tag_raw.decode("ascii") for tag_raw in cmd_seq[1:i]]
        msg_ids = [int(msg_id_raw) for msg_id_raw in cmd_seq[i + 1 :]]

        tag_placeholders = ", ".join(["%s"] * len(tags))
        msg_placeholders = ", ".join(["%s"] * len(msg_ids))

        async with ctx.conn.cursor() as cur:
            await cur.execute(
                f"""DELETE FROM message_tags
                WHERE tag_id IN (
                    SELECT tag_id FROM tags
                    WHERE user_id = %s AND tag_name IN ({tag_placeholders})
                ) AND message_id IN ({msg_placeholders});""",
                (ctx.user.user_id, *tags, *msg_ids),
            )

            affected = cur.rowcount

            await cur.execute(
                f"""DELETE FROM tags
                WHERE user_id = %s
                AND tag_name IN ({tag_placeholders}) AND NOT EXISTS (
                    SELECT 1 FROM message_tags
                    WHERE message_tags.tag_id = tags.tag_id
                );""",
                (ctx.user.user_id, *tags),
            )

            await ctx.conn.commit()

        if affected == 0:
            return Status.OK, "No tag associations were removed"
        return Status.OK, f"{affected} tag associations removed"

    async def list_contact_cmd(self, ctx: Context, cmd_seq: list[str]):
        if ctx.mode != Mode.AUTHENTICATED:
            return Status.ERR, "Authentication required"

        if len(cmd_seq) > 3:
            return Status.ERR, "Invalid Arguments"

        glob = cmd_seq[2].decode("utf-8") if len(cmd_seq) == 3 else None

        async with ctx.conn.cursor() as cur:
            if glob is None:
                await cur.execute(
                    """SELECT contact_id, name, relation, address, blocked FROM contacts
                    WHERE user_id = %s
                    ORDER BY contact_id;""",
                    (ctx.user.user_id,),
                )
            else:
                # SQL LIKE is used here for the database-side filtering.
                # Convert protocol glob syntax to SQL LIKE syntax.
                pattern = (
                    glob.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                )
                pattern = pattern.replace("*", "%").replace("?", "_")

                await cur.execute(
                    """SELECT contact_id, contact_name, contact_relation, contact_address, is_blocked, created_on, updated_on FROM contacts
                    WHERE user_id = %s AND (name LIKE %s ESCAPE '\\' OR address LIKE %s ESCAPE '\\')
                    ORDER BY contact_id;""",
                    (ctx.user.user_id, pattern, pattern),
                )

            contacts = await cur.fetchall()

        if not contacts:
            return Status.OK, "No contacts."

        lines = []
        for (contact_id, contact_name, contact_relation, contact_address, is_blocked, created_on, updated_on) in contacts: 
            contact_relation = contact_relation or ""
            block = "\tBLOCKED"if is_blocked else ""
            lines.append(f"\nID\t{contact_id}\nNAME\t{contact_name}\nREL\t{contact_relation}\nADDR\t{contact_address}\nCTIME\t{created_on}\nUTIME\t{updated_on}\n{block}")

        if not lines:
            return Status.OK, "No contacts found. You can use `NEW CONTACT` to add a contact"
        return Status.OK, f"{''.join(lines)}"

    async def new_contact_cmd(self, ctx: Context, cmd_seq: list[str]):
        if ctx.mode != Mode.AUTHENTICATED:
            return Status.ERR, "Authentication required"

        if len(cmd_seq) not in (3, 4):
            return Status.ERR, "Invalid Arguments"

        name = cmd_seq[1].decode("utf-8")
        address = cmd_seq[2].decode("ascii")
        relation = cmd_seq[3].decode("utf-8") if len(cmd_seq) == 4 else None

        async with ctx.conn.cursor() as cur:
            await cur.execute(
                """INSERT INTO contacts (user_id, contact_name, contact_address, contact_relation)
                VALUES (%s, %s, %s, %s);""",
                (ctx.user.user_id, name, address, relation),
            )
            contact_id = cur.lastrowid
            await ctx.conn.commit()

        return Status.OK, f"Created the contact {name} ({contact_id}#)"

    async def get_contact_cmd(self, ctx: Context, cmd_seq: list[str]):
        if ctx.mode != Mode.AUTHENTICATED:
            return Status.ERR, "Authentication required"

        if len(cmd_seq) not in (3, 4):
            return Status.ERR, "Invalid Arguments"

        target = cmd_seq[2].decode("utf-8")
        mode = cmd_seq[3].decode("ascii") if len(cmd_seq) == 4 else "ID"

        if mode not in ("ID", "NAME", "ADDR"):
            return Status.ERR, "Invalid Arguments"

        column = {"ID": "contact_id", "NAME": "name", "ADDR": "address"}[mode]

        if mode == "ID":
            try:
                target = int(target)
            except ValueError:
                return Status.ERR, "Invalid Arguments"

        async with ctx.conn.cursor() as cur:
            await cur.execute(
                f"""SELECT contact_id, name, relation, address, is_blocked, created_on, updated_on FROM contacts
                WHERE user_id = %s AND {column} = %s;""",
                (ctx.user.user_id, target),
            )
            contact = await cur.fetchone()

        if contact is None:
            return Status.ERR, "Contact not found"

        contact_id, name, relation, address, is_blocked, created_on, updated_on = (
            contact
        )
        relation = relation or ""

        return Status.OK, f"Contact details are as follows:\nID\t{contact_id}\nNAME\t{name}\nREL\t{relation}\nADDR\t{address}\nCTIME\t{created_on}\nUTIME\t{updated_on}{'\nBLOCKED' if is_blocked else ''}"

    async def edit_contact_cmd(self, ctx: Context, cmd_seq: list[str]):
        if ctx.mode != Mode.AUTHENTICATED:
            return Status.ERR, "Authentication required"

        if len(cmd_seq) < 4 or (len(cmd_seq) - 2) % 2:
            return Status.ERR, "Invalid Arguments"

        try:
            contact_id = int(cmd_seq[2])
        except ValueError:
            return Status.ERR, "Invalid Arguments"

        fields = { "NAME": "contact_name", "ADDR": "contact_address", "REL": "contact_relation", }

        updates, values = [], []

        for i in range(3, len(cmd_seq), 2):
            field = cmd_seq[i]
            if field not in fields:
                return Status.ERR, "Invalid Arguments"

            column = fields[field]
            value = cmd_seq[i + 1].decode("ascii"if field == "ADDR"else "utf-8")

            updates.append(f"{column} = %s")
            values.append(value)

        values.extend((ctx.user.user_id, contact_id))

        async with ctx.conn.cursor() as cur:
            await cur.execute(
                f"""UPDATE contacts SET {", ".join(updates)}
                WHERE user_id = %s AND contact_id = %s;""",
                values,
            )

            affected = cur.rowcount
            await ctx.conn.commit()

        if affected == 0:
            return Status.ERR, "Contact not found"

        return Status.OK, "Contact updated."

    async def del_contact_cmd(self, ctx: Context, cmd_seq: list[str]):
        if ctx.mode != Mode.AUTHENTICATED:
            return Status.ERR, "Authentication required"

        if len(cmd_seq) != 3:
            return Status.ERR, "Invalid Arguments"

        try:
            contact_id = int(cmd_seq[2])
        except ValueError:
            return Status.ERR, "Invalid Arguments"

        async with ctx.conn.cursor() as cur:
            await cur.execute(
                """DELETE FROM contacts
                WHERE user_id = %s AND contact_id = %s;""",
                (ctx.user.user_id, contact_id),
            )

            affected = cur.rowcount
            await ctx.conn.commit()

        if affected == 0:
            return Status.ERR, "Contact not found"

        return Status.OK, "Contact deleted."

    async def block_contact_cmd(self, ctx: Context, cmd_seq: list[str]):
        if ctx.mode != Mode.AUTHENTICATED:
            return Status.ERR, "Authentication required"

        if len(cmd_seq) != 3:
            return Status.ERR, "Invalid Arguments"

        try:
            contact_id = int(cmd_seq[2])
        except ValueError:
            return Status.ERR, "Invalid Arguments"

        async with ctx.conn.cursor() as cur:
            await cur.execute(
                """UPDATE contacts SET blocked = TRUE
                WHERE user_id = %s AND contact_id = %s AND blocked = FALSE;""",
                (ctx.user.user_id, contact_id),
            )

            affected = cur.rowcount
            await ctx.conn.commit()

        if affected == 0:
            return Status.ERR, "Contact not found or already blocked."

        return Status.OK, "Contact blocked."

    async def set_block_contact_cmd(self, ctx: Context, cmd_seq: list[str]):
        if ctx.mode != Mode.AUTHENTICATED:
            return Status.ERR, "Authentication required"

        if len(cmd_seq) != 3:
            return Status.ERR, "Invalid Arguments"

        try:
            contact_id = int(cmd_seq[2])
        except ValueError:
            return Status.ERR, "Invalid Arguments"

        async with ctx.conn.cursor() as cur:
            await cur.execute(
                """UPDATE contacts SET blocked = FALSE
                WHERE user_id = %s AND contact_id = %s AND blocked = TRUE;""",
                (ctx.user.user_id, contact_id),
            )

            affected = cur.rowcount
            await ctx.conn.commit()

        if affected == 0:
            return Status.ERR, "Contact not found or not blocked."

        return Status.OK, "Contact unblocked."

    async def new_addr_cmd(self, ctx: Context, cmd_seq: list[str]):
        if ctx.mode != Mode.AUTHENTICATED:
            return Status.ERR, "Authentication required"

        if len(cmd_seq) not in (3, 4):
            return Status.ERR, "Invalid Arguments"

        address = cmd_seq[2].decode("ascii")

        if "&"in address:
            return Status.ERR, "Invalid Arguments"

        forwarding_address = None
        if len(cmd_seq) == 4:
            forwarding_address = cmd_seq[3].decode("ascii")

            if "&"in forwarding_address:
                return Status.ERR, "Invalid Arguments"

            if forwarding_address == address:
                # If it forwards to itself, remove the forwarding since the end destination is identical
                # when viewed as a set rather than a circular pointer chain
                forwarding_address = None

        async with ctx.conn.cursor() as cur:
            await cur.execute(
                """SELECT address_id, forwarding_address_id
                FROM user_addresses WHERE user_address = %s;""",
                (address,),
            )

            if await cur.fetchone() is not None:
                return Status.OK, "Address already exists."

            forwarding_id = None

            if forwarding_address is not None:
                await cur.execute(
                    """SELECT address_id, forwarding_address_id
                    FROM user_addresses WHERE user_id = %s AND user_address = %s;""",
                    (ctx.user.user_id, forwarding_address),
                )

                forwarding = await cur.fetchone()

                if forwarding is None:
                    return Status.ERR, "Forwarding address not found or not owned."

                forwarding_id, nested_id = forwarding

                if nested_id is not None:
                    return Status.ERR, "Forwarding address cannot itself forward."

            await cur.execute(
                """INSERT INTO user_addresses (user_id, user_address, forwarding_address_id)
                VALUES (%s, %s, %s);""",
                (ctx.user.user_id, address, forwarding_id),
            )

            address_id = cur.lastrowid
            await ctx.conn.commit()

        return Status.OK, f"{address_id}"

    async def fwrd_addr_cmd(self, ctx: Context, cmd_seq: list[str]):
        if ctx.mode != Mode.AUTHENTICATED:
            return Status.ERR, "Authentication required"

        if len(cmd_seq) != 4:
            return Status.ERR, "Invalid Arguments"

        address = cmd_seq[2].decode("ascii")
        forwarding = cmd_seq[3].decode("ascii")

        if "&"in address or "&"in forwarding:
            return Status.ERR, "Invalid Arguments"

        async with ctx.conn.cursor() as cur:
            await cur.execute(
                """SELECT address_id
                FROM user_addresses WHERE user_id = %s AND user_address = %s;""",
                (ctx.user.user_id, address),
            )

            source = await cur.fetchone()

            if source is None:
                return Status.ERR, "Address not found."

            await cur.execute(
                """SELECT address_id, forwarding_address_id
                FROM user_addresses WHERE user_id = %s AND user_address = %s;""",
                (ctx.user.user_id, forwarding),
            )

            target = await cur.fetchone()

            if target is None:
                return Status.ERR, "Forwarding address not found or not owned."

            source_id = source[0]
            target_id, nested_id = target

            if source_id == target_id:
                return Status.ERR, "Address cannot forward to itself."

            if nested_id is not None:
                return Status.ERR, "Forwarding address cannot itself forward."

            await cur.execute(
                """UPDATE user_addresses SET forwarding_address_id = %s
                WHERE user_id = %s AND address_id = %s;""",
                ( target_id if target_id != source_id else None, ctx.user.user_id, source_id, ),
            )

            await ctx.conn.commit()

        return Status.OK, "Address forwarding updated."

    async def unfwrd_addr_cmd(self, ctx: Context, cmd_seq: list[str]):
        if ctx.mode != Mode.AUTHENTICATED:
            return Status.ERR, "Authentication required"

        if len(cmd_seq) != 3:
            return Status.ERR, "Invalid Arguments"

        address = cmd_seq[2].decode("ascii")

        async with ctx.conn.cursor() as cur:
            await cur.execute(
                """UPDATE user_addresses SET forwarding_address_id = NULL 
                WHERE user_id = %s AND user_address = %s AND forwarding_address_id IS NOT NULL;""", 
                (ctx.user.user_id, address)
            )

            affected = cur.rowcount
            await ctx.conn.commit()

        if affected == 0:
            return Status.ERR, "Address not found or not forwarding."

        return Status.OK, "Address forwarding removed."

    async def del_addr_cmd(self, ctx: Context, cmd_seq: list[str]):
        if ctx.mode != Mode.AUTHENTICATED:
            return Status.ERR, "Authentication required"

        if len(cmd_seq) != 3:
            return Status.ERR, "Invalid Arguments"

        address = cmd_seq[2].decode("ascii")

        async with ctx.conn.cursor() as cur:
            await cur.execute(
                """SELECT address_id FROM user_addresses
                WHERE user_id = %s AND user_address = %s;""",
                (ctx.user.user_id, address),
            )

            if await cur.fetchone() is None:
                return Status.ERR, "Address not found."

            # If a message is sent by the address or solely received by it, remove it
            await cur.execute(
                """DELETE m FROM messages AS m 
                WHERE m.user_id = %s
                AND (
                    m.sender_address = %s
                    OR (
                        EXISTS (
                            SELECT 1 FROM message_recipients AS mr
                            WHERE mr.message_id = m.message_id AND mr.recipient_address = %s
                        )
                        AND NOT EXISTS (
                            SELECT 1 FROM message_recipients AS other
                            WHERE other.message_id = m.message_id AND other.recipient_address <> %s
                        )
                    )
                );""",
                (ctx.user.user_id, address, address, address),
            )

            deleted_messages = cur.rowcount

            await cur.execute("DELETE FROM user_addresses WHERE user_id = %s AND user_address = %s;", (ctx.user.user_id, address), )
            await ctx.conn.commit()

        return Status.OK, f"Address deleted. {deleted_messages} messages deleted."

    async def list_addr_cmd(self, ctx: Context, cmd_seq: list[str]):
        if ctx.mode != Mode.AUTHENTICATED:
            return Status.ERR, "Authentication required"

        if len(cmd_seq) > 3:
            return Status.ERR, "Invalid Arguments"

        pattern = None
        if len(cmd_seq) == 3:
            pattern = cmd_seq[2].decode("ascii")

        async with ctx.conn.cursor() as cur:
            if pattern is None:
                await cur.execute(
                    """SELECT a.address_id, a.user_address, a.created_at, a.updated_on, f.user_address,
                    (
                        SELECT COUNT(*) FROM messages AS m
                        WHERE m.user_id = a.user_id AND m.sender_address = a.user_address AND m.folder = 'Draft'
                    ) AS drafted, (
                        SELECT COUNT(*) FROM messages AS m
                        WHERE m.user_id = a.user_id AND m.sender_address = a.user_address AND m.folder = 'Sent'
                    ) AS sent, (
                        SELECT COUNT(DISTINCT mr.message_id) FROM message_recipients AS mr
                        JOIN messages AS m ON m.message_id = mr.message_id
                        WHERE m.user_id = a.user_id AND mr.recipient_address = a.user_address
                    ) AS received, (
                        SELECT COUNT(DISTINCT mr.message_id) FROM message_recipients AS mr
                        JOIN messages AS m ON m.message_id = mr.message_id
                        WHERE m.user_id = a.user_id AND mr.recipient_address = a.user_addressAND m.is_read = TRUE
                    ) AS read_count, (
                        SELECT COUNT(DISTINCT mr.message_id) FROM message_recipients AS mr
                        JOIN messages AS m ON m.message_id = mr.message_id
                        WHERE m.user_id = a.user_id AND mr.recipient_address = a.user_address AND m.is_read = FALSE
                    ) AS unread_count
                    FROM user_addresses AS a
                    LEFT JOIN user_addresses AS f ON f.address_id = a.forwarding_address_id
                    WHERE a.user_id = %s
                    ORDER BY a.address_id;""",
                    (ctx.user.user_id,),
                )
            else:
                sql_pattern = pattern.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_").replace("*", "%").replace("?", "_")

                await cur.execute(
                    """SELECT a.address_id, a.user_address, a.created_at, a.updated_on, f.user_address,
                        (
                            SELECT COUNT(*) FROM messages AS m
                            WHERE m.user_id = a.user_id AND m.sender_address = a.user_address AND m.folder = 'Draft'
                        ) AS drafted, (
                            SELECT COUNT(*) FROM messages AS m
                            WHERE m.user_id = a.user_id AND m.sender_address = a.user_address AND m.folder = 'Sent'
                        ) AS sent, (
                            SELECT COUNT(DISTINCT mr.message_id) FROM message_recipients AS mr
                            JOIN messages AS m ON m.message_id = mr.message_id
                            WHERE m.user_id = a.user_id AND mr.recipient_address = a.user_address
                        ) AS received, (
                            SELECT COUNT(DISTINCT mr.message_id) FROM message_recipients AS mr
                            JOIN messages AS m ON m.message_id = mr.message_id
                            WHERE m.user_id = a.user_id AND mr.recipient_address = a.user_address AND m.is_read = TRUE
                        ) AS read_count, (
                            SELECT COUNT(DISTINCT mr.message_id) FROM message_recipients AS mr
                            JOIN messages AS m ON m.message_id = mr.message_id
                            WHERE m.user_id = a.user_id AND mr.recipient_address = a.user_address AND m.is_read = FALSE
                        ) AS unread_count
                    FROM user_addresses AS a
                    LEFT JOIN user_addresses AS f ON f.address_id = a.forwarding_address_id
                    WHERE a.user_id = %s AND a.user_address LIKE %s ESCAPE '\\'
                    ORDER BY a.address_id;""",
                    (ctx.user.user_id, sql_pattern),
                )

            addresses = await cur.fetchall()

        if not addresses:
            return Status.OK, "No addresses."

        lines = []

        for (address_id, address, created_on, updated_on, forwarding_address, drafted, sent, received, read_count, unread_count) in addresses:
            lines.append( f"\n{address_id}\t{address}\t{created_on}\t{updated_on}\t{drafted}\t{sent}\t{received}\t{read_count}\t{unread_count}\t{forwarding_address or ''}")

        return Status.OK, f"ID    Address    Created    Updated    Drafted    Sent    Received    Read    Unread    Forwarding{''.join(lines)}"
    
    def use_cmd(self, ctx: Context, cmd_seq: list[str]) -> Result:
        if ctx.mode != Mode.AUTHENTICATED:
            return Status.ERR, "Authentication required"

        if len(cmd_seq) == 1:
            ctx.cwd = Folder.INBOX
            return Status.OK, f"The folder {Folder.INBOX} is now open"

        if len(cmd_seq) != 2:
            return Status.ERR, "Invalid Arguments"

        folder_name = cmd_seq[1]
        folder = Folder.from_string(folder_name)
        
        if folder is None:
            valid_options = ", ".join(member.value for member in Folder)
            return Status.ERR, f"'{folder_name}' is not a valid folder name\nValid folders (case-insensitive): {valid_options}"
        
        ctx.cwd = folder
        return Status.OK, f"The folder '{folder.value}' is now open"
    
    