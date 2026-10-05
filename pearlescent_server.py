import asyncio
import uuid
from database import Database
from input_frame import InputFrame, Operations
from other import SessionCoordinator, SessionMode
from output_frame import OutputFrame, Status

class ProtocolError(Exception): ...

class PearlescentServer:
    HOST = "127.0.0.1"
    UNSECURE_PORT = 25
    SECURE_PORT = 25
    POP3_PORT = 110

    PROTO_VERSION = 1
    NAMESPACE = uuid.UUID("99b00d33-11b3-4f37-bd46-18a624fcfe74")

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

    async def start(self):
        await self.db.open()

        if self.unsecure_sock is None:
            self.unsecure_sock = await asyncio.start_server(
                self._unsecure_listen, self.HOST, self.UNSECURE_PORT
            )
        if self.secure_sock is None:
            self.secure_sock = await asyncio.start_server(
                self._secure_listen, self.HOST, self.SECURE_PORT
            )    

        async with self.unsecure_sock, self.secure_sock:
            await asyncio.gather(
                self.unsecure_sock.serve_forever(),
                self.secure_sock.serve_forever()
            )

    async def stop(self):
        for sock in (self.unsecure_sock, self.secure_sock):
            if sock is None:
                continue
            sock.close()
            sock.close_clients()
            await sock.wait_closed()
            
        self.unsecure_sock = None
        self.secure_sock = None

        await self.db.close()
        
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
        
        try:
            conn = await self.db.pool.acquire()
            ses = SessionCoordinator(reader, writer, conn)
            
            await self._write_raw(writer, self.out_greeting)
            
            while True:
                await ses.read()
                
                if ses.input_frame is None:
                    continue

                match ses.input_frame.operation:
                    case Operations.PING:
                        await self._write_raw(writer, self.out_ping)
                    
                    case Operations.REGISTER:
                        self.register_op(ses)
                        
                    case _:
                        await self._write_raw(writer, self.out_invalid_cmd)

        except asyncio.IncompleteReadError as e:
            print(f"Connection ended: {e.partial!r}")
        except asyncio.InvalidStateError as e:
            print(f"Invalid state: {e}")
        finally:
            await ses.cleanup() # handles IO cleanup
            
    async def register_op(self, ses: SessionCoordinator) -> None:
        if ses.mode != SessionMode.CONNECTED:
            return
        
        async with ses.conn.cursor() as cursor:
            ...