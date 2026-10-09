import asyncio
import random
import ssl

from pearlescent_server_v4 import PearlescentServer, ServerStatus
from input_frame import InputFrame, Operations
from output_frame import OutputFrame

client_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
client_ssl_context.load_verify_locations(cafile="cert.pem")

host = '127.0.0.1'
port = 8110

async def simulate_client(client_id: int):
    try:
        # 1. Connect to secure test port
        reader, writer = await asyncio.open_connection(host, port, ssl=client_ssl_context)
        print(f"[Client {client_id}] Connected.")

        ssl_obj = writer.get_extra_info('ssl_object')
        if ssl_obj is not None:
            cipher, tls_version, secret_bits = ssl_obj.cipher()
            print(f"[Client {client_id}] VERIFIED SECURE: Connected via {tls_version} using {cipher} ({secret_bits} bits)")
        else:
            print(f"[Client {client_id}] WARNING: Connection is running in PLAINTEXT over port {port}!")

        # 2. Consume Initial Greeting Frame
        out = await OutputFrame.from_wire(reader)
        print(f"[Client {client_id}] Received: {out.status.name} {out.entries}")

        await asyncio.sleep(random.randint(5, 15))

        # 3. Request Clean Disconnect
        await InputFrame(1, Operations.DC).to_wire(writer)

        # 4. Consume Disconnect Acknowledgment
        out = await OutputFrame.from_wire(reader)
        print(f"[Client {client_id}] Received: {out.status.name} {out.entries}")
        
        print(f"[Client {client_id}] Closing connection.")
        writer.close()
        await writer.wait_closed()

    except Exception as e:
        print(f"[Client {client_id}] Error: {e}")

async def main():
    server = PearlescentServer()
    task = asyncio.create_task(server.start())

    while server.status != ServerStatus.ONLINE:
        await asyncio.sleep(0.01)
    
    print("Server is ready. Starting client simulation...")
    await asyncio.gather(*(simulate_client(i) for i in range(5)))
    
    await server.stop("Automatic Shutdown", 10)
    task.cancel()

if __name__ == '__main__':
    asyncio.run(main())
