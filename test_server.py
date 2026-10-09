import asyncio
import signal

from old.experimental import PearlescentServer

async def main():
    server = PearlescentServer()
    
    try:
        # 1. Initialize the server sockets
        await server.start()
        print("Server initialized.")
        
    except (asyncio.CancelledError, KeyboardInterrupt):
        print("\nShutdown signal caught...")
    finally:
        # 3. Guaranteed cleanup when serve_forever breaks or Ctrl+C is pressed
        print("Executing automatic shutdown...")
        await server.stop("Automatic Shutdown", 10)
        print("Server stopped cleanly.")

if __name__ == '__main__':
    asyncio.run(main())