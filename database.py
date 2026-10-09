import os
import aiomysql
import os
import aiomysql
from contextlib import AsyncExitStack

class Database:
    def __init__(self):
        self.pool: aiomysql.Pool | None = None
        self._exit_stack: AsyncExitStack | None = None
    
    async def open(self):
        if self.pool is None or self.pool.closed:
            self._exit_stack = AsyncExitStack()
            
            # 1. Grab the context wrapper
            ctx = aiomysql.create_pool(
                host=os.environ["SQL_HOST"],
                user=os.environ["SQL_USER"],
                password=os.environ["SQL_PASSWORD"],
                db=os.environ["SQL_DB"],
            )
            self.pool = await self._exit_stack.enter_async_context(ctx)
                
    async def close(self):
        if self._exit_stack is None:
            return

        await self._exit_stack.aclose()
        self.pool = None
        self._exit_stack = None
        
    async def test(self) -> bool:
        if self.pool is None or self.pool.closed:
            print("Failed to connect to MySQL: MySQL pool is closed")
            return False
        try:
            async with self.pool.acquire() as conn, conn.cursor() as cursor:
                await cursor.execute("SELECT VERSION();")
                result = await cursor.fetchone()
                if result:
                    print(f"Connected to MySQL version: {result[0]}")
                    return True
                return False
        except Exception as e:
            print(f"Failed to connect to MySQL: {e}")
            return False
