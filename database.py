import asyncio
import os
import aiomysql

class Database:
    def __init__(self):
        self.pool: aiomysql.Pool | None = None
    
    async def open(self):
        if self.pool is None or self.pool.closed:
            self.pool = await aiomysql.create_pool(
                host=os.environ["SQL_HOST"],
                user=os.environ["SQL_USER"],
                password=os.environ["SQL_PASSWORD"],
                db=os.environ["SQL_DB"],
            )
                
    async def close(self):
        if self.pool is None:
            return
        self.pool.close()
        await self.pool.wait_closed()
        self.pool = None
        
    async def test(self) -> bool:
        if self.pool is None or self.pool.closed:
            print(f"Failed to connect to MySQL: MySQL pool is closed")
            return False
        try:
            async with self.pool.acquire() as conn, conn.cursor() as cursor:
                await cursor.execute("SELECT VERSION();")
                ver, = await cursor.fetchone()
                print(f"Connected to MySQL version: {ver}")
                return True
        except Exception as e:
            print(f"Failed to connect to MySQL: {e}")
            return False