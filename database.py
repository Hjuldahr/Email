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
            
        async with self.pool.acquire() as conn, conn.cursor() as cur:
            await cur.execute("SELECT VERSION();")
            ver, = await cur.fetchone()
            print(f"Connected to MySQL version: {ver}")
                
    async def close(self):
        self.pool.close()
        await self.pool.wait_closed()
        self.pool = None
        
    async def test(self):
        await self.open()
        await self.close()
        
if __name__ == '__main__':
    test_db = Database()
    asyncio.run(test_db.test())
    
    # <aiomysql.connection.Connection>