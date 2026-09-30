import os
import aiomysql
import aioimaplib

class Client:
    def __init__(self):
        self.pool: aiomysql.Pool | None = None
        self.mail: aioimaplib.IMAP4_SSL | None = None
        self.is_logged_in = False
    
    async def open(self) -> None:
        if self.pool is None or self.pool.closed:
            self.pool = await aiomysql.create_pool(
                host=os.environ["SQL_HOST"],
                user=os.environ["SQL_USER"],
                password=os.environ["SQL_PASSWORD"],
                db=os.environ["SQL_DB"]
            )
            print("Connected to MySQL")
    
        if self.mail is None:
            self.mail = aioimaplib.IMAP4_SSL(os.environ["IMAP_HOST"])
            await self.mail.wait_hello_from_server()
            print("Connected to Mail")
            
        print("Setup Complete")

    async def login(self, user: str, password: str) -> None:
        if self.is_logged_in:
            await self.logout()
            
        await self.mail.login(user, password)
        self.is_logged_in = True

    async def logout(self) -> None:
        try:
            await self.mail.logout()
        finally:
            self.is_logged_in = False

    async def close(self) -> None:
        try:
            self.pool.close()
            await self.pool.wait_closed()
        finally:
            self.pool = None

        await self.logout()
        self.mail = None
        
    