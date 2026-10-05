import asyncio
import logging
import os
import re
from typing import Any, Callable, Coroutine, TypeVar
import aiomysql
from pymysql.err import OperationalError, InternalError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DatabaseRepairCompanion")

T = TypeVar("T")

class DatabaseRepairCompanion:
    """
    A self-healing companion that wraps an aiomysql Database context.
    Safely catches database failures, recovers connection pools, clears 
    deadlocks, and optimized/rebuilt damaged InnoDB tables.
    """
    def __init__(self, db_instance):
        self.db = db_instance
        # Map of explicit MySQL error codes to handling routines
        self.FAULT_HANDLERS: dict[int, Callable[[int, str, tuple], Coroutine[Any, Any, Any]]] = {
            2006: self._handle_connection_fault,  # MySQL server has gone away
            2013: self._handle_connection_fault,  # Lost connection during query
            1213: self._handle_deadlock_fault,    # Transaction deadlock
            1194: self._handle_table_fault,       # Table is marked as crashed
            1030: self._handle_table_fault,       # Got error from storage engine
        }

    async def execute_safely(self, query: str, params: tuple | None = None, retries: int = 3) -> list[dict] | None:
        """
        Executes a query through the pool. If a handled MySQL fault surfaces, 
        intercepts execution, resolves the issue, and retries safely.
        """
        for attempt in range(1, retries + 1):
            try:
                # Ensure the pool is active before running queries
                await self.db.open()
                
                async with self.db.pool.acquire() as conn:
                    # Using DictCursor so rows are returned mapped to schema keys
                    async with conn.cursor(aiomysql.DictCursor) as cur:
                        await cur.execute(query, params)
                        return await cur.fetchall()

            except (OperationalError, InternalError) as e:
                error_code = e.args[0] if e.args else None
                logger.warning(f"[Attempt {attempt}/{retries}] Database fault intercepted: {e}")

                if error_code in self.FAULT_HANDLERS and attempt < retries:
                    # Route to the dedicated auto-repair sub-routine
                    handler = self.FAULT_HANDLERS[error_code]
                    await handler(error_code, query, params)
                    continue # Fault repaired successfully; retry loop
                else:
                    logger.error(f"Critical unresolvable error database error: {e}")
                    raise e
            except Exception as e:
                logger.error(f"Non-database error encountered: {e}")
                raise e

    async def _handle_connection_fault(self, error_code: int, query: str, params: tuple | None):
        """Strategy: Safely tears down and hot-swaps a dropped or stale connection pool."""
        logger.info("🔧 Strategy Applied: Connection dropped. Rebuilding the aiomysql pool context...")
        await self.db.close()
        await self.db.open()

    async def _handle_deadlock_fault(self, error_code: int, query: str, params: tuple | None):
        """Strategy: Backs off exponentially during transaction locks to let other processes clear."""
        logger.info("🔧 Strategy Applied: Deadlock detected. Initiating brief backoff pause...")
        await asyncio.sleep(1.5)

    async def _handle_table_fault(self, error_code: int, query: str, params: tuple | None):
        """Strategy: Isolates corrupted schemas and triggers an online InnoDB table optimization."""
        table_name = self._parse_table_name(query)
        if not table_name:
            logger.error("Could not isolate a target table name for structural optimization.")
            return

        logger.info(f"🔧 Strategy Applied: Structural fault found on `{table_name}`. Triggering online repair...")
        
        # Open an isolated management connection completely outside the broken pool loop
        try:
            admin_conn = await aiomysql.connect(
                host=os.environ["SQL_HOST"],
                user=os.environ["SQL_USER"],
                password=os.environ["SQL_PASSWORD"],
                db=os.environ["SQL_DB"],
            )
            async with admin_conn.cursor() as cur:
                # InnoDB requires OPTIMIZE TABLE rather than REPAIR TABLE 
                # This rebuilds indexes and reclaims fragmented tablespaces.
                await cur.execute(f"OPTIMIZE TABLE `{table_name}`;")
                repair_status = await cur.fetchall()
                logger.info(f"Table optimization pipeline results for '{table_name}': {repair_status}")
            admin_conn.close()
        except Exception as admin_err:
            logger.critical(f"Administrative repair pipeline failed: {admin_err}")

    def _parse_table_name(self, query: str) -> str | None:
        """Parses standard queries to pinpoint which table is throwing errors."""
        match = re.search(r"\b(?:FROM|UPDATE|INSERT\s+INTO|JOIN)\s+`?([a-zA-Z0-9_]+)`?", query, re.IGNORECASE)
        return match.group(1) if match else None