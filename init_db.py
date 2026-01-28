from pathlib import Path
import sqlite3
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "warehouse.db"
SCHEMA_PATH = BASE_DIR / "schema.sql"


def init_db() -> None:
    schema_sql = SCHEMA_PATH.read_text(encoding="utf-8")
    with sqlite3.connect(DB_PATH) as connection:
        connection.executescript(schema_sql)


if __name__ == "__main__":
    init_db()
    print(f"Initialized database at {DB_PATH}")
