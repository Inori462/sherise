
import os
from pathlib import Path
import psycopg2

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not configured.")

schema_path = Path(__file__).parent / "database" / "she_rise_database.sql"

if not schema_path.exists():
    raise FileNotFoundError(f"SQL file not found: {schema_path}")

sql = schema_path.read_text(encoding="utf-8")

connection = None

try:
    connection = psycopg2.connect(
        DATABASE_URL,
        sslmode="require"
    )

    with connection.cursor() as cursor:
        cursor.execute(sql)

    connection.commit()
    print("Sherise database schema initialized successfully.")

except Exception as error:
    if connection:
        connection.rollback()

    print("Database initialization failed:", error)
    raise

finally:
    if connection:
        connection.close()
