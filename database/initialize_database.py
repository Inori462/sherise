
import getpass
from pathlib import Path
import psycopg2

DATABASE_URL = getpass.getpass(
    "Paste your Render External Database URL: "
).strip()

if not DATABASE_URL:
    raise RuntimeError("Database URL is required.")

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

    print("Sherise database initialized successfully!")

except Exception as error:
    if connection:
        connection.rollback()

    print("Database initialization failed:", error)
    raise

finally:
    if connection:
        connection.close()
