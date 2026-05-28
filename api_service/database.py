import os
import toml
from databases import Database
from sqlalchemy import create_engine, MetaData

# Function to read database config from flyway.toml
def get_database_url():
    try:
        # Try to find flyway.toml in parent directory structure
        current_dir = os.path.dirname(os.path.abspath(__file__))
        flyway_path = os.path.join(current_dir, "..", "database", "flyway.toml")
        
        if not os.path.exists(flyway_path):
            # Fallback for dev environment or if path is different
            return os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:test@123456@192.168.1.121:3778/argus")
            
        config = toml.load(flyway_path)
        env = config.get("environments", {}).get("default", {})
        
        url = env.get("url", "")
        user = env.get("user", "")
        password = env.get("password", "")
        
        # Convert JDBC URL to SQLAlchemy URL
        # jdbc:postgresql://host:port/dbname -> postgresql+asyncpg://user:password@host:port/dbname
        if url.startswith("jdbc:postgresql://"):
            url = url.replace("jdbc:postgresql://", "")
            return f"postgresql+asyncpg://{user}:{password}@{url}"
            
        return os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:test@123456@192.168.1.121:3778/argus")
    except Exception as e:
        print(f"Error reading flyway config: {e}")
        return os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:test@123456@192.168.1.121:3778/argus")

DATABASE_URL = get_database_url()

# `databases` 0.9.0 ignores ?sslmode= in the URL when using the asyncpg backend,
# so prod connections to Azure PG (which enforces TLS via pg_hba.conf) silently
# arrive non-encrypted and are rejected. When the URL asks for SSL, pass it as
# an explicit asyncpg kwarg. Local dev URLs without sslmode keep their behavior.
_db_kwargs = {"ssl": "require"} if "sslmode=require" in DATABASE_URL else {}
database = Database(DATABASE_URL, **_db_kwargs)
metadata = MetaData()
