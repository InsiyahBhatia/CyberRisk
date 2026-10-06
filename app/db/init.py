"""python -m app.db.init"""
from app.db.session import get_engine, init_schema

if __name__ == "__main__":
    init_schema(get_engine())
    print("Database initialised.")
