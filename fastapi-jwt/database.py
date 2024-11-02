from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


DATABASE_URL = "postgresql://postgres:root@localhost:5432/users"

ENGINE = create_engine(DATABASE_URL)

BASE = declarative_base()

SessionLocal = sessionmaker(bind=ENGINE, expire_on_commit=False)