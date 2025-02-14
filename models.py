from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

    provider = Column(String, nullable=True)  # Armazena 'google', 'apple', 'wechat' ou 'local'
    provider_id = Column(String, unique=True, nullable=True)  # ID único do usuário no provedor OAuth
