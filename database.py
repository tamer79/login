from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext

# URL de conexão com o banco de dados
DATABASE_URL = "postgresql://postgres:JIIFhrzWyZdvrzOYGdpjdhVQUbALscIf@junction.proxy.rlwy.net:47032/login"

# Criando a conexão com o banco de dados
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Contexto de criptografia para hash de senhas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Definição da tabela de usuários
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

# Função para gerar hash de senha
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

# Função para verificar se a senha fornecida está correta
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)
