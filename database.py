import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import NullPool

# 🔹 Pegando a URL do banco de dados do ambiente
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:ZkwJXjxSeeRbgewdfgilpMmxXKUDpBDD@postgres.railway.internal:5432/lili")

# 🔍 Verificação para evitar erro de variável não definida
if not DATABASE_URL:
    raise ValueError("❌ ERRO: A variável de ambiente DATABASE_URL não está definida!")

# 🚀 Criando conexão com o banco de dados
engine = create_engine(DATABASE_URL, pool_pre_ping=True, poolclass=NullPool)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# 🔄 Garante que as tabelas do banco de dados sejam criadas/atualizadas automaticamente
def init_db():
    from models import Base  # Importação interna para evitar problemas de importação circular
    Base.metadata.create_all(bind=engine)

# Chamando a função ao iniciar o banco de dados
init_db()
