from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
from models import User  # ✅ Importando o modelo User do novo arquivo models.py
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer
from security import hash_password, verify_password
import os
import psycopg2

# 🔐 Configuração do JWT
SECRET_KEY = os.getenv("SECRET_KEY", "supersecreto")  # Pegando do ambiente
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Tempo de expiração do Access Token
REFRESH_TOKEN_EXPIRE_DAYS = 7  # Tempo de expiração do Refresh Token

# 🚀 Criando a aplicação FastAPI
app = FastAPI()

# 🔄 Criando as tabelas no banco de dados
Base.metadata.create_all(bind=engine)

# ✅ Configuração do OAuth2 com Bearer Token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# 🚫 Blacklist de Tokens Revogados
revoked_tokens = set()


# 📌 Modelos Pydantic para login e registro
class UserCreate(BaseModel):
    username: str
    email: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


# 🔧 Função para obter a conexão do banco
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# 🔐 Rota de Registro de Usuário
@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Usuário já existe")

    hashed_password = hash_password(user.password)
    new_user = User(username=user.username, email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "Usuário registrado com sucesso"}


# 🔐 Rota de Login e geração de token JWT
@app.post("/login", response_model=Token)
def login(user: UserLogin, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == user.username).first()
    if not existing_user or not verify_password(user.password, existing_user.hashed_password):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    access_token = jwt.encode(
        {"sub": user.username, "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)},
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return {"access_token": access_token, "token_type": "bearer"}


# 🔍 Endpoint para testar conexão ao banco de dados 🔍
DATABASE_URL = os.getenv("DATABASE_URL")

@app.get("/test-db")
def test_db():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        conn.close()
        return {"status": "✅ Conexão bem-sucedida ao PostgreSQL!"}
    except Exception as e:
        return {"status": "❌ Erro ao conectar", "error": str(e)}
