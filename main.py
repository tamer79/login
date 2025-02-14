from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
from models import User
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer
from security import hash_password, verify_password
import os
import psycopg2

# 🔐 Configuração do JWT
SECRET_KEY = os.getenv("SECRET_KEY", "supersecreto")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Token de acesso expira em 30 minutos
REFRESH_TOKEN_EXPIRE_DAYS = 7  # Refresh Token expira em 7 dias

# 🚀 Criando a aplicação FastAPI
app = FastAPI()

# 🔄 Criando as tabelas no banco de dados
Base.metadata.create_all(bind=engine)

# ✅ Configuração do OAuth2 com Bearer Token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# 🚫 Lista de Tokens Revogados (Blacklist)
revoked_tokens = set()


# 📌 Modelos Pydantic
class UserCreate(BaseModel):
    username: str
    email: str
    password: str


class UserLogin(BaseModel):
    username: str  # Mantendo o nome original, mas agora pode ser username ou email
    password: str


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


# 🔧 Função para obter conexão do banco
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# 🔐 Função para criar tokens JWT
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    to_encode["exp"] = datetime.utcnow() + expires_delta
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


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


# 🔐 Função para autenticar usuário por username ou email
def authenticate_user(db: Session, login: str, password: str):
    user = db.query(User).filter((User.username == login) | (User.email == login)).first()

    if not user or not verify_password(password, user.hashed_password):
        return None
    return user


# 🔐 Rota de Login com Geração de Tokens (Agora aceita username ou email)
@app.post("/login", response_model=Token)
def login(user: UserLogin, db: Session = Depends(get_db)):
    existing_user = authenticate_user(db, user.username, user.password)  # Alterado para aceitar username ou email

    if not existing_user:
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    access_token = create_access_token({"sub": existing_user.username}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_access_token({"sub": existing_user.username}, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


# 🔄 Rota para Atualizar o Token de Acesso
@app.post("/refresh-token", response_model=Token)
def refresh_token(request: RefreshTokenRequest):
    try:
        payload = jwt.decode(request.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")

        if request.refresh_token in revoked_tokens:
            raise HTTPException(status_code=401, detail="Refresh token inválido")

        # Criando novos tokens
        new_access_token = create_access_token({"sub": username}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        new_refresh_token = create_access_token({"sub": username}, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))

        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer"
        }

    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")


# 🚪 Rota para Logout (Revoga Tokens)
@app.post("/logout")
def logout(request: RefreshTokenRequest):
    revoked_tokens.add(request.refresh_token)
    return {"message": "Logout realizado com sucesso!"}


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
