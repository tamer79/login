from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base, User, hash_password, verify_password
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer
from fastapi.openapi.utils import get_openapi
from authlib.integrations.requests_client import OAuth2Session
import os

# 🔐 Configuração do JWT
SECRET_KEY = "supersecreto"
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

# 🔐 Configuração para o Swagger UI exibir a autenticação JWT corretamente
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Minha API com JWT e Login Social",
        version="1.0.0",
        description="API segura com autenticação JWT, Refresh Token e Login Social",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }
    for path in openapi_schema["paths"].values():
        for method in path.values():
            method["security"] = [{"BearerAuth": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# 🔑 Configuração das credenciais OAuth (substitua pelas credenciais reais)
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "SUA_CLIENT_ID_GOOGLE")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "SUA_CLIENT_SECRET_GOOGLE")
APPLE_CLIENT_ID = os.getenv("APPLE_CLIENT_ID", "SUA_CLIENT_ID_APPLE")
APPLE_CLIENT_SECRET = os.getenv("APPLE_CLIENT_SECRET", "SUA_CLIENT_SECRET_APPLE")
WECHAT_CLIENT_ID = os.getenv("WECHAT_CLIENT_ID", "SUA_CLIENT_ID_WECHAT")
WECHAT_CLIENT_SECRET = os.getenv("WECHAT_CLIENT_SECRET", "SUA_CLIENT_SECRET_WECHAT")

# 🔗 URLs dos provedores OAuth
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
APPLE_AUTH_URL = "https://appleid.apple.com/auth/authorize"
APPLE_TOKEN_URL = "https://appleid.apple.com/auth/token"
WECHAT_AUTH_URL = "https://open.weixin.qq.com/connect/qrconnect"
WECHAT_TOKEN_URL = "https://api.weixin.qq.com/sns/oauth2/access_token"

# 📌 Modelos de Dados (Pydantic)
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class RefreshTokenRequest(BaseModel):
    refresh_token: str

# 🔄 Função para obter sessão do banco de dados
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 🔐 Função para gerar um Access Token
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 🔄 Função para gerar um Refresh Token
def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    refresh_token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return refresh_token

# 🔄 Rota para Login com Google
@app.get("/login/google")
def login_google():
    google = OAuth2Session(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, scope="openid email profile")
    authorization_url, state = google.create_authorization_url(GOOGLE_AUTH_URL, redirect_uri="http://127.0.0.1:8000/callback/google")
    return {"url": authorization_url}

@app.get("/callback/google")
def callback_google(code: str):
    google = OAuth2Session(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)
    token = google.fetch_token(GOOGLE_TOKEN_URL, authorization_response=f"http://127.0.0.1:8000/callback/google?code={code}")
    user_info = google.get("https://www.googleapis.com/oauth2/v3/userinfo").json()
    
    return {
        "email": user_info["email"],
        "name": user_info["name"],
        "picture": user_info["picture"],
        "access_token": token["access_token"]
    }

# 🔄 Rota para Login com Apple
@app.get("/login/apple")
def login_apple():
    apple = OAuth2Session(APPLE_CLIENT_ID, APPLE_CLIENT_SECRET, scope="name email")
    authorization_url, state = apple.create_authorization_url(APPLE_AUTH_URL, redirect_uri="http://127.0.0.1:8000/callback/apple")
    return {"url": authorization_url}

@app.get("/callback/apple")
def callback_apple(code: str):
    apple = OAuth2Session(APPLE_CLIENT_ID, APPLE_CLIENT_SECRET)
    token = apple.fetch_token(APPLE_TOKEN_URL, authorization_response=f"http://127.0.0.1:8000/callback/apple?code={code}")
    return {"access_token": token["access_token"]}

# 🔄 Rota para Login com WeChat
@app.get("/login/wechat")
def login_wechat():
    wechat = OAuth2Session(WECHAT_CLIENT_ID, WECHAT_CLIENT_SECRET)
    authorization_url, state = wechat.create_authorization_url(WECHAT_AUTH_URL, redirect_uri="http://127.0.0.1:8000/callback/wechat")
    return {"url": authorization_url}

@app.get("/callback/wechat")
def callback_wechat(code: str):
    wechat = OAuth2Session(WECHAT_CLIENT_ID, WECHAT_CLIENT_SECRET)
    token = wechat.fetch_token(WECHAT_TOKEN_URL, authorization_response=f"http://127.0.0.1:8000/callback/wechat?code={code}")
    return {"access_token": token["access_token"]}

# 🔄 Rota para renovar Access Token usando Refresh Token
@app.post("/refresh")
def refresh_token(request: RefreshTokenRequest):
    try:
        payload = jwt.decode(request.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")

        if username is None:
            raise HTTPException(status_code=401, detail="Refresh Token inválido")

        # Gerar um novo Access Token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        new_access_token = create_access_token(data={"sub": username}, expires_delta=access_token_expires)

        return {"access_token": new_access_token, "token_type": "bearer"}
    except JWTError:
        raise HTTPException(status_code=401, detail="Refresh Token inválido ou expirado")
