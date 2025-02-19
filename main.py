from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from typing import Optional, Union
from starlette.middleware.cors import CORSMiddleware
from authlib.integrations.starlette_client import OAuth
from starlette.responses import RedirectResponse
import os

# Configuração do FastAPI
app = FastAPI()

# Configuração do CORS para permitir conexões externas
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuração de segurança para autenticação
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
SECRET_KEY = "sua_chave_secreta"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Simulação de banco de dados com usuário fixo e senha hasheada corretamente
fake_users_db = {}

def create_default_user():
    username = "tamer79"
    email = "tamer79@gmail.com"
    password = "e2evfMBeP"
    
    if username not in fake_users_db:
        fake_users_db[username] = {
            "username": username,
            "email": email,
            "hashed_password": pwd_context.hash(password)
        }

create_default_user()

# Modelos de resposta da API
class UserResponse(BaseModel):
    username: str
    email: str

class UserLogin(BaseModel):
    login: str  # Aceita tanto username quanto email
    password: str

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

# Funções de autenticação
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 📌 Atualização: Login agora reconhece usuários registrados
@app.post("/login", response_model=Token)
def login(user: UserLogin):
    user_data = fake_users_db.get(user.login)  # Buscar usuário pelo apelido
    
    # Se não encontrar pelo apelido, buscar pelo e-mail
    if not user_data:
        for key, value in fake_users_db.items():
            if user.login == value["email"]:
                user_data = value
                break
    
    # Se usuário não for encontrado
    if not user_data:
        raise HTTPException(status_code=401, detail="Usuário não encontrado")
    
    # Verificar senha
    if not verify_password(user.password, user_data["hashed_password"]):
        raise HTTPException(status_code=401, detail="Usuário ou senha incorretos")
    
    # Criar tokens JWT
    access_token = create_access_token(data={"sub": user_data["username"]})
    refresh_token = create_access_token(data={"sub": user_data["username"]}, expires_delta=timedelta(days=7))
    
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@app.get("/me", response_model=UserResponse)
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        
        if username not in fake_users_db:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
        
        user_data = fake_users_db[username]
        return UserResponse(username=user_data["username"], email=user_data["email"])
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")

# Autenticação com Google, Apple e WeChat
oauth = OAuth()
oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    access_token_url="https://oauth2.googleapis.com/token",
    client_kwargs={"scope": "openid email profile"},
)

oauth.register(
    name='apple',
    client_id=os.getenv("APPLE_CLIENT_ID"),
    client_secret=os.getenv("APPLE_CLIENT_SECRET"),
    authorize_url="https://appleid.apple.com/auth/authorize",
    access_token_url="https://appleid.apple.com/auth/token",
    client_kwargs={"scope": "name email"},
)

oauth.register(
    name='wechat',
    client_id=os.getenv("WECHAT_CLIENT_ID"),
    client_secret=os.getenv("WECHAT_CLIENT_SECRET"),
    authorize_url="https://open.weixin.qq.com/connect/oauth2/authorize",
    access_token_url="https://api.weixin.qq.com/sns/oauth2/access_token",
    client_kwargs={"scope": "snsapi_userinfo"},
)

@app.get("/login/google")
async def login_google(request: Request):
    redirect_uri = request.url_for("auth_google")
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/google")
async def auth_google(request: Request):
    token = await oauth.google.authorize_access_token(request)
    user_info = await oauth.google.parse_id_token(request, token)
    return {"email": user_info["email"], "name": user_info["name"]}

@app.get("/login/apple")
async def login_apple(request: Request):
    redirect_uri = request.url_for("auth_apple")
    return await oauth.apple.authorize_redirect(request, redirect_uri)

@app.get("/auth/apple")
async def auth_apple(request: Request):
    token = await oauth.apple.authorize_access_token(request)
    return token

@app.get("/login/wechat")
async def login_wechat(request: Request):
    redirect_uri = request.url_for("auth_wechat")
    return await oauth.wechat.authorize_redirect(request, redirect_uri)

@app.get("/auth/wechat")
async def auth_wechat(request: Request):
    token = await oauth.wechat.authorize_access_token(request)
    return token

# 📌 Rota para registrar um novo usuário
class UserCreate(BaseModel):
    apelido: str
    email: EmailStr
    senha: str

@app.post("/register")
def register_user(user: UserCreate):
    errors = []

    # Verificar se o apelido já existe
    if user.apelido in fake_users_db:
        errors.append("Apelido já registrado")

    # Verificar se o e-mail já existe
    for value in fake_users_db.values():
        if value["email"] == user.email:
            errors.append("E-mail já registrado")
            break  # Se o e-mail já existe, não precisa continuar verificando

    # Se houver erros, retorna a lista de problemas
    if errors:
        raise HTTPException(status_code=400, detail=", ".join(errors))

    # Criar novo usuário com senha criptografada
    hashed_password = pwd_context.hash(user.senha)
    new_user = {
        "username": user.apelido,
        "email": user.email,
        "hashed_password": hashed_password
    }
    
    fake_users_db[user.apelido] = new_user

    return {"message": "Usuário registrado com sucesso"}
