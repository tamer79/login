from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from typing import Optional
from jose import JWTError, jwt
from starlette.middleware.cors import CORSMiddleware

# Configuração do FastAPI
app = FastAPI()

# Configuração do CORS para permitir conexões externas
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permite todas as origens (troque por domínios específicos em produção)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuração de segurança para autenticação
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
SECRET_KEY = "sua_chave_secreta"  # Substitua pela chave secreta real usada na API
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Simulação de banco de dados com usuário fixo e senha hasheada corretamente
fake_users_db = {}

def create_default_user():
    username = "tamer79"
    email = "tamer79@email.com"
    password = "e2evfMBeP"  # Senha real

    if username not in fake_users_db:
        fake_users_db[username] = {
            "username": username,
            "email": email,
            "hashed_password": pwd_context.hash(password)
        }

create_default_user()  # Adiciona um usuário ao iniciar a API

# Modelos de resposta da API
class UserResponse(BaseModel):
    username: str
    email: str

class UserLogin(BaseModel):
    username: str  # Pode ser username ou email
    password: str

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

# Função para verificar senha
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Função para criar token JWT
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 🔹 Correção no endpoint de login para aceitar username ou email
@app.post("/login", response_model=Token)
def login(user: UserLogin):
    user_data = None

    # 🔹 Verifica se o usuário forneceu username ou e-mail
    for key, value in fake_users_db.items():
        if user.username == value["username"] or user.username == value["email"]:
            user_data = value
            break

    if not user_data:
        raise HTTPException(status_code=401, detail="Usuário não encontrado")

    # Debug: Verificar as senhas no log
    print(f"Senha fornecida: {user.password}")
    print(f"Senha armazenada (hash): {user_data['hashed_password']}")

    if not verify_password(user.password, user_data["hashed_password"]):
        raise HTTPException(status_code=401, detail="Usuário ou senha incorretos")

    access_token = create_access_token(data={"sub": user_data["username"]})
    refresh_token = create_access_token(data={"sub": user_data["username"]}, expires_delta=timedelta(days=7))

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

# Endpoint para obter informações do usuário autenticado
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

# Endpoint de refresh token
@app.post("/refresh-token", response_model=Token)
def refresh_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")

        new_access_token = create_access_token(data={"sub": username})
        new_refresh_token = create_access_token(data={"sub": username}, expires_delta=timedelta(days=7))

        return {"access_token": new_access_token, "refresh_token": new_refresh_token, "token_type": "bearer"}
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")

# Endpoint de logout (apenas simbólico, pois tokens JWT não podem ser revogados)
@app.post("/logout")
def logout():
    return {"message": "Logout realizado com sucesso"}

# Endpoint de teste da API
@app.get("/")
def home():
    return {"message": "API rodando corretamente!"}
