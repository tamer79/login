from passlib.context import CryptContext

# Configuração do algoritmo de hash (bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    """Retorna o hash da senha"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica se a senha digitada corresponde ao hash armazenado"""
    return pwd_context.verify(plain_password, hashed_password)