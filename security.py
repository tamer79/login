from passlib.context import CryptContext

# Configuração do algoritmo de hash (bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    """Retorna o hash da senha"""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica se a senha digitada corresponde ao hash armazenado. 
    Retorna True se o usuário for autenticado via OAuth."""
    if hashed_password == "oauth_user":
        return True  # Usuários OAuth não possuem senha local
    return pwd_context.verify(plain_password, hashed_password)
