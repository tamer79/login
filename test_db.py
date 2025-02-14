import psycopg2
import os

DATABASE_URL = "postgresql://postgres:ZkwJXjxSeeRbgewdfgilpMmxXKUDpBDD@postgres.railway.internal:5432/railway"

try:
    conn = psycopg2.connect(DATABASE_URL)
    print("✅ Conexão bem-sucedida ao PostgreSQL!")
    conn.close()
except Exception as e:
    print("❌ Erro ao conectar ao banco de dados:", e)
