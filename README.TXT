Iniciar o servidor pelo terminal do VS Code: uvicorn main:app --reload
Iniciar o serviço Postgres no terminal do MacOS: brew services start postgresql
URL Externa do banco de dados Postgres: postgresql://postgres:ZkwJXjxSeeRbgewdfgilpMmxXKUDpBDD@postgres.railway.internal:5432/lili


# Documentação da API

## Visão Geral
Esta API é desenvolvida utilizando **FastAPI** e **SQLAlchemy**, com autenticação baseada em JWT. Seu principal objetivo é fornecer um sistema de login seguro e gerenciar usuários.

## Tecnologias Utilizadas
- **FastAPI**: Framework para criação de APIs.
- **SQLAlchemy**: ORM para interação com o banco de dados PostgreSQL.
- **bcrypt**: Para hashing de senhas.
- **JWT (JSON Web Token)**: Para autenticação de usuários.
- **Uvicorn**: Servidor ASGI para execução da API.

## Modelos de Dados
### User
Tabela `users` com os seguintes campos:
- **id** (Integer, chave primária)
- **username** (String, único, obrigatório)
- **email** (String, único, obrigatório)
- **hashed_password** (String, obrigatório)

## Endpoints
### Registro de Usuário
**POST /register**
- **Descrição:** Cria um novo usuário.
- **Entrada:** JSON com `username`, `email` e `password`.
- **Saída:** Detalhes do usuário criado (exceto senha).

### Autenticação de Usuário
**POST /token**
- **Descrição:** Gera um token JWT para autenticação.
- **Entrada:** JSON com `username` e `password`.
- **Saída:** Token JWT válido para acesso a endpoints protegidos.

### Obtém Dados do Usuário Logado
**GET /users/me**
- **Descrição:** Retorna os detalhes do usuário autenticado.
- **Requer:** Token JWT válido no cabeçalho `Authorization`.
- **Saída:** JSON com detalhes do usuário.

## Banco de Dados
A API se conecta ao PostgreSQL por meio da URL definida na variável de ambiente `DATABASE_URL`.

## Instalação e Execução
1. Instalar dependências: `pip install -r requirements.txt`
2. Executar o servidor: `uvicorn main:app --reload`
3. API disponível em: `http://127.0.0.1:8000`

## Considerações Finais
A API segue padrões modernos de segurança e boas práticas de desenvolvimento. Possui suporte para autenticação baseada em JWT e armazenamento seguro de senhas.

