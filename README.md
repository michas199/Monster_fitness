# Monster Fitness — Documentação Técnica

## Visão Geral da Arquitetura

```
                        ┌─────────────────────────────────────────────┐
                        │              CLIENTE (Browser)               │
                        │  HTML5 + CSS3 + Bootstrap 5 + JavaScript     │
                        │  Mobile-first · Barlow Condensed + Inter     │
                        └─────────────────┬───────────────────────────┘
                                          │  HTTP/80
                        ┌─────────────────▼───────────────────────────┐
                        │           PROXY REVERSO — Nginx              │
                        │  • Termina conexões HTTP                     │
                        │  • Serve arquivos estáticos (/static/)       │
                        │  • Rate limiting por IP (30r/m API)          │
                        │  • Headers de segurança (CSP, HSTS, etc.)    │
                        │  • Upstream para Flask                       │
                        └─────────────────┬───────────────────────────┘
                                          │  Rede interna Docker
                        ┌─────────────────▼───────────────────────────┐
                        │            API — Python Flask                │
                        │  • Roteamento de páginas (Jinja2)            │
                        │  • REST API JSON (/api/*)                    │
                        │  • Autenticação JWT (httponly cookie)        │
                        │  • Proteção CSRF (token rotativo)            │
                        │  • bcrypt para hashing de senhas             │
                        │  • flask-limiter (rate limit por endpoint)   │
                        │  • Gunicorn (4 workers em produção)          │
                        └─────────────────┬───────────────────────────┘
                                          │  mysql-connector
                        ┌─────────────────▼───────────────────────────┐
                        │         BANCO DE DADOS — MySQL 8.0           │
                        │  • usuarios   (perfil + credenciais)         │
                        │  • sessoes    (JTI revogáveis)               │
                        │  • csrf_tokens (rotação por uso)             │
                        │  • Evento SQL de limpeza automática          │
                        └─────────────────────────────────────────────┘
```

---

## Função de cada camada

### Frontend (HTML5 / CSS3 / Bootstrap 5 / JavaScript)
Responsável pela interface do usuário. Mobile-first por design — mais de 80% dos acessos
a academias são via celular. Usa Bootstrap 5 para grid responsivo, sem dependências pesadas.
Fonts: Barlow Condensed (display/títulos, peso visual forte) + Inter (corpo, legível).
JavaScript puro (vanilla), sem frameworks — mantém o bundle leve e o carregamento rápido.

### Proxy Reverso (Nginx)
Ponto de entrada de toda requisição. Responsabilidades:
- Serve arquivos estáticos direto do disco (zero Flask para CSS/JS/fontes)
- Termina conexões HTTP e faz keep-alive com o upstream Flask
- Aplica rate limiting por zona de IP (mais restrito em rotas de auth)
- Adiciona headers de segurança obrigatórios em todas as respostas
- Oculta detalhes da infraestrutura interna (server_tokens off)

### API — Backend (Python Flask)
Lógica de negócio e persistência. Responsabilidades:
- Renderiza templates Jinja2 para SSR (Server-Side Rendering)
- Expõe endpoints REST JSON em /api/*
- Gerencia sessões via JWT com JTI armazenado no banco (revogáveis)
- Valida CSRF token em todas as mutações (POST/PUT/DELETE)
- Realiza validação e sanitização de todos os inputs
- Hash de senhas com bcrypt (cost factor 12)
- Rate limiting adicional via flask-limiter

### Banco de Dados (MySQL 8.0)
Persistência relacional. Não é exposto externamente — apenas acessível pela rede Docker interna.
- `usuarios`: dados pessoais, hash bcrypt, plano, objetivo, soft delete
- `sessoes`: controle de JTI para revogação de tokens JWT
- `csrf_tokens`: tokens de uso único com expiração automática

---

## Segurança — Nível Intermediário

| Camada    | Controle                           | Implementação                        |
|-----------|------------------------------------|------------------------------------|
| Senhas    | Hash + salt                        | bcrypt cost=12                     |
| Sessões   | Token stateful revogável           | JWT + JTI no banco                 |
| CSRF      | Token rotativo de uso único        | Header X-CSRF-Token                |
| Rate limit| Por IP, por endpoint               | Nginx zones + flask-limiter        |
| Headers   | CSP, X-Frame, HSTS-ready           | Nginx + Flask after_request        |
| DB        | Rede isolada                       | Docker network interna             |
| Usuários  | Soft delete                        | ativo=0, email sufixado            |
| Inputs    | Sanitização + validação            | sanitizar() + regex                |

---

## Como rodar

### Pré-requisitos
- Docker Engine 24+
- Docker Compose v2

### Subir o ambiente

```bash
# Clonar/entrar na pasta
cd monster-fitness

# Gerar secrets (importante em produção!)
cp .env.example .env
# Edite .env com senhas fortes

# Subir todos os serviços
docker compose up -d

# Ver logs
docker compose logs -f api

# Verificar health
curl http://localhost/health
```

### Estrutura de arquivos

```
monster-fitness/
├── app.py                  # Backend Flask principal
├── requirements.txt        # Dependências Python
├── Dockerfile              # Imagem da API
├── docker-compose.yml      # Orquestração completa
├── docker/
│   ├── nginx.conf          # Configuração do proxy reverso
│   └── init.sql            # DDL inicial do MySQL
├── templates/
│   ├── index.html          # Página principal
│   ├── login.html          # Autenticação
│   ├── cadastro.html       # Registro (3 steps)
│   ├── dashboard.html      # Área do aluno
│   └── matricula.html      # Gerenciamento do plano
└── static/
    ├── css/main.css        # Design system Monster Fitness
    └── js/main.js          # Scripts do frontend
```

### Variáveis de ambiente

```env
SECRET_KEY=          # Flask secret (mínimo 32 chars aleatórios)
JWT_SECRET=          # JWT signing secret
JWT_EXPIRY_HOURS=8
DB_PASSWORD=         # Senha do usuário MySQL
DB_ROOT_PASSWORD=    # Senha root do MySQL
```

---

## Endpoints da API

| Método | Rota                  | Auth | Descrição                       |
|--------|-----------------------|------|---------------------------------|
| GET    | /api/csrf-token       | ✗    | Gera token CSRF                 |
| POST   | /api/cadastro         | ✗    | Cria nova conta                 |
| POST   | /api/login            | ✗    | Autenticação                    |
| GET    | /api/me               | ✓    | Dados do usuário logado         |
| PUT    | /api/me/update        | ✓    | Atualiza perfil                 |
| POST   | /api/logout           | ✓    | Revoga sessão JWT               |
| DELETE | /api/delete-account   | ✓    | Soft delete da conta            |
| GET    | /health               | ✗    | Health check (Nginx/DB)         |

---

## Análise de tráfego — Wireshark

Para capturar o tráfego da aplicação com Wireshark:

```bash
# Descobrir a rede Docker criada
docker network ls
docker network inspect monster-fitness_mf_net

# Capturar interface da rede Docker
wireshark -i br-<HASH_DA_REDE> -f "port 80 or port 5000 or port 3306"
```

Filtros úteis no Wireshark:
- `http` — ver requisições HTTP entre Nginx e cliente
- `tcp.port == 5000` — tráfego interno Nginx → Flask
- `tcp.port == 3306` — consultas MySQL (rede interna)
- `http.request.method == "POST"` — ver submissões de formulário

> ⚠️ Em produção use HTTPS (porta 443 com TLS). O Wireshark só mostrará tráfego
> criptografado — configure o Nginx com certificado Let's Encrypt (certbot).
