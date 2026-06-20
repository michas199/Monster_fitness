"""
Monster Fitness — Backend Flask
Segurança: bcrypt, JWT, CSRF, rate limiting, headers de segurança
"""

import os
import re
import secrets
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
import bcrypt
from flask import (Flask, render_template, request, jsonify,
                   redirect, url_for, make_response, g)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import mysql.connector
from mysql.connector import Error as MySQLError

# ─── CONFIG ───────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['JWT_SECRET']  = os.environ.get('JWT_SECRET',  secrets.token_hex(32))
app.config['JWT_EXPIRY_HOURS'] = int(os.environ.get('JWT_EXPIRY_HOURS', 8))

DB_CONFIG = {
    'host':     os.environ.get('DB_HOST',     'db'),
    'port':     int(os.environ.get('DB_PORT', 3306)),
    'database': os.environ.get('DB_NAME',     'monsterfitness'),
    'user':     os.environ.get('DB_USER',     'mf_user'),
    'password': os.environ.get('DB_PASSWORD', 'mf_secret'),
    'charset':  'utf8mb4',
    'autocommit': False,
}

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["300 per day", "60 per hour"],
    storage_uri="memory://",
)

# ─── BANCO DE DADOS ───────────────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        try:
            g.db = mysql.connector.connect(**DB_CONFIG)
        except MySQLError as e:
            log.error("DB connection failed: %s", e)
            g.db = None
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db and db.is_connected():
        db.close()

def init_db():
    """Cria tabelas se não existirem."""
    ddl = """
    CREATE TABLE IF NOT EXISTS usuarios (
        id           INT AUTO_INCREMENT PRIMARY KEY,
        nome         VARCHAR(120) NOT NULL,
        email        VARCHAR(180) NOT NULL UNIQUE,
        cpf          VARCHAR(14)  NOT NULL UNIQUE,
        nascimento   DATE,
        telefone     VARCHAR(20),
        senha_hash   VARCHAR(255) NOT NULL,
        plano        ENUM('mensal','trimestral','semestral','anual','premium') DEFAULT 'mensal',
        objetivo     VARCHAR(30),
        nivel        VARCHAR(20),
        ativo        TINYINT(1) DEFAULT 1,
        criado_em    DATETIME DEFAULT CURRENT_TIMESTAMP,
        atualizado_em DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

    CREATE TABLE IF NOT EXISTS sessoes (
        id           INT AUTO_INCREMENT PRIMARY KEY,
        usuario_id   INT NOT NULL,
        jti          VARCHAR(64) NOT NULL UNIQUE,
        criado_em    DATETIME DEFAULT CURRENT_TIMESTAMP,
        expira_em    DATETIME NOT NULL,
        revogado     TINYINT(1) DEFAULT 0,
        FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

    CREATE TABLE IF NOT EXISTS csrf_tokens (
        token     VARCHAR(64) PRIMARY KEY,
        criado_em DATETIME DEFAULT CURRENT_TIMESTAMP,
        usado     TINYINT(1) DEFAULT 0
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    try:
        db = mysql.connector.connect(**DB_CONFIG)
        cur = db.cursor()
        for stmt in ddl.strip().split(';'):
            stmt = stmt.strip()
            if stmt:
                cur.execute(stmt)
        db.commit()
        cur.close()
        db.close()
        log.info("Database initialized.")
    except MySQLError as e:
        log.error("init_db error: %s", e)

# ─── HELPERS JWT ──────────────────────────────────────────────────────────────
def gerar_token(user_id: int) -> str:
    jti = secrets.token_hex(16)
    exp = datetime.now(timezone.utc) + timedelta(hours=app.config['JWT_EXPIRY_HOURS'])
    payload = {'sub': user_id, 'jti': jti, 'exp': exp}

    db = get_db()
    if db:
        cur = db.cursor()
        cur.execute(
            "INSERT INTO sessoes (usuario_id, jti, expira_em) VALUES (%s, %s, %s)",
            (user_id, jti, exp.replace(tzinfo=None))
        )
        db.commit()
        cur.close()

    return jwt.encode(payload, app.config['JWT_SECRET'], algorithm='HS256')


def verificar_token(token: str):
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None, 'Token expirado'
    except jwt.InvalidTokenError:
        return None, 'Token inválido'

    db = get_db()
    if db:
        cur = db.cursor(dictionary=True)
        cur.execute(
            "SELECT revogado FROM sessoes WHERE jti=%s AND usuario_id=%s",
            (payload['jti'], payload['sub'])
        )
        sessao = cur.fetchone()
        cur.close()
        if not sessao or sessao['revogado']:
            return None, 'Sessão encerrada'

    return payload, None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('mf_token')
        if not token:
            if request.path.startswith('/api/'):
                return jsonify({'message': 'Não autenticado'}), 401
            return redirect(url_for('login_page'))
        payload, err = verificar_token(token)
        if err:
            if request.path.startswith('/api/'):
                return jsonify({'message': err}), 401
            return redirect(url_for('login_page'))
        g.user_id = payload['sub']
        g.jti = payload['jti']
        return f(*args, **kwargs)
    return decorated

# ─── CSRF ─────────────────────────────────────────────────────────────────────
def gerar_csrf() -> str:
    token = secrets.token_hex(32)
    db = get_db()
    if db:
        cur = db.cursor()
        cur.execute("INSERT INTO csrf_tokens (token) VALUES (%s)", (token,))
        # Limpa tokens velhos
        cur.execute("DELETE FROM csrf_tokens WHERE criado_em < NOW() - INTERVAL 2 HOUR")
        db.commit()
        cur.close()
    return token


def validar_csrf(token: str) -> bool:
    if not token:
        return False
    db = get_db()
    if not db:
        return True  # Em modo dev sem DB, permite
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT usado FROM csrf_tokens WHERE token=%s", (token,))
    row = cur.fetchone()
    if row and not row['usado']:
        cur.execute("UPDATE csrf_tokens SET usado=1 WHERE token=%s", (token,))
        db.commit()
        cur.close()
        return True
    cur.close()
    return False

# ─── SEGURANÇA — HEADERS ──────────────────────────────────────────────────────
@app.after_request
def security_headers(resp):
    resp.headers['X-Content-Type-Options']  = 'nosniff'
    resp.headers['X-Frame-Options']          = 'DENY'
    resp.headers['X-XSS-Protection']         = '1; mode=block'
    resp.headers['Referrer-Policy']           = 'strict-origin-when-cross-origin'
    resp.headers['Permissions-Policy']        = 'geolocation=(), microphone=(), camera=()'
    resp.headers['Content-Security-Policy']   = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net fonts.googleapis.com; "
        "font-src fonts.gstatic.com cdn.jsdelivr.net; "
        "img-src 'self' data:;"
    )
    return resp

# ─── VALIDAÇÃO ────────────────────────────────────────────────────────────────
EMAIL_RE = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')

def validar_email(email: str) -> bool:
    return bool(EMAIL_RE.match(email or ''))

def validar_cpf(cpf: str) -> bool:
    c = re.sub(r'\D', '', cpf or '')
    return len(c) == 11 and len(set(c)) > 1

def sanitizar(val: str, max_len: int = 200) -> str:
    if not val:
        return ''
    return str(val).strip()[:max_len]

# ─── PÁGINAS ──────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/cadastro')
def cadastro_page():
    return render_template('cadastro.html')

@app.route('/dashboard')
@login_required
def dashboard_page():
    return render_template('dashboard.html')

@app.route('/matricula')
@login_required
def matricula_page():
    return render_template('matricula.html')

# ─── API: CSRF TOKEN ──────────────────────────────────────────────────────────
@app.route('/api/csrf-token')
def api_csrf_token():
    token = gerar_csrf()
    return jsonify({'token': token})

# ─── API: CADASTRO ────────────────────────────────────────────────────────────
@app.route('/api/cadastro', methods=['POST'])
@limiter.limit("10 per hour")
def api_cadastro():
    csrf = request.headers.get('X-CSRF-Token', '')
    if not validar_csrf(csrf):
        return jsonify({'success': False, 'message': 'Token de segurança inválido.'}), 403

    data = request.get_json(silent=True) or {}

    nome      = sanitizar(data.get('nome', ''), 120)
    email     = sanitizar(data.get('email', ''), 180).lower()
    cpf       = sanitizar(data.get('cpf', ''), 14)
    nascimento= sanitizar(data.get('nascimento', ''), 10)
    telefone  = sanitizar(data.get('telefone', ''), 20)
    password  = data.get('password', '')
    plano     = sanitizar(data.get('plano', 'mensal'), 20)
    objetivo  = sanitizar(data.get('objetivo', ''), 30)
    nivel     = sanitizar(data.get('nivel', ''), 20)

    # Validações
    if not nome or len(nome) < 2:
        return jsonify({'success': False, 'message': 'Nome inválido.'}), 400
    if not validar_email(email):
        return jsonify({'success': False, 'message': 'E-mail inválido.'}), 400
    if not validar_cpf(cpf):
        return jsonify({'success': False, 'message': 'CPF inválido.'}), 400
    if not password or len(password) < 8:
        return jsonify({'success': False, 'message': 'Senha deve ter pelo menos 8 caracteres.'}), 400

    planos_validos = ('mensal','trimestral','semestral','anual','premium')
    if plano not in planos_validos:
        plano = 'mensal'

    # Hash da senha com bcrypt
    senha_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')

    db = get_db()
    if not db:
        return jsonify({'success': False, 'message': 'Serviço indisponível. Tente novamente.'}), 503

    try:
        cur = db.cursor()
        cur.execute(
            """INSERT INTO usuarios (nome,email,cpf,nascimento,telefone,senha_hash,plano,objetivo,nivel)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (nome, email, cpf, nascimento or None, telefone, senha_hash, plano, objetivo, nivel)
        )
        db.commit()
        user_id = cur.lastrowid
        cur.close()
    except MySQLError as e:
        db.rollback()
        if e.errno == 1062:  # Duplicate entry
            if 'email' in str(e):
                return jsonify({'success': False, 'message': 'E-mail já cadastrado.'}), 409
            return jsonify({'success': False, 'message': 'CPF já cadastrado.'}), 409
        log.error("Cadastro DB error: %s", e)
        return jsonify({'success': False, 'message': 'Erro interno. Tente novamente.'}), 500

    token = gerar_token(user_id)
    resp = make_response(jsonify({'success': True, 'message': 'Conta criada com sucesso.'}))
    resp.set_cookie('mf_token', token, httponly=True, secure=False,  # True em produção com HTTPS
                    samesite='Lax', max_age=3600 * app.config['JWT_EXPIRY_HOURS'])
    return resp, 201

# ─── API: LOGIN ───────────────────────────────────────────────────────────────
@app.route('/api/login', methods=['POST'])
@limiter.limit("20 per hour")
def api_login():
    csrf = request.headers.get('X-CSRF-Token', '')
    if not validar_csrf(csrf):
        return jsonify({'success': False, 'message': 'Token de segurança inválido.'}), 403

    data = request.get_json(silent=True) or {}
    email    = sanitizar(data.get('email', ''), 180).lower()
    password = data.get('password', '')

    if not validar_email(email) or not password:
        return jsonify({'success': False, 'message': 'E-mail ou senha inválidos.'}), 401

    db = get_db()
    if not db:
        return jsonify({'success': False, 'message': 'Serviço indisponível.'}), 503

    cur = db.cursor(dictionary=True)
    cur.execute("SELECT id, senha_hash, ativo FROM usuarios WHERE email=%s", (email,))
    user = cur.fetchone()
    cur.close()

    if not user or not user['ativo']:
        return jsonify({'success': False, 'message': 'E-mail ou senha inválidos.'}), 401

    if not bcrypt.checkpw(password.encode('utf-8'), user['senha_hash'].encode('utf-8')):
        return jsonify({'success': False, 'message': 'E-mail ou senha inválidos.'}), 401

    token = gerar_token(user['id'])
    resp = make_response(jsonify({'success': True, 'message': 'Login realizado.'}))
    resp.set_cookie('mf_token', token, httponly=True, secure=False,
                    samesite='Lax', max_age=3600 * app.config['JWT_EXPIRY_HOURS'])
    return resp

# ─── API: ME (dados do usuário logado) ───────────────────────────────────────
@app.route('/api/me')
@login_required
def api_me():
    db = get_db()
    if not db:
        return jsonify({'message': 'Serviço indisponível.'}), 503

    cur = db.cursor(dictionary=True)
    cur.execute(
        "SELECT id,nome,email,plano,objetivo,nivel,criado_em FROM usuarios WHERE id=%s AND ativo=1",
        (g.user_id,)
    )
    user = cur.fetchone()
    cur.close()

    if not user:
        return jsonify({'message': 'Usuário não encontrado.'}), 404

    if user.get('criado_em'):
        user['criado_em'] = user['criado_em'].isoformat()

    return jsonify({'user': user})

# ─── API: ATUALIZAR PERFIL ───────────────────────────────────────────────────
@app.route('/api/me/update', methods=['PUT'])
@login_required
def api_update_me():
    csrf = request.headers.get('X-CSRF-Token', '')
    if not validar_csrf(csrf):
        return jsonify({'success': False, 'message': 'Token de segurança inválido.'}), 403

    data = request.get_json(silent=True) or {}
    nome     = sanitizar(data.get('nome', ''), 120)
    email    = sanitizar(data.get('email', ''), 180).lower()
    telefone = sanitizar(data.get('telefone', ''), 20)
    objetivo = sanitizar(data.get('objetivo', ''), 30)
    plano    = sanitizar(data.get('plano', ''), 20)

    if not nome or len(nome) < 2:
        return jsonify({'success': False, 'message': 'Nome inválido.'}), 400
    if not validar_email(email):
        return jsonify({'success': False, 'message': 'E-mail inválido.'}), 400

    planos_validos = ('mensal','trimestral','semestral','anual','premium')
    if plano not in planos_validos:
        return jsonify({'success': False, 'message': 'Plano inválido.'}), 400

    db = get_db()
    if not db:
        return jsonify({'success': False, 'message': 'Serviço indisponível.'}), 503

    try:
        cur = db.cursor()
        cur.execute(
            "UPDATE usuarios SET nome=%s, email=%s, telefone=%s, objetivo=%s, plano=%s WHERE id=%s",
            (nome, email, telefone, objetivo, plano, g.user_id)
        )
        db.commit()
        cur.close()
        return jsonify({'success': True, 'message': 'Perfil atualizado.'})
    except MySQLError as e:
        db.rollback()
        if e.errno == 1062:
            return jsonify({'success': False, 'message': 'E-mail já em uso.'}), 409
        log.error("Update error: %s", e)
        return jsonify({'success': False, 'message': 'Erro interno.'}), 500

# ─── API: LOGOUT ──────────────────────────────────────────────────────────────
@app.route('/api/logout', methods=['POST'])
@login_required
def api_logout():
    db = get_db()
    if db:
        cur = db.cursor()
        cur.execute("UPDATE sessoes SET revogado=1 WHERE jti=%s", (g.jti,))
        db.commit()
        cur.close()

    resp = make_response(jsonify({'success': True}))
    resp.delete_cookie('mf_token')
    return resp

# ─── API: DELETE ACCOUNT ──────────────────────────────────────────────────────
@app.route('/api/delete-account', methods=['DELETE'])
@login_required
@limiter.limit("5 per hour")
def api_delete_account():
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')

    db = get_db()
    if not db:
        return jsonify({'success': False, 'message': 'Serviço indisponível.'}), 503

    cur = db.cursor(dictionary=True)
    cur.execute("SELECT senha_hash FROM usuarios WHERE id=%s AND ativo=1", (g.user_id,))
    user = cur.fetchone()
    cur.close()

    if not user:
        return jsonify({'success': False, 'message': 'Usuário não encontrado.'}), 404

    if not bcrypt.checkpw(password.encode('utf-8'), user['senha_hash'].encode('utf-8')):
        return jsonify({'success': False, 'message': 'Senha incorreta.'}), 401

    cur = db.cursor()
    # Soft delete — preserva histórico
    cur.execute("UPDATE usuarios SET ativo=0, email=CONCAT(email,'_deleted_',id) WHERE id=%s", (g.user_id,))
    cur.execute("UPDATE sessoes SET revogado=1 WHERE usuario_id=%s", (g.user_id,))
    db.commit()
    cur.close()

    resp = make_response(jsonify({'success': True, 'message': 'Conta excluída.'}))
    resp.delete_cookie('mf_token')
    return resp

# ─── HEALTH CHECK ─────────────────────────────────────────────────────────────
@app.route('/health')
def health():
    db = get_db()
    db_ok = db is not None and db.is_connected()
    return jsonify({'status': 'ok' if db_ok else 'degraded', 'db': db_ok})

# ─── ERROR HANDLERS ───────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'message': 'Rota não encontrada.'}), 404
    return render_template('index.html'), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'success': False, 'message': 'Muitas tentativas. Aguarde e tente novamente.'}), 429

# ─── MAIN ─────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(host='0.0.0.0', port=5000, debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true')
