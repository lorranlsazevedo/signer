# blueprints/auth.py
import bcrypt
from functools import wraps
from flask import (
    Blueprint, request, session, redirect, url_for, 
    render_template, flash, g, current_app
)
from database import get_db
import requests
import logging

ldap_logger = logging.getLogger('ldap_auth')

auth_bp = Blueprint('auth', __name__, url_prefix='/auth', template_folder='../templates')


def _validate_ldap_token(token: str) -> dict | None:
    """
    Função auxiliar para validar o token na API externa.
    É uma adaptação direta da sua função original.
    """
    if not token:
        return None

    # Pega a URL do arquivo de configuração do Flask
    url = current_app.config.get('LDAP_VALIDATE_TOKEN_URL')
    if not url:
        ldap_logger.error("LDAP_VALIDATE_TOKEN_URL não está configurada.")
        return None

    headers = {'Authorization': f'Bearer {token}'}

    try:
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code == 200:
            return resp.json().get('user')

        ldap_logger.warning(
            f"LDAP AUTH ERROR: status {resp.status_code} para o token."
        )
    except requests.RequestException as e:
        ldap_logger.error(f"LDAP COMM ERROR: {e}")

    return None


@auth_bp.route('/ldap-login')
def ldap_login_route():
    """
    Esta é a nova rota de login. Ela espera um 'token' como parâmetro na URL.
    Ex: /auth/ldap-login?token=ABC123XYZ
    """
    # Em Flask, pegamos parâmetros de query com 'request.args'
    ldap_token = request.args.get('token')
    if not ldap_token:
        flash("Token de autenticação não fornecido.", 'danger')
        return redirect(url_for('auth.login'))  # Redireciona para o login normal

    user_data = _validate_ldap_token(ldap_token)
    email = user_data.get('email') if user_data else None

    if not email:
        ldap_logger.warning("Payload LDAP sem 'email' ou token inválido.")
        flash("Token inválido ou dados de usuário incompletos.", 'danger')
        return redirect(url_for('auth.login'))

    # Procura o usuário no nosso banco de dados SQLite
    db = get_db()
    usuario = db.execute(
        "SELECT * FROM usuarios WHERE email = ?", (email,)
    ).fetchone()

    if not usuario:
        ldap_logger.warning(f"Usuário com e-mail '{email}' não encontrado no sistema local.")
        flash(f"Acesso negado. O usuário com e-mail {email} não está cadastrado neste sistema.", 'danger')
        return redirect(url_for('auth.login'))

    # Se o usuário foi encontrado, cria a sessão no Flask
    session.clear()
    session['user_id'] = usuario['id']

    ldap_logger.info(
        f"Login LDAP/SSO bem-sucedido para o e-mail: {email}"
    )
    flash('Login realizado com sucesso!', 'success')
    return redirect(url_for('documents.dashboard'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = request.form['login']
        senha = request.form['senha'].encode('utf-8')

        db = get_db()
        user = db.execute("SELECT id, senha FROM usuarios WHERE login = ?", (login_input,)).fetchone()

        if user and bcrypt.checkpw(senha, user['senha']):
            session.clear()
            session['user_id'] = user['id']
            # Redireciona para o dashboard DENTRO do blueprint 'documents'
            return redirect(url_for('documents.dashboard'))
        else:
            flash('Login ou senha inválidos.', 'danger')

    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('Você saiu da sua conta.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        departamento_id = request.form['departamento_id']
        nome = request.form['nome']
        login = request.form['login']
        senha = request.form['senha'].encode('utf-8')

        password_hashed = bcrypt.hashpw(senha, bcrypt.gensalt())

        db = get_db()
        try:
            db.execute(
                "INSERT INTO usuarios (departamento_id, nome, login, senha) VALUES (?, ?, ?, ?)",
                (departamento_id, nome, login, password_hashed)
            )
            db.commit()
            flash('Usuário registrado com sucesso! Faça o login.', 'success')
            return redirect(url_for('auth.login'))
        except db.IntegrityError:
            flash(f"O login '{login}' já existe.", 'danger')

    return render_template('register.html')

@auth_bp.before_app_request
def load_logged_in_user():
    """Carrega dados do usuário em 'g.user' se ele estiver logado."""
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute('SELECT * FROM usuarios WHERE id = ?', (user_id,)).fetchone()