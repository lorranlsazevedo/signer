# blueprints/auth.py
import bcrypt
from functools import wraps
from flask import (
    Blueprint, request, session, redirect, url_for, 
    render_template, flash, g
)
from database import get_db

auth_bp = Blueprint('auth', __name__, url_prefix='/auth', template_folder='../templates')

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