import bcrypt
from functools import wraps
from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, g, abort
)
from database import get_db
from .auth import login_required

# Cria um novo Blueprint para usuários
users_bp = Blueprint('users', __name__, url_prefix='/users', template_folder='../templates')


# Decorator para garantir que apenas administradores acessem a rota
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user or not g.user['is_admin']:
            abort(403)  # Proibido
        return f(*args, **kwargs)

    return decorated_function


# Rota principal: Lista todos os usuários
@users_bp.route('/')
@login_required
@admin_required
def list_users():
    db = get_db()
    # Consulta agora busca também o email
    users = db.execute("""
        SELECT u.id, u.nome, u.login, u.email, u.is_admin, d.nome as depto_nome
        FROM usuarios u
        LEFT JOIN departamentos d ON u.departamento_id = d.id
        ORDER BY u.nome
    """).fetchall()
    return render_template('user_list.html', users=users)


# Rota para criar um novo usuário (ATUALIZADA)
@users_bp.route('/new', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    db = get_db()
    if request.method == 'POST':
        nome = request.form['nome']
        login = request.form['login']
        email = request.form['email']  # <-- NOVO
        senha = request.form['senha'].encode('utf-8')
        is_admin = 'is_admin' in request.form
        departamento_id = request.form.get('departamento_id')

        if not all([nome, login, email, senha, departamento_id]):
            flash('Todos os campos são obrigatórios.', 'danger')
            return redirect(url_for('users.create_user'))

        password_hashed = bcrypt.hashpw(senha, bcrypt.gensalt())

        try:
            db.execute(
                "INSERT INTO usuarios (nome, login, email, senha, is_admin, departamento_id) VALUES (?, ?, ?, ?, ?, ?)",
                (nome, login, email, password_hashed, is_admin, departamento_id)
            )
            db.commit()
            flash('Usuário criado com sucesso!', 'success')
            return redirect(url_for('users.list_users'))
        except db.IntegrityError as e:
            if 'UNIQUE constraint failed: usuarios.login' in str(e):
                flash(f"O login '{login}' já existe. Tente outro.", 'warning')
            elif 'UNIQUE constraint failed: usuarios.email' in str(e):
                flash(f"O e-mail '{email}' já está em uso. Tente outro.", 'warning')
            else:
                flash("Ocorreu um erro de integridade ao salvar os dados.", 'danger')
            return redirect(url_for('users.create_user'))

    departamentos = db.execute("SELECT id, nome FROM departamentos ORDER BY nome").fetchall()
    return render_template('user_form.html', title="Novo Usuário", action_url=url_for('users.create_user'),
                           departamentos=departamentos)


# Rota para editar um usuário existente (ATUALIZADA)
@users_bp.route('/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM usuarios WHERE id = ?", (user_id,)).fetchone()
    if not user: abort(404)

    if request.method == 'POST':
        nome = request.form['nome']
        login = request.form['login']
        email = request.form['email']  # <-- NOVO
        is_admin = 'is_admin' in request.form
        departamento_id = request.form.get('departamento_id')

        if not all([nome, login, email, departamento_id]):
            flash('Nome, login, e-mail e departamento são obrigatórios.', 'danger')
            return redirect(url_for('users.edit_user', user_id=user_id))

        try:
            db.execute(
                "UPDATE usuarios SET nome = ?, login = ?, email = ?, is_admin = ?, departamento_id = ? WHERE id = ?",
                (nome, login, email, is_admin, departamento_id, user_id)
            )
            db.commit()
            flash('Usuário atualizado com sucesso!', 'success')
            return redirect(url_for('users.list_users'))
        except db.IntegrityError as e:
            if 'UNIQUE constraint failed: usuarios.login' in str(e):
                flash(f"O login '{login}' já pertence a outro usuário.", 'warning')
            elif 'UNIQUE constraint failed: usuarios.email' in str(e):
                flash(f"O e-mail '{email}' já pertence a outro usuário.", 'warning')
            else:
                flash("Ocorreu um erro de integridade ao salvar os dados.", 'danger')
            return redirect(url_for('users.edit_user', user_id=user_id))

    departamentos = db.execute("SELECT id, nome FROM departamentos ORDER BY nome").fetchall()
    return render_template('user_form.html', title="Editar Usuário", user=user,
                           action_url=url_for('users.edit_user', user_id=user_id), departamentos=departamentos)


# Rota para alterar a senha de um usuário
@users_bp.route('/<int:user_id>/change_password', methods=['POST'])
@login_required
@admin_required
def change_password(user_id):
    nova_senha = request.form['new_password'].encode('utf-8')
    confirm_senha = request.form['confirm_password'].encode('utf-8')

    if not nova_senha or nova_senha != confirm_senha:
        flash('As senhas não conferem ou estão em branco.', 'danger')
        return redirect(url_for('users.list_users'))

    password_hashed = bcrypt.hashpw(nova_senha, bcrypt.gensalt())
    db = get_db()
    db.execute("UPDATE usuarios SET senha = ? WHERE id = ?", (password_hashed, user_id))
    db.commit()

    flash('Senha alterada com sucesso!', 'success')
    return redirect(url_for('users.list_users'))