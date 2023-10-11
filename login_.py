import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session
import bcrypt

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database', 'signer_database.db')

login_app = Flask(__name__)
login_app.secret_key = '2765570032dac2476be7ef0c1c50a9db'



@login_app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form['login']
        senha = request.form['senha']

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("SELECT id, senha FROM usuarios WHERE login = ?", (login,))
        user = cursor.fetchone()

        conn.close()

        # Verifica se o usuário existe e se a senha fornecida combina com o hash no banco de dados
        if user and bcrypt.checkpw(senha.encode('utf-8'), user[1]):
            flash('Login bem-sucedido!', 'success')
            session['logged_in'] = True
            session['user_id'] = user[0]  # Guardando user_id na sessão
            return redirect(url_for('dashboard'))
        else:
            flash('Login ou senha inválidos.', 'danger')
            session['logged_in'] = False
            return redirect(url_for('login'))

    return render_template('login.html')

@login_app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


@login_app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        departamento_id = request.form['departamento_id']
        nome = request.form['nome']
        login = request.form['login']
        senha = request.form['senha']

        password_hashed = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())

        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO usuarios (departamento_id, nome, login, senha) VALUES (?, ?, ?, ?)",
                           (departamento_id, nome, login, password_hashed))
            conn.commit()

        flash('Usuário registrado com sucesso!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@login_app.before_request
def before_request():
    if 'logged_in' not in session and request.endpoint not in ['login', 'register', 'static']:
        return redirect(url_for('login'))


if __name__ == "__main__":
    login_app.run(debug=True)
