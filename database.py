# database.py
import sqlite3
from flask import current_app, g

def get_db():
    """
    Abre uma nova conexão com o banco de dados se não houver uma no contexto atual.
    O objeto 'g' é único para cada request.
    """
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE_PATH'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    """
    Fecha a conexão com o banco de dados se ela existir.
    """
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_app(app):
    """
    Registra os comandos do banco de dados com a aplicação Flask.
    É chamada pela factory da aplicação.
    """
    app.teardown_appcontext(close_db)