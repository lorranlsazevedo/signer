# app.py
from flask import Flask
from datetime import datetime
from blueprints.users import users_bp

def create_app():
    """
    Application Factory: cria e configura a instância do aplicativo Flask.
    """
    app = Flask(__name__)

    app.config.from_object('config.Config')

    from database import init_app as init_db_app
    init_db_app(app)

    from blueprints.auth import auth_bp
    from blueprints.documents import documents_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(documents_bp)
    app.register_blueprint(users_bp)

    @app.template_filter('format_timestamp')
    def _jinja2_filter_format_timestamp(timestamp_str):
        if not timestamp_str:
            return ""
        if isinstance(timestamp_str, datetime):
            return timestamp_str.strftime('%d/%m/%Y - %H:%M')
        try:
            dt_obj = datetime.strptime(str(timestamp_str), '%Y-%m-%d %H:%M:%S.%f')
        except ValueError:
            dt_obj = datetime.strptime(str(timestamp_str), '%Y-%m-%d %H:%M:%S')
        return dt_obj.strftime('%d/%m/%Y - %H:%M')

    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=True)