import os
import sqlite3
from flask import Flask, render_template, request, jsonify, redirect, url_for, Response, session
import requests
import bcrypt
from flask import flash
from datetime import datetime
from functools import wraps
import logging

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

flask_log = logging.getLogger('flask')
flask_log.setLevel(logging.ERROR)


DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database', 'signer_database.db')

app = Flask(__name__)
app.config['STATIC_FOLDER'] = 'static'
app.secret_key = '2765570032dac2476be7ef0c1c50a9db'

base_url = "https://www.dropsigner.com"
api_key = "9b38597a67692b42aa96f9810d18f36dec3ff49a0ca5059054f1d7f1e13364ff"
documents = []


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in', False):
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@app.template_filter('format_timestamp')
def _jinja2_filter_format_timestamp(timestamp):
    if timestamp is None:
        return
    dt_obj = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
    return dt_obj.strftime('%d/%m/%Y - %H:%M')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form['login']
        senha = request.form['senha']

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("SELECT id, senha FROM usuarios WHERE login = ?", (login,))
        user = cursor.fetchone()

        conn.close()

        if user and bcrypt.checkpw(senha.encode('utf-8'), user[1]):
            flash('Login bem-sucedido!', 'success')
            session['logged_in'] = True
            session['user_id'] = user[0]
            return redirect(url_for('dashboard'))
        else:
            flash('Login ou senha inválidos.', 'danger')
            session['logged_in'] = False
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
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


@app.before_request
def before_request():
    if 'logged_in' not in session and request.endpoint not in ['login', 'register', 'static']:
        return redirect(url_for('login'))


def translate_status(status):
    return {
        "Concluded": "Concluído",
        "Pending": "Pendente"
    }.get(status, status)


def get_documento_status(doc_db_id):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT caminho_arquivo FROM documentos WHERE id = ?", (doc_db_id,))
        result = cursor.fetchone()
        if result:
            document_id = result[0]
        else:
            print(f"Documento com ID {doc_db_id} não encontrado no banco de dados")
            return "Erro ao obter status"

    headers = {"X-Api-Key": api_key}
    response = requests.get(f"{base_url}/api/documents/{document_id}", headers=headers)
    if response.status_code == 200:
        return translate_status(response.json()["status"])
    else:
        print(
            f"Erro ao buscar status do documento {document_id}: {response.status_code} - {response.text}")
        return "Erro ao obter status"


@app.route('/envio', methods=['GET', 'POST'])
@login_required
def envio():
    error_message = None
    usuario_id = session.get('user_id', None)

    if request.method == 'POST' and 'file' in request.files:
        uploaded_file = request.files['file']

        if uploaded_file.filename != '':
            headers = {"X-Api-Key": api_key}
            response_upload = requests.post(f"{base_url}/api/uploads", headers=headers, files={"file": uploaded_file})

            if response_upload.status_code == 200:
                upload_id = response_upload.json()["id"]
                flowActions = []

                i = 1
                while f'signer_name_{i}' in request.form:
                    signer_name = request.form[f'signer_name_{i}']
                    signer_email = request.form[f'signer_email_{i}']
                    signer_cpf = request.form.get(f'signer_cpf_{i}', None)

                    if signer_cpf:
                        signer_cpf = signer_cpf.replace(".", "").replace("-", "")

                    with sqlite3.connect(DATABASE) as conn:
                        cursor = conn.cursor()
                        cursor.execute("SELECT id FROM participantes WHERE email = ?", (signer_email,))
                        existing_participante = cursor.fetchone()

                        if existing_participante:
                            participante_id = existing_participante[0]
                            if signer_cpf:  # Se o CPF foi fornecido, atualize o CPF do signatário existente
                                cursor.execute("UPDATE participantes SET cpf = ? WHERE id = ?",
                                               (signer_cpf, participante_id))
                                conn.commit()
                        else:
                            cursor.execute("""
                                    INSERT INTO participantes (nome, email, cpf)
                                    VALUES (?, ?, ?)
                                    """, (signer_name, signer_email, signer_cpf))
                            participante_id = cursor.lastrowid
                            conn.commit()

                    signer_data = {
                        "type": "Signer",
                        "step": i,
                        "user": {
                            "name": signer_name,
                            "email": signer_email
                        },
                        "allowElectronicSignature": True
                    }

                    if signer_cpf:
                        signer_data["user"]["identifier"] = signer_cpf

                    flowActions.append(signer_data)
                    i += 1

                document_data = {
                    "files": [{
                        "displayName": uploaded_file.filename,
                        "id": upload_id,
                        "name": uploaded_file.filename,
                        "contentType": "application/pdf"
                    }],
                    "flowActions": flowActions
                }

                response_document = requests.post(f"{base_url}/api/documents", headers=headers, json=document_data)

                if response_document.status_code == 200:
                    current_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    document_id_from_api = response_document.json()[0]["documentId"]
                    document_name = uploaded_file.filename

                    with sqlite3.connect(DATABASE) as conn:
                        cursor = conn.cursor()
                        cursor.execute("""
                        INSERT INTO documentos (usuario_id, caminho_arquivo, status, nome_arquivo, timestamp)
                        VALUES (?, ?, ?, ?, ?)
                        """, (usuario_id, document_id_from_api, 'Enviado', document_name, current_timestamp))

                        documento_id = cursor.lastrowid

                        i = 1
                        while f'signer_name_{i}' in request.form:
                            signer_email = request.form[f'signer_email_{i}']
                            cursor.execute("SELECT id FROM participantes WHERE email = ?", (signer_email,))
                            participante_id = cursor.fetchone()[0]

                            cursor.execute("""
                                    INSERT INTO assinaturas (documento_id, participante_id)
                                    VALUES (?, ?)
                                    """, (documento_id, participante_id))

                            i += 1

                        conn.commit()

                    return redirect(url_for('dashboard'))
                else:
                    error_message = f"Erro ao criar o documento: {response_document.text}"

    return render_template('envio.html', documents=documents, error_message=error_message)


ITEMS_PER_PAGE = 12


@app.route('/dashboard')
@app.route('/dashboard/page/<int:page>')
@login_required
def dashboard(page=1):
    ITEMS_PER_PAGE = 12
    offset = (page - 1) * ITEMS_PER_PAGE

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT COUNT(*) 
            FROM documentos 
            WHERE usuario_id = ? AND caminho_arquivo IS NOT NULL AND caminho_arquivo != ''
        """, (session['user_id'],))

        total_documents = cursor.fetchone()[0]
        total_pages = -(-total_documents // ITEMS_PER_PAGE)

        cursor.execute("""
            SELECT d.id, d.nome_arquivo, d.timestamp, GROUP_CONCAT(p.nome) 
            FROM documentos AS d
            LEFT JOIN assinaturas AS a ON d.id = a.documento_id
            LEFT JOIN participantes AS p ON a.participante_id = p.id
            WHERE d.usuario_id = ? AND d.caminho_arquivo IS NOT NULL AND d.caminho_arquivo != ''
            GROUP BY d.id
            ORDER BY d.timestamp DESC
            LIMIT ? OFFSET ?
        """, (session['user_id'], ITEMS_PER_PAGE, offset))

        documentos_db = cursor.fetchall()

    #print("Documentos recuperados do DB:", documentos_db)

    documentos = []
    for doc in documentos_db:
        doc_id, nome_arquivo, timestamp, destinatarios = doc
        status = get_documento_status(doc_id)
        documentos.append({
            'id': doc_id,
            'nome_arquivo': nome_arquivo,
            'timestamp': timestamp,
            'status': status,
            'destinatarios': destinatarios
        })

    #print("Documentos preparados para renderização:", documentos)

    return render_template('dashboard.html', documentos=documentos, current_page=page, total_pages=total_pages)


@app.route('/get_documents', methods=['GET'])
@login_required
def get_documents():
    for document in documents:
        headers = {"X-Api-Key": api_key}
        response = requests.get(f"{base_url}/api/documents/{document['id']}", headers=headers)
        if response.status_code == 200:
            document['status'] = translate_status(response.json()["status"])
    return jsonify(documents=documents)


@app.route('/download_document/<int:doc_db_id>', methods=['GET'])
@login_required
def download_document(doc_db_id):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT caminho_arquivo FROM documentos WHERE id = ?", (doc_db_id,))
        result = cursor.fetchone()
        if result:
            document_id = result[0]
        else:
            return "Documento não encontrado no banco de dados", 404

    doc_type = request.args.get('type', 'Original')
    headers = {
        "X-Api-Key": api_key,
        "accept": "*/*"
    }
    response = requests.get(f"{base_url}/api/documents/{document_id}/content", headers=headers,
                            params={'type': doc_type})

    if response.status_code == 200:
        content_disposition = f"attachment; filename={document_id}.pdf"
        return Response(response.content, headers={"Content-Disposition": content_disposition},
                        mimetype="application/pdf")
    else:
        return f"Erro ao baixar o documento: {response.status_code} - {response.text}", response.status_code


@app.route('/search_signer', methods=['POST'])
def search_signer():
    email = request.form.get('email')

    if not email:
        return jsonify({"error": "E-mail não fornecido"}), 400

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT nome, email, cpf FROM participantes WHERE email LIKE ?", ('%' + email + '%',))
    signers = cursor.fetchall()
    conn.close()

    signers_list = [{'name': name, 'email': email, 'cpf': cpf} for name, email, cpf in signers]
    return jsonify({"signers": signers_list})


@app.route('/api/documents/<int:doc_db_id>', methods=['DELETE'])
@login_required
def delete_api_document(doc_db_id):
    # Buscando o caminho_arquivo associado ao doc_db_id
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT caminho_arquivo FROM documentos WHERE id = ?", (doc_db_id,))
        result = cursor.fetchone()
        if result:
            document_id_from_api = result[0]
        else:
            return jsonify({'code': 'error', 'message': 'Documento não encontrado no banco de dados'}), 404

    # Deletando o documento usando a API
    headers = {"X-Api-Key": api_key}
    response = requests.delete(f"{base_url}/api/documents/{document_id_from_api}", headers=headers)

    if response.status_code == 200:
        # Deletando do banco de dados local
        cursor.execute("DELETE FROM documentos WHERE id = ?", (doc_db_id,))
        conn.commit()
        return jsonify({'code': 'success', 'message': 'Documento deletado com sucesso!'})
    else:
        return jsonify({'code': 'error', 'message': f"Erro ao deletar o documento na API: {response.text}"}), response.status_code


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
