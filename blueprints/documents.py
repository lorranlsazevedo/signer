from flask import (
    Blueprint, render_template, request, jsonify, redirect, url_for,
    Response, session, current_app, flash
)
from datetime import datetime
from .auth import login_required
from database import get_db
from services.signer_service import SignerService

documents_bp = Blueprint('documents', __name__, template_folder='../templates')


def translate_status(status):
    return {
        "Concluded": "Concluído", "Pending": "Pendente", "Completed": "Assinado",
        "Created": 'Aguardando', "Canceled": "Cancelado"
    }.get(status, status)


def get_document_status_from_api(document_api_id):
    """Função auxiliar para buscar status, usando o serviço."""
    try:
        service = SignerService()
        details = service.get_document_details(document_api_id)
        return translate_status(details["status"])
    except Exception as e:
        print(f"Erro ao buscar status do documento {document_api_id}: {e}")
        return "Erro de API"


# --- Rotas ---

@documents_bp.route('/')
@login_required
def root():
    return redirect(url_for('documents.dashboard'))


# Em blueprints/documents.py

# SUBSTITUA TODA A SUA FUNÇÃO 'dashboard' POR ESTA
@documents_bp.route('/dashboard', methods=['GET', 'POST'])
@documents_bp.route('/dashboard/page/<int:page>', methods=['GET'])
@login_required
def dashboard(page=1):
    db = get_db()

    # --- LÓGICA PARA BUSCA VIA AJAX (POST) ---
    if request.method == 'POST':
        query = request.form.get('query', '')
        search_params = [session['user_id'], f"%{query}%", f"%{query}%"]

        docs_from_db = db.execute("""
            SELECT d.id, d.caminho_arquivo, d.nome_arquivo, d.timestamp, GROUP_CONCAT(p.nome) as destinatarios
            FROM documentos AS d
            LEFT JOIN assinaturas AS a ON d.id = a.documento_id
            LEFT JOIN participantes AS p ON a.participante_id = p.id
            WHERE d.usuario_id = ? AND (d.nome_arquivo LIKE ? OR p.nome LIKE ?)
            GROUP BY d.id ORDER BY d.timestamp DESC
        """, tuple(search_params)).fetchall()

        documentos = []
        for doc in docs_from_db:
            doc_dict = dict(doc)
            doc_dict['status'] = get_document_status_from_api(doc['caminho_arquivo'])
            documentos.append(doc_dict)

        return render_template('_tabela_documentos.html', documentos=documentos)

    # --- LÓGICA PARA CARREGAMENTO NORMAL DA PÁGINA (GET) ---
    ITEMS_PER_PAGE = current_app.config.get('ITEMS_PER_PAGE', 12)
    offset = (page - 1) * ITEMS_PER_PAGE

    query = request.args.get('query', None)

    base_query = """
        FROM documentos AS d
        LEFT JOIN assinaturas AS a ON d.id = a.documento_id
        LEFT JOIN participantes AS p ON a.participante_id = p.id
        WHERE d.usuario_id = ?
    """
    params = [session['user_id']]

    if query:
        base_query += " AND (d.nome_arquivo LIKE ? OR p.nome LIKE ?)"
        params.extend([f"%{query}%", f"%{query}%"])

    total_documents = db.execute(f"SELECT COUNT(DISTINCT d.id) {base_query}", tuple(params)).fetchone()[0]
    total_pages = max(1, (total_documents + ITEMS_PER_PAGE - 1) // ITEMS_PER_PAGE)

    docs_query = f"""
        SELECT d.id, d.caminho_arquivo, d.nome_arquivo, d.timestamp, GROUP_CONCAT(p.nome) as destinatarios
        {base_query}
        GROUP BY d.id ORDER BY d.timestamp DESC LIMIT ? OFFSET ?
    """
    params.extend([ITEMS_PER_PAGE, offset])
    docs_from_db = db.execute(docs_query, tuple(params)).fetchall()

    documentos = []
    for doc in docs_from_db:
        doc_dict = dict(doc)
        doc_dict['status'] = get_document_status_from_api(doc['caminho_arquivo'])
        documentos.append(doc_dict)

    return render_template(
        'dashboard.html',
        documentos=documentos,
        current_page=page,
        total_pages=total_pages
    )


@documents_bp.route('/envio', methods=['GET', 'POST'])
@login_required
def envio():
    if request.method == 'POST':
        if 'file' not in request.files or not request.files['file'].filename:
            flash('Nenhum arquivo selecionado.', 'warning')
            return redirect(request.url)

        uploaded_file = request.files['file']
        db = get_db()
        service = SignerService()

        # Monta a lista de signatários (flowActions)
        flowActions = []
        participantes_db = []
        i = 1
        while f'signer_name_{i}' in request.form:
            signer_name = request.form[f'signer_name_{i}']
            signer_email = request.form[f'signer_email_{i}']
            participantes_db.append({'name': signer_name, 'email': signer_email})

            flowActions.append({
                "type": "Signer", "step": i,
                "user": {"name": signer_name, "email": signer_email},
                "allowElectronicSignature": True
            })
            i += 1

        try:
            # 1. Chama o serviço para criar o documento na API externa
            api_response = service.create_document(uploaded_file, flowActions)
            document_api_id = api_response[0]["documentId"]

            # 2. Se sucesso, salva no banco de dados local
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO documentos (usuario_id, caminho_arquivo, status, nome_arquivo, timestamp) VALUES (?, ?, ?, ?, ?)",
                (session['user_id'], document_api_id, 'Enviado', uploaded_file.filename, datetime.now())
            )
            doc_db_id = cursor.lastrowid

            # Insere/associa participantes
            for p_info in participantes_db:
                cursor.execute("INSERT OR IGNORE INTO participantes (nome, email) VALUES (?, ?)",
                               (p_info['name'], p_info['email']))
                participante_id = \
                cursor.execute("SELECT id FROM participantes WHERE email = ?", (p_info['email'],)).fetchone()[0]
                cursor.execute("INSERT INTO assinaturas (documento_id, participante_id) VALUES (?, ?)",
                               (doc_db_id, participante_id))

            db.commit()
            flash('Documento enviado com sucesso!', 'success')
            return redirect(url_for('documents.dashboard'))

        except Exception as e:
            db.rollback()
            flash(f"Erro ao criar o documento: {e}", 'danger')

    return render_template('envio.html')


@documents_bp.route('/detalhes_documento/<int:doc_db_id>', methods=['GET'])
@login_required
def detalhes_documento(doc_db_id):
    db = get_db()
    doc_info = db.execute('SELECT caminho_arquivo FROM documentos WHERE id = ?', (doc_db_id,)).fetchone()
    if not doc_info:
        return render_template('erro.html', mensagem='Documento não encontrado'), 404

    try:
        service = SignerService()
        api_data = service.get_document_details(doc_info['caminho_arquivo'])

        participantes = [
            {
                "nome": action.get("user", {}).get("name"),
                "email": action.get("user", {}).get("email"),
                "status": action.get("status"),
            } for action in api_data.get("flowActions", [])
        ]

        documento = {"id": doc_info['caminho_arquivo']}
        return render_template(
            'detalhes_documento.html',
            participantes=participantes,
            translate_status=translate_status,
            documento=documento
        )
    except Exception as e:
        flash(f'Houve um problema ao acessar a API: {e}', 'danger')
        return redirect(url_for('documents.dashboard'))


@documents_bp.route('/download_document/<int:doc_db_id>', methods=['GET'])
@login_required
def download_document(doc_db_id):
    db = get_db()
    doc_info = db.execute("SELECT caminho_arquivo, nome_arquivo FROM documentos WHERE id = ?", (doc_db_id,)).fetchone()
    if not doc_info:
        return "Documento não encontrado", 404

    # Pega o tipo de download da URL (ex: ?type=PrinterFriendlyVersion)
    # Se não for fornecido, o padrão é 'Original'
    doc_type = request.args.get('type', 'Original')

    try:
        service = SignerService()
        # Passa o tipo de documento para o serviço
        file_content = service.download_document(doc_info['caminho_arquivo'], doc_type=doc_type)

        # Define um nome de arquivo mais descritivo
        download_filename = f"{doc_info['nome_arquivo'].replace('.pdf', '')}_{doc_type}.pdf"

        return Response(
            file_content,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=\"{download_filename}\""}
        )
    except Exception as e:
        flash(f"Erro ao baixar o documento: {e}", "danger")
        return redirect(url_for('documents.dashboard'))


@documents_bp.route('/search', methods=['POST'])
@login_required
def search():
    query = request.form.get('query', '')
    db = get_db()

    # Sua lógica de consulta ao banco de dados para buscar os documentos
    docs_from_db = db.execute("""
        SELECT d.id, d.caminho_arquivo, d.nome_arquivo, d.timestamp, GROUP_CONCAT(p.nome) as destinatarios
        FROM documentos AS d
        LEFT JOIN assinaturas AS a ON d.id = a.documento_id
        LEFT JOIN participantes AS p ON a.participante_id = p.id
        WHERE d.usuario_id = ? AND (d.nome_arquivo LIKE ? OR p.nome LIKE ?)
        GROUP BY d.id
        ORDER BY d.timestamp DESC
    """, (session['user_id'], f"%{query}%", f"%{query}%")).fetchall()

    # Atualiza o status de cada documento encontrado
    documentos_encontrados = []
    for doc in docs_from_db:
        doc_dict = dict(doc)
        doc_dict['status'] = get_document_status_from_api(doc['caminho_arquivo'])
        documentos_encontrados.append(doc_dict)

    # A MUDANÇA PRINCIPAL: Renderiza o template parcial e o retorna como resposta
    return render_template('_tabela_documentos.html', documentos=documentos_encontrados)


@documents_bp.route('/delete_document/<int:doc_db_id>', methods=['POST'])
@login_required
def delete_document(doc_db_id):
    db = get_db()
    doc_info = db.execute("SELECT caminho_arquivo FROM documentos WHERE id = ? AND usuario_id = ?",
                          (doc_db_id, session['user_id'])).fetchone()

    if not doc_info:
        return jsonify({'code': 'error', 'message': 'Documento não encontrado ou permissão negada'}), 404

    try:
        # 1. Deleta na API externa
        service = SignerService()
        service.delete_document(doc_info['caminho_arquivo'])

        # 2. Deleta no banco de dados local
        db.execute("DELETE FROM documentos WHERE id = ?", (doc_db_id,))
        db.execute("DELETE FROM assinaturas WHERE documento_id = ?", (doc_db_id,))
        db.commit()

        return jsonify({'code': 'success', 'message': 'Documento deletado com sucesso!'})
    except Exception as e:
        db.rollback()
        return jsonify({'code': 'error', 'message': f'Erro ao deletar documento: {e}'}), 500


@documents_bp.route('/search_signer', methods=['POST'])
@login_required
def search_signer():
    email = request.form.get('email', '')
    if not email:
        return jsonify({'signers': []})

    db = get_db()
    # Usamos LIKE para encontrar e-mails que contenham o texto pesquisado
    cursor = db.execute(
        "SELECT nome, email, cpf FROM participantes WHERE email LIKE ?",
        (f'%{email}%',)
    )
    signers_from_db = cursor.fetchall()

    # Converte as linhas do banco de dados em uma lista de dicionários
    signers_list = [
        {'name': row['nome'], 'email': row['email'], 'cpf': row['cpf']}
        for row in signers_from_db
    ]

    return jsonify({'signers': signers_list})

@documents_bp.route('/check_email', methods=['POST'])
@login_required
def check_email():
    email = request.form.get('email', '')
    if not email:
        return jsonify({'exists': False})

    db = get_db()
    participant = db.execute(
        "SELECT id FROM participantes WHERE email = ?", (email,)
    ).fetchone()

    if participant:
        return jsonify({'exists': True})
    else:
        return jsonify({'exists': False})


@documents_bp.route('/api/documents/<string:document_id>/action-url', methods=['POST'])
@login_required
def generate_action_url_route(document_id):
    try:
        data = request.get_json()
        if not data or 'emailAddress' not in data or 'flowActionId' not in data:
            return jsonify({'error': 'Payload inválido (dados ausentes)'}), 400

        service = SignerService()
        api_response = service.generate_action_url(
            document_api_id=document_id,
            email_address=data['emailAddress'],
            flow_action_id=data['flowActionId']
        )

        # O JavaScript espera uma chave 'action_url', então vamos garantir que ela exista
        if api_response and 'url' in api_response:
            return jsonify({'action_url': api_response.get('url')}), 200
        else:
            return jsonify({'error': 'A API externa não retornou uma URL válida'}), 500

    except Exception as e:
        print(f"Erro ao gerar URL de ação: {e}")
        return jsonify({'error': 'Erro interno ao gerar a URL de ação'}), 500