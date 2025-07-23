# services/signer_service.py
import requests
from flask import current_app


class SignerService:
    """
    Uma classe de serviço para encapsular todas as interações
    com a API da DropSigner.
    """

    def __init__(self):
        self.api_key = current_app.config['SIGNER_API_KEY']
        self.base_url = current_app.config['SIGNER_BASE_URL']
        self.headers = {
            "X-Api-Key": self.api_key,
            "Accept": "application/json"
        }

    def _make_request(self, method, endpoint, **kwargs):
        """Método auxiliar para fazer requisições e tratar erros comuns."""
        url = f"{self.base_url}/api/{endpoint}"
        try:
            response = requests.request(method, url, headers=self.headers, **kwargs)
            response.raise_for_status()  # Lança uma exceção para status 4xx/5xx

            # Para DELETE, o corpo da resposta pode estar vazio
            if response.status_code == 204 or not response.content:
                return None

            return response.json()
        except requests.exceptions.RequestException as e:
            # Aqui você pode adicionar um log mais robusto
            print(f"Erro na comunicação com a API: {e}")
            raise  # Re-lança a exceção para que a camada superior (rota) possa tratá-la

    def get_document_details(self, document_api_id):
        """Busca os detalhes completos de um documento na API."""
        return self._make_request('GET', f"documents/{document_api_id}")

    def create_document(self, uploaded_file, flow_actions):
        """
        Orquestra o processo de criação de um documento: faz o upload e depois cria o documento.
        """
        # 1. Faz o upload do arquivo
        upload_endpoint = "uploads"
        files = {"file": (uploaded_file.filename, uploaded_file.read(), uploaded_file.content_type)}
        upload_response = self._make_request('POST', upload_endpoint, files=files)
        upload_id = upload_response["id"]

        # 2. Cria o documento com o ID do upload
        document_data = {
            "files": [{
                "displayName": uploaded_file.filename,
                "id": upload_id,
                "name": uploaded_file.filename,
                "contentType": "application/pdf"
            }],
            "flowActions": flow_actions
        }
        return self._make_request('POST', 'documents', json=document_data)

    def download_document(self, document_api_id, doc_type='Original'):
        """Baixa o conteúdo de um documento."""
        url = f"{self.base_url}/api/documents/{document_api_id}/content"
        headers_download = self.headers.copy()
        headers_download["accept"] = "*/*"

        try:
            response = requests.get(url, headers=headers_download, params={'type': doc_type})
            response.raise_for_status()
            return response.content
        except requests.exceptions.RequestException as e:
            print(f"Erro ao baixar o documento: {e}")
            raise

    def delete_document(self, document_api_id):
        """Deleta um documento na API."""
        self._make_request('DELETE', f"documents/{document_api_id}")

    def generate_action_url(self, document_api_id, email_address, flow_action_id):
        """Gera uma URL de ação para um signatário."""
        data_to_send = {
            'emailAddress': email_address,
            'requireEmailAuthentication': False,
            'flowActionId': flow_action_id
        }
        return self._make_request('POST', f"documents/{document_api_id}/action-url", json=data_to_send)