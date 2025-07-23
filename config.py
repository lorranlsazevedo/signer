# config.py
import os


class Config:
    """
    Classe de configuração para o Flask.
    Usa variáveis de ambiente para dados sensíveis e fornece valores padrão
    para o ambiente de desenvolvimento.
    """
    SECRET_KEY = os.environ.get('SECRET_KEY', '2765570032dac2476be7ef0c1c50a9db')

    DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database', 'signer_database.db')

    SIGNER_API_KEY = os.environ.get('SIGNER_API_KEY',
                                    '9b38597a67692b42aa96f9810d18f36dec3ff49a0ca5059054f1d7f1e13364ff')
    SIGNER_BASE_URL = os.environ.get('SIGNER_BASE_URL', 'https://www.dropsigner.com')

    ITEMS_PER_PAGE = 12

    LDAP_VALIDATE_TOKEN_URL = 'https://auth.sleiloesjudiciais.com.br/api/ldap/validate-token'