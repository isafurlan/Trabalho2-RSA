import os
import sys
import unittest

DIRETORIO_ATUAL = os.path.dirname(os.path.abspath(__file__))
DIRETORIO_RAIZ = os.path.dirname(DIRETORIO_ATUAL)
sys.path.insert(0, DIRETORIO_RAIZ)

from AssinaturaPSSNode import AssinaturaPSSNode

# Testes unitários da Parte 3
class TestAssinaturaPSSNode(unittest.TestCase):

    # Inicializa o assinador, cria o arquivo temporário e define a chave mockada
    def setUp(self):
        self.assinador = AssinaturaPSSNode()
        self.caminho_teste = os.path.join(DIRETORIO_ATUAL, "arquivo_temporario.txt")
        with open(self.caminho_teste, 'w') as f:
            f.write("Conteúdo para teste de assinatura PSS.")
        # Chave RSA pequena para teste          
        self.chave_mock = {'n': 3233, 'd': 2753}
        
    def test_calcular_digest_arquivo(self):
        digest = self.assinador.calcular_digest_arquivo(self.caminho_teste)
        
        self.assertIsNotNone(digest, "O digest não deve ser nulo.")
        self.assertEqual(len(digest), 32, "SHA3-256 tem de gerar exatamente 32 bytes.")

    # Remove o arquivo temporário após o teste
    def tearDown(self):
        if os.path.exists(self.caminho_teste):
            os.remove(self.caminho_teste)

    # Verifica se o método trata corretamente exceções de arquivo n~~ao encontrado
    def test_calcular_digest_arquivo_inexistente(self):
        digest = self.assinador.calcular_digest_arquivo("arquivo_inexistente.txt")
        self.assertIsNone(digest)

if __name__ == '__main__':
    unittest.main()