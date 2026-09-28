import os
import sys
import unittest
import base64

DIRETORIO_ATUAL = os.path.dirname(os.path.abspath(__file__))
DIRETORIO_RAIZ = os.path.dirname(DIRETORIO_ATUAL)
sys.path.insert(0, DIRETORIO_RAIZ)

from AssinaturaPSSNode import AssinaturaPSSNode
from VerificacaoPSSNode import VerificacaoPSSNode
from ChaveRSANode import ChaveRSANode
from MillerRabinNode import MillerRabinNode

class TestVerificacaoPSSNode(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        gerador = MillerRabinNode()
        while True:
            p = gerador.generate_prime()
            q = gerador.generate_prime()
            if p != q and (p * q).bit_length() >= 2048:
                break
                
        cls.chave = ChaveRSANode(p, q)
        cls.chave_publica = cls.chave.get_public_key()
        cls.chave_privada = cls.chave.get_private_key()

        cls.caminho_teste = os.path.join(DIRETORIO_ATUAL, "arquivo_verificacao.txt")
        with open(cls.caminho_teste, 'w') as f:
            f.write("Conteudo confidencial para testar a adulteracao RSA-PSS.")

        cls.assinador = AssinaturaPSSNode()
        cls.verificador = VerificacaoPSSNode()
        
        # Gera a assinatura íntegra que servirá de base
        cls.assinatura_valida = cls.assinador.assinar_arquivo(cls.caminho_teste, cls.chave_privada)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.caminho_teste):
            os.remove(cls.caminho_teste)
        if os.path.exists(cls.caminho_teste + ".corrompido"):
            os.remove(cls.caminho_teste + ".corrompido")

    # Verifica se uma assinatura correta é validada com sucesso
    def test_assinatura_integra(self):
        integro, msg = self.verificador.verificar_assinatura(
            self.caminho_teste, self.assinatura_valida, self.chave_publica
        )
        self.assertTrue(integro, "A assinatura original deve ser considerada íntegra.")

    # Testa a adulteração de exatamente 1 byte no ficheiro original
    def test_adulterar_um_byte_arquivo(self):
        caminho_corrompido = self.caminho_teste + ".corrompido"
        
        with open(self.caminho_teste, 'rb') as f:
            dados = bytearray(f.read())
            
        dados[10] ^= 0xFF  # Inverte os bits do 10º byte
        
        with open(caminho_corrompido, 'wb') as f:
            f.write(dados)

        integro, msg = self.verificador.verificar_assinatura(
            caminho_corrompido, self.assinatura_valida, self.chave_publica
        )
        self.assertFalse(integro, "O verificador deve rejeitar um ficheiro com 1 byte corrompido.")

    # Testa a adulteração de exatamente 1 byte na assinatura Base64
    def test_adulterar_um_byte_assinatura(self):
        assinatura_bytes = bytearray(base64.b64decode(self.assinatura_valida))
        assinatura_bytes[50] ^= 0xFF # Inverte os bits do 50º byte
        
        assinatura_corrompida = base64.b64encode(assinatura_bytes).decode('utf-8')
        
        integro, msg = self.verificador.verificar_assinatura(
            self.caminho_teste, assinatura_corrompida, self.chave_publica
        )
        self.assertFalse(integro, "O verificador deve rejeitar uma assinatura com 1 byte corrompido.")

    # Testa a verificação utilizando uma chave pública adulterada (módulo errado)
    def test_adulterar_chave_publica(self):
        chave_corrompida = {
            "n": self.chave_publica["n"] + 1,
            "e": self.chave_publica["e"]
        }
        
        integro, msg = self.verificador.verificar_assinatura(
            self.caminho_teste, self.assinatura_valida, chave_corrompida
        )
        self.assertFalse(integro, "O verificador deve rejeitar a verificação se a chave pública for alterada.")

if __name__ == '__main__':
    unittest.main()