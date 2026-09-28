import math
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import MillerRabinNode
import ChaveRSANode
from GerenciadorChavesNode import GerenciadorChavesNode, InvalidKeyError


class TestParte1(unittest.TestCase):

    # Gera uma única chave de 2048 bits para todos os testes.
    @classmethod
    def setUpClass(cls):
        cls.gerador = MillerRabinNode.MillerRabinNode()
        cls.chave = GerenciadorChavesNode.generate_key()

    def test_miller_rabin_primos_e_compostos(self):
        for n in [2, 3, 5, 97, 7919, 2 ** 127 - 1]:
            self.assertTrue(self.gerador.miller_rabin(n), n)
        # Compostos comuns e números de Carmichael
        for n in [0, 1, 4, 100, 7917, 561, 1105, 1729, 2465, 2821, 6601, 8911]:
            self.assertFalse(self.gerador.miller_rabin(n), n)

    def test_primo_gerado_tem_1024_bits(self):
        p = self.gerador.generate_prime()
        self.assertEqual(p.bit_length(), 1024)
        self.assertTrue(self.gerador.miller_rabin(p))

    def test_chave_parametros_corretos(self):
        chave = self.chave
        self.assertNotEqual(chave.p, chave.q)
        self.assertEqual(chave.n, chave.p * chave.q)
        self.assertGreaterEqual(chave.n.bit_length(), 2048)
        self.assertEqual(math.gcd(chave.e, chave.phi), 1)
        self.assertEqual((chave.e * chave.d) % chave.phi, 1)

    def test_exportar_e_importar_chave(self):
        with tempfile.TemporaryDirectory() as pasta:
            publica = os.path.join(pasta, "public_key.json")
            privada = os.path.join(pasta, "private_key.json")
            self.chave.export_public_key(publica)
            self.chave.export_private_key(privada)

            self.assertEqual(ChaveRSANode.ChaveRSANode.import_public_key(publica), self.chave.get_public_key())
            self.assertEqual(ChaveRSANode.ChaveRSANode.import_private_key(privada), self.chave.get_private_key())

    # A importação da Parte I é validada pelo GerenciadorChavesNode, que converte qualquer falha em InvalidKeyError.
    def test_importar_arquivo_invalido(self):
        with tempfile.TemporaryDirectory() as pasta:
            casos = {"inexistente": None, "corrompido": '{"n": 123', "sem_e": '{"n": 12345}', "lista": "[1, 2]"}
            for nome, conteudo in casos.items():
                with self.subTest(caso=nome):
                    arquivo = os.path.join(pasta, nome + ".json")
                    if conteudo is not None:
                        with open(arquivo, "w") as file:
                            file.write(conteudo)
                    with self.assertRaises(InvalidKeyError):
                        GerenciadorChavesNode.load_public_key(arquivo)


if __name__ == '__main__':
    unittest.main()
