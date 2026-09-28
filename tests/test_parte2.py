import contextlib
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import main_oaep
from CifragemOAEPNode import CifragemOAEPNode, DecryptionError, MessageTooLongError
from GerenciadorChavesNode import GerenciadorChavesNode
from MGF1Node import MGF1Node
from PrimitivasRSANode import PrimitivasRSANode

HLEN = MGF1Node.HLEN
I2OSP = PrimitivasRSANode.I2OSP
OS2IP = PrimitivasRSANode.OS2IP


class TestParte2(unittest.TestCase):

    # Gera uma única vez a chave de teste e uma segunda chave para o teste de chave errada.
    @classmethod
    def setUpClass(cls):
        cls.chave = GerenciadorChavesNode.generate_key()
        outra = GerenciadorChavesNode.generate_key()
        cls.pub = (cls.chave.n, cls.chave.e)
        cls.priv = (cls.chave.n, cls.chave.d)
        cls.outra_priv = (outra.n, outra.d)
        cls.k = PrimitivasRSANode.key_size_bytes(cls.chave.n)

    # Verifica que decifrar C gera DecryptionError com a mensagem genérica.
    def assertDecryptionError(self, C, L=b"", private_key=None):
        with self.assertRaises(DecryptionError) as contexto:
            CifragemOAEPNode.decrypt(private_key or self.priv, C, L)
        self.assertEqual(str(contexto.exception), "decryption error")

    def test_cifrar_e_decifrar(self):
        mensagens = {"vazia": b"", "utf8": "Segurança — ção, é".encode("utf-8"), "190 bytes": os.urandom(190)}
        for nome, M in mensagens.items():
            with self.subTest(caso=nome):
                C = CifragemOAEPNode.encrypt(self.pub, M)
                self.assertEqual(len(C), self.k)
                self.assertEqual(CifragemOAEPNode.decrypt(self.priv, C), M)

    def test_mensagem_acima_do_limite_rejeitada(self):
        with self.assertRaises(MessageTooLongError):
            CifragemOAEPNode.encrypt(self.pub, os.urandom(191))

    def test_cifragem_probabilistica(self):
        M = b"mesma mensagem"
        self.assertNotEqual(CifragemOAEPNode.encrypt(self.pub, M), CifragemOAEPNode.encrypt(self.pub, M))

    def test_mgf1_tamanho_e_determinismo(self):
        for maskLen in [0, 1, 32, 33, 223]:
            self.assertEqual(len(MGF1Node.MGF1(b"seed", maskLen)), maskLen)
        self.assertEqual(MGF1Node.MGF1(b"seed", 223), MGF1Node.MGF1(b"seed", 223))

    def test_ciphertext_adulterado_detectado(self):
        C = CifragemOAEPNode.encrypt(self.pub, b"mensagem secreta")
        for posicao in [0, self.k // 2, self.k - 1]:
            with self.subTest(posicao=posicao):
                adulterado = bytearray(C)
                adulterado[posicao] ^= 0x01
                self.assertDecryptionError(bytes(adulterado))

    def test_chave_errada_falha(self):
        C = CifragemOAEPNode.encrypt(self.pub, b"mensagem")
        self.assertDecryptionError(C, private_key=self.outra_priv)

    def test_label_diferente(self):
        C = CifragemOAEPNode.encrypt(self.pub, b"mensagem", b"label A")
        self.assertEqual(CifragemOAEPNode.decrypt(self.priv, C, b"label A"), b"mensagem")
        self.assertDecryptionError(C, b"label B")

    # Monta EMs com cada tipo de erro de padding e confere que todos geram o mesmo erro genérico.
    def test_erros_de_padding_tem_mensagem_unica(self):
        M = b"mensagem"
        lHash = MGF1Node.sha3_256(b"")
        PS = bytes(self.k - len(M) - 2 * HLEN - 2)

        def cifrar_em(DB, Y=0x00):
            seed = os.urandom(HLEN)
            maskedDB = CifragemOAEPNode._xor(DB, MGF1Node.MGF1(seed, self.k - HLEN - 1))
            maskedSeed = CifragemOAEPNode._xor(seed, MGF1Node.MGF1(maskedDB, HLEN))
            EM = bytes([Y]) + maskedSeed + maskedDB
            return I2OSP(PrimitivasRSANode.RSAEP(self.pub, OS2IP(EM)), self.k)

        casos = {
            "lHash errado": cifrar_em(MGF1Node.sha3_256(b"outro") + PS + b"\x01" + M),
            "PS com byte nao nulo": cifrar_em(lHash + b"\x07" + PS[1:] + b"\x01" + M),
            "sem separador 0x01": cifrar_em(lHash + bytes(self.k - 2 * HLEN - 1)),
            "Y diferente de 0x00": cifrar_em(lHash + PS + b"\x01" + M, Y=0x01),
            "c >= n": I2OSP(self.chave.n, self.k),
            "tamanho errado": b"\x00" * (self.k - 1),
        }
        for nome, C in casos.items():
            with self.subTest(caso=nome):
                self.assertDecryptionError(C)

    # Pela linha de comando, arquivo de chave inválido e ciphertext adulterado geram erro curto, sem stack trace.
    def test_cli_entradas_invalidas(self):
        with tempfile.TemporaryDirectory() as pasta:
            publica = os.path.join(pasta, "public_key.json")
            privada = os.path.join(pasta, "private_key.json")
            self.chave.export_public_key(publica)
            self.chave.export_private_key(privada)

            casos = {
                "chave inexistente": ["cifrar", "--chave", os.path.join(pasta, "x.json"), "--mensagem", "x"],
                "chave privada para cifrar": ["cifrar", "--chave", privada, "--mensagem", "x"],
                "base64 invalido": ["decifrar", "--chave", privada, "--ciphertext", "@@@"],
                "ciphertext adulterado": ["decifrar", "--chave", privada, "--ciphertext", "A" * 344],
            }
            for nome, argv in casos.items():
                with self.subTest(caso=nome):
                    erro = io.StringIO()
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(erro):
                        codigo = main_oaep.main(argv)
                    self.assertEqual(codigo, 1)
                    self.assertTrue(erro.getvalue().startswith("Erro:"))


if __name__ == '__main__':
    unittest.main()
