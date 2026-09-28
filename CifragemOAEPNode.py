import hmac
import secrets

from MGF1Node import MGF1Node
from PrimitivasRSANode import PrimitivasRSANode

HLEN = MGF1Node.HLEN


# Erro lançado quando a mensagem ultrapassa k - 2hLen - 2 bytes
class MessageTooLongError(ValueError):
    def __init__(self):
        super().__init__("message too long")


# Erro único da decifragem, que não revela qual verificação falhou
class DecryptionError(Exception):
    def __init__(self):
        super().__init__("decryption error")


# Cifragem e decifragem RSAES-OAEP da RFC 8017 com SHA3-256 e MGF1
class CifragemOAEPNode:

    # Faz o XOR byte a byte de duas sequências de mesmo tamanho
    @staticmethod
    def _xor(a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    # Retorna o tamanho máximo da mensagem em bytes para um módulo de k bytes
    @staticmethod
    def max_message_length(k):
        return k - 2 * HLEN - 2

    # Codifica M no bloco EM = 0x00 || maskedSeed || maskedDB de k bytes
    @staticmethod
    def eme_oaep_encode(M, k, L=b"", seed=None):
        mLen = len(M)
        if mLen > CifragemOAEPNode.max_message_length(k):
            raise MessageTooLongError()

        lHash = MGF1Node.sha3_256(L)
        PS = bytes(k - mLen - 2 * HLEN - 2)
        DB = lHash + PS + b"\x01" + M

        if seed is None:
            seed = secrets.token_bytes(HLEN)
        elif len(seed) != HLEN:
            raise ValueError("seed must have hLen bytes")

        dbMask = MGF1Node.MGF1(seed, k - HLEN - 1)
        maskedDB = CifragemOAEPNode._xor(DB, dbMask)

        seedMask = MGF1Node.MGF1(maskedDB, HLEN)
        maskedSeed = CifragemOAEPNode._xor(seed, seedMask)

        return b"\x00" + maskedSeed + maskedDB

    # Decodifica EM avaliando todas as verificações sem retorno antecipado,
    # para evitar oráculo de padding (ataque de Manger)
    @staticmethod
    def eme_oaep_decode(EM, k, L=b""):
        lHash = MGF1Node.sha3_256(L)

        Y = EM[0]
        maskedSeed = EM[1:1 + HLEN]
        maskedDB = EM[1 + HLEN:]

        seedMask = MGF1Node.MGF1(maskedDB, HLEN)
        seed = CifragemOAEPNode._xor(maskedSeed, seedMask)

        dbMask = MGF1Node.MGF1(seed, k - HLEN - 1)
        DB = CifragemOAEPNode._xor(maskedDB, dbMask)

        lHash_linha = DB[:HLEN]
        resto = DB[HLEN:]

        encontrou = 0
        indice = 0
        ps_invalido = 0
        for i, byte in enumerate(resto):
            eh_um = int(byte == 0x01)
            eh_zero = int(byte == 0x00)
            primeiro_um = eh_um & (1 - encontrou)
            indice |= i * primeiro_um
            ps_invalido |= (1 - encontrou) & (1 - eh_zero) & (1 - eh_um)
            encontrou |= eh_um

        lhash_ok = int(hmac.compare_digest(lHash_linha, lHash))
        y_ok = int(Y == 0x00)

        valido = y_ok & lhash_ok & encontrou & (1 - ps_invalido)
        if not valido:
            raise DecryptionError()

        return resto[indice + 1:]

    # Cifra M com a chave pública (n, e)
    @staticmethod
    def encrypt(public_key, M, L=b"", seed=None):
        n, e = public_key
        k = PrimitivasRSANode.key_size_bytes(n)

        EM = CifragemOAEPNode.eme_oaep_encode(M, k, L, seed)
        m = PrimitivasRSANode.OS2IP(EM)
        c = PrimitivasRSANode.RSAEP((n, e), m)

        return PrimitivasRSANode.I2OSP(c, k)

    # Decifra C com a chave privada (n, d), lançando DecryptionError em qualquer falha
    @staticmethod
    def decrypt(private_key, C, L=b""):
        n, d = private_key
        k = PrimitivasRSANode.key_size_bytes(n)

        if len(C) != k or k < 2 * HLEN + 2:
            raise DecryptionError()

        c = PrimitivasRSANode.OS2IP(C)

        try:
            m = PrimitivasRSANode.RSADP((n, d), c)
        except ValueError:
            raise DecryptionError() from None

        EM = PrimitivasRSANode.I2OSP(m, k)

        return CifragemOAEPNode.eme_oaep_decode(EM, k, L)
