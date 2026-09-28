import hashlib

from PrimitivasRSANode import PrimitivasRSANode


# Função de geração de máscara MGF1 da RFC 8017 instanciada com SHA3-256
class MGF1Node:
    HLEN = 32

    # Retorna o digest SHA3-256 (32 bytes) dos dados
    @staticmethod
    def sha3_256(data):
        return hashlib.sha3_256(data).digest()

    # Gera uma máscara de maskLen bytes concatenando SHA3-256 (seed || contador)
    @staticmethod
    def MGF1(mgfSeed, maskLen):
        if maskLen > (2 ** 32) * MGF1Node.HLEN:
            raise ValueError("mask too long")

        T = b""
        counter = 0
        while len(T) < maskLen:
            C = PrimitivasRSANode.I2OSP(counter, 4)
            T += MGF1Node.sha3_256(mgfSeed + C)
            counter += 1

        return T[:maskLen]
