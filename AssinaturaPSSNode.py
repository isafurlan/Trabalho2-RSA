import os
import hashlib
import math
import base64

from MGF1Node import MGF1Node
from PrimitivasRSANode import PrimitivasRSANode

# Implementação da assinatura digital RSA-PSS da RFC 8017
class AssinaturaPSSNode:
    def __init__(self):
        self.tamanho_salt = MGF1Node.HLEN

    # Calcula e retorna o digest SHA3-256 do arquivo em bytes
    def calcular_digest_arquivo(self, caminho_arquivo):
        hasher = hashlib.sha3_256()
        try:
            with open(caminho_arquivo, 'rb') as f:
                for bloco in iter(lambda: f.read(4096), b""):
                    hasher.update(bloco)
            return hasher.digest()
        except FileNotFoundError:
            print(f"Erro: O ficheiro '{caminho_arquivo}' não foi encontrado.")
            return None

    # Implementa a codificação probabilística EMSA-PSS-ENCODE
    def codificacao_probabilistica_pss(self, m_hash, em_bits):
        em_len = math.ceil(em_bits / 8)
        h_len = MGF1Node.HLEN
        s_len = self.tamanho_salt

        if em_len < h_len + s_len + 2:
            raise ValueError("Erro de codificação: o módulo da chave é demasiado pequeno.")

        salt = os.urandom(s_len)

        m_linha = bytes(8) + m_hash + salt
        h = MGF1Node.sha3_256(m_linha)

        ps = bytes(em_len - s_len - h_len - 2)
        db = ps + bytes([0x01]) + salt

        db_mask = MGF1Node.MGF1(h, em_len - h_len - 1)

        masked_db_list = [a ^ b for a, b in zip(db, db_mask)]
        masked_db = bytes(masked_db_list)

        # Zera os bits mais significativos para garantir que o valor seja menor que o módulo
        bits_a_zerar = (8 * em_len) - em_bits
        if bits_a_zerar > 0:
            mascara_bits = 0xFF >> bits_a_zerar
            primeiro_byte_ajustado = masked_db[0] & mascara_bits
            masked_db = bytes([primeiro_byte_ajustado]) + masked_db[1:]

        em = masked_db + h + bytes([0xbc])

        return em

    # Orquestra o PSS e a assinatura matemática RSA, retornando em Base64
    def assinar_arquivo(self, caminho_arquivo, chave_privada):
        n = chave_privada['n']
        d = chave_privada['d']
        bits_modulo = n.bit_length()

        chave_tuplo = (n, d)
        
        m_hash = self.calcular_digest_arquivo(caminho_arquivo)
        if not m_hash:
            raise ValueError("Falha ao calcular o hash do ficheiro.")

        em = self.codificacao_probabilistica_pss(m_hash, bits_modulo - 1)

        m_inteiro = PrimitivasRSANode.OS2IP(em)
        assinatura_inteiro = PrimitivasRSANode.RSADP(chave_tuplo, m_inteiro)
        
        k = PrimitivasRSANode.key_size_bytes(n)
        assinatura_bytes = PrimitivasRSANode.I2OSP(assinatura_inteiro, k)

        assinatura_base64 = base64.b64encode(assinatura_bytes).decode('utf-8')

        return assinatura_base64