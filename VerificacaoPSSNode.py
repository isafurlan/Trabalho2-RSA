import hashlib
import math
import base64

from MGF1Node import MGF1Node
from PrimitivasRSANode import PrimitivasRSANode

class VerificacaoPSSNode:
    def __init__(self):
        self.h_len = MGF1Node.HLEN
        self.s_len = MGF1Node.HLEN

    def calcular_digest_arquivo(self, caminho_arquivo):
        hasher = hashlib.sha3_256()
        with open(caminho_arquivo, 'rb') as f:
            for bloco in iter(lambda: f.read(4096), b''):
                hasher.update(bloco)
        return hasher.digest()

    def verificar_assinatura(self, caminho_arquivo, assinatura_b64, chave_publica):
        try:
            n = chave_publica['n']
            e = chave_publica['e']
            chave_tuplo = (n, e)
            bits_modulo = n.bit_length()
            em_bits = bits_modulo - 1
            em_len = math.ceil(em_bits / 8)

            # Parsing da assinatura
            assinatura_bytes = base64.b64decode(assinatura_b64)
            k = PrimitivasRSANode.key_size_bytes(n)
            if len(assinatura_bytes) != k:
                return False, 'Assinatura inválida: tamanho incorreto'

            # Verificação matemática RSA
            s_inteiro = PrimitivasRSANode.OS2IP(assinatura_bytes)
            m_inteiro = PrimitivasRSANode.RSAEP(chave_tuplo, s_inteiro)
            em = PrimitivasRSANode.I2OSP(m_inteiro, em_len)

            # Verificação do EMSA-PSS
            m_hash = self.calcular_digest_arquivo(caminho_arquivo)
            if em_len < self.h_len + self.s_len + 2:
                return False, 'Assinatura inválida: comprimento do EM insuficiente'
            if em[-1] != 0xbc:
                return False, 'Assinatura inválida: byte final incorreto'
            masked_db = em[:em_len - self.h_len - 1]
            h = em[em_len - self.h_len - 1:em_len - 1]

            # Verifica os bits mais significativos antes da máscara
            bits_a_zerar = 8 * em_len - em_bits
            if bits_a_zerar > 0:
                mascara_verificacao = 0xFF << (8 - bits_a_zerar)
                if (masked_db[0] & (mascara_verificacao & 0xFF)) != 0:
                    return False, 'Assinatura inválida: bits mais significativos incorretos'

            db_mask = MGF1Node.MGF1(h, em_len - self.h_len - 1)
            db_list = [a ^ b for a, b in zip(masked_db, db_mask)]

            # Limpa o bit mais significativo no DB recuperado
            if bits_a_zerar > 0:
                mascara_bits = 0xFF >> bits_a_zerar
                db_list[0] &= mascara_bits
            db = bytes(db_list)

            # Validação do padding e do salt
            tamanho_ps = em_len - self.s_len - self.h_len - 2
            for i in range(tamanho_ps):
                if db[i] != 0x00:
                    return False, 'Assinatura inválida: padding incorreto (bytes nulos ausentes)'
                if db[tamanho_ps] != 0x01:
                    return False, 'Assinatura inválida: padding incorreto (byte 0x01 ausente)'

            salt = db[-self.s_len:]
            m_linha = bytes(8) + m_hash + salt
            h_linha = MGF1Node.sha3_256(m_linha)

            if h == h_linha:
                return True, 'VERIFICADO: O arquivo é íntegro e a assinatura é válida.'
            else:
                return False, 'REJEITADO: A assinatura é inválida (os hashes não correspondem).'

        except Exception:
            return False, 'REJEITADO: Estrutura inválida ou corrompida.'