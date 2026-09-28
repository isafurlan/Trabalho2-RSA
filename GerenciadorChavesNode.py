import MillerRabinNode
import ChaveRSANode


# Erro lançado quando um arquivo de chave está ausente, corrompido ou inválido
class InvalidKeyError(Exception):
    pass


# Geração de chaves e carregamento validado dos arquivos JSON da Parte I
class GerenciadorChavesNode:
    MIN_KEY_BITS = 2048

    # Gera uma chave RSA com a Parte I, garantindo p != q e módulo de pelo menos 2048 bits
    @staticmethod
    def generate_key():
        gerador = MillerRabinNode.MillerRabinNode()

        while True:
            p = gerador.generate_prime()
            q = gerador.generate_prime()

            if p == q or (p * q).bit_length() < GerenciadorChavesNode.MIN_KEY_BITS:
                continue

            try:
                return ChaveRSANode.ChaveRSANode(p, q)
            except ValueError:
                continue

    # Lê o JSON da chave com a função de importação da Parte I,
    # convertendo falhas em InvalidKeyError
    @staticmethod
    def _import(import_function, filename):
        try:
            conteudo = import_function(filename)
        except FileNotFoundError:
            raise InvalidKeyError(f"arquivo de chave não encontrado: {filename}") from None
        except OSError as erro:
            raise InvalidKeyError(f"não foi possível ler {filename}: {erro.strerror}") from None
        except ValueError:
            raise InvalidKeyError(f"arquivo de chave corrompido (JSON inválido): {filename}") from None

        if not isinstance(conteudo, dict):
            raise InvalidKeyError(f"formato de chave inválido: {filename}")

        return conteudo

    # Retorna o campo pedido, exigindo que exista e seja um inteiro positivo
    @staticmethod
    def _int_field(conteudo, campo, filename, tipo):
        if campo not in conteudo:
            raise InvalidKeyError(
                f"campo '{campo}' ausente em {filename} (este arquivo é uma chave {tipo}?)"
            )

        valor = conteudo[campo]
        if not isinstance(valor, int) or isinstance(valor, bool) or valor <= 0:
            raise InvalidKeyError(f"campo '{campo}' inválido em {filename}")

        return valor

    # Rejeita módulos com menos de 2048 bits
    @staticmethod
    def _validate_modulus(n, filename):
        if n.bit_length() < GerenciadorChavesNode.MIN_KEY_BITS:
            raise InvalidKeyError(
                f"módulo com {n.bit_length()} bits em {filename}; "
                f"o mínimo é {GerenciadorChavesNode.MIN_KEY_BITS} bits"
            )

    # Carrega e valida a chave pública, retornando a tupla (n, e)
    @staticmethod
    def load_public_key(filename):
        conteudo = GerenciadorChavesNode._import(ChaveRSANode.ChaveRSANode.import_public_key, filename)

        n = GerenciadorChavesNode._int_field(conteudo, "n", filename, "pública")
        e = GerenciadorChavesNode._int_field(conteudo, "e", filename, "pública")

        GerenciadorChavesNode._validate_modulus(n, filename)
        if not 1 < e < n:
            raise InvalidKeyError(f"expoente público fora do intervalo em {filename}")

        return n, e

    # Carrega e valida a chave privada, retornando a tupla (n, d)
    @staticmethod
    def load_private_key(filename):
        conteudo = GerenciadorChavesNode._import(ChaveRSANode.ChaveRSANode.import_private_key, filename)

        n = GerenciadorChavesNode._int_field(conteudo, "n", filename, "privada")
        d = GerenciadorChavesNode._int_field(conteudo, "d", filename, "privada")

        GerenciadorChavesNode._validate_modulus(n, filename)
        if not d < n:
            raise InvalidKeyError(f"expoente privado fora do intervalo em {filename}")

        return n, d
