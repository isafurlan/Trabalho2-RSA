import argparse
import base64
import binascii
import sys

from CifragemOAEPNode import CifragemOAEPNode, DecryptionError, MessageTooLongError
from GerenciadorChavesNode import GerenciadorChavesNode, InvalidKeyError
from PrimitivasRSANode import PrimitivasRSANode

DECRYPTION_ERROR_MESSAGE = "Erro: falha na decifragem (ciphertext inválido ou adulterado)"


# Erro de leitura ou escrita de arquivos informados na linha de comando
class InputError(Exception):
    pass


# Lê um arquivo em bytes, convertendo falhas de acesso em InputError
def _read_file(filename):
    try:
        with open(filename, "rb") as file:
            return file.read()
    except OSError as erro:
        raise InputError(f"não foi possível ler {filename}: {erro.strerror}") from None


# Grava bytes em um arquivo, convertendo falhas de acesso em InputError
def _write_file(filename, conteudo):
    try:
        with open(filename, "wb") as file:
            file.write(conteudo)
    except OSError as erro:
        raise InputError(f"não foi possível escrever {filename}: {erro.strerror}") from None


# Gera um par de chaves de 2048 bits e exporta nos arquivos JSON da Parte I
def command_generate_keys(args):
    print("Gerando par de chaves RSA de 2048 bits...")
    chave = GerenciadorChavesNode.generate_key()

    try:
        chave.export_public_key(args.publica)
        chave.export_private_key(args.privada)
    except OSError as erro:
        raise InputError(f"não foi possível salvar as chaves: {erro}") from None

    print(f"Módulo n com {chave.n.bit_length()} bits.")
    print(f"Chave pública salva em {args.publica}")
    print(f"Chave privada salva em {args.privada}")
    return 0


# Cifra a mensagem com a chave pública e mostra o ciphertext em Base64
def command_encrypt(args):
    public_key = GerenciadorChavesNode.load_public_key(args.chave)

    if args.mensagem is not None:
        M = args.mensagem.encode("utf-8")
    else:
        M = _read_file(args.arquivo)

    L = args.label.encode("utf-8")

    try:
        C = CifragemOAEPNode.encrypt(public_key, M, L)
    except MessageTooLongError:
        limite = CifragemOAEPNode.max_message_length(PrimitivasRSANode.key_size_bytes(public_key[0]))
        print(f"Erro: mensagem longa demais ({len(M)} bytes; o máximo para esta chave é {limite} bytes).",
              file=sys.stderr)
        return 1

    C_base64 = base64.b64encode(C).decode("ascii")

    if args.saida:
        _write_file(args.saida, C_base64.encode("ascii"))
        print(f"Ciphertext (Base64) salvo em {args.saida}")
    else:
        print(C_base64)

    return 0


# Decifra o ciphertext em Base64 com a chave privada e mostra a mensagem
def command_decrypt(args):
    private_key = GerenciadorChavesNode.load_private_key(args.chave)

    if args.ciphertext is not None:
        texto = args.ciphertext
    else:
        texto = _read_file(args.arquivo_cifrado).decode("ascii", errors="replace")

    try:
        C = base64.b64decode("".join(texto.split()), validate=True)
    except (binascii.Error, ValueError):
        print("Erro: o ciphertext não está em Base64 válido.", file=sys.stderr)
        return 1

    L = args.label.encode("utf-8")

    try:
        M = CifragemOAEPNode.decrypt(private_key, C, L)
    except DecryptionError:
        print(DECRYPTION_ERROR_MESSAGE, file=sys.stderr)
        return 1

    if args.saida:
        _write_file(args.saida, M)
        print(f"Mensagem decifrada ({len(M)} bytes) salva em {args.saida}")
        return 0

    try:
        print(M.decode("utf-8"))
    except UnicodeDecodeError:
        print(f"Mensagem decifrada tem {len(M)} bytes e não é texto UTF-8; use --saida para salvá-la em arquivo.")

    return 0


# Define os subcomandos gerar-chaves, cifrar e decifrar e suas opções
def create_parser():
    parser = argparse.ArgumentParser(
        prog="main_oaep.py",
        description="Cifragem e decifragem RSA-OAEP (RFC 8017) com SHA3-256 e MGF1.",
    )
    subparsers = parser.add_subparsers(dest="comando", required=True)

    gerar = subparsers.add_parser("gerar-chaves", help="gera um par de chaves RSA de 2048 bits (Parte I)")
    gerar.add_argument("--publica", default="public_key.json", help="arquivo da chave pública")
    gerar.add_argument("--privada", default="private_key.json", help="arquivo da chave privada")
    gerar.set_defaults(funcao=command_generate_keys)

    cifrar = subparsers.add_parser("cifrar", help="cifra uma mensagem curta com a chave pública")
    cifrar.add_argument("--chave", required=True, help="arquivo JSON da chave pública")
    origem = cifrar.add_mutually_exclusive_group(required=True)
    origem.add_argument("--mensagem", help="mensagem em texto (codificada em UTF-8)")
    origem.add_argument("--arquivo", help="arquivo com a mensagem (lido como bytes)")
    cifrar.add_argument("--label", default="", help="label L do OAEP (padrão: vazio)")
    cifrar.add_argument("--saida", help="salva o ciphertext em Base64 neste arquivo")
    cifrar.set_defaults(funcao=command_encrypt)

    decifrar = subparsers.add_parser("decifrar", help="decifra um ciphertext em Base64 com a chave privada")
    decifrar.add_argument("--chave", required=True, help="arquivo JSON da chave privada")
    origem = decifrar.add_mutually_exclusive_group(required=True)
    origem.add_argument("--ciphertext", help="ciphertext em Base64")
    origem.add_argument("--arquivo-cifrado", help="arquivo com o ciphertext em Base64")
    decifrar.add_argument("--label", default="", help="label L usado na cifragem (padrão: vazio)")
    decifrar.add_argument("--saida", help="salva a mensagem decifrada neste arquivo")
    decifrar.set_defaults(funcao=command_decrypt)

    return parser


# Executa o subcomando escolhido e transforma erros de entrada em mensagens sem stack trace
def main(argv=None):
    args = create_parser().parse_args(argv)

    try:
        return args.funcao(args)
    except (InvalidKeyError, InputError) as erro:
        print(f"Erro: {erro}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
