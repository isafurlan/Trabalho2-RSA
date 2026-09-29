import argparse
import sys
from AssinaturaPSSNode import AssinaturaPSSNode
from VerificacaoPSSNode import VerificacaoPSSNode
from GerenciadorChavesNode import GerenciadorChavesNode, InvalidKeyError

def main():
    parser = argparse.ArgumentParser(description="Sistema de Assinatura Digital RSA-PSS")
    subparsers = parser.add_subparsers(dest="comando", help="Comandos disponíveis")
    parser_assinar = subparsers.add_parser("assinar", help="Gera a assinatura de um arquivo")
    parser_assinar.add_argument("--chave", required=True, help="Caminho para a chave privada (ex: private_key.json)")
    parser_assinar.add_argument("--arquivo", required=True, help="Arquivo que será assinado")
    parser_assinar.add_argument("--saida", required=True, help="Arquivo de saída para a assinatura em Base64")

    parser_verificar = subparsers.add_parser("verificar", help="Verifica a assinatura de um arquivo")
    parser_verificar.add_argument("--chave", required=True, help="Chave pública (JSON)")
    parser_verificar.add_argument("--arquivo", required=True, help="Arquivo que será verificado")
    parser_verificar.add_argument("--assinatura", required=True, help="Assinatura em Base64")

    args = parser.parse_args()

    if args.comando == "assinar":
        try:
            n, d = GerenciadorChavesNode.load_private_key(args.chave)
            chave_privada = {"n": n, "d": d}
            # Garante que o arquivo existe antes de assinar
            with open(args.arquivo, "rb"):
                pass
            assinador = AssinaturaPSSNode()
            assinatura_b64 = assinador.assinar_arquivo(args.arquivo, chave_privada)
            with open(args.saida, "w") as f:
                f.write(assinatura_b64)

            print(f"Sucesso! Assinatura gerada e salva em '{args.saida}'.")
            return 0

        except InvalidKeyError as e:
            print(f"Erro: {e}")
        except OSError as e:
            print(f"Erro: não foi possível acessar o arquivo '{e.filename}'.")
        except ValueError:
            print("Erro: falha na assinatura.")
        return 1

    elif args.comando == "verificar":
        try:
            n, e = GerenciadorChavesNode.load_public_key(args.chave)
            chave_publica = {"n": n, "e": e}
            with open(args.assinatura, "r") as f:
                assinatura_b64 = f.read().strip()
            # Garante que o arquivo existe antes de verificar
            with open(args.arquivo, "rb"):
                pass

            verificador = VerificacaoPSSNode()
            integro, mensagem = verificador.verificar_assinatura(args.arquivo, assinatura_b64, chave_publica)

            print(mensagem)
            return 0 if integro else 1
        except InvalidKeyError as erro:
            print(f"Erro: {erro}")
        except OSError as erro:
            print(f"Erro: não foi possível acessar o arquivo '{erro.filename}'.")
        return 1

    else:
        parser.print_help()
        return 1

if __name__ == "__main__":
    sys.exit(main())
