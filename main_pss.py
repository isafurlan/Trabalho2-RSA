import argparse
from ChaveRSANode import ChaveRSANode
from AssinaturaPSSNode import AssinaturaPSSNode
from VerificacaoPSSNode import VerificacaoPSSNode

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
            chave_privada = ChaveRSANode.import_private_key(args.chave)
            assinador = AssinaturaPSSNode()
            assinatura_b64 = assinador.assinar_arquivo(args.arquivo, chave_privada)
            with open(args.saida, "w") as f:
                f.write(assinatura_b64)
                
            print(f"Sucesso! Assinatura gerada e salva em '{args.saida}'.")
            
        except Exception as e:
            print(f"Erro: falha na assinatura ({e})")

    elif args.comando == "verificar":
        try:
            chave_publica = ChaveRSANode.import_public_key(args.chave)
            with open(args.assinatura, "r") as f:
                assinatura_b64 = f.read().strip()

            verificador = VerificacaoPSSNode()
            integro, mensagem = verificador.verificar_assinatura(args.arquivo, assinatura_b64, chave_publica)

            print(mensagem)
        except Exception as e:
            print(f"Erro: falha na execução da verificação ({e})")
            
    else:
        parser.print_help()

if __name__ == "__main__":
    main()