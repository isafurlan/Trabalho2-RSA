import argparse
from ChaveRSANode import ChaveRSANode
from AssinaturaPSSNode import AssinaturaPSSNode

def main():
    parser = argparse.ArgumentParser(description="Sistema de Assinatura Digital RSA-PSS")
    subparsers = parser.add_subparsers(dest="comando", help="Comandos disponíveis")
    parser_assinar = subparsers.add_parser("assinar", help="Gera a assinatura de um arquivo")
    parser_assinar.add_argument("--chave", required=True, help="Caminho para a chave privada (ex: private_key.json)")
    parser_assinar.add_argument("--arquivo", required=True, help="Arquivo que será assinado")
    parser_assinar.add_argument("--saida", required=True, help="Arquivo de saída para a assinatura em Base64")

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
            
    else:
        parser.print_help()

if __name__ == "__main__":
    main()