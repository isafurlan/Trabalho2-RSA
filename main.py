import MillerRabinNode
import ChaveRSANode


def main():

    # =========================
    # Geração dos primos
    # =========================

    gerador = MillerRabinNode.MillerRabinNode()

    while True:

        p = gerador.generate_prime()
        q = gerador.generate_prime()

        if p != q and (p * q).bit_length() >= 2048:
            break

    # =========================
    # Construção das chaves RSA
    # =========================

    chave = ChaveRSANode.ChaveRSANode(p, q)

    # =========================
    # Exibição
    # =========================

    print("p:", p)
    print("q:", q)

    print("\nn:", chave.n)
    print("bits de n:", chave.n.bit_length())

    print("\nphi(n):", chave.phi)

    print("\ne:", chave.e)
    print("d:", chave.d)

    print("\nChave pública:")
    print(chave.get_public_key())

    print("\nChave privada:")
    print(chave.get_private_key())

    # =========================
    # Teste da relação RSA
    # =========================

    print("\nVerificação de e*d mod phi:")
    print((chave.e * chave.d) % chave.phi) # = 1

    # =========================
    # Exportação
    # =========================

    chave.export_public_key("public_key.json")
    chave.export_private_key("private_key.json")

    print("\nChaves exportadas.")

    # =========================
    # Importação
    # =========================

    public_key = ChaveRSANode.ChaveRSANode.import_public_key(
        "public_key.json"
    )

    private_key = ChaveRSANode.ChaveRSANode.import_private_key(
        "private_key.json"
    )

    print("\nChave pública importada:")
    print(public_key)

    print("\nChave privada importada:")
    print(private_key)


if __name__ == '__main__':
    main()