# Primitivas de conversão e de cifragem RSA da RFC 8017, compartilhadas pelo OAEP e pelo PSS
class PrimitivasRSANode:

    # Retorna k, o tamanho do módulo n em bytes
    @staticmethod
    def key_size_bytes(n):
        return (n.bit_length() + 7) // 8

    # Converte um inteiro em xLen bytes big-endian
    @staticmethod
    def I2OSP(x, xLen):
        if x < 0:
            raise ValueError("integer must be non-negative")

        if x >= 256 ** xLen:
            raise ValueError("integer too large")

        return x.to_bytes(xLen, "big")

    # Converte bytes big-endian em um inteiro não negativo
    @staticmethod
    def OS2IP(X):
        return int.from_bytes(X, "big")

    # Cifragem RSA pura, c = m^e mod n, com verificação de 0 <= m < n
    @staticmethod
    def RSAEP(public_key, m):
        n, e = public_key

        if not 0 <= m < n:
            raise ValueError("message representative out of range")

        return pow(m, e, n)

    # Decifragem RSA pura, m = c^d mod n, com verificação de 0 <= c < n
    @staticmethod
    def RSADP(private_key, c):
        n, d = private_key

        if not 0 <= c < n:
            raise ValueError("ciphertext representative out of range")

        return pow(c, d, n)
