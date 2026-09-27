import random

class MillerRabinNode:
    def __init__(self):
        self.die = random.SystemRandom()
        self.bits = 1024 # Chave precisa de um minímo de 2048 bits

    def single_test(self, n, a):
        d = n - 1
        s = 0

        # n - 1 = 2^s * d
        while d % 2 == 0:
            d //= 2
            s += 1

        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            return True

        for _ in range(s - 1):
            x = pow(x, 2, n)

            if x == n - 1:
                return True

        return False


    def miller_rabin(self, n, k=40):
        if n < 2:
            return False

        if n == 2 or n == 3:
            return True

        if n % 2 == 0:
            return False

        for _ in range(k):
            a = self.die.randrange(2, n - 1)

            if not self.single_test(n, a):
                return False

        return True


    def generate_prime(self):
        while True:
            candidate = self.die.getrandbits(self.bits)

            # Garante que tenha exatamente self.bits bits
            candidate |= (1 << (self.bits - 1))

            # Garante que seja ímpar
            candidate |= 1

            if self.miller_rabin(candidate):
                return candidate