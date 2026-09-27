import json
import math


class ChaveRSANode:
    def __init__(self, p, q):
        self.p = p
        self.q = q

        self.n = p * q
        self.phi = (p - 1) * (q - 1)

        self.e = 65537

        if math.gcd(self.e, self.phi) != 1: # máximo divisor comum
            raise ValueError("e não é coprimo com phi(n)")

        self.d = pow(self.e, -1, self.phi)

    def get_public_key(self):
        return {
            "n": self.n,
            "e": self.e
        }

    def get_private_key(self):
        return {
            "n": self.n,
            "d": self.d
        }

    def export_public_key(self, filename):
        with open(filename, "w") as file:
            json.dump(self.get_public_key(), file, indent=4)

    def export_private_key(self, filename):
        with open(filename, "w") as file:
            json.dump(self.get_private_key(), file, indent=4)

    @staticmethod
    def import_public_key(filename):
        with open(filename, "r") as file:
            return json.load(file)

    @staticmethod
    def import_private_key(filename):
        with open(filename, "r") as file:
            return json.load(file)