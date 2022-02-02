'''
An implementation of the Schmidt-Samoa Cryptosystem

N : public key
d : private key
n : decryption modulus (p * q)
λ : Carmichael's λ function: λ(n) = lcm[ λ(p), λ(q) ] = lcm(p - 1, q - 1)
        - λ(p) = p - 1, for any prime p
'''
from numtheory import decode, encode, lcm, make_prime, mod_inverse, pow_mod


def key_gen(nbits: int, k: int) -> int:
    '''
    generates two large random primes, p and q, such that
    p !/ q - 1 and q !/ p - 1.

    computes: n = pq (decrypt mod), N = p^2*q (pub key)
    and d = N^-1 mod λ(n) (priv key)
    '''
    bitsz = nbits // 2

    p = make_prime(bitsz, k)
    q = make_prime(bitsz, k)

    while p == q or (p - 1) % q == 0 or (q - 1) % p == 0:
        q = make_prime(bitsz, k)

    n = p * q              # decrypt modulus
    N = (p ** 2) * q       # public key
    λ = lcm(p - 1, q - 1)  # Carmichael's λ function
    d = mod_inverse(N, λ)  # private key

    return N, (d, n)


def encrypt(m: int, N:int) -> int:
    '''
    Schmidt-Samoa Encryption of message m:

    compute ciphertext c: c = m^N mod N
    '''
    c = pow_mod(m, N, N)
    return c


def decrypt(c: int, d: int, n: int) -> int:
    '''
    Schmidt-Samoa Decrpytion of ciphertext c:

    compute message m: m = c^d mod pq
    '''
    m = pow_mod(c, d, n)
    return m


def main() -> None:
    pub, priv = key_gen(1024, 100)
    d, n = priv

    print("public key: {}\n".format(pub))
    print("private key: {}\n".format(d))
    print("private mod: {}\n".format(n))
    msg = ""

    while True:
        msg = str(input("message to encrypt: "))
        if msg.lower() in ["q", "quit", "exit"]:
            break

        c = encrypt(encode(msg), pub)
        print("encrypted message: {}\n".format(c))
        m = decrypt(c, d, n)
        print("decrypted message: {}\n".format(decode(m)))

if __name__ == '__main__':
    main()
