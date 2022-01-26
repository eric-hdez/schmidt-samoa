from random import getrandbits, randint


def odd(n: int) -> bool: return n % 2 != 0


def even(n: int) -> bool: return n % 2 == 0


def gcd(a: int, b: int) -> int:
    '''
    computes the greatest common denominator of a & b
    '''
    while b != 0:
        a, b = b, a % b
    return a


def lcm(a: int, b: int) -> int:
    '''
    computes the least common multiple of a & b
    '''
    return (a * b) // gcd(a, b)


def mod_inverse(a: int, n: int) -> int:
    ''' 
    computes the modular inverse of a mod n (a^-1 % n)
    '''
    r, r_prime = n, a
    t, t_prime = 0, 1

    while r_prime != 0:
        q = r // r_prime
        r, r_prime = r_prime, r - q * r_prime
        t, t_prime = t_prime, t - q * t_prime

    if r > 1:
        t = 0

    if t < 0:
        t = t + n

    return t


def pow_mod(a: int, d: int, n: int) -> int:
    '''
    computes the modular exponentiation a^d mod n (a^d % n)
    '''
    v, p = 1, a
    
    while d > 0:
        if odd(d):
            v = (v * p) % n

        p = (p * p) % n
        d = d // 2

    return v


def is_prime(n: int, k: int) -> bool:
    '''
    Rabin-Miller probabalistic primality test for validating
    the primality of really large primes.
    '''
    if n <= 1 or n == 4:
        return False

    if n <= 3:
        return True

    r, s = n - 1, 0
    while even(r):
        s += 1
        r = r // 2

    for i in range(k):
        a = 2 + randint(1, n - 4)
        y = pow_mod(a, r, n)

        if y != 1 and y != n - 1:
            j = 1

            while j <= s - 1 and y != n - 1:
                y = pow_mod(y, 2, n)

                if y == 1:
                    return False
                
                j += 1

            if y != n - 1:
                return False

    return True


def make_prime(nbits: int, k: int) -> int:
    '''
    generates a large prime of size nbits and
    uses Rabin-Miller primality test to validate prime.
    '''
    p = 0

    while not is_prime(p, k):
        p = getrandbits(nbits)

    return p


