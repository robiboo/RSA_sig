# Robert Panerio
# Programming Language - Python 3

# CS 427 - Cryptography
# Project 2 - RSA Signatures
# Dr. Grant Williams
# March 22, 2023

import sys
import random

# https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers
def ex_gcd(a, b):
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    return old_s

# https://en.wikipedia.org/wiki/PJW_hash_function
def ElfHash(s):
    h = 0
    # h += 1
    # h <<= 2
    bits = 32
    for i in range(len(s)):
        h = (h << (bits // 8)) + ord(s[i])
        high = h & 0xF0000000
        if high != 0:
            h = h ^ (high >> (bits * 3//4))
            h = h & ~high
    return h

# https://wsu.instructure.com/courses/1618005/assignments/7951326
def miller_rabin(n):
    k = 20

    s = 0 
    d = n -1
    while d % 2 == 0:
        s += 1
        d //= 2

    for i in range(k):
        a = random.randint(2, n - 1 )
        x = modular_exp(n, a, d)
        if x != 1 or x != (n -1):
            for j in range(s-1):
                x = modular_exp(n, x, 2)
                if x == (n - 1):
                    break
            else:
                return False
    return True

def modular_exp(mod, base, exponent):
    # calculating the modular exponentation
    res = 1
    while exponent > 0:
        if exponent % 2:
            res = ( res * base ) % mod
        base = ( base ** 2 ) % mod
        exponent = exponent // 2
    return res

def sign_mode(msg_text, n, d, t):

    # get the encryption key
    e = ex_gcd(d, t) % t

    # has the message
    h = ElfHash(msg_text)

    # encrypt and decrypt
    encrypted = modular_exp(n, h, e)

    # check for integrity
    decrypted = modular_exp(n, encrypted, d)
    print("message hash:", hex(h)[2:])
    print("signing with the following private key:", hex(e)[2:])
    print("signed hash:", hex(encrypted)[2:])
    print("uninverted message to ensure integrity:", hex(decrypted)[2:])
    print("complete output for verification:")
    print(hex(n)[2:], msg_text, hex(encrypted)[2:], "\n")

def main():
    d = 0x10001
 
    p, q = 0, 0

    # generate random prime numbers for p and q
    random.seed()
    while(1):
        n = random.randint(0x8000, 0xFFFF)
      
        if (miller_rabin(n)):
            p = int(hex(n), 16)
            break

    random.seed()
    while(1):
        
        m = random.randint(0x8000, 0xFFFF)
        if (miller_rabin(m)):
                q = int(hex(m), 16)
                break

    # n is modulo
    n = p * q

    # t is totient
    t = (p-1) * (q-1)
    
    for line in sys.stdin:
        if line[:4] == "sign":
            msg_text = line[5:-1][1:-1]
            print(f"p = {hex(p)[2:]}, q = {hex(q)[2:]}, n = {hex(n)[2:]}, t = {hex(t)[2:]}")
            print("received message:", msg_text)
            
            sign_mode(msg_text, n, d, t)

        if line[:6] == "verify":

            #input manipulation
            verify_input = line[7:].split("\"")
            verify_modulos = int(verify_input[0][:-1], 16)
            verify_msg = verify_input[1]
            verify_sig = int(verify_input[2][1:-1], 16)

            # decrypt the signature
            decrypted = modular_exp(verify_modulos, verify_sig, d )

            # hash the message
            hash = ElfHash(verify_msg)

            # compare to verify
            if decrypted == hash:
                print("message verified!\n")
            else:
                print("!!! message is forged !!!\n")

main()    