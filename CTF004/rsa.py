import sys, os
import base64
import glob
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.number import GCD, inverse
import numpy as np

with open('file1', 'rb') as f:
    file1 = f.read()
with open('file2', 'rb') as f:
    file2 = f.read()

nonce = file1[:16]
tag = file1[16:32]
ciphertext = file1[32:]
# print(nonce)
# print(tag)
# print(ciphertext)

# print('file1 base64-encoded:')
# print(base64.b64encode(file1).decode('utf8'), '\n')
# print('file1 hex: ')
# print(file1.hex(), '\n')
# print('file2 base64-encoded: ')
# print(base64.b64encode(file2).decode('utf8'), '\n')
# print('file2 hex: ')
# print(file2.hex(), '\n')

# file12 = bytes(b1 ^ b2 for b1, b2 in zip(file1, file2))
# print('file1 XOR file2 base64-encoded: ')
# print(base64.b64encode(file12).decode('utf8'), '\n')
# print('file1 XOR file2 hex: ')
# print(file12.hex())

# print(len(file1))

# mod = '00af9072a3acd34f9a1d9f1cf0fbb1902ab182ff7d40eb74607b417c7a6ae9a94dc2e6a1ee0e5349f26eac6499a37fc23e382b84b39258eded0e2fa2699ee956ef9aebd3061a0dd151e16598dd2ad87a41ca1817267b14dc1aff4a713a35fbc5cb7e508d5072447924e2e23c1b9ca2160f410a5ccede7da5226a0d855dfd2ac673360583a63b4d812202c34a8d40fd8c08b97408c65296b2e83c0d9573ecd52e56b37c7b8438b2bd2d5fa19fe7aed63847d940991fd9f396f3f18a2b47b364dabef2f2e288c2426456877ba9f26037cd073c98a09952fbc6e5d782696d18c9935b4d7a9c584b452533ea77248453b9821b45e5fbbd43a9a48d2f021fa587dfa7d1'
# print(len(bytes.fromhex(mod)))

# pems = []
# for fname in glob.glob('file3_content/file3/*.der'):
#     with open(fname, 'rb') as f:
#         pem = f.read()
#         if pem in pems:
#             print(f'{fname} already in PEMs')
#         print('ttm4536{' + fname.split('/')[2][:-8] + '}')
#         if file1 == pem:
#             print(f'File1 is {fname}')
#         if file2 == pem:
#             print(f'File2 is {fname}')
#         pems.append(pem)

# public_keys = []
# for fname in glob.glob('file3_content/file3/*.pem'):
#     with open(fname) as f:
#         rsa = RSA.importKey(f.read())
#     for key in public_keys:
#         p = GCD(rsa.n, key[1])
#         if p != 1:
#             print(f'{fname} and {key[0]} has common factor:')
#             print(p)
#     public_keys.append((fname, rsa.n))

p = 164560916106431892840411395405964063201738536482816105138692070093090582456480658013938325624379492491532095016141077895943767960802625345867613182641011879030159699218960146198527476488592981287069434022928767020805337506970996188207253475686506536107557264104779823376040152249764453515414010888753176936847
# file3_content/file3/Maximus Benitez.pem
# file3_content/file3/Quinten Curtis.pem

def lcm(a, b):
    return a * b // GCD(a, b)

with open('file3_content/file3/Maximus Benitez.pem') as f:
    rsa_pub_maximus = RSA.importKey(f.read())
with open('file3_content/file3/Quinten Curtis.pem') as f:
    rsa_pub_quinten = RSA.importKey(f.read())

q_maximus = rsa_pub_maximus.n // p
lambda_maximus = lcm(p - 1, q_maximus - 1)
d_maximus = inverse(rsa_pub_maximus.e, lambda_maximus)

q_quinten = rsa_pub_quinten.n // p
lambda_quinten = lcm(p - 1, q_quinten - 1)
d_quinten = inverse(rsa_pub_quinten.e, lambda_quinten)

rsa_priv_maximus = RSA.construct((rsa_pub_maximus.n, rsa_pub_maximus.e, d_maximus))
rsa_priv_quinten = RSA.construct((rsa_pub_quinten.n, rsa_pub_quinten.e, d_quinten))
print(rsa_priv_maximus.decrypt(file2) + rsa_priv_quinten.decrypt(file1))
