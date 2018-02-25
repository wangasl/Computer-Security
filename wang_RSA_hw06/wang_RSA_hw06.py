import sys
import pickle
import PrimeGenerator
from BitVector import *

e = 65537


def geneKey():
    global e
    generator = PrimeGenerator.PrimeGenerator(bits=128)
    while True:
        p, q = generator.findPrime(), generator.findPrime()
        if p == q or (bgcd(e, p) != 1) or (bgcd(e, q) != 1):
            continue
        n = p * q
        break
    tn = (p - 1) * (q - 1)
    tn_bv = BitVector(intVal=tn)
    e_v = BitVector(intVal=e)
    d_v = e_v.multiplicative_inverse(tn_bv)
    pickle.dump((e_v.int_val(), d_v.int_val(), n), open('key.p', 'wb'))
    return


def bgcd(a, b):
    if a == b:
        return a
    if a == 0:
        return b
    if b == 0:
        return a
    if (~a & 1):
        if (b & 1):
            return bgcd(a >> 1, b)
        else:
            return bgcd(a >> 1, b >> 1) << 1
    if (~b & 1):
        return bgcd(a, b >> 1)
    if (a > b):
        return bgcd((a - b) >> 1, b)
    return bgcd((b - a) >> 1, a)


def Encryption(message, output):
    e, d, n = pickle.load(open('key.p', 'rb'))
    bv = BitVector(filename=message)
    FILEOUT = open(output, 'w')
    final_result = BitVector(size=0)
    while bv.more_to_read:
        bv_read = bv.read_bits_from_file(128)
        bv_read.pad_from_left(256 - len(bv_read))
        encrypted_number = bv_read.int_val() ** e % n
        encrypted_number_bv = BitVector(intVal=encrypted_number)
        if(len(encrypted_number_bv) % 4 != 0):
            encrypted_number_bv.pad_from_right(4 - len(encrypted_number_bv) % 4)
        final_result += encrypted_number_bv
    FILEOUT.write(final_result.get_bitvector_in_hex())
    FILEOUT.close()


def Decryption(output, decrypted):
    e, d, n = pickle.load(open('key.p', 'rb'))
    FILEIN = open(output)
    encrypted_bv = BitVector(hexstring=FILEIN.read())
    final_result = BitVector(size=0)
    FILEOUT = open(decrypted, 'w')
    length = 0
    while length < len(encrypted_bv):
        if (length + 256) > len(encrypted_bv):
            encrypted_bv += BitVector(size=(length + 256 - len(encrypted_bv)))
        bv_read = encrypted_bv[length:length + 256]
        decrypted_number = bv_read.int_val() ** d % n
        decrypted_number_bv = BitVector(intVal=decrypted_number)
        print(decrypted_number_bv)
        length += 256


def main():
    if sys.argv[1] == '-e':
        geneKey()
        Encryption(sys.argv[2], 'output.txt')
    elif sys.argv[1] == '-d':
        Decryption(sys.argv[2], 'decrypted.txt')


if __name__ == "__main__":
    main()
