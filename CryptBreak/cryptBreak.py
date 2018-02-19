#! usr/bin/env python3

# Shulin Wang
# ECE 404
# HW 1

# This is the modified version of DecryptForFun, instead of asking user to enter
# the key, it will launch the brute force attack and try to decrypt the message.
# Most of the codes are taken from DecryptForFun.py

# Call syntax:
#
#      cryptBreak.py encrypted.txt recover.txt
#
# The decrypted message and the original key is deposited in the file
# "recover.txt"

import sys
from BitVector import *

BLOCKSIZE = 16
numbytes = BLOCKSIZE // 8
PassPhrase = "Hopes and dreams of a million years"


def decrypt(possible_key, encrypted_bv):

    # Reduce the passphrase to a bit array of size BLOCKSIZE:
    bv_iv = BitVector(bitlist=[0] * BLOCKSIZE)
    for i in range(0, len(PassPhrase) // numbytes):
        textstr = PassPhrase[i * numbytes:(i + 1) * numbytes]
        bv_iv ^= BitVector(textstring=textstr)

    # Create a bitvector for storing the decrypted plaintext bit array:
    key_bv = BitVector(intVal=possible_key, size=16)

    # Create a bitvector for storing the decrypted plaintext bit array:
    msg_decrypted_bv = BitVector(size=0)

    # Carry out differential XORing of bit blocks and decryption:
    previous_decrypted_block = bv_iv
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):
        bv = encrypted_bv[i * BLOCKSIZE:(i + 1) * BLOCKSIZE]
        temp = bv.deep_copy()
        bv ^= previous_decrypted_block
        previous_decrypted_block = temp
        bv ^= key_bv
        msg_decrypted_bv += bv

    return msg_decrypted_bv.get_text_from_bitvector()


def main():
    # Check if the input arguments are correct
    if len(sys.argv) is not 3:
        sys.exit('''Needs two command-line arguments, one for '''
                 '''the message file and the other for the '''
                 '''encrypted output file''')

    # Create a bitvector from the ciphertext hex string:
    FILEIN = open(sys.argv[1])
    encrypted_bv = BitVector(hexstring=FILEIN.read())

    # go through all possible key
    for possible_key in range(2**BLOCKSIZE):
        decrypted_message = decrypt(possible_key, encrypted_bv)

        # Check if the desired output was found
        if "Benjamin Franklin" in decrypted_message:
            FILEOUT = open(sys.argv[2], 'w')
            FILEOUT.write(decrypted_message + '\n')
            FILEOUT.write(str(possible_key))
            FILEOUT.close()
            sys.exit()

    # Original quote =
    #
    #   The doorstep to the temple of wisdom is a knowledge of our own ignorance.
    #   -Benjamin Franklin
    #
    # encryption key =
    #
    #   29556


if __name__ == '__main__':
    main()
