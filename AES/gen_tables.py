#!/usr/bin/env python

## gen_tables.py
## Avi Kak (February 15, 2015)

##  This is a Python implementation of the byte substitution explanations in Sections
##  8.5 and 8.5.1 of Lecture 8.  In keeping with the explanation in Section 8.5, the
##  goal here is to construct two 256-element arrays for byte substitution, one for
##  the SubBytes step that goes into the encryption rounds of the AES algorithm, and
##  the other for the InvSubBytes step that goes into the decryption rounds. 

import sys
from BitVector import *

AES_modulus = BitVector(bitstring='100011011')
subBytesTable = []                                                  # for encryption
invSubBytesTable = []                                               # for decryption

def genTables():
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal = i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1,b2,b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))

genTables()
print "SBox for Encryption:"
print subBytesTable
print "\nSBox for Decryption:"
print invSubBytesTable
