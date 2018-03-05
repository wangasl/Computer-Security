#!/usr/bin/env python

# sha256_from_command_line.py
# by Avi Kak (kak@purdue.edu)
# January 3, 2018

# Call syntax:
##
# sha256_from_command_line.py   your_message_string

# With this call syntax, the script implemented here takes its message on the standard input from
# the command line and sends the hash to its standard output.  NOTE: IT ADDS A NEWLINE AT THE END
# OF THE OUTPUT TO SHOW THE HASHCODE IN A LINE BY ITSELF.

# SHA256 algorithm in summary:
##
# STEP 1:   Pad the message so that its length is an integral multiple of 512 bits, the block size.
# The only complication here is that the last 64 bits of the last block must contain a
# value that is the length of the message.
##
# STEP 2:   Generate the MESSAGE SCHEDULE required for processing a 512-bit block of the input
# message.  The message schedule consists of 64 32-bit WORDS. The first 16 of these
# words are obtained directly from the 512-bit block.  The rest of the words are
# obtained by applying permutation and mixing operations to the some of the
# previously generated words.
##
# STEP 3:   Apply round-based processing to each 512-bit input message block. There are 64 rounds to
# be carried out.  For this round-based processing, we first store the hash values calculated
# for the PREVIOUS MESSAGE BLOCK in temporary 32-bit variables denoted a,b,c,d,e,f,g,h. In the
# i-th round, we permute the values stored in these eight variables and, with two of the
# variables, we mix in the message schedule word words[i] and a round constant K[i].
##
# STEP 4:   We update the hash values calculated for the PREVIOUS message block by adding to it the
# values in the temporary variables a,b,c,d,e,f,g,h.


import sys
import BitVector
if BitVector.__version__ < '3.2':
    sys.exit("You need BitVector module of version 3.2 or higher")
from BitVector import *

if len(sys.argv) != 2:
    sys.stderr.write("Usage: %s  <string to be hashed>\n" % sys.argv[0])
    sys.exit(1)

message = sys.argv[1]

#  The 8 32-words used for initializing the 512-bit hash buffer before we start scanning the
#  input message block for its hashing. See page 13 (page 17 of the PDF) of the NIST standard.
#  Note that the hash buffer consists of 8 32-bit words named h0, h1, h2, h3, h4, h5, h6, and h7.
h0 = BitVector(hexstring='6a09e667')
h1 = BitVector(hexstring='bb67ae85')
h2 = BitVector(hexstring='3c6ef372')
h3 = BitVector(hexstring='a54ff53a')
h4 = BitVector(hexstring='510e527f')
h5 = BitVector(hexstring='9b05688c')
h6 = BitVector(hexstring='1f83d9ab')
h7 = BitVector(hexstring='5be0cd19')

#  The K constants (also referred to as the "round constants") are used in round-based processing of
#  each 512-bit input message block.  There is a 32-bit constant for each of the 64 rounds. These are
#  as provided on page 10 (page 14 of the PDF) of the NIST standard.  Note that these are ONLY USED
#  in STEP 3 of the hashing algorithm where we take each 512-bit input message block through 64
#  rounds of processing.
K = ["428a2f98", "71374491", "b5c0fbcf", "e9b5dba5", "3956c25b", "59f111f1", "923f82a4", "ab1c5ed5",
     "d807aa98", "12835b01", "243185be", "550c7dc3", "72be5d74", "80deb1fe", "9bdc06a7", "c19bf174",
     "e49b69c1", "efbe4786", "0fc19dc6", "240ca1cc", "2de92c6f", "4a7484aa", "5cb0a9dc", "76f988da",
     "983e5152", "a831c66d", "b00327c8", "bf597fc7", "c6e00bf3", "d5a79147", "06ca6351", "14292967",
     "27b70a85", "2e1b2138", "4d2c6dfc", "53380d13", "650a7354", "766a0abb", "81c2c92e", "92722c85",
     "a2bfe8a1", "a81a664b", "c24b8b70", "c76c51a3", "d192e819", "d6990624", "f40e3585", "106aa070",
     "19a4c116", "1e376c08", "2748774c", "34b0bcb5", "391c0cb3", "4ed8aa4a", "5b9cca4f", "682e6ff3",
     "748f82ee", "78a5636f", "84c87814", "8cc70208", "90befffa", "a4506ceb", "bef9a3f7", "c67178f2"]

#  Store the 64 K constants as an array of BitVector objects:
K_bv = [BitVector(hexstring=k_constant) for k_constant in K]


#  STEP 1 OF THE HASHING ALGORITHM: Pad the input message so that its length is an integer multiple
#                                   of the block size which is 512 bits.  This padding must account
#                                   for the fact that the last 64 bit of the padded input must store
#                                   length of the input message:
bv = BitVector(textstring=message)
length = bv.length()
bv1 = bv + BitVector(bitstring="1")
length1 = bv1.length()
howmanyzeros = (448 - length1) % 512
zerolist = [0] * howmanyzeros
bv2 = bv1 + BitVector(bitlist=zerolist)
bv3 = BitVector(intVal=length, size=64)
bv4 = bv2 + bv3

#  Initialize the array of "words" for storing the message schedule for a block of the input message:
words = [None] * 64

for n in range(0, bv4.length(), 512):
    block = bv4[n:n + 512]

    #  STEP 2 OF THE HASHING ALGORITHM: Now we need to create a message schedule for this 512-bit input
    #                                   block.  The message schedule contains 64 words, each 32-bits long.
    #                                   As shown below, the first 16 words of the message schedule are
    #                                   obtained directly from the 512-bit input block:
    words[0:16] = [block[i:i + 32] for i in range(0, 512, 32)]
    #  Now we need to expand the first 16 32-bit words of the message schedule into a full schedule that
    #  contains 64 32-bit words. This involves using the functions sigma0 and sigma1 as shown below:
    for i in range(16, 64):
        i_minus_2_word = words[i - 2]
        i_minus_15_word = words[i - 15]
        #  The sigma1 function is applied to the i_minus_2_word and the sigma0 function is applied to
        #  the i_minus_15_word:
        sigma0 = (i_minus_15_word.deep_copy() >> 7) ^ (
            i_minus_15_word.deep_copy() >> 18) ^ (i_minus_15_word.deep_copy().shift_right(3))
        sigma1 = (i_minus_2_word.deep_copy() >> 17) ^ (
            i_minus_2_word.deep_copy() >> 19) ^ (i_minus_2_word.deep_copy().shift_right(10))
        words[i] = BitVector(intVal=(int(words[i - 16]) + int(sigma1) +
                                     int(words[i - 7]) + int(sigma0)) & 0xFFFFFFFF, size=32)

    #  Before we can start STEP 3, we need to store the hash buffer contents obtained from the previous
    #  input message block in the variables a,b,c,d,e,f,g,h:
    a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

    #  STEP 3 OF THE HASHING ALGORITHM: In this step, we carry out a round-based processing of a
    #                                   512-bit input message block.  There are a total of 64 rounds
    #                                   and the calculations carried out in each round are referred
    #                                   to as calculating a "round function".  The round function for
    #                                   the i-th round consists of permuting the previously calculated
    #                                   contents of the hash buffer registers as stored in the
    #                                   temporary variables a,b,c,d,e,f,g and replacing the values of
    #                                   two of these variables with values that depend of the i-th word
    #                                   in the message schedule, words[i],  and i-th round constant,
    #                                   K[i]. As you see below, this requires that we first calculate
    #                                   the functions ch, maj, sum_a, and sum_e.
    for i in range(64):
        ch = (e & f) ^ ((~e) & g)
        maj = (a & b) ^ (a & c) ^ (b & c)
        sum_a = ((a.deep_copy()) >> 2) ^ (
            (a.deep_copy()) >> 13) ^ ((a.deep_copy()) >> 22)
        sum_e = ((e.deep_copy()) >> 6) ^ (
            (e.deep_copy()) >> 11) ^ ((e.deep_copy()) >> 25)
        t1 = BitVector(intVal=(int(h) + int(ch) + int(sum_e) +
                               int(words[i]) + int(K_bv[i])) & 0xFFFFFFFF, size=32)
        t2 = BitVector(intVal=(int(sum_a) + int(maj)) & 0xFFFFFFFF, size=32)
        h = g
        g = f
        f = e
        e = BitVector(intVal=(int(d) + int(t1)) & 0xFFFFFFFF, size=32)
        d = c
        c = b
        b = a
        a = BitVector(intVal=(int(t1) + int(t2)) & 0xFFFFFFFF, size=32)

    #  STEP 4 OF THE HASHING ALGORITHM:  The values in the temporary variables a,b,c,d,e,f,g,h AFTER 64
    #                                    rounds of processing are now mixed with the contents of the
    #                                    hash buffer as calculated for the previous block of the input
    #                                    message:
    h0 = BitVector(intVal=(int(h0) + int(a)) & 0xFFFFFFFF, size=32)
    h1 = BitVector(intVal=(int(h1) + int(b)) & 0xFFFFFFFF, size=32)
    h2 = BitVector(intVal=(int(h2) + int(c)) & 0xFFFFFFFF, size=32)
    h3 = BitVector(intVal=(int(h3) + int(d)) & 0xFFFFFFFF, size=32)
    h4 = BitVector(intVal=(int(h4) + int(e)) & 0xFFFFFFFF, size=32)
    h5 = BitVector(intVal=(int(h5) + int(f)) & 0xFFFFFFFF, size=32)
    h6 = BitVector(intVal=(int(h6) + int(g)) & 0xFFFFFFFF, size=32)
    h7 = BitVector(intVal=(int(h7) + int(h)) & 0xFFFFFFFF, size=32)

#  Concatenate the contents of the hash buffer to obtain a 512-element BitVector object:
message_hash = h0 + h1 + h2 + h3 + h4 + h5 + h6 + h7

#  Get the hex representation of the binary hash value:
hash_hex_string = message_hash.getHexStringFromBitVector()

sys.stdout.writelines((hash_hex_string, "\n"))
