#! usr/bin/env python3

# Shulin Wang
# ECE 404
# HW 04

# This is the python script to process the AES encryption and decryption
#
# Call syntax:  python3 ece404_hw04_wang.py plaintext.txt decrypted.txt
#
# A key.txt file is needed for the purpose of encryption key
# The result will be saved into text file

import sys
from BitVector import *

AES_modulus = BitVector(bitstring='100011011')
keysize = 128
subBytesTable = []
invSubBytesTable = []


def getRoundKey():
    # Get the encryption/decryption key from user
    key_bv = get_key_from_user()
    # Generate the key schedule
    key_words = gen_key_schedule_128(key_bv)
    # Generate the roundkeys in hex form
    round_keys = [None for i in range(11)]
    for i in range(11):
        round_keys[i] = (key_words[i * 4] + key_words[i * 4 + 1] + key_words[i * 4 + 2] + key_words[i * 4 + 3])
    return round_keys


def gen_key_schedule_128(key_bv):
    # Generate the key schedule for given key
    key_words = [None for i in range(44)]
    round_constant = BitVector(intVal=0x01, size=8)
    for i in range(4):
        # First round key is just the encryption key
        key_words[i] = key_bv[i * 32: i * 32 + 32]
    for i in range(4, 44):
        # First 4-bytes word of each round will be treated differently
        if i % 4 == 0:
            kwd, round_constant = gee(key_words[i - 1], round_constant)
            key_words[i] = key_words[i - 4] ^ kwd
        else:
            # Calculate next 3 4-bytes word of each round
            key_words[i] = key_words[i - 4] ^ key_words[i - 1]
    return key_words


def gee(keyword, round_constant):
    # the g() function used to help generating first 4-byte word in each round key
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size=0)
    for i in range(4):
        newword += BitVector(intVal=subBytesTable[rotated_word[8 * i:8 * i + 8].intValue()], size=8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal=0x02), AES_modulus, 8)
    return newword, round_constant


def gen_tables():
    subBytesTable = []
    invSubBytesTable = []
    # Generate the S-Box and Inverse S-Box for substitution
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal=i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1, a2, a3, a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal=i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1, b2, b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))
    return subBytesTable, invSubBytesTable


def get_key_from_user():
    # Get the encryption/decryption key from user
    with open('key.txt') as myFile:
        key = myFile.read()
    # If not 16 bytes then pad from left, if exceed then only take first 16 bytes
    key += '0' * (keysize // 8 - len(key)) if len(key) < keysize // 8 else key[:keysize // 8]
    key_bv = BitVector(textstring=key)
    return key_bv


def add_round_key(bv_read, round_key):
    # xoring with the round key
    bv_read ^= round_key
    return bv_read


def byte_substitution(state_array):
    # Process the byte substitution
    for i in range(4):
        for j in range(4):
            bv = BitVector(size=8, intVal=subBytesTable[state_array[i][j].intValue()])
            state_array[i][j] = bv
    return state_array


def inv_byte_substitution(state_array):
    # Process the inverse byte substitution
    for i in range(4):
        for j in range(4):
            bv = BitVector(size=8, intVal=invSubBytesTable[state_array[i][j].intValue()])
            state_array[i][j] = bv
    return state_array


def inv_shift_rows(state_array):
    # Process the inverse row shifting
    state_array[1] = state_array[1][-1:] + state_array[1][:-1]
    state_array[2] = state_array[2][-2:] + state_array[2][:-2]
    state_array[3] = state_array[3][-3:] + state_array[3][:-3]
    return state_array


def inv_mix_columns(state_array):
    # Process the inverse column mixing
    E = BitVector(hexstring='0E')
    B = BitVector(hexstring='0B')
    D = BitVector(hexstring='0D')
    N = BitVector(hexstring='09')

    for j in range(4):
        first_row = (E.gf_multiply_modular(state_array[0][j], AES_modulus, 8)) ^ (B.gf_multiply_modular(state_array[1][j], AES_modulus, 8)) ^ (D.gf_multiply_modular(state_array[2][j], AES_modulus, 8)) ^ (N.gf_multiply_modular(state_array[3][j], AES_modulus, 8))
        second_row = (N.gf_multiply_modular(state_array[0][j], AES_modulus, 8)) ^ (E.gf_multiply_modular(state_array[1][j], AES_modulus, 8)) ^ (B.gf_multiply_modular(state_array[2][j], AES_modulus, 8)) ^ (D.gf_multiply_modular(state_array[3][j], AES_modulus, 8))
        third_row = (D.gf_multiply_modular(state_array[0][j], AES_modulus, 8)) ^ (N.gf_multiply_modular(state_array[1][j], AES_modulus, 8)) ^ (E.gf_multiply_modular(state_array[2][j], AES_modulus, 8)) ^ (B.gf_multiply_modular(state_array[3][j], AES_modulus, 8))
        fourth_row = (B.gf_multiply_modular(state_array[0][j], AES_modulus, 8)) ^ (D.gf_multiply_modular(state_array[1][j], AES_modulus, 8)) ^ (N.gf_multiply_modular(state_array[2][j], AES_modulus, 8)) ^ (E.gf_multiply_modular(state_array[3][j], AES_modulus, 8))

        state_array[0][j] = first_row
        state_array[1][j] = second_row
        state_array[2][j] = third_row
        state_array[3][j] = fourth_row

    return state_array


def shift_rows(state_array):
    # Process the row shifting
    state_array[1] = state_array[1][1:] + state_array[1][:1]
    state_array[2] = state_array[2][2:] + state_array[2][:2]
    state_array[3] = state_array[3][3:] + state_array[3][:3]
    return state_array


def mix_columns(state_array):
    # Process the column mixing
    two_times = BitVector(hexstring='02')
    three_times = BitVector(hexstring='03')
    for j in range(4):
        first_row = (two_times.gf_multiply_modular(state_array[0][j], AES_modulus, 8)) ^ (three_times.gf_multiply_modular(state_array[1][j], AES_modulus, 8)) ^ state_array[2][j] ^ state_array[3][j]
        second_row = state_array[0][j] ^ (two_times.gf_multiply_modular(state_array[1][j], AES_modulus, 8)) ^ (three_times.gf_multiply_modular(state_array[2][j], AES_modulus, 8)) ^ state_array[3][j]
        third_row = state_array[0][j] ^ state_array[1][j] ^ (two_times.gf_multiply_modular(state_array[2][j], AES_modulus, 8)) ^ (three_times.gf_multiply_modular(state_array[3][j], AES_modulus, 8))
        fourth_row = (three_times.gf_multiply_modular(state_array[0][j], AES_modulus, 8)) ^ state_array[1][j] ^ state_array[2][j] ^ (two_times.gf_multiply_modular(state_array[3][j], AES_modulus, 8))

        state_array[0][j] = first_row
        state_array[1][j] = second_row
        state_array[2][j] = third_row
        state_array[3][j] = fourth_row

    return state_array


def convert_state_bv(state_array):
    # Convert the 4*4 state_array into a 1-D array
    state_bv = BitVector(size=0)
    for i in range(4):
        for j in range(4):
            state_bv += state_array[j][i]
    return state_bv


def AES_Encryption(plaintext, ciphertext):
    # Generate the round key based on user input key
    round_keys = getRoundKey()
    bv = BitVector(filename=plaintext)
    # Generate the 4x4 state array
    state_array = [[0 for x in range(4)] for x in range(4)]
    FILEOUT = open(ciphertext, 'w')
    final_result = BitVector(size=0)
    while bv.more_to_read:
        # Read 128 bit from plain text
        bv_read = bv.read_bits_from_file(128)
        # Check if it is 128 bit, otherwise pad
        if len(bv_read) < 128:
            bv_read.pad_from_right(128 - len(bv_read))
        # xoring with first round key
        bv_read = add_round_key(bv_read, round_keys[0])
        # Fill in the state array
        for i in range(4):
            for j in range(4):
                state_array[j][i] = bv_read[32 * i + 8 * j: 32 * i + 8 * (j + 1)]
        # Process the ten rounds of encryption
        for i in range(1, 11):
            # Byte substitution
            state_array = byte_substitution(state_array)
            # Shift rows
            state_array = shift_rows(state_array)
            if i != 10:
                # if it's not the last round, then mix columns
                state_array = mix_columns(state_array)
            # Convert to 1-D array and add round key
            state_bv = convert_state_bv(state_array)
            state_bv = add_round_key(state_bv, round_keys[i])
            # Convert back to 4*4 state_array
            for r in range(4):
                for c in range(4):
                    state_array[c][r] = state_bv[32 * r + 8 * c: 32 * r + 8 * (c + 1)]
        # Convert the final 4*4 state_array to 1-D array
        final_bv = convert_state_bv(state_array)
        # Add to the final string
        final_result += final_bv
    FILEOUT.write(final_result.get_bitvector_in_hex())
    FILEOUT.close()


def AES_Decryption(ciphertext, decrypted):
    # Generate round key
    round_keys = getRoundKey()
    FILEIN = open(ciphertext)
    encrypted_bv = BitVector(hexstring=FILEIN.read())
    final_result = BitVector(size=0)
    state_array = [[0 for x in range(4)] for x in range(4)]
    # Reverse round key for decryption
    round_keys.reverse()
    FILEOUT = open(decrypted, 'w')
    length = 0
    while length < len(encrypted_bv):
        # If not 128 bit, then pad from right
        if (length + 128) > len(encrypted_bv):
            encrypted_bv += BitVector(size=(length + 128 - len(encrypted_bv)))
        bv_read = encrypted_bv[length: length + 128]
        # xoring with first round key
        bv_read = add_round_key(bv_read, round_keys[0])
        # fill in the state_array
        for i in range(4):
            for j in range(4):
                state_array[j][i] = bv_read[32 * i + 8 * j: 32 * i + 8 * (j + 1)]
        # Process the ten round of decryption
        for i in range(1, 11):
            # Inverse row shifting
            state_array = inv_shift_rows(state_array)
            # Inverse byte substitution
            state_array = inv_byte_substitution(state_array)
            # Convert to 1-D array and add round key
            state_bv = convert_state_bv(state_array)
            state_bv = add_round_key(state_bv, round_keys[i])
            # Convert back to 4*4 state_array
            for r in range(4):
                for c in range(4):
                    state_array[c][r] = state_bv[32 * r + 8 * c: 32 * r + 8 * (c + 1)]
            # If not the last round, then inverse column mixing
            if i != 10:
                state_array = inv_mix_columns(state_array)
        # Convert the final state_array to 1-D array
        final_bv = convert_state_bv(state_array)
        # Add to the final string
        final_result += final_bv
        length += 128
    FILEOUT.write(final_result.get_bitvector_in_ascii())
    FILEOUT.close()


def main():
    # Generate S-Box and Inverse S-Box
    global subBytesTable, invSubBytesTable
    print('Set up S-Box')
    subBytesTable, invSubBytesTable = gen_tables()
    # Perform encryption
    print('Perform encryption')
    AES_Encryption('message.txt', 'encrypted.txt')
    # Perform decryption
    print('Perform decryption')
    AES_Decryption('encrypted.txt', 'decrypted.txt')
    print('Done')

    # Encryption output
    #
    # a91f1c43f99b3116275d576ad8ee2eba140c1a00e3d5bce66bc31c105cc10b8b25035ea4fb66c87bd5d65a8c2e4a2981060d3d9244268b9d39
    # cc6bb60f5a54b4126c1d129e29607ff06dab802bc6b6a8fcecb53ea730061d4a507745857228328f27fc599c99e4fcbc928398fe094cd47b96
    # 4bb5163e874027e93e784e7fa20766933a37f108e49638ed2c6b49487c6416d0f1574dbec63ff2d9aa715cbe2658c3dee3d78990c606a253db
    # 5827c4366e7811b1737f19cda3d07de74069e4b7a4133129e48b133f289d8ccba80d8160cdb1a54bcbc4b0f00db3a3942755aaa0c3e87eca25
    # 8b7e1a690145bf7578c3da96e3f0fca4c00091023de5d7b5a0c66692a359ef0704bcb0e001b0b62357dc0a13e5114b47b2ab359cb8440559f8
    # ef1726a193f8b91d88683ba82c4ae99d6715baa50206eea56e8889da90fb6f181c6b1c30211ac0115bd8a335712b2450802779b8fa8fbfb541
    # 361d9a9ac63f3dbf16fd3ff0e51c7a7b1d55ea9375b476b1fb0a1dda6a874fb4e903e62daf2e354526725971c1edba58fdf79e07aaaf7c1ca2
    # 5d16ad35cbe2440f73a2e94a10fdf17747dc23b2e8c15db0cbd1ac46ba36ac5ee20fb3167b971c6c5b52db3d0f298649efebdaa55dfe5ba27f
    # ec531dff023597205761d95d275bd4b29ed5dd49d65512455bb90d349b18e3eedbd4da6a7bbfbe8c283ad5b38eb628afa3ed42b2cb2eedf30f
    # 34461f106a012e6dbe1ee0298efa94da84e46a9c92ece40280b06202f7e1b3cc496262bd75aeef860b906a9ea80dc10db4de51c8cdf9e7f0f3
    # 4f809817cd894cc8675f89883e5fd79549b4e74ea615356bafc5ee680a2e1f0002b578f5d40d2d68a25d09ebb4484c21775204827f0b9dae1d
    # 0c00292d34a2d496d35eb12cc7f135f6375f1e6683c5310c2817994d6c106861038d647ec7576597929c16b662ffa7bbedae2eaf1bf3fc6f42
    # 63a9694d95c20e7c4f007effca018df261af9d6a3019126fc8a7d86d5e5fc5eb00020c5c339e15bfb1e370d2d41ce105b2414443

    # Decryption output
    #
    # This is an unusual paragraph. I'm curious how quickly you can find out what is so unusual about it? It looks so plain
    # you would think nothing was wrong with it! In fact, nothing is wrong with it! It is unusual though. Study it, and think
    # about it, but you still may not find anything odd. But if you work at it a bit, you might find out! Try to do so without
    # any coaching! You most probably won't, at first, find anything particularly odd or unusual or in any way dissimilar to any
    # ordinary composition. That is not at all surprising, for it is no strain to accomplish in so short a paragraph a stunt
    # similar to that which an author did throughout all of his book, without spoiling a good writing job, and it was no small book at that.


if __name__ == '__main__':
    main()
