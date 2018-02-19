#! usr/bin/env python3

# Shulin Wang
# ECE 404
# Hw 02

import sys
from BitVector import *

# This is the python script to implement the DES encryption and decryption.
# Most of the functions were referenced to the lecture notes
# Call syntax:   python3 DES_wang.py
# output encypted and decrypted text will be stored into files


# Initial P_Box
expansion_permutation = [31, 0, 1, 2, 3, 4,
                         3, 4, 5, 6, 7, 8,
                         7, 8, 9, 10, 11, 12,
                         11, 12, 13, 14, 15, 16,
                         15, 16, 17, 18, 19, 20,
                         19, 20, 21, 22, 23, 24,
                         23, 24, 25, 26, 27, 28,
                         27, 28, 29, 30, 31, 0]

# Initial key permutation table
key_permutation_1 = [56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17,
                     9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35,
                     62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
                     13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3]

key_permutation_2 = [13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11,
                     3, 25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46,
                     54, 29, 39, 50, 44, 32, 47, 43, 48, 38, 55, 33, 52,
                     45, 41, 49, 35, 28, 31]

shifts_for_round_key_gen = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# Initial S_Box
s_boxes = {i: None for i in range(8)}

s_boxes[0] = [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
              [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
              [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
              [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]]

s_boxes[1] = [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
              [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
              [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
              [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]]

s_boxes[2] = [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
              [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
              [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
              [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]]

s_boxes[3] = [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
              [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
              [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
              [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]]

s_boxes[4] = [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
              [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
              [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
              [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]]

s_boxes[5] = [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
              [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
              [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
              [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]]

s_boxes[6] = [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
              [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
              [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
              [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]]

s_boxes[7] = [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
              [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
              [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
              [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]

pbox_permutation = [15, 6, 19, 20, 28, 11, 27, 16,
                    0, 14, 22, 25, 4, 17, 30, 9,
                    1, 7, 23, 13, 31, 26, 2, 8,
                    18, 12, 29, 5, 21, 10, 3, 24]


def get_encryption_key():
  with open('key.txt', 'r') as myFile:
    key = myFile.read()
  key = BitVector(textstring=key)
  key = key.permute(key_permutation_1)
  return key


def generate_round_keys(encryption_key):
  round_keys = []
  key = encryption_key.deep_copy()
  for round_count in range(16):
    [LKey, RKey] = key.divide_into_two()
    shift = shifts_for_round_key_gen[round_count]
    LKey << shift
    RKey << shift
    key = LKey + RKey
    round_key = key.permute(key_permutation_2)
    round_keys.append(round_key)
  return round_keys


def substitute(expanded_half_block):
  output = BitVector(size=32)
  segments = [expanded_half_block[x * 6:x * 6 + 6] for x in range(8)]
  for sindex in range(len(segments)):
    row = 2 * segments[sindex][0] + segments[sindex][-1]
    column = int(segments[sindex][1:-1])
    output[sindex * 4:sindex * 4 + 4] = BitVector(intVal=s_boxes[sindex][row][column], size=4)
  return output


def DES(input_path, output_path, selection):
  # get the user-defined key
  key = get_encryption_key()
  # generate the round key
  round_keys = generate_round_keys(key)
  # If is decryption, reverse the round_key
  if selection:
    round_keys.reverse()
  bv = BitVector(filename=input_path)
  FILEOUT = open(output_path, 'wb')
  final_message = BitVector(size=0)
  while(bv.more_to_read):
    # Read in the next block to process
    bv_read = bv.read_bits_from_file(64)
    # Check if it is 64 bit, otherwise pad
    if len(bv_read) < 64:
      bv_read.pad_from_right(64 - len(bv_read))
    # Divide the block into two halves
    [left_half, right_half] = bv_read.divide_into_two()
    # Process the DES
    for round_key in round_keys:
      # Expand the right half into 48 bit
      right_temp = right_half.permute(expansion_permutation)
      # XORing with the round key
      out_xor = right_temp ^ round_key
      # Process the S_Box substitution
      right_new = substitute(out_xor)
      # Process the P_Box permuation
      right_new = right_new.permute(pbox_permutation)
      # XORing with the left half
      right_final = right_new ^ left_half
      # The results will go to next round
      left_half = right_half
      right_half = right_final
    # combine two final blocks
    final_result = right_half + left_half
    final_message += final_result
  # FILEOUT.write(final_message.get_hex_string_from_bitvector())
  final_message.write_to_file(FILEOUT)
  FILEOUT.close()


def main():
  DES('message.txt', 'encrypted.txt', 0)
  DES('encrypted.txt', 'decrypted.txt', 1)

#   output of encrypted text
#   ‘lÁ?7dÀﬁ∞Î T_húØÑˆê£  |ÿ™FØåW-îı>É{√√Œs≤Jve>ùﬁI#8¯Ø”&Ÿò∏ﬁ˚î†/ª"zzÙ;g°G≥"¢ÊC∂_ÌÑ®gçr√≠ËıΩ¯iˇT√R©B3 ‹Qa,p£I¡~±deË&Ç:We“0åÓ\¥9¡∑,–¨Ï«Ó+
# ÊN|n‹/élf;⁄≤Ÿüœ∏ ¥[ó3äÁ¯⁄é]g©óÅ≈]0¢◊ÑÑ’˛s∆
# ˘ö~qWê`PEú#—©©›qÓÈ$™V:õà¥vÊ—ÆFu¬µ„Ày¶Ö5.∫Bb¿çñπâ•d‰òïπÈ*≥ﬂ=bÃqà@ßíôZRÙ=B[M à@3¡XZo–DÚe1#C}ªø\OòÉ7‚.07Ó}¬&á˘è∫
# ¬ÇåÚF”3•JLÏ,«¡ˆÁø%«Oê{‘øÌﬁå›"á2ﬂª—kKsüü$Î¡@ó])[ §i[úi1
# Óó‹öAï‰≠€◊
# AhÔ–J„&°^ÀÏœµN-≠äïòôNûyn§⁄∞¿ó‚]–;~™ó£´44¡7ﬁÀ4æî=~ötÊÊ∞%Ïü!‘ºD∆Ó5ÀÄŸä;œ/¥ù"∫%t€möØƒnX˘˝&Ü›_i
# yS\Ö ò°€ú˘–ëW∫˘–»⁄µ2ü∑f}˘/õ•}πU_j®9ô¢¸îÈ¸S‚6–WLÒÌn≤.Ì§3…Äö«

# output of decrypted text
# Meltdown exploits a race condition, inherent in the design of many modern CPUs. This occurs between memory access 
# and privilege checking during instruction processing. Additionally, combined with a cache side-channel attack, 
# this vulnerability allows a process to bypass the normal privilege checks that isolate the exploit process 
# from accessing data belonging to the operating system and other running processes. The vulnerability allows
#  an unauthorized process to read data from any address that is mapped to the current process' memory space. 
#  Since instruction pipelining is in the affected processors, the data from an unauthorized address will 
#  almost always be temporarily loaded into the CPU's cache during speculative execution-from which the data 
#  can be recovered. This can occur even if the original read instruction fails due to privilege checking,
#   and/or if it never produces a readable result. Since many operating systems map physical memory, kernel 
#   processes, and other running user space processes into the address space of every process, Meltdown effectively 
#   makes it possible for a rogue process to read any physical, kernel or other processes' mapped memory-regardless 
#   of whether it should be able to do so.




if __name__ == '__main__':
  main()
