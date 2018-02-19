#! usr/bin/env python3

# Shulin Wang
# ECE 404
# Hw 02

import sys
from BitVector import *
import random
import copy

# This is the python script for Problem 2. There are three sub problems in this part
# Most of the functions are referenced to the lecture notes and DES_wang.py
# Call syntax: python3 Average_wang.py
#

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


def substitute_for_diffusion(expanded_half_block):
  dif_s_boxes = randome_s_box()
  output = BitVector(size=32)
  segments = [expanded_half_block[x * 6:x * 6 + 6] for x in range(8)]
  for sindex in range(len(segments)):
    row = 2 * segments[sindex][0] + segments[sindex][-1]
    column = int(segments[sindex][1:-1])
    output[sindex * 4:sindex * 4 + 4] = BitVector(intVal=dif_s_boxes[sindex][row][column], size=4)
  return output


def DES(input_path, position, selection):
  # get the user-defined key
  key = get_encryption_key()
  # Change one bit in the key based on preference
  if position != 0:
    key[position] ^= 1
  # generate the round key
  round_keys = generate_round_keys(key)
  # If is decryption, reverse the round_key
  if selection:
    round_keys.reverse()
  bv = BitVector(filename=input_path)
  # FILEOUT = open(output_path, 'wb')
  final_message = BitVector(size=0)
  total_round = 0
  while(bv.more_to_read):
    # Read in the next block to process
    bv_read = bv.read_bits_from_file(64)
    # Check if it is 64 bit, otherwise pad
    if len(bv_read) < 64:
      bv_read.pad_from_right(64 - len(bv_read))
    # Divide the block into two halves
    [left_half, right_half] = bv_read.divide_into_two()
    total_round += 1
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
  return final_message, total_round


def Modified_DES(input_path, round, selection, position, problem):
  # get the user-defined key
  key = get_encryption_key()
  # generate the round key
  round_keys = generate_round_keys(key)
  # If is decryption, reverse the round_key
  if selection:
    round_keys.reverse()
  bv = BitVector(filename=input_path)
  final_message = BitVector(size=0)
  difference = 0
  count = 0
  while(bv.more_to_read and count < round):
    # Read in the next block to process
    bv_read = bv.read_bits_from_file(64)
    # If problem 1, then change the first bit of the plaintext,
    # if problem3, then use different s_box for substitution
    if problem == 1:
      modified_bv = bv_read.deep_copy()
      modified_bv[0] ^= 1
    elif problem == 3:
      modified_bv = bv_read.deep_copy()
    # Check if it is 64 bit, otherwise pad
    if len(bv_read) < 64:
      bv_read.pad_from_right(64 - len(bv_read))
    # Divide the block into two halves
    [left_half, right_half] = bv_read.divide_into_two()
    if problem == 1 or problem == 3:
      [modified_left_half, modified_right_half] = modified_bv.divide_into_two()
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
      # Process the different plaintext and calculate the difference
      if problem == 1 or problem == 3:
        modified_right_temp = modified_right_half.permute(expansion_permutation)
        modified_out_xor = modified_right_temp ^ round_key
        # use different s_box if it's problem 3
        if problem == 3:
          modified_right_new = substitute_for_diffusion(modified_out_xor)
        else:
          modified_right_new = substitute(modified_out_xor)
        modified_right_new = modified_right_new.permute(pbox_permutation)
        modified_right_final = modified_right_new ^ modified_left_half
        modified_left_half = modified_right_half
        modified_right_half = modified_right_final

    # combine two final blocks
    final_result = right_half + left_half
    modified_final_result = modified_right_half + modified_left_half
    count += 1
    # zip two string and calculate the difference
    compare = zip(final_result, modified_final_result)

    # difference in original text and modified text were calculated
    for x, y in compare:
      if x != y:
        difference += 1
  return int(difference / round)


def Diffusion():
  # change one bit in plaintext and calculate the difference
  result = Modified_DES('message.txt', 10, 0, 0, 1)
  return result


def randome_s_box():
  # This is the function used to generate random set
  # of s_box

  s_boxes = {x: None for x in range(8)}
  entries = [x for x in range(16)]

  for key in s_boxes.keys():
    random.shuffle(entries)
    a = copy.deepcopy(entries)
    random.shuffle(entries)
    b = copy.deepcopy(entries)
    random.shuffle(entries)
    c = copy.deepcopy(entries)
    random.shuffle(entries)
    d = copy.deepcopy(entries)
    s_boxes[key] = [a, b, c, d]
  return s_boxes


def s_box_diffusion():
  # 3 sets of s_boxes were tested, and the difference were returned to the main function
  result = Modified_DES('message.txt', 10, 0, 0, 3)
  result2 = Modified_DES('message.txt', 10, 0, 0, 3)
  result3 = Modified_DES('message.txt', 10, 0, 0, 3)
  return result, result2, result3


def Confusion():
  # 3 different key were used and difference were calculated
  result, round1 = DES('message.txt', 0, 0)
  result2, round2 = DES('message.txt', 1, 0)
  result3, round3 = DES('message.txt', 2, 0)
  result4, round4 = DES('message.txt', 3, 0)
  compare = zip(result, result2)
  compare2 = zip(result, result3)
  compare3 = zip(result, result4)
  count = 0
  for x, y in compare:
    if x != y:
      count += 1
  for x, y in compare2:
    if x != y:
      count += 1
  for x, y in compare3:
    if x != y:
      count += 1

  return int(count / (round2 + round3 + round4))


def main():
  # Problem 2.1
  # Process 10 blocks of plaintext and calculate the average difference
  result = Diffusion()
  print(result)    # Average of 33 bit for 10 blocks

  # Problem 2.2
  # Process several combination of s_box and calculate the average difference
  result = s_box_diffusion()
  print(result, int(sum(result) / 3))   # result = (30, 33, 34), average = 32

  # Problem 2.3
  # Process 3 different key and calculate the average difference
  result = Confusion()
  print(result)    # Average of 31 bit for entire ciphertext


if __name__ == '__main__':
  main()
