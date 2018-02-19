#!/usr/bin/env python

# GF_Arithmetic.py
# Author: Avi Kak
# Date:   February 13, 2011

# Note: The code you see in this file has already been incorporated in
# Version 2.1 and above of the BitVector module.  If you like
# object-oriented approach to scripting, just use that module
# directly.  The documentation in that module shows how to make
# function calls for doing GF(2^n) arithmetic.

from BitVector import *


def gf_divide(num, mod, n):
    '''
    Using the arithmetic of the Galois Field GF(2^n), this function divides 
    the bit pattern 'num' by the modulus bit pattern 'mod'
    '''
    if mod.length() > n + 1:
        raise ValueError("Modulus bit pattern too long")
    quotient = BitVector(intVal=0, size=num.length())
    remainder = num.deep_copy()
    i = 0
    while 1:
        i = i + 1
        if (i == num.length()):
            break
        mod_highest_power = mod.length() - mod.next_set_bit(0) - 1
        if remainder.next_set_bit(0) == -1:
            remainder_highest_power = 0
        else:
            remainder_highest_power = remainder.length() \
                - remainder.next_set_bit(0) - 1
        if (remainder_highest_power < mod_highest_power) \
                or int(remainder) == 0:
            break
        else:
            exponent_shift = remainder_highest_power - mod_highest_power
            quotient[quotient.length() - exponent_shift - 1] = 1
            quotient_mod_product = mod.deep_copy()
            quotient_mod_product.pad_from_left(remainder.length() -
                                               mod.length())
            quotient_mod_product.shift_left(exponent_shift)
            remainder = remainder ^ quotient_mod_product
    if remainder.length() > n:
        remainder = remainder[remainder.length() - n:]
    return quotient, remainder


def gf_multiply(a, b):
    '''
    Using the arithmetic of the Galois Field GF(2^n), this function multiplies
    the bit pattern 'a' by the bit pattern 'b'.
    '''
    a_highest_power = a.length() - a.next_set_bit(0) - 1
    b_highest_power = b.length() - b.next_set_bit(0) - 1
    result = BitVector(size=a.length() + b.length())
    a.pad_from_left(result.length() - a.length())
    b.pad_from_left(result.length() - b.length())
    for i, bit in enumerate(b):
        if bit == 1:
            power = b.length() - i - 1
            a_copy = a.deep_copy()
            a_copy.shift_left(power)
            result ^= a_copy
    return result


def gf_multiply_modular(a, b, mod, n):
    '''
    Using the arithmetic of the Galois Field GF(2^n), this function returns 'a'
    divided by 'b' modulo the bit pattern in 'mod'.
    '''
    a_copy = a.deep_copy()
    b_copy = b.deep_copy()
    product = gf_multiply(a_copy, b_copy)
    quotient, remainder = gf_divide(product, mod, n)
    return remainder


def gf_MI(num, mod, n):
    '''
    Using the arithmetic of the Galois Field GF(2^n), this function returns the
    multiplicative inverse of the bit pattern 'num' when the modulus polynomial
    is represented by the bit pattern 'mod'.
    '''
    NUM = num.deep_copy()
    MOD = mod.deep_copy()
    x = BitVector(size=mod.length())
    x_old = BitVector(intVal=1, size=mod.length())
    y = BitVector(intVal=1, size=mod.length())
    y_old = BitVector(size=mod.length())
    while int(mod):
        quotient, remainder = gf_divide(num, mod, n)
        num, mod = mod, remainder
        x, x_old = x_old ^ gf_multiply(quotient, x), x
        y, y_old = y_old ^ gf_multiply(quotient, y), y
    if int(num) != 1:
        return "NO MI. However, the GCD of ", str(NUM), " and ", \
            str(MOD), " is ", str(num)
    else:
        quotient, remainder = gf_divide(x_old ^ MOD, MOD, n)
        return remainder


mod = BitVector(bitstring='11001')             # AES modulus

a = BitVector(bitstring='0101')
result = gf_MI(a, mod, 4)
print("\nMI of %s is: %s" % (str(a), str(result)))

# a = BitVector( bitstring = '10010101' )
# result = gf_MI( a, mod, 8 )
# print("\nMI of %s is: %s" % (str(a), str(result)))

# a = BitVector( bitstring = '00000000' )
# result = gf_MI( a, mod, 8 )
# print("\nMI of %s is: %s" % (str(a), str(result)))
