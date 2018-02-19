#! usr/bin/env python3

# Shulin Wang
# ECE 404
# HW 03

# This is the python script to determine if Zn is a field or commutative ring
# Call syntax:	python3 wang_Field.py
# The result will be outputted on terminal

import sys


def read_input():
    if sys.version_info[0] == 3:
        number = int(input("Enter the number: "))
    else:
        number = int(raw_input("Enter the number: "))
    return number


def field_or_ring(number):
    check = True
    # if number is less than 2, then it is not field
    if number < 2:
        check = False
    else:
        # detminer if the number is prime, if it is then field
        # Otherwiese ring
        for i in range(2, number):
            if number % i == 0:
                check = False
                break
    if check:
        return 'Number {0} is a field'.format(number)
    else:
        return 'Number {0} is a ring'.format(number)


def main():
    # Read user input number
    number = read_input()
    # Determine if it's a field or ring
    result = field_or_ring(number)
    print(result)

    # Enter the number: 2
    # Number 2 is a field

 	# Enter the number: 8
	# Number 8 is a ring

    # Enter the number: 17
    # Number 17 is a field

    # Enter the number: 50
    # Number 50 is a ring


if __name__ == '__main__':
    main()
