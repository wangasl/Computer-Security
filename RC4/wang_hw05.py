#! usr/bin/env python3

# Shulin Wang
# ECE 404
# HW 04

# This is the python script to process the RC4 Stream Cipher Algorithm
#
# Call syntax:  python3 wang_hw05.py
#

import copy


class RC4:
        # Generate the class RC4
    def __init__(self, key_string):
        # Initial s_array and key_string
        self.key_string = key_string
        self.s_array = [x for x in range(256)]

        # Initial k_array
        k_array = list(key_string)
        for index, element in enumerate(k_array):
            k_array[index] = ord(element)
        length = len(key_string)

        # Initial t_array
        t_array = [k_array[x % length] for x in range(256)]

        # Initial permutation of s_array
        j = 0
        for i in range(256):
            j = (j + self.s_array[i] + t_array[i]) % 256
            self.s_array[i], self.s_array[j] = self.s_array[j], self.s_array[i]

    def encrypt(self, image):

        # Process the encryption
        i = 0
        j = 0
        temp_s_array = copy.deepcopy(self.s_array)
        final_result = []

        for byte in image:
            # Generate the pseudorandom byte stream
            i = (i + 1) % 256
            j = (j + temp_s_array[i]) % 256
            temp_s_array[i], temp_s_array[j] = temp_s_array[j], temp_s_array[i]
            k = (temp_s_array[i] + temp_s_array[j]) % 256
            result = byte ^ temp_s_array[k]
            final_result.append(result)

        return final_result

    def decrypt(self, image):
        # Process the encryption
        i = 0
        j = 0
        temp_s_array = copy.deepcopy(self.s_array)
        final_result = []

        for byte in image:
            # Generate the pseudorandom byte stream
            i = (i + 1) % 256
            j = (j + temp_s_array[i]) % 256
            temp_s_array[i], temp_s_array[j] = temp_s_array[j], temp_s_array[i]
            k = (temp_s_array[i] + temp_s_array[j]) % 256
            result = byte ^ temp_s_array[k]
            final_result.append(result)

        return final_result


def removeHeader(filename):
    headers = []
    with open(filename, 'rb') as myFile:
        for i in range(3):
            headers.append(myFile.readline())
        contents2 = myFile.read()
    image = contents2
    return image, headers


def main():
    rc4Cipher = RC4('abcdefghijklmnop')
    # Seperate the header and image data
    image, header = removeHeader('winterTown.ppm')
    # Encrypt the image data and write to file
    encryptedImage = rc4Cipher.encrypt(image)
    with open('test.ppm', 'wb') as myFile:
        for i in header:
            myFile.write(i)
        myFile.write(bytearray(encryptedImage))
    # Seperate the header and encrypted data
    image2, header2 = removeHeader('test.ppm')
    decryptedImage = rc4Cipher.decrypt(image2)
    # Decrypt the image data and write to file
    with open('test_decrypted.ppm', 'wb') as myFile2:
        for i in header:
            myFile2.write(i)
        myFile2.write(bytearray(decryptedImage))


if __name__ == "__main__":
    main()
