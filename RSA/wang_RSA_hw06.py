import sys
import pickle
import PrimeGenerator
from BitVector import *

# This is the script that process the RSA algorithm for encryption and decryption

e = 65537


def geneKey():
    # Generate the public and private keys
    global e
    # Generate a random 128 bit prime
    generator = PrimeGenerator.PrimeGenerator(bits=128)
    while True:
        p, q = generator.findPrime(), generator.findPrime()
        # Check if all necessary requirements are meet
        if p == q or (bgcd(e, p) != 1) or (bgcd(e, q) != 1):
            continue
        n = p * q
        break
    # Calculate pair keys
    tn = (p - 1) * (q - 1)
    tn_bv = BitVector(intVal=tn)
    e_v = BitVector(intVal=e)
    d_v = e_v.multiplicative_inverse(tn_bv)
    # Store the keys
    pickle.dump((e_v.int_val(), d_v.int_val(), n, p, q), open('key.p', 'wb'))
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
    # Load key from system
    e, _, n, _, _ = pickle.load(open('key.p', 'rb'))
    bv = BitVector(filename=message)
    FILEOUT = open(output, 'w')
    final_result = BitVector(size=0)
    while bv.more_to_read:
        # Perform 256 bit block operation
        bv_read = bv.read_bits_from_file(128)
        if len(bv_read) != 128:
            bv_read.pad_from_right(128 - len(bv_read))
        bv_read.pad_from_left(256 - len(bv_read))
        # Perform calculation
        encrypted_number = pow(bv_read.int_val(), e, n)
        encrypted_number_bv = BitVector(intVal=encrypted_number, size=256)
        final_result += encrypted_number_bv
    FILEOUT.write(final_result.get_bitvector_in_hex())
    FILEOUT.close()


def Decryption(output, decrypted):
    # Load key and other components
    _, d, n, p, q = pickle.load(open('key.p', 'rb'))
    FILEIN = open(output)
    encrypted_bv = BitVector(hexstring=FILEIN.read())
    final_result = BitVector(size=0)
    FILEOUT = open(decrypted, 'w')
    FILEOUT2 = open('hex_decrypted.txt', 'w')
    length = 0
    final_result = BitVector(size=0)
    while length < len(encrypted_bv):
        bv_read = encrypted_bv[length:length + 256]
        length += 256
        # Perform CRT to speed up the process
        v_p = pow(bv_read.int_val(), d, p)
        v_q = pow(bv_read.int_val(), d, q)
        q_inverse = BitVector(intVal=q).multiplicative_inverse(
            BitVector(intVal=p)).int_val()
        p_inverse = BitVector(intVal=p).multiplicative_inverse(
            BitVector(intVal=q)).int_val()
        x_p = q * q_inverse
        x_q = p * p_inverse
        result = (v_p * x_p + v_q * x_q) % n
        final_result += BitVector(intVal=result, size=256)[128:]
    FILEOUT.write(final_result.get_bitvector_in_ascii())
    FILEOUT2.write(final_result.get_bitvector_in_hex())
    FILEOUT.close()
    FILEOUT2.close()


def main():
    # Perform either encryption or decryption
    if sys.argv[1] == '-e':
        # Generate pair keys
        geneKey()
        Encryption(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == '-d':
        Decryption(sys.argv[2], sys.argv[3])

    e, d, n, p, q = pickle.load(open('key.p', 'rb'))
    print('e: {0}\nd: {1}\nn: {2}\np: {3}\nq: {4}\n'.format(e, d, n, p, q))

    # Value of keys
    # e: 65537
    # d: 16945876204946888090609812992800035972874039643883809042368495585150885377073
    # n: 107959744225100049071089269379715753627005693985439442686935867184927894498971
    # p: 335780416097713360869808813641100662761
    # q: 321518882726273584868032205831989232611

    # Encryption result
    # 819175cead10a0df29ae5424c1fae97a3c1712d517ad87c2c27b0aeb30fae3ba1520912784871d17cc1
    # ef33ed4cc928c99d91526b6a8926968b5b11b9383374c7136a2d7a42f67c93c7550d14eee6a38d35c71
    # f150ad14d5b07a11b292c8e417000359dd23fd5bc9fca48670623855e06f50e7be6d229db398f08b7b2
    # 9ce74d8381443ba39fe1b1eef21d20a0514ed219dfe4f02e94980bb13ed610a9f70d7b27476e5ffad5e
    # 2188febcff9edc97a06b509e885d6f5772fa11ea4ce4c5296ac1a92497250c7311a6fe2b1ce43fd4868
    # 0b65d97857c5ea66d766502ad4eaf02af1e050c6a12c3a94b75af9526d1029502aaf350cac64a740d13
    # 7897cbdd8be8594597f9d775a63e5eac1e17f5b54b856128fe22dc8a2785286e585532f58aac953a494
    # 12eb8005920d6e2f15b1d1f85f2335f06c6a46c58d49599a484f6a9b75e24ed38a4eafa1faa135e1132
    # 441143c9fc6adc89ae4993687d6f5625fe4b4e892057155f6b526a8fdf990b05d470e5a0e711ab10c9e8
    # 75542e7380eb3cac4119

    # Decryption result(hex)
    # 20224c69666527732062757420612077616c6b696e6720736861646f772c206120706f6f7220706c6179657220746
    # 861742073747275747320616e642066726574732068697320686f75722075706f6e2074686520737461676520616e
    # 64207468656e206973206865617264206e6f206d6f72652e20497420697320612074616c6520746f6c64206279206
    # 16e206964696f742c2066756c6c206f6620736f756e6420616e6420667572792c207369676e696679696e67206e6f7
    # 468696e6722

    # Decryption result(ascii)
    # "Life's but a walking shadow, a poor player that struts and frets his hour upon the stage and
    # then is heard no more. It is a tale told by an idiot, full of sound and fury, signifying nothing"


if __name__ == "__main__":
    main()
