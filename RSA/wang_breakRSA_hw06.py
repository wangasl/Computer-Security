import sys
import pickle
import PrimeGenerator
from BitVector import *
import numpy as np

# This is the script that perform RSA breaking operation

e = 3
n_list = []


def solve_pRoot(p, y):
    p = int(p)
    y = int(y)
    # Initial guess for xk
    try:
        xk = int(pow(y, 1.0 / p))
    except:
        # Necessary for larger value of y
        # Approximate y as 2^a * y0
        y0 = y
        a = 0
        while (y0 > sys.float_info.max):
            y0 = y0 >> 1
            a += 1
        # log xk = log2 y / p
        # log xk = (a + log2 y0) / p
        xk = int(pow(2.0, (a + np.log2(float(y0))) / p))

    # Solve for x using Newton's Method
    err_k = int(pow(xk, p)) - y
    while (abs(err_k) > 1):
        gk = p * int(pow(xk, p - 1))
        err_k = int(pow(xk, p)) - y
        xk = int(-err_k / gk) + xk
    return xk


def geneKey():
    # Generate the public and private keys
    global e
    # Generate a random 128 bit prime
    generator = PrimeGenerator.PrimeGenerator(bits=128)
    i = 0
    while True:
        p, q = generator.findPrime(), generator.findPrime()
        # Check if all necessary requirements are meet
        if p == q or (bgcd(e, p) != 1) or (bgcd(e, q) != 1):
            continue
        n = p * q
        tn = (p - 1) * (q - 1)
        tn_bv = BitVector(intVal=tn)
        e_v = BitVector(intVal=e)
        d_v = e_v.multiplicative_inverse(tn_bv)
        if d_v is None:
            continue
        break
    # Store the keys
    pickle.dump((e_v.int_val(), d_v.int_val(), n, p, q), open('key.p', 'wb'))
    return n


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


def Break(encrypted1, encrypted2, encrypted3, cracked):
    # Perform breaking operation
    global n_list
    total = n_list[0] * n_list[1] * n_list[2]
    FILEIN1 = open(encrypted1)
    FILEIN2 = open(encrypted2)
    FILEIN3 = open(encrypted3)
    encrypted_bv1 = BitVector(hexstring=FILEIN1.read())
    encrypted_bv2 = BitVector(hexstring=FILEIN2.read())
    encrypted_bv3 = BitVector(hexstring=FILEIN3.read())
    n1 = total // n_list[0]
    n2 = total // n_list[1]
    n3 = total // n_list[2]
    temp1 = BitVector(intVal=n1).multiplicative_inverse(
        BitVector(intVal=n_list[0])).int_val()
    temp2 = BitVector(intVal=n2).multiplicative_inverse(
        BitVector(intVal=n_list[1])).int_val()
    temp3 = BitVector(intVal=n3).multiplicative_inverse(
        BitVector(intVal=n_list[2])).int_val()
    length = 0
    final_result = BitVector(size=0)
    FILEOUT = open(cracked, 'w')
    FILEOUT2 = open('hex_cracked.txt', 'w')
    while length < len(encrypted_bv1):
        bv_read1 = encrypted_bv1[length:length + 256]
        bv_read2 = encrypted_bv2[length:length + 256]
        bv_read3 = encrypted_bv3[length:length + 256]
        length += 256
        result = (bv_read1.int_val() * n1 * temp1 + bv_read2.int_val()
                  * n2 * temp2 + bv_read3.int_val() * n3 * temp3) % total
        result = solve_pRoot(3, result)
        result = BitVector(intVal=result, size=256)[128:]
        final_result += result
    FILEOUT.write(final_result.get_bitvector_in_ascii())
    FILEOUT2.write(final_result.get_bitvector_in_hex())
    FILEOUT.close()
    FILEOUT2.close()


def main():
    # Encrypt the given plaintext for three times
    n1 = geneKey()
    Encryption(sys.argv[1], 'encrypted1.txt')
    n2 = geneKey()
    Encryption(sys.argv[1], 'encrypted2.txt')
    n3 = geneKey()
    Encryption(sys.argv[1], 'encrypted3.txt')
    # The attacker will know the public key pair, which are e and n
    global n_list
    n_list = [n1, n2, n3]
    # Perform breaking operation
    Break('encrypted1.txt', 'encrypted2.txt', 'encrypted3.txt', sys.argv[2])
    print(n_list)

    # N value lists
    # [84556582957431936780618979080763805882902527637437321482381128142869049563093,
    # 103672330104585936154982397997065267947477154317158628711817806757377106361669,
    # 94808978637660797922441590841736238038824180908670177181411609265464729976857]

    # Three encrypted files
    # 5003da3a57d44baa6a01fcb7cd6e8433e758d6153d21147f38d46de610e879ae26345497ff975a031b
    # 3303a8f59dd1ecf46ee46533c00659d83ce123972cdaf98e46b36ae989c442a74cb660bd059547cb76
    # 2ab7b220b97706123ca8c3938fcb1a6738102ffd4340006cb262ce5c811bea426e2c91e0dd58415554
    # a7a458dbc8a8824d6972b8af5db344af193168f54026f1dc33328e9590f23d9e0ad70ecf3c60622008
    # e8747607c1ab52362e33de0528b060a873718f49fd803d4308e0c84da95705924f91eb5825c6455b01
    # 059918b59661cd74a8443702ca7f46108e1e7d41b13f985e4e9d16c35ee82b06e120fa6da70e672abd
    # 8da2ddcef608230ed10000203502893ba3fa0e16adca95e82b34f12fd06538a6ea980f924a4257e72a
    # 5a28939cfc563bf76a30baca495b7df529fe1758d2c301860df16d9ba06018729b2aff6579c0d328b1e
    # 649134312f120e5febece21cbe2a2d7563108a6e5b83bc1b1b1cb46ef91cc78ac06597fb6510003fe2b33
    # 51d781d004bffb0c350c604b6d

    # 9e6a4a964f83767f6dd3efd56c03fd18ea7b29b94ee8da696a8c8601caae7d4b8ed20191ea1ce2f4d2765a
    # 3eb278248d35e349159fc21bc54fe34d5bc994b8bf196d94b96aeb2d377b00d78a9016a486a2c88f62b6b0
    # dc05a74e41d622d8e01f7bb4edcca2c4fdc74576078e187089663ecb1a80ac780cac92aa94205455d5bb7c
    # 74a336dafea8a28374fa40cf37635500fcfe435e4476f93c59273a3453028a9e465a3dc64b8ad31ae80a46
    # 39abbb54f2d86e76f9cae97cf989f15374b41789dfaefff475dfc73dc93d500ca99c7571e3ea667aec2c47
    # 86e369b5e1f1a4cd6f27ff61c59427f8e6acfec7d95f8e26e4213e5e1ba2809e2be5e4d8ebcecb08a4c731
    # 870a81b4f09809700ee16d0e3cf4bc6261f898faa791897698bdf3edbbb34df7fa44d82b238f7b11fbb39a
    # 6314bd6eb22f2be24d6202f0c64037119f134a53c260fda10b6baf71bc7d59758b9bba348d093f298e42f8
    # 231eab2dde935a7cb4c972e6b3e8568a92a3aa5db7d2272106c05442bab195a6b0bdf6f6ba940b82

    # 6ebfe99575c7c8fb9a61f76ca6330dba05cf2d437f566465b3e2e2d01c01658b1ca5067ff0ff89f87e61368
    # 165d723047a53b368eaf37cef3aadc1cc81881f615ed031d8ec1389e7519846f0ec99a30965be5a57ca8fcd
    # 89413c9358fdb85b2271bf0a2a92c3b7272a99bb135dad50b34ee54c149a3c90a40c6d9fc2f68c0e5eaf568
    # ec4a2653cf540fbd5472e1b1298dfc8325c3ab0c382c6928331dd0ac30d6ba49d9a60b21b24b7cd6bd93f5a
    # fd96d7904541cc2f8826a89e7bdf5e2c95fbcf805885663c8ba44c56d45ad20ef6363116b9c4ad0efdea016
    # ba612ddfa2077b43ec62217c0bebe9346d4e323c11cef8c20c29c2bbf2c114286efa66577e34d64a721f11e
    # 1324a964232b62ac118573df22775b219a9d242d73d18c6455913a8975bb3b8299c310a231fb477b3465e21
    # f6589a6e60519bf81deeee2d3d3e386476ba490105f51a02453a8b1b69f77ae2319f61aeeee459d354d8b0b
    #b3f81837c2e87eed3042730dd1ca8b58e5198727499341555fa0249abeefb375df93995f

    # Cracked file(hex)
    # 20224c69666527732062757420612077616c6b696e6720736861646f772c206120706f6f7220706c6179657
    # 220746861742073747275747320616e642066726574732068697320686f75722075706f6e20746865207374
    # 61676520616e64207468656e206973206865617264206e6f206d6f72652e20497420697320612074616c652
    # 0746f6c6420627920616e206964696f742c2066756c6c206f6620736f756e6420616e6420667572792c2073
    # 69676e696679696e67206e6f7468696e6722

    # Cracked file(ascii)
    # "Life's but a walking shadow, a poor player that struts and frets his hour upon the stage
    #  and then is heard no more. It is a tale told by an idiot, full of sound and fury, signifying nothing"


if __name__ == "__main__":
    main()
