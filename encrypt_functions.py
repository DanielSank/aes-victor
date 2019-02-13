import numpy as np

from constants import Nb, Nk, Nr


def get_key(filename: str='key.txt') -> np.ndarray:
    """Returns: 8 element array of i32

    The key file must contain set of eight space-separated blocks of data in
    hex representation, each one 8 characters long (32 bits) for a total of
    256 bits. For example:
        00010203 04050607 08090a0b 0c0d0e0f 10111213 14151617 18191a1b 1c1d1e1f
    """
    with open(filename, 'r') as keyfile:
        keytext = keyfile.read()
    return np.array([int(x, 16) for x in keytext.split(' ')])
    """
    textarray = keytext.split(' ')
    key = [0] * 8
    i = 0
    while i < 8:
        key[i] = int(textarray[i], 16)
        i = i + 1
    return key
    """


def key_expansion(key: np.ndarray) -> np.ndarray:
    """
    Args:
        key: eight 4-byte words = 256 bits. Each word is an integer with values
            from 0 to 2^32 - 1.

    Returns:
        The expanded key, an array of 60 4-byte elements
    """
    w = np.zeros(60, dtype='uint32')
    w[0: Nk] = key[0: Nk]
    i = Nk  # i = 8
    while i < Nb * (Nr + 1):
        temp = w[i - 1]  # Start with temp = w(7)
        if i % Nk == 0:  # If i is a multiple of 8.
            temp = int(sub_word(rot_word(temp))) ^ r_con(int(i / Nk))
        elif i % Nk == 4:
            temp = int(sub_word(temp))
        w[i] = w[i - Nk] ^ temp
        i = i + 1
    return w


def sub_word(wordin):  # breaks wordin into bytes and calls SBoxByte
    # Input:  4 byte word
    # Output: 4 byte word after application of S-box in SBoxByte()
    # Called from:  KeyExpansion
    # functions called:  SBoxByte(), int()
    """
    wordin is a 4 byte word.  It gets separated into individual bytes.
    Each byte will be applied to SBoxByte then reassembled into a
    word.
    """
    byte0 = wordin >> 24  # byte0 is the left most byte.  >> function is bit oriented
    msbyte = byte0 << 24  # put byte0 back in left most position
    temp = wordin - msbyte  # remove byte0 from most significant position
    byte1 = temp >> 16  # byte1 is next most significant byte
    nmsbyte = byte1 << 16  # put byte1 back in the next most significant position
    temp = temp - nmsbyte  # remove byte1 from next most significant position
    byte2 = temp >> 8  #
    byte3 = temp % 256  #
    sbox0 = sbox_byte(byte0)  # find the inverse plus affine transform of byte0
    sbox1 = sbox_byte(byte1)
    sbox2 = sbox_byte(byte2)
    sbox3 = sbox_byte(byte3)
    word = (sbox0 << 24) + (sbox1 << 16) + (sbox2 << 8) + sbox3
    return word


def rot_word(x):  # x is a 4 byte word,  perform cyclic shift one byte left
    # input:  a 4 byte word    called from KeyExpansion
    # output: input word x cyclic shifted left one byte
    # other functions used:  none
    x = int(x)
    byte0 = x >> 24  # byte0 is the left most byte
    msbyte = byte0 << 24  # put byte0 back in left most position
    x = x - msbyte  # remove byte0 from most significant left most position
    x = x << 8  # shift 3 right most bytes one byte left
    x = x + byte0  # put byte0 in right most position, where byte3 was
    return x


def r_con(i):  # Generate 7 or 8 4 byte words used for xor
    # Input: i, a number between 1 and 8; called from KeyExpansion
    # Output: a 4 byte word representing powers of i in upper byte
    # other functions used:  none
    # called from KeyExpansion
    if i < 1 or i > 8:
        raise ValueError("Rcon index {} not valid".format(i))
    return 1 << (23 + i)  # returns this value as (Rcon(i)


def get_pt_data():
    """
    read in plaintext data written in hex from file PTCTData.txt
    split into 4 elements where each represents 32 bits = 4 bytes
    convert each element from hex to integer
    """
    datafile = open('plaintex.txt', 'r')  # open('plaintex.txt', 'r')
    datatext = datafile.read()
    datafile.close()

    print('GetPTData: datatext (str) = ',
          datatext)  # Print the data which is in text format
    textarray = datatext.split(' ')
    data = [0] * 4  # defines an array of 4 integer zeros
    i = 0
    while i < 4:  # convert each element of text to int and put in data()
        data[i] = int(textarray[i], 16)  # Convert hex to int and insert in data()
        i = i + 1
    state = np.zeros((4, 4),
                     dtype='u8')  # state is a 4x4 byte array defined here
    c = 0  # c is the column index
    while c < 4:  # this loop is to put data in the 4x4 byte state array
        temp = data[c]
        r = 0  # r is the row intex
        while r < 4:  # for a given column put the 4 bytes of data[] in rows 0 to 3
            state[r, c] = temp >> (
                3 - r) * 8  # >> (3-r)*8 byte0 is the left most byte.
            msbyte = int(state[r, c]) << (
                3 - r) * 8  # put byte back in original position
            temp = temp - msbyte  # remove byte from temp
            r = r + 1
        c = c + 1
    return state


def add_round_key(state, w, rround):  # xor expanded key word with columns of state
    # input:  state array, w (round key), round number
    # output: state array xored with 4 words of w     Size w = (Nr+1)*Nb
    # other functions used:  none     ^ is bitwise xor
    # w (called "round key" from Key Expansion) is a 4 byte word, ie. < 2^32 - 1
    sp = state  # sp = state prime  no need to make separate array
    wbyte = np.zeros(4, dtype='int')  # this is one way to make byte() an int array
    c = 0  # c is column number, r is row number
    while c < 4:  # for a given column and round.   section 5.1.4 of NIST 197
        wtemp = int(w[rround * Nb + c])  # for each round inc w[] by 4  (=Nb)
        wbyte[0] = int(
            wtemp
        ) >> 24  # byte0 is the left most byte.  >> function is bit oriented
        msbyte = int(wbyte[0]) << 24  # put byte0 back in left most position
        wtemp = wtemp - msbyte  # remove byte0 from most significant position
        wbyte[1] = int(wtemp) >> 16  # byte1 is next most significant byte
        nmsbyte = int(
            wbyte[1]
        ) << 16  # put byte1 back in the next most significant position
        wtemp = int(wtemp) - int(
            nmsbyte)  # remove byte1 from next most significant position
        wbyte[2] = int(wtemp) >> 8  #
        wbyte[3] = wtemp % 256  # we now have w[i] broken into bytes
        # xor this column of sp with w[] byte at a time  (similar done in a loop in one of the funct)
        r = 0
        while r < 4:  # xor each byte with a byte of state
            sp[r, c] = int(sp[r, c]) ^ wbyte[r]  # do xor byte at a time
            r = r + 1
        c = c + 1  # now go to next column and do it again until c = 4


def sbox_byte(byte):
    #  called from SubWord which is called from KeyExpansion
    #  input    a single byte
    #  output   a single byte polynomial inverse via S-box transform
    # other functions used:  ValueError
    nibble0 = int(
        byte / 16)  # treating byte as an integer.  nibble0 has value 0 to 15
    nibble1 = int(
        byte % 16)  # select least sig 4 bits.      nibble1 has value 0 to 15

    sbox = np.array(  # open pre ")" allows continuation lines.  no need for \
        # each row is in [ ] and entire array is in another [ ]
        [[
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
            0x2b, 0xfe, 0xd7, 0xab, 0x76
        ],
         [
             0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2,
             0xaf, 0x9c, 0xa4, 0x72, 0xc0
         ],
         [
             0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5,
             0xf1, 0x71, 0xd8, 0x31, 0x15
         ],
         [
             0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80,
             0xe2, 0xeb, 0x27, 0xb2, 0x75
         ],
         [
             0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
             0xb3, 0x29, 0xe3, 0x2f, 0x84
         ],
         [
             0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0x1b, 0x5b, 0x6a, 0xcb, 0xbe,
             0x39, 0x4a, 0x4c, 0x58, 0xcf
         ],
         [
             0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02,
             0x7f, 0x50, 0x3c, 0x9f, 0xa8
         ],
         [
             0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda,
             0x21, 0x10, 0xff, 0xf3, 0xd2
         ],
         [
             0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e,
             0x3d, 0x64, 0x5d, 0x19, 0x73
         ],
         [
             0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8,
             0x14, 0xde, 0x5e, 0x0b, 0xdb
         ],
         [
             0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac,
             0x62, 0x91, 0x95, 0xe4, 0x79
         ],
         [
             0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
             0xea, 0x65, 0x7a, 0xae, 0x08
         ],
         [
             0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74,
             0x1f, 0x4b, 0xbd, 0x8b, 0x8a
         ],
         [
             0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57,
             0xb9, 0x86, 0xc1, 0x1d, 0x9e
         ],
         [
             0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87,
             0xe9, 0xce, 0x55, 0x28, 0xdf
         ],
         [
             0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d,
             0x0f, 0xb0, 0x54, 0xbb, 0x16
         ]],
        dtype='u8')
    invbyte = int(
        sbox[nibble0, nibble1]
    )  # value read from sbox table is the poly inverse of the input
    return invbyte


def sub_bytes(state):
    # input:  state
    # output: state with bytes replaced by polynomial inverse
    # called by: Main
    c = 0
    while c < 4:
        r = 0
        while r < 4:
            state[r, c] = sbox_byte(state[r, c])  # this line does all the work
            r = r + 1
        c = c + 1


def shift_rows(state):
    # Input:  state
    # Output: state with rows shifted r bytes where r is row number
    # other functions used:  print()
    # no shifts in first row
    ta = state  # ta is just an alais for state, points to same memory
    r = 1  # no shift in row 0, start with row 1
    while r < 4:  # do shifting in rows 1 to 3 with r shifts in row r
        numshifts = 0
        while numshifts < r:
            temp = ta[r, 0]
            j = 0
            while j < 3:
                ta[r, j] = ta[r, j + 1]
                j = j + 1
            ta[r, 3] = temp
            numshifts = numshifts + 1
        r = r + 1


# for testing
"""
state = np.matrix('1 5 9 13;2 6 10 14;3 7 11 15;4 8 12 16')
state is a square matrix    and after running shiftRows
 1 5  9 13                 1  5   9 13
 2 6 10 14                 6  10 14  2
 3 7 11 15                 11 15  3  7
 4 8 12 16                 16  4  8 12
"""


def mix_columns(state):
    # See sections 5.1.3 and 5.3.3 of NIST 197
    # input: state array
    # output: state array with changes based on non-binary polynomial multiply
    # other functions used:  none     ^ is bitwise xor
    # multiplying a poly by x is equivalent to shifting its bit representation one left
    # Calculate values of state prime array one column at a time
    s = state  # s now points to same memory as the state array
    sp = np.zeros(
        (4, 4), dtype='u8')  # sp is s' array, where state values are returned
    twos = np.zeros(
        (4, 4),
        dtype='u8')  # polynomial multiply by x, a temp during processing
    threes = np.zeros(
        (4, 4), dtype='u8')  # poly multiply by x+1, a temp during processing
    c = 0  # c is column number, r is row number
    while c < 4:  # section 5.1.3 of NIST 197
        r = 0
        while r < 4:  # calculate {02} * s[r,c]  section 4.2.1
            twos[r, c] = 2 * int(s[r, c])  # twos[r,c] temporary {02}*s[r,c]
            if twos[r, c] > 255:  # then the high bit was set and we need to xor
                twos[r, c] = (
                    (int(s[r, c]) - 128) << 1) ^ 27  # this is now {02}*s[r,c]
            r = r + 1  # Do this for all 4 rows, one column at a time
        # Now we need to calculate {03}*s[0,c] for all rows
        r = 0
        while r < 4:  # calculate {03} * s[r,c]  section 4.2.1
            # {03} * s[r,c] = ({02} * s[r,c]) + s[r,c] where "+" is "^"   no more concern about high bit
            threes[r, c] = int(twos[r, c]) ^ int(
                s[r, c])  # threes[r,c] temporary {03}*s[r,c]
            r = r + 1  # Do this for all 4 rows, one column at a time
        # Calculate column values for current column and put in state prime matrix, sp[].
        sp[0, c] = (twos[0, c]) ^ (threes[1, c]) ^ s[2, c] ^ s[3, c]
        sp[1, c] = (twos[1, c]) ^ (threes[2, c]) ^ s[0, c] ^ s[3, c]
        sp[2, c] = (twos[2, c]) ^ (threes[3, c]) ^ s[0, c] ^ s[1, c]
        sp[3, c] = (twos[3, c]) ^ (threes[0, c]) ^ s[1, c] ^ s[2, c]
        c = c + 1  # Now go to next column and do it again until c = 4
    c = 0
    while c < 4:
        r = 0
        while r < 4:
            state[r, c] = sp[r, c]
            r = r + 1
        c = c + 1


def out_ct_data(state):
    # Convert each column of state to integer then write as hex string.
    ct_data = [0] * 4  # Create an array(4)  type = 'list'
    c = 0
    while c < 4:  # Convert column elements to int and put in CTData()
        ct_data[c] = (int(state[0, c]) << 24) + (int(state[1, c]) << 16) + \
                    (int(state[2, c]) << 8) + int(state[3, c])
        c = c + 1

    textfile = open('CTData.txt', 'a')
    c = 0
    while c < 4:  # Could combine this while loop with the one above
        textfile.write(format(int(ct_data[c]), '02x'))  # x implies hex
        textfile.write(' ')  # Put a space between groups of 4 bytes
        c = c + 1
    textfile.write('\n')  # Put CR between groups of 16 bytes = 128 bits
    textfile.close()
    print(hex(ct_data[0]), hex(ct_data[1]), hex(ct_data[2]), hex(ct_data[3]))


def print_hex(state):
    for row in state:
        print(*(hex(element) for element in row))
