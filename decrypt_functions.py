# decrypt_functions.py                             V. Sank 2/7/19 10:00pm
# Functions defined in this file:
#     These functions and order of data is based on NIST FIPS 197.
#     Figure and section numbers refer to that document.
#     GetKey()
#     KeyExpansion(key)              returns w, decypher is same as cypher
#     SBoxByte(Byte)     does polynomial inversion and shift via table on a single byte
#     RotWord()                      cyclic shift elements in state left by r
#     Rcon()                         generates number used for xor
#     GetPTData()                    returns data, generates and returns state
#     AddRoundKey(state,w, round)    returns state
#     ISBoxByte(Byte)    reverses SBoxByte via table on a single byte
#     SubWord(w)                     breaks up 32 bit word into 8 bit bytes
#     InvSubBytes(state)   Polynomial inversion on state array independent on each byte
#     InvShiftRows(state)
#     InvMixColumns(stata)
#     OutPTData()                    Output CT Data to PTCTData.txt
#     printhex()                     print array in hex

Nb = int(4)    #  constants place before first “def” are available to all functions
Nk = int(8)
Nr = int(14)
import numpy as np
import math    # do we need this?

def get_key():  # tested 1/4/19    same as in cypher routine
    #Input:  none
    #Output: 8 element int array with 32 bits size in each element
#        keystr = cykeystr.read().replace'\n', '')
#   read in key written in hex from file CyKey.txt, then parce for use in KeyExpansion
#   key must be input with space between every 4 bytes = 8 hex characters
#   split into 8 word elements where each represents 32 bits = 4 bytes
#   convert each element from hex to integer  Word will have 8 pieces of 8 hex characters each
    keyfile = open('key.txt', 'r')   # open('CyKey.txt', 'r')  cyph and decyph uses same key
    keytext = keyfile.read()           # do the read
    keyfile.close()

    textarray = keytext.split(' ')
    print('GetKey: textarray')    #print the key which is in text format
    print(textarray)  #print the key which is now in 8 element array
    #key = np.array(8, int) # create the 8 word key() array, 32 bits each word
    key = [0] * 8     # another way to create an 8 word int array
    i = 0
    while i < 8:      # convert each element of text to int and put in key
        key[i] = int(textarray[i],16)  #convert to int and insert in key
        i = i + 1
    # end while i     # must be a global way to do this, instead of element by element
    #print('GetKey: int = ',key)        # print int value of the key() elements
    return key        #  no need to put () on array name in return statement
#End GetKey()


#   KeyExpansion tested and agrees with NIST 197 1/26/19   called from DeCypherMain
def key_expansion(key):    # 12/24/18  treat key as a 8 word linear array
    # input   key(8) words.  read in as eight 4-byte words = 256 bits
    #         each word is an integers with values from 0 to 2^32 - 1
    # output  w(60) words.  an array of 60 4-byte word with 0 <= i <= 59
    # Functions called:  RotWord, Rcon, SubWord
    # might be easier to deal with w[] as a single byte elements wbyte[j] with 0<= j <= 239 = 4*60 - 1
    # key() = np.array((8), dtype = 'uint32') # 8 element 4-byte-word array = 32 byte total = 256 bits
#    print('KeyExpansion:  key =', key)
    #input('KeyExpansion:  pause after printing key ')
    w = np.zeros(60, dtype = 'uint32') # w[] is a 60 word array and is the output of this function
#    print('KeyExpansion: type of key', type(key))    #  list
#    print('KeyExpansion: type of w', type(w))        #  numpy.ndarray  make this an int array
         # "zeros" is a np function, w is a one dimension array of 60 zeros
         # if this was a tuple array, since zeros is a function, w = np.zeros((4,4))
    i = int(0)
    while i < Nk:     # Nk = 8, create first 8 values of w from the key, w[0] to w[7]
        w[i] = key[i] # arrays are previously defined, put value of key[i] into first Nk of w[i]
        i = i + 1
    #end while i      not necessary to import SubWord, RotWord, Rcon" since they are in this file
    i = Nk                        # i = 8
    while i < Nb*(Nr+1):          # while i < 60
        temp = w[i-1]  # start with temp = w(7)    temp is a 4 byte word
        if i % Nk == 0:     # if i is a multiple of 8.  Runs between 8 and 56
            temp = int(SubWord(RotWord(temp))) ^  Rcon(int(i/Nk))   # ^ is bitwise xor
            #print('KeyExpansion  i, Rcon(int(i/Nk)) = ', i, Rcon(index))
        elif i % Nk == 4:
            temp = int(SubWord(temp))  # convert each byte of w[] via sbox, one word at a time
        # end if
        #print('KeyExpansion  i, temp, w[i-Nk] = ', i, temp, w[i-Nk])
        w[i] = w[i-Nk] ^ temp   # xor 8th previous w[] starting with w[0] with temp(w[7])
        i = i + 1
    # end while i
    """
    print('KeyExpansion:   w = ')
    i = 0
    while i < 10:
        print('{:08x}'.format(int(w[6*i+0])), '{:08x}'.format(int(w[6*i+1])), '{:08x}'.format(int(w[6*i+2])),
              '{:08x}'.format(int(w[6*i+3])), '{:08x}'.format(int(w[6*i+4])), '{:08x}'.format(int(w[6*i+5])))
        i = i + 1
    # end while i
    """
    print()     # leave blank line after printing w
    return w
# end KeyExpansion()

def get_ct_data():  # 1/26/19
#   read in plaintext data written in hex from file PTCTData.txt
#   split into 4 elements where each represents 32 bits = 4 bytes
#   convert each element from hex to integer
    datafile = open('CTData.txt', 'r')   # open('PTCTData.txt', 'r')
    datatext = datafile.read()
    datafile.close()

#    print('GetCTData: datatext (str) = ', datatext)    #print the data which is in text format
    textarray = datatext.split(' ')
#    print('GetCTData: (textarray) = ', textarray)  #print the data which is now in 8 element array
    data = [0] * 4     # defines an array of 4 integer zeros
    i = 0
    while i < 4:       # convert each element of text to int and put in data()
        data[i] = int(textarray[i],16)  #convert to int and insert in data()
        i = i + 1
    # end while i
#    print('GetCTData (int) =         ', data)   #print int value of the data() elements
    # convert into a 4x4 state array
    state = np.zeros((4,4), dtype='u8')    # state is a 4x4 integer matrix
    c = 0               # c is the column index
    while c < 4:        # this loop is to put data in the 4x4 byte state array
        temp = data[c]
        r = 0  # r is the row intex
        while r < 4:     # for a given column put the 4 bytes of data[] in rows 0 to 3
            state[r,c] = temp >> (3-r)*8   # >> (3-r)*8 byte0 is the left most byte.
            #print('GetCTData: state r ', r, '  c ', c, '  ', state[r,c])
            msbyte = int(state[r,c]) << (3-r)*8 # put byte back in original position
            temp = temp - msbyte           # remove byte from temp
            r = r + 1
        # end while r
        c = c + 1
    #end while c
#    print('GetCTdata: state = ')
#    print(state)
    return state        #  no need to put () on array name in return statement
#End GetCTData()


def add_round_key(state, w, round):  # 1/26/19  xor w with columns of state
    # input:  state array, w (called round key), round #
    # output: state array xored with 4 words of w     Size w = (Nr+1)*Nb
    # other functions used:  none     ^ is bitwise xor
    # w (called "round key" from Key Expansion) is a 4 byte word, ie. < 2^32 - 1
    sp = state            # sp = state prime  make separate array
    # able to just say sp = state since element change only involved the element being changed.
    wbyte = np.zeros((4), dtype='int')    # this is one way to make byte() an int array
    c = 0  # c is column number, r is row number
    #print('RoundKey:  c, wbyte = ', c, wbyte)
    while c < 4:  # for a given column and round.   section 5.1.4 of NIST 197
        # for column c separate w[round*Nb + c] into bytes
        wtemp = int(w[round*Nb + c])  #for each round inc w[] by 4  (=Nb)
        wbyte[0] = int(wtemp) >> 24   # byte0 is the left most byte.  >> function is bit oriented
        msbyte = int(wbyte[0]) << 24  # put byte0 back in left most position
        wtemp = wtemp - msbyte  # remove byte0 from most significant position
        wbyte[1] = int(wtemp) >> 16   # byte1 is next most significant byte
        nmsbyte = int(wbyte[1]) << 16 # put byte1 back in the next most significant position
        wtemp = int(wtemp) - int(nmsbyte)  # remove byte1 from next most significant position
        wbyte[2] = int(wtemp) >> 8    #
        wbyte[3] = wtemp % 256        #
        # xor this column of sp with w[] byte at a time  (similar done in a loop in one of the funct)
        #print('RoundKey:  c, w[round*Nb+c], byte = ', c, w[round*Nb+c], wbyte)
        r = 0
        while r < 4:
            sp[r, c] = int(sp[r,c]) ^ wbyte[r]   # do xor byte at a time
            r = r + 1
        #end while r
        c = c + 1  # now go to next column and do it again until c = 4
    # end While c
    #print('AddRoundKey: int(state) then hex(sp) = ')
    #print(state)
    #printhex(sp)
    return state
#end AddRoundKey(state,w,round):



#                       same as in Cypher routine
def RotWord(x):         # x is a 4 byte word,  perform cyclic shift one byte left
    # called from KeyExpansion  other functions used:  none
    x = int(x)
    byte0 = x >> 24     # byte0 is the left most byte
    msbyte = byte0<<24  # put byte0 back in left most position
    x = x - msbyte      # remove byte0 from most significant left most position
    x = x << 8          # shift 3 right most bytes one byte left
    x = x + byte0       # put byte0 in right most position, where byte3 was
    return x
#end RotWord(x):        return 4 byte word, x


#                       same as in Cypher routine
def Rcon(i):            # Generate 8 4 byte words used for xor.  Rcon(8) not used
    # called from KeyExpansion
    # Input: i    Output: a 4 byte word representing powers of X in upper byte
    # other functions used:  none
    if i < 1 or i > 8:  #
        raise ValueError("Rcon index {} not valid".format(i))  # make sure 0<i<9
    #Rcon(1) = 1 << 24  # in hex {01){00}{00}{00}
    #Rcon(2) = 1 << 25  # in hex {02}{00}{00}{00}
    #Rcon(3) = 1 << 26  #        {04}{00}{00}{00}
    return 1<<(23+i)    # returns this value as (Rcon(i)
#end Rcon(i):


def SBoxByte(byte):     #  same as in the cypher routine
    #  called from SubWord which is called from KeyExpansion
    #  input    a single byte
    #  output   a single byte after conversion via S-box transform
    # other functions used:  ValueError
#    if byte > 255:
#        raise ValueError("SBoxByte byte {} not valid".format(byte))
#    #end if
    nibble0 = int(byte/16)    # treating byte as an integer.  nibble0 has value 0 to 15
    nibble1 = int(byte % 16)  # select least sig 4 bits.      nibble1 has value 0 to 15
    # print("nibble0 = ", nibble0, '    n1=',nibble1= ')

    sbox = np.array(      # open pre ")" allows continuation lines.  no need for \
                          # each row is in [ ] and entire array is in another [ ]
        [[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
         [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
         [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
         [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
         [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
         [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0x1b, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
         [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
         [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
         [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
         [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
         [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
         [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
         [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
         [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
         [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
         [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]],
        dtype='u8')
    # print ('sbox ',sbox)
    invbyte = int(sbox[nibble0, nibble1])    # value read from sbox table is the poly inversion of the input
    #print('SBoxByte: invbyte = ', invbyte)       #
    return invbyte       # in calling routine, SBoxByte(byte) now has this value
# end SBoxByte(byte):



def ISBoxByte(byte):   #  values here are the inverse of the Encrypt version, SBoxByte
    # input:    a single byte representing a polynomial
    # output:   a single byte, inverse of the S-box transform used for encrypting
    # other functions used:  none
    # called from: InvSubBytes
    if byte > 255:
        raise ValueError("ISBoxByte byte {} not valid".format(byte))
    nibble0 = int(byte/16)    # treating byte as an integer.  nibble0 has value 0 to 15
    nibble1 = int(byte % 16)  # select least sig 4 bits.      nibble1 has value 0 to 15

    sbox = np.array(      # open pre ")" allows continuation lines.  no need for "\"
                          # each row is in [ ] and entire array is in another [ ]
        [[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
         [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
         [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
         [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
         [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
         [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
         [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
         [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
         [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
         [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
         [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
         [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
         [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
         [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
         [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
         [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]],
        dtype='u8')
    # print ('sbox ',sbox)
    invbyte = int(sbox[nibble0, nibble1])    # value read from sbox table is the poly inversion of the input
    #print('SBoxByte: invbyte = ', invbyte)       #
    return invbyte       # in calling routine, SBoxByte(byte) now has this value
# end ISBoxByte(byte):


def SubWord(wordin):       # breaks wordin into bytes and calls SBoxByte
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
    temp = wordin - msbyte   # remove byte0 from most significant position
    byte1 = temp >> 16  # byte1 is next most significant byte
    nmsbyte = byte1 << 16 # put byte1 back in the next most significant position
    temp = temp - nmsbyte  # remove byte1 from next most significant position
    byte2 = temp >> 8   #
    byte3 = temp % 256  #
    # print('byte0 1 2 3 = ', byte0, byte1, byte2, byte3)
    sbox0 = SBoxByte(byte0)   # find the inverse plus affine transform of byte0
    sbox1 = SBoxByte(byte1)
    sbox2 = SBoxByte(byte2)
    sbox3 = SBoxByte(byte3)
    # print('sbox0 1 2 3 = ', sbox0, sbox1, sbox2, sbox3)
    #print('')
    word = (sbox0 << 24) + (sbox1 << 16) + (sbox2 << 8) + sbox3
    #input('SubWord:  hit any key to continue')
    return word    # this is a real return
# end SubWord(x):



def invert_sub_bytes(state):
    #input: state
    #output: state   each byte represents polynomial inverse of original
    #functions used: ISBoxByte, hexprint (print, input)
    # called by: Main
    c = 0
    while c < 4:
        r = 0
        while r < 4:
            state[r,c] = ISBoxByte(state[r,c])  # this line does all the work
            r = r + 1
        #end while r
        c = c + 1
    # end while c
    #print('SubBytes: int(state)')
    #printhex(state)
    x = 0
    #x = input('pause before return from SubBytes')
    return state
# end InvSubBytes(state)


def invert_shift_rows(state):     # reverse process from ShiftRows
    # Input:   state
    # Output:  state with rows shifted right by r
    # functions used:  none (print)
    # no shifts in first row   r = 0
    # ta = np.zeros((4,4), dtype='u8')  #define a 4x4 array of integer zeros
    ta = state
    r = 1  # no shift in row 0, start with row 1
    while r < 4:  # do shifting in rows 1 to 3 with r shifts right in row r
        #print('ShiftRows: r = ', r)
        numshifts = 0
        while numshifts < r:
            temp = ta[r,3]       # save right most byte
            #print('IShiftRows: numshifts = ', numshifts)
            j = 0
            while j < 3:
                ta[r,3-j] = ta[r,2-j]
                j = j + 1
            # end j loop
            ta[r,0] = temp
            #print('ShiftRows: r, ta', r, ta)
            numshifts = numshifts + 1
        # end numshifts loop
        r = r + 1
    #end r loop
    state = ta     #is this needed?  since ta and state point to the same memory?
    #print('ShiftRows: int(state)')
    #printhex(state)
    return state
#for testing
#started by defining  import numby as np
#state = np.matrix('1 5 9 13;2 6 10 14;3 7 11 15;4 8 12 16')
#this is a square matrix    and after running shiftRows. InvShiftRows puts it back
# 1 5  9 13                 1  5   9 13
# 2 6 10 14                 6  10 14  2
# 3 7 11 15                 11 15  3  7
# 4 8 12 16                 16  4  8 12
# end InvShiftRows(state):

def invert_mix_columns(state):     #  see sections 5.1.3 and 5.3.3 of NIST 197
    # input:   state array,
    # output: state array with changes based on non binary polynomial multiply
    # other functions used:  none     ^ is bitwise xor
    # multiplying a poly by x is equivalent to shifting its bit representation one left
    # 9s = 8 s + 1 s = 8 s ^ 1 s = 8s ^ s
    # 8s = shift left 3 modulo m(x)   if s[r,c] < 31 : sp[r,c] = s[r,c] << 3 # no mod needed
    # 8s = shift left 3 modulo m(x)   else :      sp[r,c] = ((s[r,c] % 32) << 3) ^ 1b
    # 9s = 8s ^ s
    # bs = 8s ^ 2s ^ s
    # ds = 8s ^ 4s ^ s
    # es = 8s ^ 4s ^ 2s
    s = state   # s now points to same memory as the state array
    sp     = np.zeros((4,4), dtype='u8')  # sp is s' array, where state values are returned
    twos   = np.zeros((4,4), dtype='u8')  # polynomial multiply by x, a temp during processing
    fours  = np.zeros((4,4), dtype='u8')  # fours[] array, a temp during processing
    eights = np.zeros((4,4), dtype='u8')  # eights[] array, a temp during processing
    nines  = np.zeros((4,4), dtype='u8')  # nines[] array, a temp during processing
    bees   = np.zeros((4,4), dtype='u8')  # bees[] array, 0x0b = 11.
    dees   = np.zeros((4,4), dtype='u8')  # dees[] array, 0x0d = 13.
    eees   = np.zeros((4,4), dtype='u8')  # eees[] array, 0x0e = 14.
    # must keep state array and sp array separate.    ^ is bitwise xor
    oneb = 27   # represents part of the m(x) polynomial = 00011011 = {1b} hex
    c = 0       # c is column number, r is row number
    while c < 4:    # section 5.1.3 of NIST 197
        #sp[0,c] = ({0e}*s[0,c]) ^ ({0b}*s[1,c]) ^ ({0d}*s[2,c]) ^ ({09}*s[3,c])
        #sp[1,c] = ({09}*s[0,c]) ^ ({0e}*s[1,c]) ^ ({0b}*s[2,c]) ^ ({0d}*s[3,c])
        #sp[2,c] = ({0d}*s[0,c]) ^ ({09}*s[1,c]) ^ ({0e}*s[2,c]) ^ ({0b}*s[1,c])
        #sp[3,c] = ({0b}*s[0,c]) ^ ({0d}*s[1,c]) ^ ({09}*s[2,c]) ^ ({0e}*s[2,c])
        r = 0
        while r < 4:    # calculate {02} * s[r,c]  section 4.2.1
            twos[r,c] = 2 * int(s[r,c])   # if twos[r,c] < 256 done and this is now {02}*s[r,c]
            if twos[r,c] > 255:   # then the high bit was set after shift and we need to xor
                twos[r,c] = ((int(s[r,c]) - 128) << 1) ^ 27  # this is now {02}*s[r,c]
            #end if

            fours[r,c] = 2 * int(twos[r,c])   # if fours[r,c] < 256 done and this is now {04}*s[r,c]
            if fours[r,c] > 255:   # then the high bit was set after shift and we need to xor
                fours[r,c] = ((int(twos[r,c]) - 128) << 1) ^ 27  # this is now {04}*s[r,c]
            #end if

            eights[r,c] = 2 * int(fours[r,c])   # if eights[r,c] < 256 done and this is now {08}*s[r,c]
            if eights[r,c] > 255:   # then the high bit was set after shift and we need to xor
                eights[r,c] = ((int(fours[r,c]) - 128) << 1) ^ 27  # this is now {08}*s[r,c]
            #end if

            nines[r,c] = eights[r,c] ^ s[r,c]                 # {09}*s[r,c]
            bees[r,c]  = eights[r,c] ^ twos[r,c] ^ s[r,c]     # {0b}*s[r,c]
            dees[r,c]  = eights[r,c] ^ fours[r,c] ^ s[r,c]    # {0d}*s[r,c]
            eees[r,c]  = eights[r,c] ^ fours[r,c] ^ twos[r,c] # {0e}*s[r,c]

            r = r+1    # do this for all 4 rows, one column at a time
        # end while r    For given column c we now have 1,2,4,8,9,11,13,14*s[r,c]) for all rows.

        #calculate column values for current column and put in state prime matrix, sp[].
        sp[0,c] = (eees[0,c]) ^ (bees[1,c]) ^ (dees[2,c]) ^ (nines[3,c])
        sp[1,c] = (nines[0,c]) ^ (eees[1,c]) ^ (bees[2,c]) ^ (dees[3,c])
        sp[2,c] = (dees[0,c]) ^ (nines[1,c]) ^ (eees[2,c]) ^ (bees[3,c])
        sp[3,c] = (bees[0,c]) ^ (dees[1,c]) ^ (nines[2,c]) ^ (eees[3,c])
        #print('MixColumns:')
        #print(sp)
        #printhex(sp)
        c = c+1     # now go to next column and do it again until c = 4
    # end While c
    c = 0               # put sp values into state and return
    while c < 4:
        r = 0
        while r < 4:
            state[r,c] = sp[r,c]  # this line does all the work
            r = r + 1
        #end while r
        c = c + 1
    # end while c
#    print('InvMixColumns:   state = ')
#    printhex(state)
    return               #  no need to return "state"
#end InvMixColumns(state):



def out_pt_data(state):    #output cypher text (CT) data to plaintex.txt
#   convert each column of state to integer then write as hex string
    PTData = [0] * 4     # create an int array(4)
    c = 0
    while c < 4:       # convert column elements to int and put in CTData()
        PTData[c] = (int(state[0,c])<<24) + (int(state[1,c])<<16) + \
                    (int(state[2,c])<<8)  + int(state[3,c])
        c = c + 1
    # end while c

    textfile = open('plaintex.txt', 'a')  # open('plaintex.txt', 'for appending')
    c = 0
    while c < 4:         # could combine this while loop with the one above
#        textfile.write('{:08x}'.format(int(PTData[c])))  # 08 forces the leading zeros, x for hex
        textfile.write(format(int(PTData[c]), '08x'))    # this also works
        textfile.write(' ')      # put a space between groups of 4 bytes
        c = c + 1
    # end while c

#   {:08x}'.format(int(w[6*i+0]))

    textfile.write('\n')  # put CR between groups of 16 bytes = 128 bits
    textfile.close()      #
    print(hex(PTData[0]), hex(PTData[1]), hex(PTData[2]), hex(PTData[3]) )
    return                #  no need to return anything
#End OutPTData()


def print_hex(state):
    r = 0
    while r < 4:
        print(hex(int(state[r,0])), hex(int(state[r,1])),hex(int(state[r,2])),hex(int(state[r,3])) )
        r = r + 1
    #end while r
    return

