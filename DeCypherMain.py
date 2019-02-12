# Filename DeCypherMain.py     2/7/19  10:00pm
print( 'This is the main routine for performing AES-256 decryption. It will:')
print('   read a key from CyKey.txt and perform KeyExpansion')
print('   read the cypher text data from  CTData.txt')
print('   decypher the data using the key in CyKey.txt and return the plain text')
print('     in PTData.txt and also write the plain text to the screen.')
print('     In some cases leading zeros may not be shown')
input('   press Enter to continue')


#set parameters for AES-256
Nb = int(4)
Nr = int(14)
Nk = int(8)

#import numpy as np    # only needed once at top of file.  np known to all functions below
import DeCyFunctions
from importlib import reload   #only needs to be done once(and only when developing)
reload(DeCyFunctions)          #only needs to be done once(and only when developing)
from DeCyFunctions import GetKey, GetCTData, OutPTData, printhex
from DeCyFunctions import KeyExpansion, AddRoundKey, InvSubBytes, InvShiftRows, InvMixColumns
#  RotWord, Rcon, SubWord not listed since these functions are only called in KeyExpansion in DeCyFunctions.
# in file DeCyFunctions.py several of these functions manipulates the state array
# key = np.zeros((8), dtype = 'int')  # key is a 1x8 integer array
# defined in GetKey and returned from there so no need to define it here.
#     Get 32 byte key and expand it to 60 words = 240 bytes
key = GetKey()   # since key defined in GetKey and is returned, GetKey() has () empty
#print('  Main: Finished GetKey  key = ')
#print(key)
#input('Main: Finished GetKey, hit any key to continue')
w = KeyExpansion(key)   # perform KeyExpansion  input key(8), output w(60) = expanded key
#print('  Main: Finished KeyExpansion  w = ')    # w is the same as in the cypher routine
#print(w)
#input('  Main: hit any key to continue')
#            Get Cypher Text Data
#state = np.zeros((4,4), dtype = 'u8')     # state is a 4x4 matrix
state = GetCTData()       #enter data into 4x4 State array, byte oriented  no element > 255
print('  Main: Finished GetCTData   state = ')
printhex(state)
#print(state)

round = int(14)        # round 14 first for de-cyph, only AddRoundKey is called.  15 rounds total
AddRoundKey(state,w,round)   #first call to AddRoundKey uses last 4 words of w[], w[56] to w[59]
print('  Main:                round = ', round)
# next 13 calls to AddRoundKey are with w(52 to 5) to w(4 to 7).  round 14 uses w[0] to w[3].
#print('  Main: Finished AddRoundKey   round = ', round)
#printhex(state)
#input('  Main: hit any key to continue  ')
for round in range(Nr-1, 0, -1):        # 13 to 1
    print('  Main:                round = ', round)
    #input('  hit any key to continue')
    InvShiftRows(state)  # shifts Rows of state right r bytes, r = row number
        # print('  Main: Finished InvShiftRows   state =')
        # printhex(state)
        #input('  hit any key to continue')
    InvSubBytes(state)                     #calls inv s-box, a byte array
        #print('  Main: Finished InvSubBytes   state =')
        #printhex(state)
        #input('  hit any key to continue')
    AddRoundKey(state,w,round)             #Adds dw, the RouncKey to columns of state
        #print('  Main: Finished AddRoundKey   state =')
        #printhex(state)
        #input('  hit any key to continue')
    InvMixColumns(state)                   #polynomial multiply of state modulo x^4 + 1
        #print('  Main: Finished InvMixColumns   state =')
        #printhex(state)
        #input('  hit any key to continue')
        # next 13 calls to AddRoundKey are with w(52,55) to w(4,7)

round = 0        #for round 0, (15th round) there is no MixColumns
print('  Main:                round = ', round)
#input('  hit any key to continue')
InvSubBytes(state)
    #print('  Main: Finished InvSubBytes   state =')
    #printhex(state)
InvShiftRows(state)
    #print('  Main: Finished InvShiftRows   state =')
    #printhex(state)
AddRoundKey(state,w,round)       # last calls to AddRoundKey is with w(0,3)
print('  Main: Finished AddRoundKey   state =')
#printhex(state)
#print('This is the PlainText Data (in hex above and in PTData.txt)')
OutPTData(state)   # print to text file PTData.txt
print('Decrypted Data written to PTData.txt)')

# end DeCypherMain