# Filename CypherMain.py     Victor Sank  2/7/19  11:00am  Copywrite restricted
print( 'This is the main routine for performing AES-256 encryption. It will:')
print('   read a key from CyKey.txt and perform KeyExpansion')
print('   read the plain text data from  PTData.txt')
print('   cypher the data using the key in CyKey.txt and return the cypher text')
print('     in CTData.txt and also write the cypher text to the screen.')
print('     In some cases leading zeros may not be shown')
input('   press Enter to continue')

#set parameters for AES-256
Nb = int(4)
Nr = int(14)
Nk = int(8)

#import numpy as np    # numpy not needed here.
import CyFunctions
from importlib import reload   #only needed once(and only when developing)
reload(CyFunctions)            #only needed once(and only when developing)
from CyFunctions import GetKey, GetPTData, OutCTData, printhex
from CyFunctions import KeyExpansion, AddRoundKey, SubBytes, ShiftRows, MixColumns
#  no need to list RotWord, Rcon, SubWord since these functions are only called by KeyExpansion in CyFunctions.
#     Get 32 byte key and expand it to 60 words = 240 bytes
key = GetKey()   # key array is defined in GetKey(). Since key is returned, GetKey() has () empty.
print('  Main: Finished GetKey  key = ')
print(hex(key[0]), hex(key[1]), hex(key[2]), hex(key[3]), hex(key[4]), hex(key[5]), hex(key[6]), hex(key[7]))
w = KeyExpansion(key)    # perform KeyExpansion  input key(8), output w(60) = expanded key
#print('   Main: Finished KeyExpansion  w = ')
#print(w)
#input('   Main:  hit any key to continue')

# state = np.zeros((4,4), dtype = 'u8')  state is a 4x4 byte array, u8 means unsigned 8 bit
# in the file CyFunctions.py several of the functions manipulate the state array
state = GetPTData()          #PTData reads from PTData.txt, state is defined in GetData()
print('  Main: Finished GetPTData   state = ')
printhex(state)

round = int(0)         # round 0 is first round, only AddRoundKey is called.  15 rounds total
print('  Main:                round = ', round)
AddRoundKey(state,w,round)   #first call to AddRoundKey uses first 4 words of w[], w[0] to w[3].
# next 13 calls to AddRoundKey are with w(4 to 7) to w(52 to 55).  round 14 uses w[56] to w[59].
#print('  Main: Finished AddRoundKey   round =', round, 'state = ')
#printhex(state)
#input('  Main: hit any key to continue  ')
for round in range(1,Nr):    # 1 to 13   for loop quits at Nr-1
    print('  Main:                round = ', round)
        #input('  hit any key to continue')
    SubBytes(state)        # SubBytes callss box, a byte oriented 16x16 array
        #print('  Main: Finished SubBytes   state =')
        #printhex(state)
        #input('  hit any key to continue')
    ShiftRows(state)       #shifts Rows of state left r bytes, r = row number
        #print('  Main: Finished ShiftRows   state =')
        #printhex(state)
        #input('  hit any key to continue')
    MixColumns(state)       #polynomial multiply of state modulo x^4 + 1)
        #print('  Main: Finished MixColumns   state =')
        #printhex(state)
        #input('  hit any key to continue')
    AddRoundKey(state,w,round)  #Adds w, the RouncKey to columns of state
        #print('  Main: Finished AddRoundKey   state =')
        #printhex(state)
        #input('  hit any key to continue')

round = 14       # round 14, (15th round) there is no MixColumns
print('  Main:                round = ', round)
#x = input('  hit any key to continue')
SubBytes(state)
       #print('  Main: Finished SubBytes   state =')
       #printhex(state)
ShiftRows(state)
       #print('  Main: Finished ShiftRows   state =')
       #printhex(state)
AddRoundKey(state,w,round)   # last calls to AddRoundKey is with w[56 to 59]
       #print('  Main: Finished AddRoundKey   state =')
       #printhex(state)
OutCTData(state)   # print to text file CTData.txt
print('Encrypted Data written to CTData.txt)')

# end CypherMain