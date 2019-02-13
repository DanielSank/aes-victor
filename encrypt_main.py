"""
This is the main routine for performing AES-256 encryption. It reads a key from
key.txt and performs key expansion. Then it reads plain text data from
plaintex.txt', and encrypts that data using the key. It then writes the
encrypted data to CTData.txt.
"""

from constants import Nr
from encrypt_functions import get_key, get_pt_data, out_ct_data, print_hex
from encrypt_functions import key_expansion, add_round_key, sub_bytes, shift_rows, mix_columns

key = get_key()
w = key_expansion(key)  # Perform KeyExpansion  input key(8), output w(60) = expanded key

state = get_pt_data()
print('  Main: Finished GetPTData   state = ')
print_hex(state)

rround = 0
print('Main: round = ', rround)
add_round_key(state, w, rround)  # First call to AddRoundKey uses first 4 words of w[], w[0] to w[3].
# The next 13 calls to AddRoundKey are with w(4 to 7) to w(52 to 55).  round 14 uses w[56] to w[59].
for rround in range(1, Nr):  # 1 to 13   for loop quits at Nr-1
    print('  Main:                round = ', rround)
    sub_bytes(state)  # SubBytes callss box, a byte oriented 16x16 array
    shift_rows(state)  # shifts Rows of state left r bytes, r = row number
    mix_columns(state)  # polynomial multiply of state modulo x^4 + 1)
    add_round_key(state, w, rround)  # Adds w, the RouncKey to columns of state

rround = 14  # round 14, (15th round) there is no MixColumns
print('  Main:                round = ', rround)
sub_bytes(state)
shift_rows(state)
add_round_key(state, w, rround)  # last calls to AddRoundKey is with w[56 to 59]
out_ct_data(state)  # print to text file CTData.txt
print('Encrypted Data written to CTData.txt)')
