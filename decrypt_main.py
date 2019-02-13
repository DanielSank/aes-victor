from constants import Nb, Nr, Nk

from decrypt_functions import get_key, get_ct_data, out_pt_data, print_hex
from decrypt_functions import key_expansion, add_round_key, invert_sub_bytes, invert_shift_rows, invert_mix_columns

print( 'This is the main routine for performing AES-256 decryption. It will:')
print('   read a key from CyKey.txt and perform KeyExpansion')
print('   read the cypher text data from  CTData.txt')
print('   decypher the data using the key in CyKey.txt and return the plain text')
print('     in plaintex.txt and also write the plain text to the screen.')
print('     In some cases leading zeros may not be shown')
input('   press Enter to continue')


key = get_key()
w = key_expansion(key)
state = get_ct_data()
print('  Main: Finished GetCTData   state = ')
print_hex(state)

round = int(14)  # Round 14 first for de-cyph, only AddRoundKey is called. 15 rounds total
add_round_key(state, w, round)  # First call to AddRoundKey uses last 4 words of w[], w[56] to w[59]
print('  Main:                round = ', round)

for round in range(Nr - 1, 0, -1):
    print('  Main:                round = ', round)
    invert_shift_rows(state)  # Shift rows of state right r bytes, r = row number
    invert_sub_bytes(state)  # Calls inv s-box, a byte array
    add_round_key(state, w, round)  # Adds dw, the RouncKey to columns of state
    invert_mix_columns(state)  # Polynomial multiply of state modulo x^4 + 1

round = 0  # For round 0, (15th round) there is no MixColumns
print('  Main:                round = ', round)
invert_sub_bytes(state)
invert_shift_rows(state)
add_round_key(state, w, round)       # last calls to AddRoundKey is with w(0,3)
print('  Main: Finished AddRoundKey   state =')
out_pt_data(state)
print('Decrypted Data written to plaintex.txt)')
