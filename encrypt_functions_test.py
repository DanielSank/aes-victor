import numpy as np

import encrypt_functions as ef


KEY_TEXT = ('00010203·04050607·08090a0b·0c0d0e0f'
            '10111213·14151617·18191a1b·1c1d1e1f')

KEY = np.array([
    66051,
    67438087,
    134810123,
    202182159,
    269554195,
    336926231,
    404298267,
    471670303,])

KEY_EXPANDED = np.array([
    66051, 67438087,  134810123,  202182159,  269554195,
    336926231,  404298267,  471670303, 2775827103, 2708915352,
    2843725459, 2775761052,  374450381,   38059738,  442344641,
    104905438, 2928140272,  267459432, 2794378747,   66852199,
    1843523912, 1873104786, 1979247443, 1941459341, 3327558271,
    3383204119, 1864977644, 1825921419, 1038236277, 1380414951,
    666869428, 1409797945,  199004255, 3262843208, 2907850148,
    3246857263, 1173726816,  397595527,  806178099, 1678410250,
    2094003996, 3199532628,  333888496, 3529615327, 4028300030,
    3886557561, 3617940554, 3014649408,  625081969, 2616524837,
    2282994645, 1517427722, 1314547353, 2851229664, 2119642026,
    3455634922,  620526028, 3205069289,  924500540, 1835589174],
    dtype='uint32')


def test_get_key():
    assert np.allclose(
        ef.get_key('key_test.txt'),
        KEY,)


def test_key_expansion():
    assert np.allclose(
        ef.key_expansion(KEY),
        KEY_EXPANDED,)
