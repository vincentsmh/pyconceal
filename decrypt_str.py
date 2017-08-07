def decrypt_str(ciphertext):
    cipher_ascii_list = []
    for c in b64decode(ciphertext):
        cipher_ascii_list.append(ord(c))

    cipher_sum = sum(cipher_ascii_list)
    key_pos = cipher_sum % (len(cipher_ascii_list) - 1)
    key = cipher_ascii_list[key_pos]
    del cipher_ascii_list[key_pos]

    ascii_list = []
    for i in xrange(0, len(cipher_ascii_list)):
        ascii_list.append(chr(cipher_ascii_list[i] ^ (key >> (i % 4))))

    return ''.join(ascii_list)

