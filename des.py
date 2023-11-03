#  Алгоритм DES
##############################################################################################

# IP (початкова перестановка)
initial_permutation = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12,
                       4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16,
                       8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
                       61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

# Функція розширення Е
extension_e = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
               12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22,
               23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

# Р-перестановка
p_permutation = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
                 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

# Перетворення S
s_box = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
          [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
          [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
          [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

         [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
          [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
          [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
          [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

         [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
          [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
          [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
          [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

         [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
          [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
          [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
          [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

         [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
          [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
          [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
          [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

         [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
          [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
          [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
          [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

         [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
          [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
          [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
          [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

         [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
          [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
          [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
          [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

# Зворотня перестановка IP^-1 (кінцева перестановка)
final_permutation = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
                     38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
                     36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
                     34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

# Початкова перестановка біт ключа
permutation_key_bits = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
                        10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
                        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
                        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

# Таблиця стиснення ключа (cтиснення ключа з 56-48 біт)
key_comp = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

# Циклічний зсув для ключа (к-ть бітових зсувів)
shift_table = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


##########################################################################################################
# Ф-ція переводить з шістнадцяткового в бінарний рядок
def hex_to_bin(hex_string):
    hex_to_bin_mapping = {'0': "0000", '1': "0001", '2': "0010", '3': "0011", '4': "0100", '5': "0101",
                          '6': "0110", '7': "0111", '8': "1000", '9': "1001", 'A': "1010", 'B': "1011",
                          'C': "1100", 'D': "1101", 'E': "1110", 'F': "1111"}
    bin_string = ""
    for el in hex_string:
        bin_string += hex_to_bin_mapping[el]
    return bin_string


# Ф-ція переводить з бінарного рядка в шістнадцятковий
def bin_to_hex(bin_string):
    bin_to_hex_mapping = {"0000": '0', "0001": '1', "0010": '2', "0011": '3',
                          "0100": '4', "0101": '5', "0110": '6', "0111": '7',
                          "1000": '8', "1001": '9', "1010": 'A', "1011": 'B',
                          "1100": 'C', "1101": 'D', "1110": 'E', "1111": 'F'}

    hex_string = ""
    for el in range(0, len(bin_string), 4):
        fragment = bin_string[el:el + 4]
        hex_string += bin_to_hex_mapping[fragment]

    return hex_string


#  Ф-ція перетворює бінарний рядок в десятковий
def bin_to_dec(binary):
    dec_string = 0
    counter = 0
    while binary != 0:
        digit = binary % 10
        dec_string += digit * pow(2, counter)
        binary //= 10
        counter += 1
    return dec_string


# Ф-ція перетворює десятковий в бінарний рядок
def dec_to_bin(dec_string):
    bin_string = bin(dec_string).replace("0b", "")
    if len(bin_string) % 4 != 0:
        format_bin_str = int(len(bin_string) / 4)
        num_of_zeroes = (4 * (format_bin_str + 1) - len(bin_string))
        for i in range(0, num_of_zeroes):
            bin_string = '0' + bin_string
    return bin_string


# Ф-ція перетворює з строки в шістнадцятирічну систему
def latin_to_hex(latin_string):
    hex_str = ""
    for letter in latin_string:
        number = ord(letter)
        hex_str += hex(number)
    return hex_str.replace('0x', '').upper()
################################################################################################


# Ф-ція перестановки для перестановки бітів
def permuted_bits(string, ip_arr, arr_size):
    permuted_bit_str = ""
    for i in range(0, arr_size):
        permuted_bit_str += string[ip_arr[i] - 1]
    return permuted_bit_str


# Ф-ція виконує циклічний зсув вліво
def circular_shift_left(string, num_shifts):
    shifted_str = ""
    for i in range(num_shifts):
        for j in range(1, len(string)):
            shifted_str += string[j]
        shifted_str += string[0]
        string = shifted_str
        shifted_str = ""
    return string


# Ф-ція виконує побітову операцію XOR між двома рядками
def bitwise_xor(str_1, str_2):
    result_xor = ""
    for bit in range(len(str_1)):
        if str_1[bit] == str_2[bit]:
            result_xor += "0"
        else:
            result_xor += "1"
    return result_xor


# Фу-ція генерації ключів
def generation_key(key_hex):
    key_edit = hex_to_bin(key_hex)

    # Отримання 56-бітного ключа з 64-бітного
    key_edit = permuted_bits(key_edit, permutation_key_bits, 56)

    # Розділення ключа на дві половини (С0 і D0)
    left_c0 = key_edit[0:28]
    right_d0 = key_edit[28:56]

    round_key_bin = []
    for i in range(0, 16):
        # Зсув бітів на n-ні зсуви шляхом перевірки за таблицею зсувів
        left_c0 = circular_shift_left(left_c0, shift_table[i])
        right_d0 = circular_shift_left(right_d0, shift_table[i])

        # Скріплюємо дві половинки в одну
        combine_str = left_c0 + right_d0

        # Стиснення ключа з 56 до 48 біт
        round_key = permuted_bits(combine_str, key_comp, 48)

        round_key_bin.append(round_key)
    return round_key_bin


######################################################################################################


# Ф-ція шифрування
def des_encrypt(text, round_keys_binary):
    text = hex_to_bin(text)

    # Початкова перестановка
    text = permuted_bits(text, initial_permutation, 64)

    # Розділення
    left_half = text[0:32]
    right_half = text[32:64]

    for raund in range(0, 16):
        # Розширення до 48 біт
        right_expanded = permuted_bits(right_half, extension_e, 48)

        # XOR з раундовим ключем
        xor_result = bitwise_xor(right_expanded, round_keys_binary[raund])

        # Заміна значень через S-блоки
        s_box_output = ""
        for j in range(8):
            row = bin_to_dec(int(xor_result[j * 6] + xor_result[j * 6 + 5]))
            col = bin_to_dec(int(xor_result[j * 6 + 1] + xor_result[j * 6 + 2] +
                                 xor_result[j * 6 + 3] + xor_result[j * 6 + 4]))
            s_box_value = s_box[j][row][col]
            s_box_output += dec_to_bin(s_box_value)

        # Перестановка
        s_box_output = permuted_bits(s_box_output, p_permutation, 32)

        # XOR з лівою половиною
        result_xor = bitwise_xor(left_half, s_box_output)
        left_half = result_xor

        if raund != 15:
            left_half, right_half = right_half, left_half

    # Поєднання двох половин
    combined_data = left_half + right_half

    # Кінцева перестановка
    cipher_text = permuted_bits(combined_data, final_permutation, 64)
    return cipher_text


# Функція для розшифрування DES
def des_decrypt(textcipher, round_keys_binary):
    textcipher = hex_to_bin(textcipher)

    textcipher = permuted_bits(textcipher, initial_permutation, 64)

    left_half = textcipher[0:32]
    right_half = textcipher[32:64]

    for raund in range(15, -1, -1):  # Зворотній порядок раундів
        right_expanded = permuted_bits(right_half, extension_e, 48)

        xor_result = bitwise_xor(right_expanded, round_keys_binary[raund])

        s_box_output = ""
        for j in range(8):
            row = bin_to_dec(int(xor_result[j * 6] + xor_result[j * 6 + 5]))
            col = bin_to_dec(int(xor_result[j * 6 + 1] + xor_result[j * 6 + 2] +
                                 xor_result[j * 6 + 3] + xor_result[j * 6 + 4]))
            s_box_value = s_box[j][row][col]
            s_box_output += dec_to_bin(s_box_value)

        s_box_output = permuted_bits(s_box_output, p_permutation, 32)

        # XOR з лівою половиною (порядок зворотній до зашифрування)
        result_xor = bitwise_xor(left_half, s_box_output)
        left_half = result_xor

        if raund != 0:
            left_half, right_half = right_half, left_half

    combined_data = left_half + right_half

    decrypted_text = permuted_bits(combined_data, final_permutation, 64)

    return bin_to_hex(decrypted_text)


latin_text = "Anzhelik"
latin_key = "password"

if len(latin_text) > 0 and len(latin_key) > 0:
    plain_text = latin_to_hex(latin_text)
    key = latin_to_hex(latin_key)

    key_modified = generation_key(key)
    ciphertext = bin_to_hex(des_encrypt(plain_text, key_modified))
    decrypt_text = des_decrypt(ciphertext, key_modified)

    print(f"{'=' * 40}\n{' ' * 5}DES (Data Encryption Standard)\n{'=' * 40}")
    print(f"ЗАШИФРУВАННЯ:\n{'-' * 15}")
    print(f"Відкритий текст -> {latin_text}")
    print(f"Ключ -> {latin_key}")
    print(f"Текст в hex -> {plain_text}")
    print(f"Ключ в hex -> {key}")
    print(f"Зашифрований текст -> {ciphertext}")
    print(f"{'-' * 15}\nРОЗШИФРУВАННЯ:\n{'-' * 15}")
    print(f"Зашифрований текст -> {ciphertext}")
    print(f"Ключ -> {latin_key}")
    print(f"Ключ в hex -> {key}")
    print(f"Розшифрований текст -> {decrypt_text}")
else:
    plain_text = "0123456789ABCDEF"
    key = "FEFEFEFEFEFEFEFE"

    key_modified = generation_key(key)
    ciphertext = bin_to_hex(des_encrypt(plain_text, key_modified))
    decrypt_text = des_decrypt(ciphertext, key_modified)

    print(f"{'=' * 40}\n{' ' * 5}DES (Data Encryption Standard)\n{'=' * 40}")
    print(f"ЗАШИФРУВАННЯ:\n{'-' * 15}")
    print(f"Текст в hex -> {plain_text}")
    print(f"Ключ в hex -> {key}")
    print(f"Зашифрований текст -> {ciphertext}")
    print(f"{'-' * 15}\nРОЗШИФРУВАННЯ:\n{'-' * 15}")
    print(f"Зашифрований текст -> {ciphertext}")
    print(f"Ключ в hex -> {key}")
    print(f"Розшифрований текст -> {decrypt_text}")
