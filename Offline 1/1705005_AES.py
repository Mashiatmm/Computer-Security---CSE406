import bitvectordemo
from BitVector import *
import copy
import time

# number of round_keys
key_length = 128
nr = 11
AES_modulus = BitVector(bitstring='100011011')
round_vector = ['01', '02',	'04', '08', '10', '20',	'40', '80', '1B', '36', '6C', 'D8', 'AB', '4D']
round_constant  = [BitVector(hexstring="00"), BitVector(hexstring="00"), BitVector(hexstring="00"), BitVector(hexstring="00")]
rows = 4
columns = 4

def set_key_length(key_len):
    global key_length
    global nr
    key_length = key_len
    nr = int(key_length / 32) + 6 + 1
    




def sbytes(plain_w):
    # print("SBox")
    # print_vec(plain_w)
    for i in range(4):
        for j in range(4):
            plain_w[i][j] = BitVector( intVal = bitvectordemo.Sbox[ plain_w[i][j].int_val() ], size = 8 ) 
            # plain_w[i] = [ BitVector( intVal = bitvectordemo.Sbox[ plain_w[i][j].int_val() ], size = 8 ) for j in range(4)]
    # print("SBox")
    # print_vec(plain_w)
    return plain_w

def inv_sbytes(plain_w):
    for i in range(4):
        for j in range(4):
            plain_w[i][j] = BitVector( intVal = bitvectordemo.InvSbox[ plain_w[i][j].int_val() ], size = 8 ) 
            # plain_w[i] = [ BitVector( intVal = bitvectordemo.Sbox[ plain_w[i][j].int_val() ], size = 8 ) for j in range(4)]
    # print("SBox")
    # print_vec(plain_w)
    return plain_w


def shift_rows(plain_w):
    temp = copy.deepcopy(plain_w)
    for i in range(4):
        # shift_amount = i
        for j in range(4):
            temp[j][i] = plain_w[(j+i)%4][i]
    # print("Shifted rows")
    # print_vec(temp)
    return temp

def inv_shift_rows(plain_w):
    temp = copy.deepcopy(plain_w)
    for i in range(4):
        # shift_amount = i
        for j in range(4):
            temp[j][i] = plain_w[(j-i)%4][i]
    # print("Shifted rows")
    # print_vec(temp)
    return temp

def mix_columns(plain_w):
    temp = copy.deepcopy(plain_w)
    for i in range(4):
        for j in range(4):
            sum = BitVector(intVal = 0, size = 8)
            for k in range(4):
                sum = sum ^ ( bitvectordemo.Mixer[i][k].gf_multiply_modular(plain_w[j][k], AES_modulus, 8) )
            temp[j][i] = sum
    # print("Mixed Columns")
    # print_vec(temp)
    return temp

def inv_mix_columns(plain_w):
    temp = copy.deepcopy(plain_w)
    for i in range(4):
        for j in range(4):
            sum = BitVector(intVal = 0, size = 8)
            for k in range(4):
                sum = sum ^ ( bitvectordemo.InvMixer[i][k].gf_multiply_modular(plain_w[j][k], AES_modulus, 8) )
            temp[j][i] = sum
    # print("Mixed Columns")
    # print_vec(temp)
    return temp


def g(word, round_no):
    # Circular Byte Shift

    temp = word[0]
    for i in range(3):
        word[i] = word[i + 1]
    word[3] = temp
    
    round_constant[0] = BitVector(hexstring = round_vector[round_no])
    
    for i in range(4):
        # Byte Substitution
        int_val = word[i].intValue()
        word[i] = BitVector( intVal = bitvectordemo.Sbox[int_val], size = 8)
        # Adding round keys
        word[i] = word[i] ^ round_constant[i] 
    # print("g : ")
    # for i in range(4):
    #     print(word[i].get_bitvector_in_hex())
    return word



def generate_round_key(key):

    # 4x4 matrix of key
    global rows
    global columns
    rows = int( key_length / (4 * 8) )
    columns = 4
    total_bytes = rows * columns
    keys_row = [ key[i*8 : i*8 + 8] for i in range(total_bytes) ]
    key_w = [ keys_row[i*4 : i*4 + 4] for i in range(rows) ]

    round_key = [None] * nr
    round_key[0] = key_w

    # print("ROUND 0 ")
    # print_vec(round_key[0])

    for i in range(nr-1):
        new_key_w = [None] * rows
        temp = round_key[i][rows-1].copy() # 3-> 128, 5->192 
        # print(temp[0].get_bitvector_in_hex())
        new_key_w[0] = [ a^b for a, b in zip( round_key[i][0], g(temp, i ) ) ]
        for r in range(1, rows):
            new_key_w[r] = [ a^b for a, b in zip( new_key_w[r-1], round_key[i][r] ) ]

        round_key[i+1] = new_key_w
        # print("ROUND : ", i+1)
        # print_vec(round_key[i+1])

    return round_key




def add_round(key_w, plain_w):

    for i in range(4):
        plain_w[i] = [ key_w[i][j] ^ plain_w[i][j] for j in range(4) ]

  
    # print("Add round key")
    # print_vec(plain_w)
    # print("Round key")
    # print_vec(new_key_w)
    return plain_w


def key_expansion(key):

    # Key Expansion
    if len(key) < key_length:
        key.pad_from_left(key_length - len(key))
    if len(key) > key_length:
        key = key[:key_length]

    return key




def print_vec(vector):
    # pass
    for i in range( len( vector[0] ) ):
        for j in range( len( vector ) ):
            print(vector[j][i].get_bitvector_in_hex(), end = ' ')
        print()


#-------------------------------------Encryption--------------------------------------------------

def encrypt(plain_hex_text, round_keys):
    plain_row = [ plain_hex_text[i*8 : i*8 + 8] for i in range(16) ]
    plain_w = [ plain_row[i*4 : i*4 + 4] for i in range(4) ]
    
    # print_vec(plain_w)

   
    #Add round key initially
    plain_w = add_round(round_keys[0], plain_w)
    
    # print("before 9 rounds")
    # first 9 rounds
    for r in range(nr - 2):
        # 4x4 matrix of hex - plain text
        # print("Round : ", r)
        # print_vec(plain_w)
        # Sbytes
        plain_w = sbytes(plain_w)

        # Shift Rows
        plain_w = shift_rows(plain_w)

        # Mix Columns
        plain_w = mix_columns(plain_w)

        # Add round key
        plain_w = add_round(round_keys[r+1], plain_w)
        # key_w , plain_w = add_round(key_w, plain_w, r)


    # Final 11th round
    # print("Round : 11")
    # Sbytes
    plain_w = sbytes(plain_w)

    # Shift Rows
    plain_w = shift_rows(plain_w)

    # Add round key
    plain_w = add_round(round_keys[ nr - 1], plain_w)
    # key_w, plain_w = add_round(key_w, plain_w, 9)

    # print("Final Cipher Text")
    # print_vec(plain_w)

    hex_encrypted = ""
    for i in range(4):
        for j in range(4):
            hex_encrypted += plain_w[i][j].get_bitvector_in_hex()
            
    
    return hex_encrypted


#-----------------------------------Decryption---------------------------------------------------

def decrypt(encrypted_text, round_keys):
    hex = BitVector( textstring = encrypted_text )


    plain_row = [ hex[i*8 : i*8 + 8] for i in range(16) ]
    plain_w = [ plain_row[i*4 : i*4 + 4] for i in range(4) ]
    # Initial Round
    # Add round key initially
    plain_w = add_round(round_keys[nr-1], plain_w)
    # print("Round : 0 ")
    # print_vec(plain_w)

    # Shift Rows
    plain_w = inv_shift_rows(plain_w)

    # Subbytes
    plain_w = inv_sbytes(plain_w)


    # first 9 rounds
    for r in range(nr - 2):
        # 4x4 matrix of hex - plain text
        # print("Round : ", r)
        # print_vec(plain_w)

        # Add round key
        # key_w , plain_w = add_round(key_w, plain_w, r)
        plain_w = add_round(round_keys[nr-2-r], plain_w)

        # Mix Columns
        plain_w = inv_mix_columns(plain_w)

        # Shift Rows
        plain_w = inv_shift_rows(plain_w)

        # Sbytes
        plain_w = inv_sbytes(plain_w)
    
    # Add round key
    plain_w = add_round(round_keys[0], plain_w)


    # print("Final Decrypted Text")
    # print_vec(plain_w)

    hex_decrypted = ""
    for i in range(4):
        for j in range(4):
            hex_decrypted += plain_w[i][j].get_bitvector_in_hex()
            
    
    return hex_decrypted

        
def key_schedule(key_text):
    key = key_expansion( BitVector( textstring = key_text ) )
    round_keys = generate_round_key(key)
    return round_keys
        

def encrypt_aes(plain_hex_text, key_text):
    round_keys = key_schedule(key_text)
    encrypted_hex_text = encrypt(plain_hex_text, round_keys)
    encrypted = BitVector( hexstring = encrypted_hex_text)
    cipher_text = encrypted.get_bitvector_in_ascii()
    return cipher_text



def decrypt_aes(cipher_text, key_text):
    round_keys = key_schedule(key_text)
    decrypted_hex_text = decrypt(cipher_text, round_keys)
    decrypted = BitVector( hexstring = decrypted_hex_text)
    # decrypted_text = decrypted.get_bitvector_in_ascii()
    return decrypted

#-------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    print("Plain Text : ")
    plain_text = input()
    print()
    print("Key : ")
    key_text = input()

    differ_key_len = [128, 192, 256]
    #---------------------------------change key length-----------------------------------
    for key_len in differ_key_len:
        print("Key Length : ", key_len)
        set_key_length(key_len)
        #-------------------------------------------------------------------------------------

        if len(plain_text) > 128 :
            plain_text = plain_text[:128]
        elif len(plain_text) < 128:
            plain_text = plain_text.ljust(128, '\0')

        # generate round keys
        start_time = time.time()
        round_keys = key_schedule(key_text)
        print("---Key Scheduling : %s seconds ---" % (time.time() - start_time))

        start_time = time.time()
        plain_hex_text = BitVector( textstring = plain_text )
        encrypted_hex_text = encrypt(plain_hex_text, round_keys)
        print("---Encryption : %s seconds ---" % (time.time() - start_time))
        encrypted = BitVector( hexstring = encrypted_hex_text)
        cipher_text = encrypted.get_bitvector_in_ascii()

        start_time = time.time()
        decrypted_hex_text = decrypt(cipher_text, round_keys)
        print("---Decryption : %s seconds ---" % (time.time() - start_time))
        decrypted = BitVector( hexstring = decrypted_hex_text)
        decrypted_text = decrypted.get_bitvector_in_ascii()


        print("Cipher text : ")
        print( encrypted_hex_text )
        print(cipher_text)
        print("Deciphered text : ")
        print( decrypted_hex_text )
        print(decrypted_text)





