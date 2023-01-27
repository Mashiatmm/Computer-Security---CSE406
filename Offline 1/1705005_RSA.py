import bitvectordemo
from BitVector import *
import math
import time



#------------------------------------------------------------------


def power(x, y, p):
    res = 1;     # Initialize result
    x = x % p   # Update x if it is more than or equal to p
    while (y > 0):
        # If y is odd, multiply x with result
        if (y & 1):
            res = (res*x) % p
 
        # y must be even now
        y = y >> 1 # y = y/2
        x = (x*x) % p

    return res

 

#-------------------------------------------------------------------
def prime_gen(k):
    n = int( k / 2)
    count = 0
    p = -1
    q = -1

    bv = BitVector(intVal = 0)

    while True:
        bv = bv.gen_random_bits(n)
        # print("bv: ", bv)
        check = bv.test_for_primality()
        # print(check)   

        
        if check > 0.98:
            if p != -1 and p == bv.int_val():
                continue
            count +=  1
            if p == -1:
                p = bv.int_val()
            else:
                q = bv.int_val() 
    
        if count == 2:
            return p, q
   




#-------------------------------------------------------------------





def coprime(phi):
    for i in range(2, phi):
        if ( math.gcd(i, phi) == 1 ):
            return i
    return -1




def multiplicative_inverse(e, phi):
    bv_modulus = BitVector(intVal = phi)
    bv = BitVector(intVal = e) 
    inverse = bv.multiplicative_inverse( bv_modulus )
    if inverse is None:
        print("No Inverse")
        quit()
    else: 
        return inverse.int_val()


def key_pair_gen( k):

    # get two prime numbers of length k / 2 bits
    p, q = prime_gen(k)

    n = p * q
    phi = ( p - 1 ) * ( q - 1 )
    e = coprime(phi)

    # multiplicative inverse
    d = multiplicative_inverse(e, phi)

    # d, y, gcd = gcdExtended(e, phi)
    # print(e, d, n)

    return e, d, n



#--------------------------------Encrypt------------------------------
def encrypt_rsa(plain_text, e, n):
    cipher_text = []
    for i in range(len(plain_text)):
        # print(plain_text[i])
        # print(ord(plain_text[i]))
        cipher_text.append( power( ord(plain_text[i] ), e, n) ) 
    

    return cipher_text


#--------------------------------Decrypt------------------------------
def decrypt_rsa(cipher_text, d, n):
    decrypted_text = ""
    for i in range(len(cipher_text)): 
        decrypted_text += chr( power( cipher_text[i], d, n) ) 
    

    return decrypted_text


#-----------------------------------------------------------------------------
if __name__ == "__main__":

    print("Plain Text : ")
    plain_text = input()

    var_len = [16, 32, 64, 128, 256, 512, 1024]
    for k in var_len:
        print("Key length : ", k)
        #-------------------------------Key Generation--------------------------
        start_time = time.time()
        e, d, n = key_pair_gen(k)
        print("---Key Scheduling : %s seconds ---" % (time.time() - start_time))
        # print(e, d, n)
        # public key - e, n
        # private key - d, n

        #-------------------------------------------------------------------

        

        start_time = time.time()
        cipher_text = encrypt_rsa(plain_text, e, n)
        print("---Encryption : %s seconds ---" % (time.time() - start_time))
        # print(cipher_text)

        # print(type(cipher_text[0]))
        start_time = time.time()
        decrypted_text = decrypt_rsa(cipher_text, d, n)
        print("---Decryption : %s seconds ---" % (time.time() - start_time))
        print(decrypted_text)