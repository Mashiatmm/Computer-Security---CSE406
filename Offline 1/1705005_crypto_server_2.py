# first of all import the socket library
import os
import socket  
import AES      
import RSA    
from BitVector import *
import filecmp

try:
    os.mkdir('Dont Open This')
except:
    pass

# next create a socket object
s = socket.socket()        
print ("Socket successfully created")
 
# reserve a port on your computer in our
# case it is 12345 but it can be anything
port = 12345   

block_size = 128
file_path = None

# Next bind to the port
# we have not typed any ip in the ip field
# instead we have inputted an empty string
# this makes the server listen to requests
# coming from other computers on the network
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', port))        
print ("socket binded to %s" %(port))

# put the socket into listening mode
s.listen(5)    
print ("socket is listening")  

def send_public_key(k):
     # Encrypt key with RSA
    e, d, n = RSA.key_pair_gen(k)

    # Send public key
    c.send( len( str( e ) ).to_bytes(4, 'little') )
    c.send( ( str(e) ).encode() )

    c.send( len(  str( n ) ).to_bytes(4, 'little') )
    c.send(( str(n) ).encode() )

    # receive acknowledgement
    buf_len = int.from_bytes( c.recv(4), 'little' )
    ack = c.recv(buf_len).decode()
    if ack != 'received':
        quit()
    return e, d, n


 
# a forever loop until we interrupt it or
# an error occurs
while True:
    try:
        # Establish connection with client.
        c, addr = s.accept()    
        print ('Got connection from', addr )

        #---------------------------------------------Input--------------------------------------------
        print("What do you want to send? 1. File    2. Text")
        option = int( input() )
        plain_text = None
        
        if option == 1:
            print("Input file name with path : ")
            file_path = input()
            filetosend = open(file_path, "rb")
            data = filetosend.read(1024)
            plain_hex_text = data.hex()
            while data:
                data = filetosend.read(1024)
                plain_hex_text += data.hex()
            # print(plain_text)
            plain_text = BitVector( hexstring = plain_hex_text )
            filetosend.close()
        elif option == 2:
            # take input for plain_text
            print("Plain Text : ")
            plain_text = input()
            plain_text = BitVector( textstring = plain_text )
        print("Key : ")
        key = input()
        print("k for RSA : ")
        k = int( input() )

        #-----------------------------------------------------------------------------

        # send option and if file send filename with type

        # send option
        # 1. File   2. Text
        c.send(option.to_bytes(4, 'little'))
        if option == 1:
            file_name = os.path.basename(file_path)
            c.send( len( file_name ).to_bytes(4, 'little') )
            c.send( ( file_name ).encode() )

        #---------------------------------------------------------------------------------

        # --------------------------Find e, d, n with RSA & send e, n---------------------------------
        #  # Encrypt key with RSA
        e, d, n = send_public_key(k)
        # print(e, n)
        #---------------------------Public Key Sent-----------------------------------------

        #----------------------------Send Encrypted Key-----------------------------------
        encrypted_key = RSA.encrypt_rsa(key, e, n)

        c.send( len( encrypted_key ).to_bytes(4, 'little') )

        for i in range(len( encrypted_key ) ):
            c.send( len(  str( encrypted_key[i] ) ).to_bytes(4, 'little') )
            c.send( ( str(encrypted_key[i]) ).encode() )

        #---------------------------Encrypted Key Sent-------------------------------------

        # -----------------send encrypted data block by block----------------------------
        # plain text - > BitVector Object
        bit_length = len(plain_text)

        # send bit length
        c.send(  bit_length.to_bytes(4, 'little') )

        # total iterations
        iter = int(bit_length / block_size )
        if bit_length % block_size != 0:
            iter += 1
        # print("iter : ", iter)

        # encrypt and sent data block by block
        sent = 0
        for i in range(iter):
            start_len = sent 
            end_len = sent  + block_size
            sent = end_len
            if sent > bit_length:
                sent = bit_length
                data_block = plain_text[start_len : bit_length] 
                data_block.pad_from_left(block_size - (bit_length - start_len))
            else:
                data_block = plain_text[start_len : end_len]
            
            # encrypto data block
            # print("Before encryption : ", data_block)
            encrypted_message = AES.encrypt_aes(data_block, key)
            # print("Encrypted : ", encrypted_message)

            # send data block
            c.send( len(  str( encrypted_message ) ).to_bytes(4, 'little') )
            c.send( ( encrypted_message ).encode() )
            # print("data_block sent")

            # receive acknowledgement
            buf_len = int.from_bytes( c.recv(4), 'little' )
            ack = c.recv(buf_len).decode()
            # print(ack)
            if ack != 'received':
                print("ack not received")
                quit()

        c.close()

        #-----------------------------------------Store decrypted Key-------------------------
        f = open("Dont Open This/private_key.txt","w")
        f.write( str( d ) )      
        f.close()

        #----------------------------------Check if sent properly---------------------------------
        # check decrypted message
        if option == 2:
            file_name = "decrypted_msg.txt"
        rec_file_path = "Dont Open This/" + file_name
        while not os.path.exists(rec_file_path):
            continue
        
        f = open(rec_file_path, "r")

        while True:
            try:
                os.rename(rec_file_path, rec_file_path)
                break
            except:
                print('FILE IN USE')
        
        
    
        # for plain text
        if option == 2:
            decrypted_msg = f.read()
            print("Decrypted message : ", decrypted_msg)
            if decrypted_msg == plain_text.get_bitvector_in_ascii():
                print("Message correctly decrypted")
            else:
                print("Message not correctly decrypted")
                # # print(decrypted_msg[len( plain_text.get_bitvector_in_ascii() ) : ] )
                # print(decrypted_msg)
                # print(type(decrypted_msg))
                # print(len(decrypted_msg))
                # print(plain_text.get_bitvector_in_ascii())
                # print(type(plain_text))
                # print( len( plain_text.get_bitvector_in_ascii() ) )
                # for i in range(len(decrypted_msg)):
                #     print(i, " : ", decrypted_msg[i], " ,ascii : ", ord( decrypted_msg[i] ) )
            os.remove(rec_file_path)

        elif option == 1:
            if filecmp.cmp(rec_file_path, file_path) :
                print("Successfully received")
            else:
                print("Not successfully received")



        f.close()
        
        #-------------------------------------------------------------------------------------------
        break
    except Exception as e:
        print("Exception : ", e )
        c.close()
        break