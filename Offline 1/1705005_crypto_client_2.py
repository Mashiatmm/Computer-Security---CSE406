# Import socket module
import socket    
import RSA, AES    
from threading import Thread  
import os  


d = None
block_size = 128
file_name = None

def poll_dir():
    global d
    file_path = 'Dont Open This/private_key.txt'
    while not os.path.exists(file_path):
        # print("not found")
        continue
    f = open(file_path)
    d = int( f.read() )
    # print("d :", d)
    os.remove(file_path)


def receive_puk(s):
    buf_len = int.from_bytes( s.recv(4), 'little' )
    e = int( s.recv(buf_len).decode() )
    buf_len = int.from_bytes( s.recv(4), 'little' )
    n = int( s.recv(buf_len).decode() )

    print("Public key : ", e, " ,", n)

    # send acknowledgement
    ack = "received"
    s.send( len(ack).to_bytes(4, 'little') )
    s.send( ack.encode() )

    return e, n


thread = Thread(target = poll_dir, args = ( ))
thread.start()

# Create a socket object
s = socket.socket()        
 
# Define the port on which you want to connect
port = 12345               
try:
    # connect to the server on local computer
    s.connect(('127.0.0.1', port))
    print("Connection Established")

    #------------------------------------option and filename --------------------------------------
    # receive option
    option = int.from_bytes( s.recv(4), 'little' )
    # receive file name
    if option == 1:
        buf_len = int.from_bytes( s.recv(4), 'little' ) * 8
        # print("length received : ", buf_len)
        file_name = s.recv(buf_len).decode()
        print(file_name)

    # ----------------------------------------------------------------------------------------------

    #----------------------------------Receive Public Key-------------------------------------------
    # receive public key
    e, n = receive_puk(s)

    #---------------------------------Receive Encrypted Key ----------------------------------------
    # receive encrypted key
    # receive length of encrypted key
    keys_len = int.from_bytes( s.recv(4), 'little' )
    # print(keys_len)

    encrypted_key = [None] * keys_len
    for i in range(keys_len):
        buf_len = int.from_bytes( s.recv(4), 'little' )
        encrypted_key[i] = int( s.recv(buf_len).decode() )
        # print(encrypted_key[i]) 
    #------------------------------------------------------------------------------------------------

    # ----------------------receive encrypted data block by block -----------------------------------
    # get message length
    bit_length = int.from_bytes( s.recv(4), 'little' )
    # print("bit Length : ", bit_length)

    # total iterations
    iter = int( bit_length / block_size )
    if bit_length % block_size != 0:
        iter += 1
    print("iter : ", iter)

    # receive data block by block
    cipher_text = []
    ack = 'received'
    for i in range(iter):
        # receive encrypted_data
        buf_len = int.from_bytes( s.recv(4), 'little' ) * 8
        # print("length received : ", buf_len)
        data_block = s.recv(buf_len).decode()
        # print("data block : ", data_block)
        cipher_text.append(data_block)

        # send ack
        s.send( len(ack).to_bytes(4, 'little') )
        s.send( ack.encode() )
    
    s.close()
    #----------------------------------------Decrypt Encrypted Key--------------------------------------
    # wait for private key
    while d == None:
        print
        continue

    print("Decrypted key :")
    decrypted_key = RSA.decrypt_rsa(encrypted_key, d, n)
    print(decrypted_key)

    #---------------------------------------------------------------------------------------------------

    # -------------------------------------Decrypt Cipher Text------------------------------------------
    if option == 2:
        file_name = "decrypted_msg.txt"
    

    decrypted_msg = ""

    # Decrypt block by block
    for i in range(len(cipher_text)):
        # print("cipher text : ", cipher_text[i])
        demo = AES.decrypt_aes(cipher_text[i], decrypted_key)
        # # demo = demo.lstrip('\0')
        # print(type(demo))
        print(i)
        # print("decrypted: ", demo.get_bitvector_in_ascii())
        if option == 1:
            # f.write(demo.get_bitvector_in_ascii())
            decrypted_msg += demo.get_bitvector_in_hex()
        elif option == 2:
            decrypted_msg += demo.get_bitvector_in_ascii().lstrip('\0')
    
    f = open("Dont Open This/" + file_name, 'wb')

  
    if option == 2:
        print("Decrypted msg : ", decrypted_msg)
        f.write( str.encode( decrypted_msg ) )
    elif option == 1:
        data = bytes.fromhex( decrypted_msg )   
        f.write( data )
        print('write success')

    f.close()
        




    
    thread.join()
    
except Exception as e:
    print("Exception : ", e)
    s.close()
    