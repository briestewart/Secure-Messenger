#Name: Brianna Stewart
#Date: 9/29/2022

from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode
from time import perf_counter
import random

class AESCipher(object):
    def __init__(self, key):
        self.block = AES.block_size                                   #Saving block size and key
        self.key = hashlib.sha256(key.encode()).digest()            

    def encrypt(self, plain_text):
        plain_text = self.pad(plain_text)                             #Padding Alice's message
        i_vec = Random.new().read(self.block)                         #Getting iv
        aescipher = AES.new(self.key, AES.MODE_CBC, i_vec)            #Getting aes cipher in CBC mode
        encrypted_text = aescipher.encrypt(plain_text.encode())       #Encrypting Alice's message
        return b64encode(i_vec + encrypted_text).decode('UTF-8')      #Encoding ciphertext + iv in b64 

    def pad(self, plain_text):      
        padding_amount = self.block - len(plain_text) % self.block    #Getting the amount of bytes to pad
        tempstring = chr(padding_amount)                               
        padding = padding_amount * tempstring                         
        padded_text = plain_text + padding                            #Adding the padding to message
        return padded_text

    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)                    #Decoding ciphertext and 
        i_vec = encrypted_text[:self.block]                           #Getting iv
        aescipher = AES.new(self.key, AES.MODE_CBC, i_vec)            #Getting aes cipher in CBC mode
        plain_text = aescipher.decrypt(encrypted_text[self.block:]).decode('UTF-8') 
        return self.unpad(plain_text)                                 

    @staticmethod
    def unpad(plain_text):                                  
        last = plain_text[len(plain_text) - 1:]                       #Getting last character
        remove_this = ord(last)                                       #Getting which ones to remove
        return plain_text[:-remove_this]                              #Returning unpadded

class RSACipher(object):
    def __init__(self, size):
        private, public = '', ''                                      #Initializing key variables
        random_gen = Random.new().read                                #Getting random gen
        self.private = RSA.generate(size, random_gen)                 #Generating random private key pair
        self.public = self.private.publickey()                        #Getting public key from private key

    def encrypt(self, plain_text):          
        padding = PKCS1_OAEP.new(self.public)                         #Getting padding with PKCS1
        encrypted = padding.encrypt(plain_text.encode())              #Adding the padding and encrypting message
        return b64encode(encrypted).decode('UTF-8')                   #Encoding ciphertext in b64 

    def decrypt(self, encrypted_text):                     
        encrypted_text = b64decode(encrypted_text)                    #Decoding ciphertext
        depadding = PKCS1_OAEP.new(self.private)                      #Depadding message with PKCS1
        plain_text = depadding.decrypt(encrypted_text).decode('UTF-8')
        return plain_text

def measureAESPerformance(key, keysize, msg, mode):
    global aes          #Global variable for object
    encryptmsg = ''
    i = 0

    if mode == 1:       #Encrypt 100 times and save the amount of time lapsed                                           
        aes = AESCipher(key)
        start = perf_counter()
        while i < 100:
            encryptmsg = aes.encrypt(msg)
            i += 1
        end = perf_counter()
        t = (((end - start)/100)*1000)      #Getting average time and converting it into ms
        print(f'AES ENCRYPTION ({keysize}):', ('%.4f' % t), 'ms') 
        return encryptmsg

    elif mode == 2:     #Decrypt 100 times and save the amount of time lapsed 
        start = perf_counter()
        while i < 100:
            decryptmsg = aes.decrypt(msg)
            i += 1
        end = perf_counter()
        t = (((end - start)/100)*1000)     
        print(f'AES DECRYPTION ({keysize}):', ('%.4f' % t), 'ms')
        return decryptmsg

def measureRSAPerformance(key, keysize, msg, mode):
    global rsa          #Global variable for object
    encryptmsg = ''
    i = 0

    if mode == 3:       #Encrypt 100 times and save the amount of time lapsed 
        rsa = RSACipher(key)
        start = perf_counter()
        while i < 100:
            encryptmsg = rsa.encrypt(msg)
            i += 1
        end = perf_counter()
        t = (((end - start)/100)*1000)      
        print(f'RSA ENCRYPTION ({keysize}):', ('%.4f' % t), 'ms')
        return encryptmsg

    elif mode == 4:     #Decrypt 100 times and save the amount of time lapsed
        start = perf_counter()
        while i < 100:
            rsa.decrypt(msg)
            i += 1
        end = perf_counter()
        t = (((end - start)/100)*1000)
        print(f'RSA DECRYPTION ({keysize}):', ('%.4f' % t), 'ms')
    
    else:
        return


while True:
    #Keys for AES
    key128 = hex(random.getrandbits(128))
    key192 = hex(random.getrandbits(192))
    key256 = hex(random.getrandbits(256))
    line = '--------------------------------------'

    print('\nChoose which you would like to measure the performance of:')
    print('\n[1] AES Encryption/Decryption', '\n[2] RSA Encryption/Decryption', '\n\nEnter Q to quit')
    selection = input()
    #AES Cipher
    if selection == '1':
        print('Enter message:')
        message = input()
        #Encryption & Decryption for each key size
        encryptmsg = measureAESPerformance(key128, '128-bit', message, 1) #Encrypt
        measureAESPerformance(key128, '128-bit', encryptmsg, 2)           #Decrypt
        print(line)
        encryptmsg = measureAESPerformance(key192, '192-bit', message, 1)
        measureAESPerformance(key128, '192-bit', encryptmsg, 2)
        print(line)
        encryptmsg = measureAESPerformance(key256, '256-bit', message, 1)
        measureAESPerformance(key128, '256-bit', encryptmsg, 2)
        print(line)

    elif selection == '2':
        print('Enter message:')
        message = input()
        #Encryption & Decryption for each key size 
        encryptmsg = measureRSAPerformance(1024, '1024-bit', message, 3) #Encrypt
        measureRSAPerformance(1024, '1024-bit', encryptmsg, 4)           #Decrypt
        print(line)
        encryptmsg = measureRSAPerformance(2048, '2048-bit', message, 3)
        measureRSAPerformance(2048, '2048-bit', encryptmsg, 4)
        print(line)
        encryptmsg = measureRSAPerformance(4096, '4096-bit', message, 3)
        measureRSAPerformance(4096, '4096-bit', encryptmsg, 4)
        print(line)

    elif selection.lower() == 'q': #Quit program
        break
    else: 
        print('Enter a valid option')


        

