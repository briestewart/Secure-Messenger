#Name: Brianna Stewart
#Date: 9/29/2022

from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from base64 import b64encode
from time import perf_counter
from Crypto.PublicKey import RSA

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

class RSACipher(object):
    def __init__(self, key):
        public = ""
        self.public = RSA.importKey(key)                              #Saving public key

    def encrypt(self, plain_text):          
        padding = PKCS1_OAEP.new(self.public)                         #Getting padding with PKCS1
        encrypted = padding.encrypt(plain_text.encode())              #Adding the padding and encrypting message
        return b64encode(encrypted).decode('UTF-8')                   #Encoding ciphertext in b64 


def writeFile(filename, encryptmsg):
    file = open(filename, 'w')       #Open file and overwrite
    file.write(encryptmsg)           #Write message to file
    file.close()

def readFile(filename):
    file = open(filename, 'r')       #Open file and read
    key = file.read()                #Store contents of file
    file.close()
    return key

while True:
    print('\nWelcome to Alice\'s program')
    print('\n[1] AES Encryption', '\n[2] RSA Encryption', '\n\nEnter Q to quit')
    selection = input()
    #AES Cipher
    if selection == '1':
        shared_key = readFile('sharedkey.txt')      #Getting shared key
        aes = AESCipher(shared_key)
        print('Enter message:')
        message = input()                           #Taking message from user
        encryptedmsg = aes.encrypt(message)         #Encrypting message
        print('Ciphertext:', encryptedmsg)
        writeFile('ctext.txt', encryptedmsg)        #Writing message to file
    #RSA Cipher
    elif selection == '2':
        public_key = readFile('publickey.txt')      #Getting public key
        rsa = RSACipher(public_key)
        print('Enter message:')
        message = input()                           #Taking message from user
        encryptmsg = rsa.encrypt(message)           #Encrypting message
        print("Ciphertext:", encryptmsg)            
        writeFile('ctext.txt', encryptmsg)          #Writing message to file
    elif selection.lower() == 'q':
        break
    else:
        print('Enter a valid option')
       



