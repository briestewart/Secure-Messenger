#Name: Brianna Stewart
#Date: 9/29/2022

from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from base64 import b64decode
from Crypto.PublicKey import RSA
  

class AESCipher(object):
    def __init__(self, key):
        self.block = AES.block_size                                   #Saving block size and key
        self.key = hashlib.sha256(key.encode()).digest()            

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
    def __init__(self, key):
        self.private = RSA.importKey(key)                 #Save private key

    def generateKeys(self, size):
        private, public = '', ''
        random_gen = Random.new().read
        private = RSA.generate(size, random_gen)          #Generating private key 
        writeKeyFile('privatekey.txt', (private.exportKey()).decode('UTF-8'))
        public = private.publickey()                      #Generating public key
        writeKeyFile('publickey.txt', (public.exportKey()).decode('UTF-8'))

    def decrypt(self, encrypted_text):                     
        encrypted_text = b64decode(encrypted_text)                    #Decoding ciphertext
        depadding = PKCS1_OAEP.new(self.private)                      #Depadding message with PKCS1
        plain_text = depadding.decrypt(encrypted_text).decode('UTF-8')
        return plain_text

def readMessageFile(filename):
    file = open(filename, 'r')       #Open file and read
    encryptedmsg = file.read()       #Store contents of file
    file.close()
    return encryptedmsg

def readKeyFile(filename):
    file = open(filename, 'r')       #Open file and read
    key = file.read()                #Store contents of file
    file.close()
    return key

def writeKeyFile(filename, key):
    file = open(filename, 'w')       #Open file and overwrite
    file.write(key)                  #Write key to file
    file.close()

while True:
    print('\nWelcome to Bob\'s program')
    print('\n[1] AES Decryption', '\n[2] RSA Decryption', '\n[3] Generate Keys', '\n\nEnter Q to quit')
    selection = input()
    #AES Cipher
    if selection == '1':
        shared_key = readKeyFile('sharedkey.txt')   #Getting shared key
        aes = AESCipher(shared_key)               
        encryptedmsg = readMessageFile('ctext.txt') #Reading in message
        print('Ciphertext:', encryptedmsg)          
        decryptedmsg = aes.decrypt(encryptedmsg)    #Decrypting message
        print('Plaintext:', decryptedmsg)
    #RSA Cipher
    elif selection == '2': 
        private_key = readKeyFile('privatekey.txt') #Getting private key
        rsa = RSACipher(private_key) 
        encryptmsg = readMessageFile('ctext.txt')   #Reading in message
        print('Ciphertext:', encryptmsg)
        decryptmsg = rsa.decrypt(encryptmsg)        #Decrypting message
        print('Plaintext:', decryptmsg)
    #RSA Cipher (Generate keys)
    elif selection == '3':
        tempkey = (RSA.generate(2048)).exportKey()
        rsa = RSACipher(tempkey)
        rsa.generateKeys(2048)
        print('Keys generated')
    elif selection.lower() == 'q': #Quitting program
        break
    else: 
        print('Enter a valid option')

