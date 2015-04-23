################################################################################
#                   Kostra k 2. projektu do predmetu KRY                       #
################################################################################
import sys
from OracleModule import paddingOracle
from OracleModule import genNewKey
from OracleModule import setKey
from OracleModule import encrypt
import string

'''
Utok budete provadet na funkci paddingOracle():
    
paddingOracle(ciphertext):
  Funkce "zjisti" zda je zasifrovany plaintext korektne zarovnan podle PKCS#7
  a vrati tuto informaci v podobe True/False.
  Parametr ciphertext je retezec zasifrovaneho textu prevedeny do hexa formatu!



Pro jistotu upozorneni:
  Nezapomente, ze zasifrovany text je v rezimu "CBC s nahodnym IV" ve formatu:
      IV | CT

  IV - inicializacni vektor (16 bajtu)
  |  - kontatenace
  CT - zasifrovany text rezimem CBC (nasobek 16 bajtu)



Pro testovani muzete pouzit funkce genNewKey(), setKey(key) a encrypt(plaintext).
---------------------
genNewKey():
  Provede vygenerovani noveho klice, ktery zaroven nastavi jako aktualni sifrovaci
  klic pro padding orakulum. Rovnez vrati vygenerovany klic (ascii, nikoli hexa).

setKey(key):
  Provede nastaveni sifrovaciho klice pro padding orakulum. Argument key ocekava
  sifrovaci klic v ascii, nikoli jako hexa retezec.
  
encrypt(plaintext):
  Provede zarovnani PKCS#7 ascii plaintextu a nasledne jeho zasifrovani 
  s vyuzitim aktualne nastaveneho sifrovaciho klice, ktery sdili s padding 
  orakulem. Sifrovani probiha algoritmem AES-CBC (128b varianta). 
'''

def decodeHex(ciphertext):
  hexatext = ""
  for i in ciphertext:
    if ( len(str(hex(i))[2:]) < 2 ):
      hexatext = hexatext + "0" + (str(hex(i))[2:])
    else :
      hexatext = hexatext + (str(hex(i))[2:])

  return hexatext

def concatBlocks(b):
    tmp = ""
    for i in b:
        tmp = tmp + decodeHex(i)
    return tmp

def decodeCiphertext(ciphertext):

    ciphertext = bytearray(ciphertext.decode('hex'))
    plaintext = bytearray()

    b = []
    for i in range(16, len(ciphertext) + 1, 16):
        b.append(ciphertext[i-16:i])

    # lets guess the padding number
    for i in range(1, 16):
        b[-2][15] ^= 0x01 ^ i
        ciphertextp = concatBlocks(b)
        if paddingOracle(ciphertextp):
            paddingLen = i
            print paddingLen
            b[-2][15] ^= 0x01 ^ i
            continue
        b[-2][15] ^= 0x01 ^ i

    paddingLen = 16
    
    # crack the last block
    pl = paddingLen
    lbplaintext = bytearray(0x10)
    lbplaintext[-paddingLen] = paddingLen
    for i in range(16 - paddingLen -1, -1, -1):
        paddingLen = paddingLen + 1
        padding = bytearray(0x10)
        padding[-paddingLen:] = bytearray([paddingLen]) * paddingLen

#        print repr(padding)
#        print repr(lbplaintext)
#        print

        # guess
        for i in range(0,256) : 
            lbplaintext[-paddingLen] = i
            bp = xorBlock(lbplaintext, padding, b[-2])
            req = joinBA(b[0:-2]) + bp + b[-1]
            if(paddingOracle(decodeHex(req))):
     #         print "symbol is : " + repr(hex(i))
               break
            if(i == 255):
                print ("symbol was not found")
                exit(1)

    #exit(1)

    #plaintext = lbplaintext[0:-pl]
    plaintext = lbplaintext
    # for every remaining block from end
    for i in range(-3, -len(b) -1, -1):
        padding = bytearray(0x10)
        lbplaintext = bytearray(0x10)
        
        # for every character in that block
        for j in range(15,-1,-1):
            padding[-(16-j):] = bytearray([16-j]) * (16-j)
            #print repr(padding)
            #print repr(lbplaintext)
            # gess a character
            for g in range(0,256):
                lbplaintext[j] = g
                bp = xorBlock(lbplaintext, padding, b[i])
                req = joinBA(b[0:i]) + bp + b[i+1]
                if(paddingOracle(decodeHex(req))):
                    break

        plaintext = lbplaintext + plaintext

    return plaintext
                

# because the stupid python cannot join bytearrays the normal way
def joinBA(inba):
    out = bytearray()
    for i in inba:
        out += i

    return out

def xorBlock(x, y, w):
    if len(x) != len(y):
        exit(1)
    
    z = bytearray(0x10)
        
    for i in range(0,len(x)):
        z[i] = x[i] ^ y[i] ^ w[i]

    return z

if __name__ == "__main__":
    if len(sys.argv) > 1:
        ciphertext = sys.argv[1]
    else:
        ciphertext = "fa485ab028cb239a39a9e52df1ebf4c30911b25d73f8906cc45b6bf87f7a693f47609094ccca42050ad609bb3cf979ac"

    # vypis desifrovaneho textu provedte nasledujicim zpusobem: 
    print decodeCiphertext(ciphertext)
    
    sys.exit(0)
    
