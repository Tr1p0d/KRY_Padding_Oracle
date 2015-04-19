################################################################################
#                   Kostra k 2. projektu do predmetu KRY                       #
################################################################################
import sys
from OracleModule import paddingOracle
from OracleModule import genNewKey
from OracleModule import setKey
from OracleModule import encrypt

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

def decodeCiphertext(ciphertext):
    # zde provedte utok CBC Padding Oracle
    answer = paddingOracle(ciphertext)
    #plaintextWithoutPadding = "Plaintext by mel by vypsan bez pripadneho zarovnani!"
    print len(ciphertext)
    bytearray(ciphertext)
    print len(ciphertext)

    iv = bytearray(ciphertext[0:16])
    block1 = bytearray(ciphertext[16:32])
    block2 = bytearray(ciphertext[32:48])
    rest = bytearray(ciphertext[48:])

    print block1[15]
  #  block1[15] ^= 0x6C
    print block1[15]
    block1[15] ^= 0x01
    print block1[15]

    print ciphertext
    request = iv + block1 + block2 + rest
    print request
    
    return paddingOracle(request[0:48].decode('ascii'))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        ciphertext = sys.argv[1]
    else:
        ciphertext = "fa485ab028cb239a39a9e52df1ebf4c30911b25d73f8906cc45b6bf87f7a693f47609094ccca42050ad609bb3cf979ac"

    # vypis desifrovaneho textu provedte nasledujicim zpusobem: 
    print decodeCiphertext(ciphertext)
    
    sys.exit(0)
    
