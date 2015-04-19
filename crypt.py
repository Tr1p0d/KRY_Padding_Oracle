import sys

class Encryption(object):
    def __init__(self, key):
        self.message = []
        self.key = self.hexListToIntList(self.stringToHexList(key))
        self.ciphertext = []

    def __str__(self):
        return self.hexListToString(self.trimHexList(self.intListToHexList(self.ciphertext)))

    def encrypt(self, message):
        self.message = self.stringToOrdList(message)
        self.ciphertext = self.listXOR(self.message, self.key)

    @staticmethod
    def listXOR(a, b):
        # vydy mensi delka
        length = len(a) if len(a) < len(b) else len(b)
        result = []

        for i in range(0, length):
            result.append(a[i] ^ b[i])

        return result

    @staticmethod
    def stringToOrdList(text):
        result = []

        for char in text:
            result.append(ord(char))

        return result

    @staticmethod
    def intListToHexList(intList):
        result = []

        for intitem in intList:
            hexnumber = hex(intitem) if len(hex(intitem)) > 3 else '0x0' + hex(intitem)[-1]
            result.append(hexnumber)
        return result

    @staticmethod
    def trimHexList(hexList):
        result = []

        for item in hexList:
            result.append(item[2:])
        return result

    @staticmethod
    def reTrimHexList(hexList):
        result = []

        for item in hexList:
            result.append("0x" + item)
        return result

    @staticmethod
    def hexListToIntList(hexList):
        result = []

        for item in hexList:
            result.append(int(item, 16))
        return result

    @staticmethod
    def hexListToString(hexList):
        result = ""

        for hexItem in hexList:
            result += hexItem

        return result

    @staticmethod
    def stringToHexList(hexString):
       result = []
       for i in range(0, len(hexString) - 1, 2):
           result.append(str(hexString[i]) + str(hexString[i + 1]))
       return result


    def getMessage(self):
        return self.message

    def getKey(self):
        return self.key

    def getCipherText(self):
        return self.ciphertext

    @staticmethod
    def ordListToString(ordList):
        result = ""

        for item in ordList:
            result += chr(item)
        return result

