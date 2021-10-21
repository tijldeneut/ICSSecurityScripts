
'''
	Copyright 2019 Tinus Umans(c)
        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.
        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.
        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>.       
        
        File name S7_300_Password.py
        written by tinus[dot]umans[at]ugent[dot]be
		---
		Decrypt en Encrypt Passwords found by sniffing network between TIA PORTAL and S7_300

		Source of encryption algorithm :   https://www.slideshare.net/AlexanderTimorin/industrial-protocols-for-pentesters
'''


import os, binascii


def Decrypt(Pass_in_Hex):
	if len(Pass_in_Hex) != 16:
		print("Hex string not long enough. Expected 8 bytes")
		exit()
	Pass_in_byte = [int(Pass_in_Hex[x*2:x*2+2],16) for x in range(0,8)]

	# Decrypt
	Pass_Result = []
	Pass_Result.append( Pass_in_byte[0] ^ 0x55)
	Pass_Result.append( Pass_in_byte[1] ^ 0x55)
	for x in range(2, 8):
		Pass_Result.append( Pass_in_byte[x]  ^ Pass_in_byte[x-2]  ^0x55)
	return Pass_Result


def Encrypt(Pass): 	
	if len(Pass) > 8 :
		print(" Password cannot exceed 8 characters")
		exit()	
	Pass_in_byte = [ord(c) for c in Pass]
	while len(Pass_in_byte ) != 8:
		Pass_in_byte.append(32)
	# encryption
	Pass_in_byte[0] = Pass_in_byte[0] ^ 0x55
	Pass_in_byte[1] = Pass_in_byte[1] ^ 0x55
	for x in range(2, 8):
		Pass_in_byte[x] = Pass_in_byte[x]  ^ Pass_in_byte[x-2] ^ 0x55
	# Show
	return Pass_in_byte





def GUI_Decrypt():
	os.system('cls' if os.name == 'nt' else 'clear')

	print("""
[*********************************************************************************************************]"
                                              Decrypt

[*********************************************************************************************************]

""")
	Pass_in_Hex = input ("hex string to decrypt : ")
	Pass_in_Hex = Pass_in_Hex.replace(" " , "")
	Pass_Result = Decrypt(Pass_in_Hex)
	# Show
	print ("Decrypted pass ")
	print( "", end = "==> ")
	[ print(chr(c), end = ' ') for c in Pass_Result]
	print("<==")


def GUI_Encrypt():
	os.system('cls' if os.name == 'nt' else 'clear')

	print("""
[*********************************************************************************************************]"
                                              Encrypt

[*********************************************************************************************************]

""")
	Pass = input ("Password to encrypt : ")
	Pass_in_byte = Encrypt(Pass)
	print ("Encrypted pass ")
	print( "", end = "==> ")
	[	print(hex(c).split('x')[-1] , end = ' ') for c in Pass_in_byte]
	print("<==")


def GUI_Main():
	os.system('cls' if os.name == 'nt' else 'clear')
	print ("""
[*********************************************************************************************************]
                                       --- S7-300 Password ---

                                        Created By Tinus Umans(c) 
                                 For more Industrial Security : www.ic4.be
            
[*********************************************************************************************************]
	""")

	print("1: Decrypt")
	print("2: Encrypt")
	print("q: Exit")
	print()
	iChoise = input("Option [q] :")
	if iChoise == '1'	:	GUI_Decrypt()
	elif iChoise == '2'	:	GUI_Encrypt()
	else : exit()




GUI_Main()
