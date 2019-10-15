#! /usr/bin/env python
'''
	Copyright 2019 Photubias(c)

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

        This should work on Linux & Windows using Python2
        
        File name MitsubishiScan.py
        written by tijl[dot]deneut[at]howest[dot]be

        --- Mitsubishi Scanner ---
        It uses the same scanning packets as used in the GX WorksV3 software
'''
import socket, binascii, os, subprocess

def getAddresses():
    interfaces=[]
    if os.name == 'nt': # This should work on Windows
        proc=subprocess.Popen("ipconfig | FINDSTR \"IPv4 Address\" | FINDSTR /V \"IPv6\"",shell=True,stdout=subprocess.PIPE)
        for interface in proc.stdout.readlines():
            ip = interface.split(':')[1].rstrip().lstrip()
            interfaces.append(ip)
    else: # And this on any Linux
        proc=subprocess.Popen("ip address | grep inet | grep -v \"127.0.0.1\" | grep -v \"inet6\"", shell=True, stdout=subprocess.PIPE)
        for interface in proc.stdout.readlines():
            ip = interface.lstrip().split(' ')[1].split('/')[0]
            interfaces.append(ip)
    return interfaces

def send_only(s, ip, port, string):
    data = binascii.unhexlify(string.replace(' ',''))
    s.sendto(data, (ip, port))

def recv_only(s):
    data, addr=s.recvfrom(1024)
    return data, addr

def getDevices(sSrcIP, iTimeout):
    print('[*] Scanning for Devices')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(iTimeout)
    sock.bind((sSrcIP,0))
    
    data='57010000001111070000ffff030000fe0300001e001c0a161400000000000000000000000000000000000000000b2001000000'
    send_only(sock, '255.255.255.255', 5561, data)
    receivedData = []
    while True:
        try: receivedData.append(recv_only(sock))
        except: break
    sock.close()
    
    arrDevices=[]
    for data in receivedData:
        data,ip=data
        ## Retrieve CPU Title
        try:
            sOptionalData = binascii.hexlify(data).split('202020')[2]
            iLength1 = int(sOptionalData[:2],16)
            sTitle = sOptionalData[12:12+(iLength1*2)].replace('00','')
            sTitle = binascii.unhexlify(sTitle)
        except: sTitle = ''
        ## Retrieve Comment
        try:
            sOptionalData = binascii.hexlify(data).split('202020')[2]
            iLength2 = int(sOptionalData[4:6],16)
            sComment = sOptionalData[12+iLength1*2:(12+iLength1*2)+(iLength2*2)].replace('00','')
            sComment = binascii.unhexlify(sComment)
        except: sComment = ''
        ## Retrieve Type
        try: sType = binascii.unhexlify(binascii.hexlify(data).split('202020')[1].split('00')[0])
        except: sType = 'Unknown'
        arrDevices.append({'IP':ip[0],'TYPE':sType,'TITLE':sTitle,'COMMENT':sComment})
    return arrDevices

### MAIN ###
## Select Adapter, IP does not have to be in the same subnet
i=1
arrInterfaces=getAddresses()
for ip in arrInterfaces:
    print('['+str(i)+'] '+ip)
    i+=1
print('[Q] Quit now')
if i>2: answer=raw_input('==> Please select the physical adapter to use [1]: ')
else: answer=str(i-1)
if answer.lower()=='q': exit(0)
if answer=='' or not answer.isdigit() or int(answer)>=i: answer=1

sSrcAddr = arrInterfaces[int(answer)-1]
print('[*] Sending the discovery packet and waiting 2 seconds for answers...')
arrDevices=getDevices(sSrcAddr, 2)
for Device in arrDevices:
    sExtra = ''
    if not Device['TITLE'] == '': sExtra = sExtra + 'CPU Title: ' + Device['TITLE']
    if not Device['COMMENT'] == '': sExtra = sExtra + ', Comment: ' + Device['COMMENT']
    print('[+] Found device at address '+Device['IP']+' with identifier '+Device['TYPE'] + '('+sExtra+')')
if len(arrDevices) == 0: print('[-] Too bad, no devices found')
bla=raw_input('Press Enter To Close')
exit(0)
