#! /usr/bin/env python3
'''
    Copyright 2019 Deneut Tijl

    Written for Howest(c) College University

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.*)

File name Schneider_FlashMyLED.py
written by tijl.deneut@howest.be
'''
import socket, binascii, os, subprocess

ssIP = '10.20.3.10'
sSubnet = '255.255.0.0'
iSPort = 63397 ## Source UDP port does not seem to matter, but it is always the same in the software
iDPort = 27127
iTimeout = 1 ## Seconds waittime for answers

def send_and_recv(s, ip, port, string):
    data = binascii.unhexlify(string)
    s.sendto(data, (ip, port))
    data, addr = s.recvfrom(1024)
    print("received "+binascii.hexlify(data)+" from "+addr[0])
    return data

def send_only(s, ip, port, string):
    data = binascii.unhexlify(string.replace(' ',''))
    s.sendto(data, (ip,port))
    
def recv_only(s):
    data, addr = s.recvfrom(1024)
    return (data,addr)

def getAddresses():
    interfaces=[]
    if os.name == 'nt': # This should work on Windows
        proc=subprocess.Popen("ipconfig | FINDSTR \"IPv4 Address Subnet\" | FINDSTR /V \"IPv6\"",shell=True,stdout=subprocess.PIPE)
        allines=proc.stdout.readlines()
        for i in range(0,len(allines),2):
            ip = allines[i].split(b':')[1].rstrip().lstrip()
            mask = allines[i+1].split(b':')[1].rstrip().lstrip()
            interfaces.append((ip.decode(),mask.decode()))
    else: # And this on any Linux
        proc=subprocess.Popen("ip address | grep inet | grep -v \"127.0.0.1\" | grep -v \"inet6\"", shell=True, stdout=subprocess.PIPE)
        for interface in proc.stdout.readlines():
            ip = interface.lstrip().split(b' ')[1].split(b'/')[0]
            cidr = int(interface.lstrip().split(b' ')[1].split(b'/')[1])
            bcidr = (cidr*'1'+(32-cidr)*'0')
            mask = str(int(bcidr[:8],2)) + '.' + str(int(bcidr[8:16],2)) + '.' + str(int(bcidr[16:24],2)) + '.' + str(int(bcidr[24:],2))
            interfaces.append((ip.decode(),mask))
    return interfaces

#### MAIN PROGRAM ####
os.system('cls' if os.name == 'nt' else 'clear')
## Select Adapter
i=1
arrInterfaces=getAddresses()
for interface in arrInterfaces:
    print('['+str(i)+'] '+interface[0]+' / '+interface[1])
    i+=1
print('[Q] Quit now')
if i>2: answer=input('Please select the adapter [1]: ')
else: answer=str(i-1)
if answer.lower()=='q': exit()
if answer=='' or not answer.isdigit() or int(answer)>=i: answer=1
ssIP = arrInterfaces[int(answer)-1][0]
sSubnet = arrInterfaces[int(answer)-1][1]

os.system('cls' if os.name == 'nt' else 'clear')
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.settimeout(iTimeout)
sock.bind((ssIP, 0))

### For now this is a simple replay attack, too bad :-(
send_only(sock, '255.255.255.255', iDPort, 'cc:85:5b:51:08:03:55:0f:6f:79:0d:53:47:55:c6:14:04:6d:9e:33:6a:75:76:6c:b9:c2:58:40:80:72:6e:66:f6:73:2a:dc:62:47:58:55:5a:47:59:6c:38'.replace(':',''))
input('press enter for next packet, that should stop it')
send_only(sock, '255.255.255.255', iDPort, 'cc 85 5b 51 08 03 55 0f 6f 79 0d 53 47 55 c6 14 04 6d 9e 33 6a 75 76 6c ba c2 58 40 80 72 6e 66 f6 73 2a dc 63 47 58 55 5a 47 59 6c 38'.replace(' ',''))

input("press enter")
