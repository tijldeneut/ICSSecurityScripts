#! /usr/bin/env python3
'''
    Copyright 2021 Deneut Tijl

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

    It scans your local subnet for Schneider devices, still in beta.

File name Schneider_Scanner_v1.py
written by tijl.deneut@howest.be
'''
import socket, binascii, os, subprocess

ssIP = '192.168.1.1'
sSubnet = '255.255.255.0'
iDPort = 1740
iSPort = 1740 ## Official software also uses ports 1741 & 1742
iTimeout = 3 ## Seconds waittime for answers

def send_and_recv(s, ip, port, string):
    data = binascii.unhexlify(string)
    s.sendto(data, (ip, port))
    data, addr = s.recvfrom(1024)
    print(("received "+binascii.hexlify(data)+" from "+addr[0]))
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
    print(('[{}] {} / {}'.format(i, interface[0], interface[1])))
    #print(('['+str(i)+'] '+interface[0]+' / '+interface[1]))
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
sock.bind((ssIP, iSPort))

# Calculate packet c5 74 40 03 00 <sn> xx xx <B1> <B2> <B3> <B4> 90 00 00 00 02 c2 03 01 yy yy 00 00
## Where <sn> is 0x30 for 24B datalength & 0x30 for 20B of datalength
## Where B1,B2,B3,B4 is IP AND REVERSED SNM (/16 == becomes 0000ffff)
B=[]
B.append(hex(int(ssIP.split('.')[0]) & (255-int(sSubnet.split('.')[0])))[2:].zfill(2))
B.append(hex(int(ssIP.split('.')[1]) & (255-int(sSubnet.split('.')[1])))[2:].zfill(2))
B.append(hex(int(ssIP.split('.')[2]) & (255-int(sSubnet.split('.')[2])))[2:].zfill(2))
B.append(hex(int(ssIP.split('.')[3]) & (255-int(sSubnet.split('.')[3])))[2:].zfill(2))
data = ('c5 74 40 03 00 30'+'3d7d'+B[0]+B[1]+B[2]+B[3]+'90000000'+'02c20301'+'3b54'+'0000').replace(' ','')

# Calculate broadcast ip
sBroadcast = str(int(ssIP.split('.')[0]) | 255-int(sSubnet.split('.')[0])) + '.'
sBroadcast += str(int(ssIP.split('.')[1]) | 255-int(sSubnet.split('.')[1])) + '.'
sBroadcast += str(int(ssIP.split('.')[2]) | 255-int(sSubnet.split('.')[2])) + '.'
sBroadcast += str(int(ssIP.split('.')[3]) | 255-int(sSubnet.split('.')[3]))

print('Sending the discovery packets and waiting {} seconds for answers...'.format(iTimeout))
send_only(sock, sBroadcast, iDPort, data)
receivedData = []
while True:
    try: receivedData.append(recv_only(sock))
    except: break
print(('Got {} response(s): '.format(len(receivedData)-1)))
for data in receivedData:
    if not data[1][0] == ssIP:
        ip = data[1][0]
        print(('Answer from IP {}'.format(ip)))
        hexdata = binascii.hexlify(data[0])
        ## splitting with offset, no idea if this is correct ...
        if len(hexdata)> 100:
            #firmware = '{}.{}.{}.{}'.format(int(hexdata[102:104],16), int(hexdata[100:102],16), int(hexdata[98:100],16), int(hexdata[96:98],16))
            firmware = '.'.join((str(int(hexdata[102:104],16)), str(int(hexdata[100:102],16)), str(int(hexdata[98:100],16)), str(int(hexdata[96:98],16))))
            device = hexdata[104:]
            device = binascii.unhexlify(device).replace(b'\x00\x00',b' ').replace(b'\x00',b'')
            print('The device identifies as: {}'.format(device.decode()))
            print(' with firmware version: {}'.format(firmware))
    
input('press enter')
