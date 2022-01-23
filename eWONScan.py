#! /usr/bin/env python3
'''
    Copyright 2015 Deneut Tijl

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

File name eWon_Scanner.py
written by tijl.deneut@howest.be
'''
import socket, os, subprocess

iDPort = 1507
iResponsePort = 1506
iTimeout = 2

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
            int_parts = interface.lstrip().split(b' ')
            ip = int_parts[1].split(b'/')[0]
            cidr = int(int_parts[1].split(b'/')[1])
            bcidr = (cidr*'1'+(32-cidr)*'0')
            mask = str(int(bcidr[:8],2)) + '.' + str(int(bcidr[8:16],2)) + '.' + str(int(bcidr[16:24],2)) + '.' + str(int(bcidr[24:],2))
            intname = int_parts[len(int_parts)-1].rstrip()
            interfaces.append((ip.decode(),mask,intname))
    return interfaces

def send_only(s, ip, port, string):
    data = bytes.fromhex(string)
    s.sendto(data, (ip,port))
    
def recv_only(s):
    data, addr = s.recvfrom(1024)
    return data

def parseData(bResp):
    def fromhex(bByte): return hex(bByte)[2:].zfill(2)
    ip = netmask = mac = token = serial = pcode = ''
    ip = '.'.join((str(bResp[23]), str(bResp[22]), str(bResp[21]), str(bResp[20])))
    netmask = '.'.join((str(bResp[27]), str(bResp[26]), str(bResp[25]), str(bResp[24])))
    mac = ':'.join((fromhex(bResp[32]), fromhex(bResp[33]), fromhex(bResp[34]), fromhex(bResp[35]), fromhex(bResp[36]), fromhex(bResp[37])))
    token = bResp[16:20].hex()
    pcode = str(bResp[16]) ## This identifies the product

    serialp1 = str(bResp[19])
    serialp2 = str(int(int((bResp[18:19] + bResp[17:18]).hex(),16)/1000))
    serialp3 = bResp[17]
    if int((bResp[18:19] + bResp[17:18]).hex(), 16) % 1000  >= 500: serialp3 += 0x100
    serialp4 = bResp[16]
    serial = '{}{}-{}-{}'.format(serialp1,serialp2,str(serialp3).zfill(4),serialp4)
    return ip, netmask, mac, token, serial, pcode

###MAIN###
i=1
arrInterfaces=getAddresses()
for interface in arrInterfaces:
    print(('[{}] {} / {}'.format(i, interface[0], interface[1])))
    i+=1
print('[Q] Quit now')

if i>2: answer=input('Please select the adapter [1]: ')
else: answer=str(i-1)
if answer.lower()=='q': exit()
if answer=='' or not answer.isdigit() or int(answer)>=i: answer=1
ssIP = arrInterfaces[int(answer)-1][0]


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.settimeout(iTimeout)
## The response are also broadcasted (255.255.255.255:1506), so we listen on all interfaces
sock.bind(('', iResponsePort))
if not os.name == 'nt': 
    bSrcDev = arrInterfaces[int(answer)-1][2]
    sock.setsockopt(socket.SOL_SOCKET, 25, bSrcDev)

print(('Sending the discovery packets and waiting ' + str(iTimeout) + ' seconds for answers...'))
send_only(sock, '255.255.255.255', iDPort, '4950434f4e4600000000000000000000000000000000000000000000000000000000000000000000')
send_only(sock, '255.255.255.255', iDPort, '4950434f4e460000000000000000000a000000000000000000000000000000000000000000000000')
receivedData = []
while True:
    try: receivedData.append(recv_only(sock))
    except: break
print('Got {} response(s):'.format(int(len(receivedData)/2)))
for data in receivedData:
    iResponseType = str(data[15])
    if iResponseType == '2': ## contains ip, snm, mac, token, serial, pcode (last one identifies product type, e.g. 24 == Flexy 205)
        ip, netmask, mac, token, serial, pcode = parseData(data)
        print(('- ' + data[:4].decode() + ", " + ip + ", " + netmask + ", " + mac + ", " + serial + ", Pcode: " + pcode))
    if iResponseType == '5': ## contains firmware, token & serial
        sFirmware = data[20:].strip(b'\x00').decode()
        print('    Firmware: {} '.format(sFirmware))
input('press enter')
