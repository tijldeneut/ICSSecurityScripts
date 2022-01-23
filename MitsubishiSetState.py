#! /usr/bin/env python3
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
        
        File name MitsubishiSetState.py
        written by tijl[dot]deneut[at]howest[dot]be

        --- Mitsubishi Set State ---
        It broadcasts the packets used to stop or start a Mitsubishi PLC.
        Verified working on a FX5U-32M
'''
import socket,binascii, subprocess, os

### RUN a PLC
## UDP packets for run sent to 255.255.255.255:5560 (ff:ff:ff:ff:ff:ff)  ## ((eth.addr == 10:4b:46:28:4f:08 || eth.addr == 00-0C-29-CB-BF-EF)&&data) && !(data.len == 57) && !data.len==1003 && !data.len==167 && ip.src==192.168.3.64
def send_and_recv(s, ip, port, string):
    data = bytes.fromhex(string.replace(' ',''))
    s.sendto(data, (ip, port))
    data, addr = s.recvfrom(1024)
    return data

def send_only(s, ip, port, string):
    data = bytes.fromhex(string.replace(' ',''))
    s.sendto(data, (ip, port))

def getAddresses():
    interfaces=[]
    if os.name == 'nt': # This should work on Windows
        proc=subprocess.Popen("ipconfig | FINDSTR \"IPv4 Address Subnet\" | FINDSTR /V \"IPv6\"",shell=True,stdout=subprocess.PIPE)
        allines=proc.stdout.readlines()
        for i in range(0,len(allines),2):
            ip = allines[i].split(b':')[1].rstrip().lstrip()
            mask = allines[i+1].split(b':')[1].rstrip().lstrip()
            interfaces.append((ip.decode(), mask.decode(), None))
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


def initConnection(srcIP, bSrcDev): ## The PLC needs to accept our IP address, this will do that (should actually only be done once every boot cycle or src IP change)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(4)
    if os.name == 'nt': s.bind((srcIP,0))
    else: s.setsockopt(socket.SOL_SOCKET, 25, bSrcDev)

    data='5a000001'
    send_only(s,'255.255.255.255',5560,data)
    data='5a000001'
    response = send_and_recv(s,'255.255.255.255',5560,data)
    data='5a000001'
    send_only(s,'255.255.255.255',5560,data)
    data='5a000001'
    response = send_and_recv(s,'255.255.255.255',5560,data)
    data='5a000022'
    send_only(s,'255.255.255.255',5560,data)
    data='5a000022'
    response = send_and_recv(s,'255.255.255.255',5560,data)
    data='5a000001'
    send_only(s,'255.255.255.255',5560,data)
    data='5a000001'
    response = send_and_recv(s,'255.255.255.255',5560,data)
    data='5a000011'
    send_only(s,'255.255.255.255',5560,data)
    data='5a000011'
    response = send_and_recv(s,'255.255.255.255',5560,data)
    data='5a0000ff'
    send_only(s,'255.255.255.255',5560,data)
    data='5a0000ff'
    response = send_and_recv(s,'255.255.255.255',5560,data)
    data='57010000001111070000ffff030000fe03000020001c0a161400000000000000000000000000000000000000000121010000000001'
    send_only(s,'255.255.255.255',5560,data)
    data='57010000001111070000ffff030000fe03000020001c0a161400000000000000000000000000000000000000000121010000000001'
    response = send_and_recv(s,'255.255.255.255',5560,data)
    data='57010000001111070000ffff030000fe03000023001c0a1614000000000000000000000000000000000000000001a0020000000854067dc9'
    send_only(s,'255.255.255.255',5560,data)
    data='57010000001111070000ffff030000fe03000023001c0a1614000000000000000000000000000000000000000001a0020000000854067dc9'
    response = send_and_recv(s,'255.255.255.255',5560,data)
    s.close()

def sendSTOP(srcIP, bSrcDev):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(4)
    if os.name == 'nt': s.bind((srcIP,0))
    else: s.setsockopt(socket.SOL_SOCKET, 25, bSrcDev)
    print('Now sending the command ...')
    ##### This seems to be the actual packet sending it in RUN mode
    data='57010000001111070000ffff030000fe03000020001c0a161400000000000000000000000000000000000000001002090000000100'
    response = send_and_recv(s,'255.255.255.255',5560,data)
    if response.hex()[-8:] == '09000000': print('Should\'ve worked')
    ## Valid response seems to be d70100000011117f000000a80300ffff03000020009c0a181400000000000000000000000000000000000000000000100109000000
    s.close()

def sendPAUSE(srcIP, bSrcDev):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(4)
    if os.name == 'nt': s.bind((srcIP,0))
    else: s.setsockopt(socket.SOL_SOCKET, 25, bSrcDev)
    print('Now sending the command ...')
    ##### This seems to be the actual packet sending it in RUN mode
    data='57010000001111070000ffff030000fe03000020001c0a161400000000000000000000000000000000000000001003090000000100'
    response = send_and_recv(s,'255.255.255.255',5560,data)
    if response.hex()[-8:] == '09000000': print('Should\'ve worked')
    ## Valid response seems to be d70100000011117f000000a80300ffff03000020009c0a181400000000000000000000000000000000000000000000100109000000
    s.close()


def sendRUN(srcIP, bSrcDev):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(4)
    if os.name == 'nt': s.bind((srcIP,0))
    else: s.setsockopt(socket.SOL_SOCKET, 25, bSrcDev)
    print('Now sending the command ...')
    ##### This seems to be the actual packet sending it in STOP mode
    data='57010000001111070000ffff030000fe03000022001c0a1614000000000000000000000000000000000000000010010900000001000000'
    response = send_and_recv(s,'255.255.255.255',5560,data)
    if response.hex()[-8:] == '09000000': print('Should\'ve worked')
    ## Valid response seems to be d70100000011117f000000a80300ffff03000020009c0a181400000000000000000000000000000000000000000000100109000000
    s.close()

## Select Adapter, IP does not have to be in the same subnet
i=1
arrInterfaces=getAddresses()
for interface in arrInterfaces:
    print('['+str(i)+'] '+interface[0])
    i+=1
print('[Q] Quit now')
if i>2: answer = input('==> Please select the physical adapter to use [1]: ').lower()
else: answer=str(i-1)
if answer=='q': exit(0)
if answer=='' or not answer.isdigit() or int(answer)>=i: answer=1

sLocalIP = arrInterfaces[int(answer)-1][0]
bSrcDev = arrInterfaces[int(answer)-1][2]
ans=input('Run, Stop or Pause the PLC? [R/s/p]: ').lower()
if ans=='': ans='r'
initConnection(sLocalIP, bSrcDev)
if ans == 's': sendSTOP(sLocalIP, bSrcDev)
elif ans == 'p': sendPAUSE(sLocalIP, bSrcDev)
else: sendRUN(sLocalIP, bSrcDev)
input('All done, press Enter')
