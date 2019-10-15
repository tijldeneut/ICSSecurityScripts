#! /usr/bin/env python
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
    
    This should work on Linux & Windows using Python2
    
    File name eWON_Scanner.py
    written by tijl[dot]deneut[at]howest[dot]be
    
    --- eWON Scanner ---
    It uses the same scanning packets as used in the eBuddy software...
'''
import sys, socket, binascii, time, os, subprocess

iDPort = 1507
iSPort = 1506
iTimeout = 1

def send_and_recv(s, ip, port, string):
    data = binascii.unhexlify(string)
    s.sendto(data, (ip, port))
    data, addr = s.recvfrom(1024)
    print("received "+binascii.hexlify(data)+" from "+addr[0])
    return data

def send_only(s, ip, port, string):
    data = binascii.unhexlify(string)
    s.sendto(data, (ip,port))
    
def recv_only(s):
    data, addr = s.recvfrom(1024)
    return data

def parseData(hexdata):
    ip = str(int(hexdata[46:48], 16)) + '.'
    ip += str(int(hexdata[44:46], 16)) + '.'
    ip += str(int(hexdata[42:44], 16)) + '.'
    ip += str(int(hexdata[40:42], 16))
    netmask = str(int(hexdata[54:56], 16)) + '.'
    netmask += str(int(hexdata[52:54], 16)) + '.'
    netmask += str(int(hexdata[50:52], 16)) + '.'
    netmask += str(int(hexdata[48:50], 16))
    mac = hexdata[64:66] + ':' + hexdata[66:68] + ':'
    mac += hexdata[68:70] + ':' + hexdata[70:72] + ':'
    mac += hexdata[72:74]+ ':' + hexdata[74:76]
    token = hexdata[28:40]
    serial = str("%02d" % int(token[-2:], 16)) + str("%02d" % (70 - int(token[8:10], 16))) + '-'
    serial += str("%02d" % int(token[:2], 16)) + str("%02d" % int(token[6:8], 16)) + '-'
    serial += str("%02d" % int(token[4:6], 16))
    token = token[-8:]
    return ip, netmask, mac, token, serial

def parseFirmware(hexdata):
    firmware = binascii.unhexlify(hexdata[40:])
    return firmware

def getAddresses():
    interfaces=[]
    if os.name == 'nt': # This should work on Windows
        proc=subprocess.Popen("ipconfig | FINDSTR \"IPv4 Address Subnet\" | FINDSTR /V \"IPv6\"",shell=True,stdout=subprocess.PIPE)
        allines=proc.stdout.readlines()
        for i in range(0,len(allines),2):
            ip = allines[i].split(':')[1].rstrip().lstrip()
            mask = allines[i+1].split(':')[1].rstrip().lstrip()
            interfaces.append(ip)
    else: # And this on any Linux
        proc=subprocess.Popen("ip address | grep inet | grep -v \"127.0.0.1\" | grep -v \"inet6\"", shell=True, stdout=subprocess.PIPE)
        for interface in proc.stdout.readlines():
            ip = interface.lstrip().split(' ')[1].split('/')[0]
            cidr = int(interface.lstrip().split(' ')[1].split('/')[1])
            bcidr = (cidr*'1'+(32-cidr)*'0')
            mask = str(int(bcidr[:8],2)) + '.' + str(int(bcidr[8:16],2)) + '.' + str(int(bcidr[16:24],2)) + '.' + str(int(bcidr[24:],2))
            interfaces.append(ip)
    return interfaces

#### MAIN PROGRAM ####
os.system('cls' if os.name == 'nt' else 'clear')
## Select Adapter
i=1
arrInterfaces=getAddresses()
for interface in arrInterfaces:
    print('['+str(i)+'] '+interface)
    i+=1
print('[Q] Quit now')
if i>2: answer=raw_input('Please select the adapter [1]: ')
else: answer=str(i-1)
if answer.lower()=='q': exit()
if answer=='' or not answer.isdigit() or int(answer)>=i: answer=1
ssIP = arrInterfaces[int(answer)-1]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.settimeout(iTimeout)
#sock.bind((ssIP, iSPort))
sock.bind(('',iSPort))

print('Sending the discovery packets and waiting ' + str(iTimeout) + ' seconds for answers...')
send_only(sock, '255.255.255.255', iDPort, '4950434f4e4600000000000000000000000000000000000000000000000000000000000000000000')
send_only(sock, '255.255.255.255', iDPort, '4950434f4e460000000000000000000a000000000000000000000000000000000000000000000000')
receivedData = []
while True:
    try: receivedData.append(recv_only(sock))
    except: break
print("Got "+str(len(receivedData)/2)+" response(s):")
for data in receivedData:
    hexdata = binascii.hexlify(data)
    responsetype = hexdata[30:32]
    if responsetype == '02': ## contains ip, snm, mac, token & serial
        ip, netmask, mac, token, serial = parseData(hexdata)
        print('- ' + data[:4] + " " + ip + " " + netmask + " " + mac + " " + serial)
    if responsetype == '05': ## contains firmware, token & serial
        print('    Firmware ' + parseFirmware(hexdata))
raw_input("press enter")
