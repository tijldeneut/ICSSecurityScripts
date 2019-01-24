#! /usr/bin/env python
'''
	Copyright 2019 Photubias(c)

	Written for Howest(c) University College, Ghent University, XiaK

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
        written by tijl[dot]deneut[at]howest[dot]be for www.xiak.be
        --- Beckhoff UDP Scanner ---
        It will perform a UDP discovery scan for Beckhoff devices (and software?)
        and then lists their info

        --- Beckhoff Hacker ---
        It also performs detailed scanning using ADS, followed by controlling the
        Twincat service.
'''
import sys, os, binascii, socket, subprocess, time
iTimeout=1 ## Seconds, waittime for answers

def send_and_recv(s, packet):
    data=binascii.unhexlify(packet.replace(' ',''))
    s.send(data)
    return s.recv(4096)

def send_only(s, ip, port, string):
    data=binascii.unhexlify(string.replace(' ',''))
    s.sendto(data, (ip, port))

def recv_only(s):
    data, addr=s.recvfrom(1024)
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

def getDevices(LHOST,LNETID,iTimeout):
    print('## Scanning for Devices on network '+LHOST)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(iTimeout)
    sock.bind((LHOST,0))
    
    print('Sending the discovery packets and waiting ' + str(iTimeout) + ' seconds for answers...')
    send_only(sock, '255.255.255.255', 48899, '03661471 0000000001000000' + LNETID + '1027 00000000')
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
        twincatversion=str(int(hexdata[-8:-6]))+'.'+str(int(hexdata[-6:-4]))+'.'+str(int(hexdata[-2:]+hexdata[-4:-2],16))
        namelength=int(hexdata[54:56]+hexdata[52:54],16)
        name=data[28:27+namelength]
        kernelstart=hexdata.split('14011401')[1]
        try:
            kernel=str(int(kernelstart[4:6]))+'.'+str(int(kernelstart[12:14]))+'.'+str(int(kernelstart[22:24]+kernelstart[20:22],16))
        except:
            kernel='Unknown'
        if name!='':
            arrDevices.append({'IP':ip[0],'NAME':name,'RNETID':netid,'TCVER':twincatversion,'WINVER':kernel})
    return arrDevices ## Array of devices[ip, name, netid, twincatversion, kernel]

def getState(device,LNETID):
    ## ADS Read State Request
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((device['IP'],48898))
    s.settimeout(iTimeout)
    
    packet='000020000000'+device['RNETID']+'1027'+LNETID+'018004000400000000000000000009000000'
    try: resp=binascii.hexlify(send_and_recv(s, packet))
    except: resp=''
    s.close()
    if len(resp)>0:
        if resp[-8:-6]=='06': return 'STOP'
        elif resp[-8:-6] == '0f': return 'CONFIG'
        else: return 'RUN'
    else:
        return 'ERROR'

def verifyDevice(device,LHOST,LNETID):
    os.system('cls' if os.name == 'nt' else 'clear')
    state=getState(device,LNETID)
    if state=='RUN':
        print('Device is reachable and Twincat is running')
    elif state=='CONFIG':
        print('Device is reachable and Twincat is in CONFIG mode')
    elif state=='STOP':
        print('Device is reachable and Twincat is stopped')
    else:
        print('Device unreachable. Please add remote route!')
        ans=raw_input('Do you want to add one now? [y/N]: ').lower()
        if ans=='y': 
            addRoute(device,LHOST,LNETID)
        return state
    raw_input('Press [Enter] to continue')
    return state

def addRoute(device,LHOST,LNETID):
    os.system('cls' if os.name == 'nt' else 'clear')
    user = passw = ''
    if not getState(device,LNETID)=='ERROR':
        print('Device seems reachable, sure to add a route?')
        ans=raw_input('Please type \'Y\' to do so [y/N]: ')
        if not ans.lower()=='y': return
    if not device['WINVER'].split('.')[1]=='0':
        print('Device is running non Windows CE (kernel '+device['WINVER']+'), correct credentials needed:')
        user=raw_input('Device username [guest]: ')
        passw=raw_input('Device password [1]: ')
    if user=='': user='guest'
    if passw=='': passw='1'
    print('\nAdding route on '+device['NAME']+' ('+device['IP']+')')
    routename=socket.gethostname()
    ans=raw_input('Use default route name ('+routename+')? [Y/n]: ')
    if ans=='': ans='y'
    if not ans.lower()=='y':
        routename=raw_input('Please provide Route Name: ')
    udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udpsock.settimeout(iTimeout)
    udpsock.bind((LHOST,0))
    ## This Route has same credentials (user/pass), but not encrypted:
    ##packet = '036614710000000006000000 ac1001200101 1027 050000000c001000 46494354494c452d5457494e43415400 07000600 ac1001200101 0d000500 7573657200 02000500 7061737300 05000c00 3137322e32302e302e353000'
    ##static, LNETID, static+length, hostname+nullbyte (FICTILE-TWINCAT), static, LNETID, static+length, user+nullbyte, static+length, pass+nullbyte, static+length, LHOST+nullbyte

    namelength=hex(1+len(routename))[2:].zfill(2)
    routenamehex=binascii.hexlify(routename)
    userlength=hex(1+len(user))[2:].zfill(2)
    userhex=binascii.hexlify(user)
    passlength=hex(1+len(passw))[2:].zfill(2)
    passhex=binascii.hexlify(passw)
    lhostlength=hex(1+len(LHOST))[2:].zfill(2)
    lhosthex=binascii.hexlify(LHOST)

    packet='036614710000000006000000'+LNETID+'1027050000000c00'+namelength+'00'+routenamehex+'00 07000600'+LNETID
    packet+='0d00'+userlength+'00'+userhex+'00 0200'+passlength+'00'+passhex+'00 0500'+lhostlength+'00'+lhosthex+'00'
   
    print('Adding route '+routename+' for '+LHOST+' with credentials '+user+'/'+passw)
    send_only(udpsock, device['IP'], 48899, packet)
    resp = recv_only(udpsock)
    hexdata = binascii.hexlify(resp[0])
    amsnetid = str(int(hexdata[24:26],16))+'.'+str(int(hexdata[26:28],16))+'.'
    amsnetid += str(int(hexdata[28:30],16))+'.'+str(int(hexdata[30:32],16))+'.'
    amsnetid += str(int(hexdata[32:34],16))+'.'+str(int(hexdata[34:36],16))
    print('Received AMS Net ID: '+amsnetid)
    print('Route added!')
    udpsock.close()
    raw_input('Press [Enter] to continue')
    return

def getRemoteRoutes(s,device,LNETID,showme=True):
    ## Just keep requesting routes untill there is no answer
    returnarr = []
    i=0
    while i>=0:
        ## IndexID, first route is '0', second is '1' etc...
        packet = '00002c000000' + device['RNETID'] + '1027' + LNETID + '9f80 0200 04000c00000000000000 '+str(i+30)+'000000 23030000 0'+str(i)+'000000 00080000'
        resp = send_and_recv(s, packet)
        
        if len(resp)<2094:
            print(str(i)+' routes found')
            i = -1
        else:
            HexNetID = binascii.hexlify(resp[46:52])
            NetID = str(int(HexNetID[:2],16))+'.'+str(int(HexNetID[2:4],16))+'.'
            NetID += str(int(HexNetID[4:6],16))+'.'+str(int(HexNetID[6:8],16))+'.'
            NetID += str(int(HexNetID[8:10],16))+'.'+str(int(HexNetID[10:12],16))
            Address = resp[90:].split(binascii.unhexlify('00'))[0]
            Name = resp[90:].split(binascii.unhexlify('00'))[1]
            if showme:
                print('NetID = '+NetID+', Address = '+Address+', Name = '+Name)
            returnarr.append((Name,Address))
            i += 1
    return returnarr

def delRoute(device,LHOST,LNETID):
    os.system('cls' if os.name == 'nt' else 'clear')
    if getState(device,LNETID)=='ERROR':
        print('Device unreachable. Please add remote route!')
        raw_input('Press [Enter] to continue')
        return
    
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((device['IP'],48898))
    s.settimeout(iTimeout)
    bMyRoute=False

    print('Hold on, receiving...')
    time.sleep(1)
    os.system('cls' if os.name == 'nt' else 'clear')
    arrRouteNames=getRemoteRoutes(s,device,LNETID,False)
    i=1
    for route in arrRouteNames:
        print('['+str(i)+'] '+route[0]+' ('+route[1]+')')
        i+=1
    print('[C] Cancel')
    answer=raw_input('Which route to delete? [C]: ')
    if answer=='' or not answer.isdigit() or int(answer)>=i:
        s.close()
        return
    if arrRouteNames[int(answer)-1][1]==LHOST:
        bMyRoute=True
        ans=raw_input('Deleting your own route will result in connection failure, sure? [y/N]: ')
        if not ans.lower()=='y':
            s.close()
            return
    
    routename=arrRouteNames[int(answer)-1][0]
    namelength=hex(1+len(routename))[2:].zfill(2)
    routenamehex=binascii.hexlify(routename)
    datalength=hex(13+len(routename))[2:].zfill(2)
    totallength=hex(45+len(routename))[2:].zfill(2)
    print
    print('Deleting Route "'+routename+'"')
    packet = '0000 '+totallength+' 000000 '+device['RNETID']+' 1027 '+LNETID+' ce80 0300 0400 '+datalength+'000000 00000000 38000000 22030000 00000000 '+namelength+'000000 '+routenamehex+'00'

    try:
        resp = send_and_recv(s,packet)
        s.close()
        if bMyRoute:
            if getState(device,LNETID)=='ERROR': print('Successful!')
            else: print('There was an error')
        else:
            if binascii.hexlify(resp)[-8:]=='00000000': print('Successful!')
            else: print('Some error occured')
    except:
        s.close()
        print('Something went wrong!')
    raw_input('Press [Enter] to continue')
    return

def getInfo(device,LNETID):
    os.system('cls' if os.name == 'nt' else 'clear')
    '''
    if getState(device,LNETID)=='ERROR':
        print('Device unreachable. Please add remote route!')
        raw_input('Press [Enter] to continue')
        return
    '''
    
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(iTimeout)
    s.connect((device['IP'],48898))
    import xml.etree.ElementTree as ET
    ##ADS Read Request (extensive, invokeid 0x26, indexgroup 0x2bc, offset 0x1, cblength 0x240,d576)
    packet = '00002c000000'+device['RNETID']+'1027'+LNETID+'8f80 0200 0400 0c000000 00000000 26000000 bc020000 01000000 40020000'
    ## Has: TargetType, TargetVersion (Version, Revision, Build), TargetFeatures (NetId), Hardware (Model, SerialNo, CPUVersion, Date, CPUArchitecture)
    ##        OsImage (ImageDevice, ImageVersion, ImageLevel, OsName, OsVersion)
    ## Example:
    ## <TargetType>CB3011-0001-M9002215923-001-CE</TargetType>
    ## <TargetVersion><Version>3</Version><Revision>1</Revision><Build>4018</Build></TargetVersion>
    ## <TargetFeatures><NetId>5.35.18.112.1.1</NetId></TargetFeatures>
    ## <Hardware><Model>CB3011-0001-M900</Model><SerialNo>2215923-001</SerialNo><CPUVersion>2.2</CPUVersion><Date>25.11.15</Date><CPUArchitecture>5</CPUArchitecture></Hardware>
    ## <OsImage><ImageDevice>CB3011</ImageDevice><ImageVersion>6.02e</ImageVersion><ImageLevel>HPS</ImageLevel><OsName>Windows CE</OsName><OsVersion>7.0</OsVersion></OsImage>
    resp = send_and_recv(s, packet)[46:-1]
    
    root = ET.fromstring(resp)

    print('      ###--- DEVICE INFO ---###')
    print('TargetType: '+root[0].text)
    print('TargetVersion: '+root[1][0].text+'.'+root[1][1].text+'.'+root[1][2].text)
    print('TargetFeatures (NetId): '+root[2][0].text)
    print('Hardware: Model='+root[3][0].text+', Serial='+root[3][1].text+', Version='+root[3][2].text+', Date='+root[3][3].text+', Architecture='+root[3][4].text)
    print('OSImage: Device='+root[4][0].text+', Version='+root[4][1].text+', Level='+root[4][2].text+', OsName='+root[4][3].text+', OsVersion='+root[4][4].text)
    print
    print('      ###--- DEVICE REMOTE ROUTES ---###')
    getRemoteRoutes(s,device,LNETID)
    print
    s.close()
    state=getState(device,LNETID)
    print('      ###--- TWINCAT SERVICE ---###')
    print('Twincat is currently in '+state+' mode')
    print
    raw_input('Press [Enter] to continue')

def setTwincat(device,LNETID):
    os.system('cls' if os.name == 'nt' else 'clear')
    state=getState(device,LNETID)
    print('      ###--- TWINCAT SERVICE ---###')
    print('Twincat is currently in '+state+' mode')
    print
    print('[1] RUN')
    print('[2] STOP')
    print('[3] CONFIG')
    print('[C] Cancel')
    answer=raw_input('Which mode you want to restart Twincat? [C]: ').lower()
    if answer=='' or not answer.isdigit() or int(answer)>3 or answer=='c': return
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(2*iTimeout)
    s.connect((device['IP'],48898))
    if answer=='1':
        print('## (Re)Start in RUN') ## 0200
        packet = '000028000000 '+device['RNETID']+' 1027 '+LNETID+'a780 0500 040008000000000000000d050000 0200 000000000000'
    elif answer=='2':
        print('## STOP Twincat') ## 0600
        packet = '000028000000 '+device['RNETID']+' 1027 '+LNETID+'a780 0500 040008000000000000000d050000 0600 000000000000'
    elif answer=='3':
        print('## (Re)Start in CONFIG') ## 1000
        packet = '000028000000 '+device['RNETID']+' 1027 '+LNETID+'a780 0500 040008000000000000000d050000 1000 000000000000'
    try:
        resp = binascii.hexlify(send_and_recv(s,packet))
        print('Successful!')
    except:
        return
    raw_input('Press [Enter] to continue')
    return
    

#### MAIN PROGRAM ####
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
LHOST=arrInterfaces[int(answer)-1]
LNETID=hex(int(LHOST.split('.')[0]))[2:].zfill(2) + hex(int(LHOST.split('.')[1]))[2:].zfill(2)
LNETID+=hex(int(LHOST.split('.')[2]))[2:].zfill(2) + hex(int(LHOST.split('.')[3]))[2:].zfill(2) + '0101'

os.system('cls' if os.name == 'nt' else 'clear')
## Get Devicelist (array of 'IP', 'Name', 'AMSNetID', 'Twincatversion', 'Kernelbuild')
arrDevices=getDevices(LHOST,LNETID,iTimeout)
if len(arrDevices)==0:
    print('No devices found, stopping')
    raw_input('Press [Enter]')
    exit()

## Main Functionality
while True:
    os.system('cls' if os.name == 'nt' else 'clear')
    print('      ###--- DEVICELIST ---###')
    i=1
    for device in arrDevices:
        amsnetid = str(int(device['RNETID'][:2],16))+'.'+str(int(device['RNETID'][2:4],16))+'.'
        amsnetid += str(int(device['RNETID'][4:6],16))+'.'+str(int(device['RNETID'][6:8],16))+'.'
        amsnetid += str(int(device['RNETID'][8:10],16))+'.'+str(int(device['RNETID'][10:12],16))
        print('['+str(i)+'] '+device['IP']+' ('+device['NAME']+', '+amsnetid+', '+device['WINVER']+')')
        i+=1
    print('[Q] Quit now')
    answer=raw_input('Please select the device [1]: ')
    if answer.lower() == 'q': exit()
    if answer=='' or not answer.isdigit() or int(answer)>=i: answer=1
    device=arrDevices[int(answer)-1]
    ## Device Menu
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('###--- MAIN MENU FOR '+device['NAME']+' ---###')
        print('Kernel: '+device['WINVER']+'\n')
        print('[T] Verify connectivity')
        print('[L] List more information, including routes')
        print('[A] Add Route')
        print('[D] Delete Route')
        print('[C] Change Twincat State')
        print
        print('[O] Choose other device')
        print('[Q] Quit now')
        print
        answer2 = raw_input('Please select what you want to do with ' + device['NAME'] + ' (' + device['IP'] + ')' + ' [T]: ')
        if answer2.lower()=='q': exit()
        if answer2.lower()=='l': getInfo(device,LNETID)
        if answer2.lower()=='a': addRoute(device,LHOST,LNETID)
        if answer2.lower()=='d': delRoute(device,LHOST,LNETID)
        if answer2.lower()=='c': setTwincat(device,LNETID)
        if answer2.lower()=='o': break
        if answer2.lower()=='t' or answer2=='': verifyDevice(device,LHOST,LNETID)
