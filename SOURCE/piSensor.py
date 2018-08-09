''' 
Packet Sensor/Recorder GUI Version
Version IoT Book Release
    
Copyright (c) 2018 Python Forensics and Chet Hosmer

Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the "Software"), to deal in the Software without restriction, 
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial 
portions of the Software.
    
'''
# Python Standard Library Module Imports

import sys          # System specifics
import platform     # Platform specifics
import os           # Operating/Filesystem Module
import time         # Basic Time Module
import logging      # Script Logging
import time         # Time Functions
import webbrowser   # Webbrowser
import datetime     # Time Methods
import calendar     # Calendar Conversions
import pickle       # Data Serialization
import struct       # Data Structures
import socket       # low level socket standard library
import netaddr      # Network Address Conversions
                    # pip install netaddr

# binary ascii conversions standard libary
from binascii import hexlify    

import rpt          # Local Report Source File

'''
tkinter GUI Components from the Standard Library
'''
import Tkinter
import ttk
from Tkinter import *
import tkMessageBox
import tkFileDialog

# 3rd Party Libraries
import pygeoip     # 3rd Party Geo IP Lookup  
                   #   sudo pip install pygeoip

# Script Constants

NAME    = "PiSensor"
VERSION = " IoT Book Release "
AUTHOR  = "C. Hosmer"
TITLE   = NAME+VERSION
OVERWRITE = True
LOG = './log.txt'

LOG_INFO = 1
LOG_WARN = 2
LOG_ERR  = 3

DEBUG = False            # Set to True for additional Logging

# Conversion to seconds
CONVERT = {
    '1-Min'  : 60, 
    '10-Min' : 600,
    '30-Min' : 1800,
    '1-Hr'   : 3600,
    '4-Hr'   : 14400,
    '8-Hr'   : 28800,
    '12-Hr'  : 43200,
    '18-Hr'  : 64800,
    '1-Day'  : 86400,
    '2-Day'  : 172800,
    '4-Day'  : 345600,
    '7-Day'  : 604800,
    '2-Week' : 1209600,
    '4-Week' : 2418200
}

# PSUEDO Constants
INCLUDE_EPHEMERAL = False       # Should we include ephemeral port in keys?
EPHEMERAL_START   = 49151       # Ephemeral Port Starting Value
CORE_PORTS        = 1024
REG_PORTS         = 4951

# key index constants
SRCIP      = 0
DSTIP      = 1
PORTNUM    = 2
FRAMETYPE  = 3
PROTOCOL   = 4

# value index constants

AM12        = 0
AM6         = 1
PM12        = 2
PM6         = 3
WKEND       = 4
ALERT       = 5
SRCPORT     = 6
SRCPORTNAME = 7
DSTPORT     = 8
DSTPORTNAME = 9
SRCMAC      = 10
SRCMFG      = 11
DSTMAC      = 12
DSTMFG      = 13
SRCCC       = 14
DSTCC       = 15
AVGPCKSIZE  = 16
POV         = 17

BG = 'lightgrey'
AB = 'black'
FG = 'black'
AF = 'yellow'


# PORT Assignments for possible ICS and Iot Ports
ICS_LOOKUP = ['102','443','502','530','593','789','1089','1090',
              '1091','1911','1962','2222','2404','4000','4840','4843',
              '4911','9600','19999','20000','20547','34962','34963',
              '34964','34980','44818','46823','46824','55000','55001',
              '55002','55003']

IOT_LOOKUP = ['5353', '1900','1883', '8883', '5683', '5684','7672', 
              '7673', '5222', '5269', '5298', '5671', '5672','44900', 
              '9001', '7672', '5087''137', '138','139','5445','1099']

def getOccurrenceValue():
    ''' use the current time and day to determine the index

        Weekdays
        12:00 AM - 05:59 AM  = ndx 0
        06:00 AM - 11:59 AM  = ndx 1
        12:00 PM - 05:59 PM  = ndx 2
        06:00 PM - 11:59 PM  = ndx 3
        Weekend              = ndx 4

    '''

    # get current local time and date
    now = datetime.datetime.now()
    yr = now.year
    mth = now.month
    day = now.day
    # Note day of week 0 = Monday
    dayOfWeek = calendar.weekday(yr,mth,day)

    # if the weekend, then set the ndx = 4
    if dayOfWeek == 6 or dayOfWeek == 7:
        ndx = 4
    else:    
        # otherwise check the hour range
        hour = now.hour-1
        if hour >= 0 and hour < 6:
            ndx = 0
        elif hour >=6 and hour < 12:
            ndx = 1
        elif hour >=12 and hour < 18:
            ndx = 2
        else:
            ndx = 3

    return ndx



def InitLog():
    '''
    InitLog: Initialize the Forensic Log
    '''
    try:            
        # If LOG should be overwritten before
        # each run, the remove the old log
        if OVERWRITE:
            # Verify that the log exists before removing
            if os.path.exists(LOG):
                os.remove(LOG)

        # Initialize the Log include the Level and message
        logging.basicConfig(filename=LOG, 
                            format='%(levelname)s\t:%(message)s', 
                            level=logging.DEBUG)

    except:
        quit()

def GetTime(timeStyle = "UTC"):
    ''' Get Current Time based on
        timeStyle UTC is default
        returns time (str)
    '''

    if timeStyle == 'UTC':
        return ('UTC Time:  ', 
                time.asctime(time.gmtime(time.time()))) 
    elif timeStyle == 'LOCAL':
        return ('Local Time:', 
                time.asctime(time.localtime(time.time())))
    else:
        return "Invalid TimeStyle Specified"   


def LogEvent(eventType, eventMessage):
    ''' Log Event Function 
        input eventType (str) and eventMessage (str)
    '''
    try:

        if type(eventMessage) == str:

            re.sub(r'[^\x00-\x7f]',r'', eventMessage)         

            timeStr = GetTime('UTC')
            # Combine current Time with the eventMessage
            # You can specify either 'UTC' or 'LOCAL'
            # Based on the GetTime parameter

            eventMessage = str(timeStr)+": "+eventMessage
            if eventType == LOG_INFO:
                logging.info(eventMessage)
            elif eventType == LOG_ERR:
                logging.error(eventMessage)
            else:
                logging.warning(eventMessage)

    except:
        pass  

class ETH:
    ''' Ehternet Packet Lookup Class '''
    def __init__(self, lookupList):
        ''' FrameTypes Supported'''

        self.ethTypes = lookupList[3]       

    def lookup(self, ethType):
        ''' Returns the FrameType associated with the lookup or not=supported'''
        try:
            result = self.ethTypes[ethType]
        except:
            result = 'Unknown'
            #result = "FR:"+'{:04x}'.format(ethType)

        return result.strip()


class MAC:
    ''' MAC to MFG Lookup Class '''
    def __init__(self, lookupList):
        ''' constructor'''
        # Open the MAC Address OUI Dictionary

        self.macDict = lookupList[2]

        self.hotList = {}

        try:
            with open('hotlist.txt', 'r') as hotlist:

                for eachLine in hotlist:
                    fields = eachLine.split()
                    if len(fields) >= 2:
                        key = fields[0]
                        value = ' '.join(fields[1:])
                        self.hotList[key] = value
                    else:
                        continue

        except Exception as err:
            LogEvent(LOG_ERR, "Failed Loading HotList Lookup: "+str(err))
            sys.exit(0)

    def lookup(self, macAddress):
        try:
            result = self.macDict[macAddress]
            if len(result) >= 2:
                result = ": ".join(result[0:2])
            else:
                result = result[0]
            if result == '':
                result = 'Unknown'
            return result
        except:
            return "Unknown"

    def chkHotlist(self, macAddress):
        try:
            result = self.hotList[macAddress]
            return True, result
        except:
            return False, ''

class TRANSPORT:
    ''' Transport Protocol Lookup Class '''

    def __init__(self, lookupList):

        self.proDict = lookupList[1]

    def lookup(self, protocol):
        try:
            result = self.proDict[protocol]
            return result
        except:
            return ["unknown", "unknown", "unknown"]

class PORTS:
    ''' Port Lookup Class '''

    def __init__(self, lookupList):

        self.portsDict = lookupList[0]

    def lookup(self, port, portType):

        try:
            lookupValue = (str(port).strip(),portType.upper())
            result = self.portsDict[lookupValue]
            return result
        except:         
            return "Unknown"
        
class COUNTRY:
    ''' Country Lookup Class '''

    def __init__(self):

        try:
            # download from http://dev.maxmind.com/geoip/legacy/geolite/
            self.giv4 = pygeoip.GeoIP('geoIPv4.dat')
            self.giv6 = pygeoip.GeoIP('geoIPv6.dat')
        except Exception as err:
            LogEvent(LOG_ERR, "Failed Loading Country Lookup: "+str(err))
            sys.exit(0)


    def lookup(self, ipAddr, kind):

        if ipAddr[0:4] == '192.':
            return 'Internal'
        try:
            if kind == 'IPv4':
                cc = self.giv4.country_name_by_addr(ipAddr)
                ccLookup = ipAddr+'->'+cc
                LogEvent(LOG_INFO, ccLookup)                             
                if cc == '':
                    cc = 'Unknown'
                return cc
            elif kind == 'IPv6':
                cc = self.giv6.country_name_by_addr(ipAddr)
                if cc == '':
                    cc = 'Unknown'
                return cc
            else:
                return 'Unknown'
        except:
            return 'Unknown'

class PacketProcessor:
    """
    Packet Processor Class Methods
    __init__ Constructor
    PacketProcessor(self, packet) : processes a single packet
    """
    def __init__(self, lookupList, macF, macE, macV, baseline=None):
        """Constructor optional parameter of baseline used in monitoring mode"""
        ''' 
        Create Lookup Objects 

        These Object provide lookups for:
        Ethernet Frame Types
        MAC Addresses
        Transport Portocol Types
        TCP/UDP Port Names
        Country 
        '''

        self.traOBJ  = TRANSPORT(lookupList)
        self.ethOBJ  = ETH(lookupList)    
        self.portOBJ = PORTS(lookupList)
        self.ouiOBJ  = MAC(lookupList)
        self.cc      = COUNTRY()
        self.knownServerList = []
        
        self.macFilter       = macF
        self.macFilterEnable = macE
        self.macFilterSet    = macV

        # Record Unique Specialized Observations

        self.uniqueMFG     = {}                         # key=MFG,       value= [MAC-Address]
        self.uniquePort    = {}                         # key=(PortName, MAC-Address) value= [IP Address] 
        self.uniqueCountry = {}                         # key=Country, value=[MAC-Address, IP Address]
        self.ics           = {}                         # key=ICSPortName, value= portNumber

        # Packet Dictionary
        self.d = {}
        self.b = baseline
        
    def PacketPreProcessor(self,packet):
        
        ''' Peformed for both RECORD AND SENSOR mode '''
        
        ETH_LEN  = 14      # ETHERNET HDR LENGTH
        IP_LEN   = 20      # IP HEADER    LENGTH
        IPv6_LEN = 40      # IPv6 HEADER  LENGTH
        ARP_HDR  = 8       # ARP HEADER
        UDP_LEN  = 8       # UPD HEADER   LENGTH
        TCP_LEN  = 20      # TCP HEADER   LENGTH

        ''' Elements of the key '''

        self.srcMac = ''
        self.dstMac = ''
        self.frType = ''
        self.srcIP  = ''
        self.dstIP  = ''
        self.proto  = ''
        self.opcode = ''
        self.arpHWType   = ''
        self.arpPROTType = ''
        self.arpHWSize   = ''
        self.arpPROTSize = ''
        self.arpOPCode   = ''        
        self.port   = ''
        self.srcPort = ''
        self.dstPort = ''
        self.srcPortName = ''
        self.dstPortName = ''
        self.packetSize = 0
        self.srcMFG = ''
        self.dstMFG = ''
        self.dstMacOui =''
        self.srcMacOui = ''
        self.srcCC = ''
        self.dstCC = ''
        self.alert = ''

        self.serverDetect = False
        self.pckTime = time.ctime(time.time())
        self.alert = 'Normal'

        ethernetHeader=packet[0:ETH_LEN]
        ethFields =struct.unpack("!6s6sH",ethernetHeader)
        
        # Extract DST MAC, SRC MAC and Frame Type
        self.dstMac = hexlify(ethFields[0]).upper()
        self.srcMac = hexlify(ethFields[1]).upper()
        
        self.fType  = ethFields[2]
        
        self.srcMacOui = self.srcMac[0:6]
        self.srcMFG = self.ouiOBJ.lookup(self.srcMacOui)   
        
        self.dstMacOui = self.dstMac[0:6]
        self.dstMFG = self.ouiOBJ.lookup(self.dstMacOui) 
        
        if self.dstMac == 'FFFFFFFFFFFF':
            ''' Broadcast Packet '''
            self.proto = 'BROADCAST'
              
        if self.srcMac == 'FFFFFFFFFFFF':
            ''' Broadcast Packet '''
            self.proto = 'BROADCAST'
            
        # Check if MAC Filtering is on 
        if self.macFilterEnable and self.macFilterSet:
            if not (self.dstMac in self.macFilter) and not (self.srcMac in self.macFilter):
                # ignore packet if filtering is on
                LogEvent(LOG_INFO, 'FILTERED: '+ self.srcMac + ', '+ self.dstMac)                             
                return False

        if self.fType < 0x0101:
            # 802.3 frame length not processable packet
            return False

        # Lookup the Frame type
        frameType = self.ethOBJ.lookup(self.fType)

        # Check for DST MFG on Hot List
        chk, value = self.ouiOBJ.chkHotlist(self.dstMacOui)
        if chk:
            self.alert = value

        # Check for SRC MFG on Hot List
        chk, value = self.ouiOBJ.chkHotlist(self.srcMacOui)
        if chk:
            self.alert = value        

        self.frType = frameType

        if frameType == "IPV4":
            # Process as IPv4 Packet
            ipHeader = packet[ETH_LEN:ETH_LEN+IP_LEN]

            # unpack the ip header fields
            ipHeaderTuple = struct.unpack('!BBHHHBBH4s4s' , ipHeader)

            # extract the key ip header fields of interest
                                            # Field Contents
            verLen       = ipHeaderTuple[0] # Field 0: Version and Length
            TOS          = ipHeaderTuple[1] # Field 1: Type of Service                                                  
            packetLength = ipHeaderTuple[2] # Field 2: Packet Length      
            timeToLive   = ipHeaderTuple[5] # Field 5: Time to Live (TTL)
            protocol     = ipHeaderTuple[6] # Field 6: Protocol Number 
            sourceIP     = ipHeaderTuple[8] # Field 8: Source IP
            destIP       = ipHeaderTuple[9] # Field 9: Destination IP    


            # Calculate / Convert extracted values

            version      = verLen >> 4    # Upper Nibble = version Number
            length       = verLen & 0x0F  # Lower Nibble = the size
            ipHdrLength  = length * 4     # Calc header length in bytes

            # covert the source and destination 
            # address to typical dotted notation strings

            self.packetSize = packetLength
            self.srcIP = socket.inet_ntoa(sourceIP);
            self.dstIP = socket.inet_ntoa(destIP);
            
            self.srcCC = self.cc.lookup(self.srcIP, 'IPv4')
            self.dstCC = self.cc.lookup(self.dstIP, 'IPv4')

            translate = self.traOBJ.lookup(str(protocol))
            
            if self.proto == "BROADCAST":
                transProtocol = "BROADCAST"
            else:
                transProtocol = translate[0]

            if transProtocol == 'TCP':

                self.proto = "TCP"

                stripTCPHeader = packet[ETH_LEN+ipHdrLength:
                                        ipHdrLength+ETH_LEN+TCP_LEN]

                # unpack the TCP Header to obtain the
                # source and destination port

                tcpHeaderBuffer = struct.unpack('!HHLLBBHHH' , 
                                                stripTCPHeader)

                self.srcPort = tcpHeaderBuffer[0]
                self.dstPort = tcpHeaderBuffer[1]
                flags                  = tcpHeaderBuffer[5]
                FIN                    = flags & 0x01
                SYN                    = flags & 0x02
                RST                    = flags & 0x04
                PSH                    = flags & 0x08
                ACK                    = flags & 0x10
                URG                    = flags & 0x20
                ECE                    = flags & 0x40
                CWR                    = flags & 0x80       
                
                if SYN:
                    self.knownServerList.append(self.dstIP)

                windowSize             = tcpHeaderBuffer[6]
                tcpChecksum            = tcpHeaderBuffer[7]
                urgentPointer          = tcpHeaderBuffer[8]

                self.srcPortName = self.portOBJ.lookup(self.srcPort, 'TCP')
                self.dstPortName = self.portOBJ.lookup(self.dstPort, 'TCP')

            elif transProtocol == 'UDP':

                self.proto = "UDP"

                stripUDPHeader = packet[ETH_LEN+ipHdrLength:
                                        ETH_LEN+ipHdrLength+UDP_LEN]

                # unpack the UDP packet and obtain the
                # source and destination port

                udpHeaderBuffer = struct.unpack('!HHHH' , stripUDPHeader)

                self.srcPort = udpHeaderBuffer[0]
                self.dstPort = udpHeaderBuffer[1]

                self.srcPortName = self.portOBJ.lookup(self.srcPort, 'UDP')
                self.dstPortName = self.portOBJ.lookup(self.dstPort, 'UDP')
                
            elif transProtocol == 'BROADCAST':
            
                stripUDPHeader = packet[ETH_LEN+ipHdrLength:
                                                    ETH_LEN+ipHdrLength+UDP_LEN]
            
                # unpack the UDP packet and obtain the
                # source and destination port
            
                udpHeaderBuffer = struct.unpack('!HHHH' , stripUDPHeader)
            
                self.srcPort = udpHeaderBuffer[0]
                self.dstPort = udpHeaderBuffer[1]
            
                self.srcPortName = self.portOBJ.lookup(self.srcPort, 'UDP')
                self.dstPortName = self.portOBJ.lookup(self.dstPort, 'UDP')                

            elif transProtocol == 'ICMP':
                self.proto = "ICMP"

            elif transProtocol == 'IGMP':

                self.proto = "IGMP"

            else:
                self.proto = transProtocol

        elif frameType == 'ARP':

            # Process as IPv4 Packet
            arpHeader = packet[ETH_LEN:ETH_LEN+ARP_HDR]

            arphdr = packet[14:42]
            arp = struct.unpack("2s2s1s1s2s6s4s6s4s", arphdr)
            # skip non-ARP packets

            self.arpHWType   = hexlify(arp[0])
            self.arpPROTType = hexlify(arp[1])
            self.arpHWSize   = hexlify(arp[2])
            self.arpPROTSize = hexlify(arp[3])
            self.arpOPCode   = hexlify(arp[4])
            self.srcMac      = hexlify(arp[5]).upper()
            self.srcIP       = socket.inet_ntoa(arp[6])
            self.dstMac      = hexlify(arp[7]).upper()
            self.dstIP       = socket.inet_ntoa(arp[8])     
            self.srcPort     = 'ARP'
            self.dstPort     = 'ARP'

            self.srcMacOui = self.srcMac[0:6]
            self.srcMFG = self.ouiOBJ.lookup(self.srcMacOui)  
            
            self.dstMacOui = self.dstMac[0:6]
            self.dstMFG = self.ouiOBJ.lookup(self.dstMacOui)          
            
            self.proto = self.arpOPCode

        elif frameType == "IPV6":

            # Process as IPv6 Packet
            ipHeader = packet[ETH_LEN:ETH_LEN+IPv6_LEN]

            # unpack the ip header fields
            ipv6HeaderTuple = struct.unpack('!IHBBQQQQ' , ipHeader)

            flush = ipv6HeaderTuple[0]
            pLength = ipv6HeaderTuple[1]
            nextHdr = ipv6HeaderTuple[2]
            hopLmt  = ipv6HeaderTuple[3]
            srcIP   = (ipv6HeaderTuple[4] << 64) | ipv6HeaderTuple[5]
            dstIP   = (ipv6HeaderTuple[6] << 64) | ipv6HeaderTuple[7]                 

            self.packetSize = pLength
            self.srcIP = str(netaddr.IPAddress(srcIP))
            self.dstIP = str(netaddr.IPAddress(dstIP))    

            self.srcCC = self.cc.lookup(self.srcIP, 'IPv6')
            self.dstCC = self.cc.lookup(self.dstIP, 'IPv6')            

            translate = self.traOBJ.lookup(str(nextHdr))
            transProtocol = translate[0]

            if transProtocol == 'TCP':

                self.proto = "TCP"

                stripTCPHeader = packet[ETH_LEN+IPv6_LEN:
                                        ETH_LEN+IPv6_LEN+TCP_LEN]

                # unpack the TCP Header to obtain the
                # source and destination port

                tcpHeaderBuffer = struct.unpack('!HHLLBBHHH' , 
                                                stripTCPHeader)

                self.srcPort = tcpHeaderBuffer[0]
                self.dstPort = tcpHeaderBuffer[1]

                self.srcPortName = self.portOBJ.lookup(self.srcPort, 'TCP')
                self.dstPortName = self.portOBJ.lookup(self.dstPort, 'TCP')    

                flags                  = tcpHeaderBuffer[5]
                FIN                    = flags & 0x01
                SYN                    = flags & 0x02
                RST                    = flags & 0x04
                PSH                    = flags & 0x08
                ACK                    = flags & 0x10
                URG                    = flags & 0x20
                ECE                    = flags & 0x40
                CWR                    = flags & 0x80           
                if SYN:
                    self.knownServerList.append(self.dstIP)       

            elif transProtocol == 'UDP':

                self.proto = "UDP"

                stripUDPHeader = packet[ETH_LEN+IPv6_LEN:
                                        ETH_LEN+IPv6_LEN+UDP_LEN]

                # unpack the UDP packet and obtain the
                # source and destination port

                udpHeaderBuffer = struct.unpack('!HHHH' , stripUDPHeader)

                self.srcPort = udpHeaderBuffer[0]
                self.dstPort = udpHeaderBuffer[1]

                self.srcPortName = self.portOBJ.lookup(self.srcPort, 'UDP')
                self.dstPortName = self.portOBJ.lookup(self.dstPort, 'UDP')                

            elif transProtocol == 'ICMP':

                self.proto = "ICMP"

            elif transProtocol == 'IGMP':

                self.proto = "IGMP"               
            else:
                self.proto = transProtocol

        else:
            self.proto = frameType
            
        return True
        

    def PacketRECORD(self, packet):
        ''' 
            Used in RECORD Mode
            Extract Packet Data input: string packet, dictionary d
            result is to update dictionary d
        '''

        ''' Attempt to pre-process the packet, if failed or filtered return '''
        if not self.PacketPreProcessor(packet):
            return
        
        valueNdx = getOccurrenceValue()     

        ''' Check for known server @ srcIP '''
        if self.srcIP in self.knownServerList:
            key = (self.srcIP, self.dstIP, self.srcPort, 
                   self.frType, self.proto)
            try:
                value = self.d[key]
                # Increment the appropriate occurrence value
                value[valueNdx] = value[valueNdx] + 1
                cnt = value[AM12]+value[AM6]+value[PM12]+value[PM6]+value[WKEND]
                value[AVGPCKSIZE] = ( (value[AVGPCKSIZE] + self.packetSize) / cnt)
                self.d[key] = value
            except:
                # New Key initialize the value
                value = [0,0,0,0,0,self.alert,self.srcPort,self.srcPortName,
                         self.dstPort, self.dstPortName, self.srcMac, 
                         self.srcMFG, self.dstMac, self.dstMFG, self.srcCC, 
                         self.dstCC, self.packetSize, 'S']
                
                value[valueNdx] = value[valueNdx] + 1    
                value[AVGPCKSIZE] = self.packetSize
                self.d[key] = value

            return

        ''' Check for known server @ dstIP '''
        if self.dstIP in self.knownServerList:
            key = (self.srcIP, self.dstIP, self.dstPort, 
                   self.frType, self.proto)
            try:
                value = self.d[key]
                # Increment the appropriate occurrence value
                value[valueNdx] = value[valueNdx] + 1
                cnt = value[AM12]+value[AM6]+value[PM12]+value[PM6]+value[WKEND]
                value[AVGPCKSIZE] = ( (value[AVGPCKSIZE] + self.packetSize) / cnt)
                self.d[key] = value
            except:
                # New Key initialize the value
                value = [0,0,0,0,0,self.alert,self.srcPort,self.srcPortName,
                         self.dstPort, self.dstPortName, self.srcMac, 
                         self.srcMFG, self.dstMac, self.dstMFG, self.srcCC, 
                         self.dstCC, self.packetSize, 'D']
                
                value[valueNdx] = value[valueNdx] + 1    
                value[AVGPCKSIZE] = self.packetSize
                self.d[key] = value

            return

        ''' Check for source port in registration range '''
        if self.srcPort < REG_PORTS and self.dstPort > REG_PORTS:

            key = (self.srcIP, self.dstIP, self.srcPort, 
                   self.frType, self.proto)
            try:
                value = self.d[key]
                # Increment the appropriate occurrence value
                value[valueNdx] = value[valueNdx] + 1
                cnt = value[AM12]+value[AM6]+value[PM12]+value[PM6]+value[WKEND]
                value[AVGPCKSIZE] = ( (value[AVGPCKSIZE] + self.packetSize) / cnt)
                self.d[key] = value
            except:
                # New Key initialize the value
                value = [0,0,0,0,0,self.alert,self.srcPort,self.srcPortName,
                         self.dstPort, self.dstPortName, self.srcMac, self.srcMFG, 
                         self.dstMac, self.dstMFG, self.srcCC, self.dstCC, 
                         self.packetSize, 'S']
                
                value[valueNdx] = value[valueNdx] + 1    
                value[AVGPCKSIZE] = self.packetSize
                self.d[key] = value
                
            return

        ''' Check for destination port in registration range '''
        if self.dstPort < REG_PORTS and self.srcPort > REG_PORTS:        
            key = (self.srcIP, self.dstIP, self.dstPort, 
                   self.frType, self.proto)
            try:
                value = self.d[key]
                # Increment the appropriate occurrence value
                value[valueNdx] = value[valueNdx] + 1
                cnt = value[AM12]+value[AM6]+value[PM12]+value[PM6]+value[WKEND]
                value[AVGPCKSIZE] = ( (value[AVGPCKSIZE] + self.packetSize) / cnt)
                self.d[key] = value
            except:
                # New Key initialize the value
                value = [0,0,0,0,0,self.alert,self.srcPort,self.srcPortName,
                         self.dstPort, self.dstPortName, self.srcMac, self.srcMFG, 
                         self.dstMac, self.dstMFG, self.srcCC, self.dstCC, 
                         self.packetSize, 'D']
                
                value[valueNdx] = value[valueNdx] + 1    
                value[AVGPCKSIZE] = self.packetSize
                self.d[key] = value
                
            return

        ''' Check for destination port in registration range '''
        if self.dstPort > REG_PORTS and self.srcPort > REG_PORTS:        

            key = (self.srcIP, self.dstIP, self.srcPort, 
                   self.frType, self.proto)
            try:
                value = self.d[key]
                # Increment the appropriate occurrence value
                value[valueNdx] = value[valueNdx] + 1
                cnt = value[AM12]+value[AM6]+value[PM12]+value[PM6]+value[WKEND]
                value[AVGPCKSIZE] = ( (value[AVGPCKSIZE] + self.packetSize) / cnt)
                self.d[key] = value
            except:
                # New Key initialize the value
                value = [0,0,0,0,0,self.alert,self.srcPort,self.srcPortName,
                         self.dstPort, self.dstPortName, self.srcMac, self.srcMFG, 
                         self.dstMac, self.dstMFG, self.srcCC, self.dstCC, 
                         self.packetSize, 'S']
                
                value[valueNdx] = value[valueNdx] + 1    
                value[AVGPCKSIZE] = self.packetSize
                self.d[key] = value

            key = (self.srcIP, self.dstIP, self.dstPort, 
                   self.frType, self.proto)
            try:
                value = self.d[key]
                # Increment the appropriate occurrence value
                value[valueNdx] = value[valueNdx] + 1
                cnt = value[AM12]+value[AM6]+value[PM12]+value[PM6]+value[WKEND]
                value[AVGPCKSIZE] = ( (value[AVGPCKSIZE] + self.packetSize) / cnt)
                self.d[key] = value
            except:
                # New Key initialize the value
                value = [0,0,0,0,0,self.alert,self.srcPort,self.srcPortName,
                         self.dstPort, self.dstPortName, self.srcMac, self.srcMFG, 
                         self.dstMac, self.dstMFG, self.srcCC, self.dstCC, 
                         self.packetSize, 'D']
                
                value[valueNdx] = value[valueNdx] + 1    
                value[AVGPCKSIZE] = self.packetSize
                self.d[key] = value
        
            return
        
        elif self.srcPort == '' and dstPort == '':
            key = (self.srcIP, self.dstIP, self.srcPort, 
                   self.frType, self.proto)
            try:
                value = self.d[key]
                # Increment the appropriate occurrence value
                value[valueNdx] = value[valueNdx] + 1
                cnt = value[AM12]+value[AM6]+value[PM12]+value[PM6]+value[WKEND]
                value[AVGPCKSIZE] = ( (value[AVGPCKSIZE] + self.packetSize) / cnt)
                self.d[key] = value
            except:
                # New Key initialize the value
                value = [0,0,0,0,0,self.alert,self.srcPort,self.srcPortName,
                         self.dstPort, self.dstPortName, self.srcMac, self.srcMFG, 
                         self.dstMac, self.dstMFG, self.srcCC, self.dstCC, 
                         self.packetSize, 'S']
                
                value[valueNdx] = value[valueNdx] + 1    
                value[AVGPCKSIZE] = self.packetSize
                self.d[key] = value     
                
            return

    def PacketSENSOR(self, packet, alertDict, baseCC, baseMAC):
        ''' 
            SENSOR MODE
            Extract Packet Data input: string packet, dictionary d
            result is to update dictionary d
        '''

        ''' Attempt to pre-process the packet, if failed or filtered return '''
        if not self.PacketPreProcessor(packet):
            return
        
        valueNdx = getOccurrenceValue()    
        self.lastObservationTime = time.ctime(time.time())

        if self.srcIP == '127.0.0.1' and self.dstIP == '127.0.0.1':
            ''' Ignore this packet '''
            return

        if self.srcPort <= CORE_PORTS:
            ''' if srcPort is definately a service port'''
            key = (self.srcIP, self.dstIP, self.srcPort, 
                   self.frType, self.proto)

        elif self.dstPort <= CORE_PORTS:
            ''' if dstPort is definately a service port'''
            key = (self.srcIP, self.dstIP, self.dstPort, 
                   self.frType, self.proto)

        elif self.srcPort < self.dstPort:
            ''' Guess that srcPort is server '''
            key = (self.srcIP, self.dstIP, self.srcPort, 
                   self.frType, self.proto)
        else:
            ''' guess destination port is server'''
            key = (self.srcIP, self.dstIP, self.dstPort, 
                   self.frType, self.proto)

        ''' Check Baseline for previously observed key '''

        try:
            ''' if match found, snag the time entries and avg packet size'''
            value = self.b[key]
            avgPckSize = value[AVGPCKSIZE]
            timeList = [value[AM12], value[AM6], value[PM12], 
                        value[PM6], value[WKEND]]          
            newEntry = False
        except:
            ''' Then this is a new observation'''
            self.CreateAlertEntry(key, alertDict, "New Observation")
            newEntry = True

        chk, value = self.ouiOBJ.chkHotlist(self.dstMacOui)
        if chk:
            self.CreateAlertEntry(key, alertDict, "HotList: "+value)

        if self.isNewMAC(self.srcMac, baseMAC):
            self.CreateAlertEntry(key, alertDict, "New MAC Address: "+self.srcMac)

        if self.isNewMAC(self.dstMac, baseMAC):
            self.CreateAlertEntry(key, alertDict, "New MAC Address: "+self.dstMac)

        if self.isNewCC(self.srcCC, baseCC):
            self.CreateAlertEntry(key, alertDict, "New Country Code: "+self.srcCC)

        if self.isNewCC(self.dstCC, baseCC):
            self.CreateAlertEntry(key, alertDict, "New Country Code: "+self.dstCC)

        ''' If this is not a new entry check pckSize and Times'''
        if not newEntry:
            if self.isUnusualPckSize(self.packetSize, avgPckSize):
                self.CreateAlertEntry(key, alertDict, 
                                      "Unusual Packet Size")       

            if self.isUnusualTime(timeList):
                self.CreateAlertEntry(key, alertDict, 
                                      "Unusual Packet Time")    

    '''
    SENSOR CHECKS AND ALERT RECORDING
    '''
    
    def isUnusualPckSize(self, pSize, avgSize):
        if float(pSize) < float(avgSize*.70):
            return True
        if float(pSize) < float(avgSize*1.30):
            return True
        return False

    def isNewMAC(self, mac, b):
        if mac == 'Unknown' or mac == '':
            return False
        if not mac in b:
            return True
        else:
            return False

    def isNewCC(self,cc, b):
        if cc == 'Unknown' or cc == '':
            return False
        if not cc in b:
            return True
        else:
            return False

    def isUnusualTime(self, occList):

        occ = getOccurrenceValue()
        if occList[occ] == 0:
            return True
        else:
            return False

    
    def CreateAlertEntry(self, key, alertDict, alertType):
        try:
            ''' See if the alert already exists '''
            value = alertDict[key]
            ''' if yes, then bump the occurrence count'''
            cnt = value[1] + 1
            alertDict[key] = [alertType, cnt, self.lastObservationTime, 
                              self.packetSize, self.srcCC, self.dstCC, 
                              self.srcMac, self.dstMac, self.srcMFG, self.dstMFG, 
                              self.srcPort, self.dstPort, self.srcPortName, 
                              self.dstPortName ]
        except:
            ''' Othewise create a new alert entry'''
            alertDict[key] = [alertType, 1, self.lastObservationTime, 
                              self.packetSize, self.srcCC, self.dstCC, 
                              self.srcMac, self.dstMac, self.srcMFG, 
                              self.dstMFG,self.srcPort, self.dstPort, 
                              self.srcPortName, self.dstPortName ]


class Application(Frame):
    '''
    APPLICATION CLASS GUI FRAME USING Tkinter
    Establish the GUI Environment
    '''    
    def __init__(self, master=None):
        # Define the instance variables to be
        # collected from the GUI

        self.folderSelection = ''
        self.baselineSelection = ''

        self.baselineGood = False
        self.reportFolderGood = False
        self.abortFlag    = False
        
        self.macEnable = False
        self.macList = []
        self.MAC = BooleanVar()
        
        self.baselineCC = {}
        self.baselineMAC = {}

        # Create the basic frame
        Frame.__init__(self, master)
        self.parent = master

        #self.parent.resizable(0,0)

        # Intialize the GUI
        self.initUI()

    def initUI(self):

        # Create Menu Bar
        menuBar = Menu(self.parent)  # menu begin
        toolsMenu = Menu(menuBar, tearoff=0)

        toolsMenu.add_command(label='About', accelerator='Ctrl+A', 
                              command=self.menuAbout, underline=0)

        toolsMenu.add_separator()

        toolsMenu.add_command(label='Exit', accelerator='Ctrl+X', 
                              command=self.menuToolsExit)

        menuBar.add_cascade(label='Help', menu=toolsMenu, underline=0)   

        self.parent.config(menu=menuBar)  # menu ends

        self.bind_all("<Control-x>", self.menuToolsExit)
        self.bind_all("<Control-a>", self.menuAbout)

        # Report Folder Selection

        self.lblReport = Label(self.parent, anchor='w', text="Report Folder")
        self.lblReport.grid(row=1, column=0, padx=5, pady=10, sticky='w')

        self.ReportFolder = Label(self.parent, anchor='w', bd=3, 
                                  bg = 'white', fg='black',width=35, relief=SUNKEN)     
        self.ReportFolder.grid(row=1, column=1, padx=5, pady=0, sticky='w')

        self.buttonReportFolder = Button(self.parent, text=' ... ', 
                                         command=self.btnSelectFolder, width=5, 
                                         bg=BG, fg=FG , activebackground=AB, 
                                         activeforeground=AF)
        
        self.buttonReportFolder.grid(row=1, column=1, padx=315, pady=0, sticky='w')

        self.lblBaseline = Label(self.parent, anchor='w', text="Select Baseline")
        self.lblBaseline.grid(row=2, column=0, padx=5, pady=10, sticky='w')

        self.fileBaseline = Label(self.parent, anchor='w', bd=3, 
                                  bg = 'white', fg='black',width=35, relief=SUNKEN)     
        self.fileBaseline.grid(row=2, column=1, padx=5, pady=0, sticky='w')

        self.buttonSelectBaseline = Button(self.parent, text=' ... ', 
                                           command=self.btnSelectBaseLine, width=5, 
                                           bg=BG, fg=FG , activebackground=AB, 
                                           activeforeground=AF)
        
        self.buttonSelectBaseline.grid(row=2, column=1, padx=315, pady=0, sticky='w')      

        self.lblInclude = Label(self.parent, anchor='w', text="MAC Filter")
        self.lblInclude.grid(row=3, column=0, padx=5, pady=10, sticky='w')
    
        self.IncludeFile = Label(self.parent, anchor='w', bd=3, bg = 'white', 
                                 fg='black',width=35, relief=SUNKEN)  
        
        self.IncludeFile.grid(row=3, column=1, padx=5, pady=0, sticky='w')
    
        self.buttonIncludeFile= Button(self.parent, text=' ... ', 
                                       command=self.btnSelectFile, width=5, 
                                       bg=BG, fg=FG , activebackground=AB, 
                                       activeforeground=AF)
        
        self.buttonIncludeFile.grid(row=3, column=1, padx=315, pady=0, sticky='w')
        
        self.enableMAC = Checkbutton(self.parent, text="MAC Filter", 
                                     variable = self.MAC, onvalue = True, 
                                     offvalue = False)
        
        self.enableMAC.grid(row=4, column=0, sticky='w', padx=0, pady=5)        

        self.lbleth= Label(self.parent, anchor='w', text='Select NIC:')
        self.lbleth.grid(row=5, column=0, padx=5, pady=10, sticky='w')       

        self.ethPortSelection = StringVar()
        self.ethPort = ttk.Combobox(self.parent, 
                                    textvariable=self.ethPortSelection)

        try:
            nicList = os.listdir('/sys/class/net')
            nicTuple = tuple(nicList)          
        except: 
            nicStr = 'eth0'
            nicTuple= tuple(['eth0', 'wlan0'])
            
        self.ethPort['values'] = nicTuple
        self.ethPort.current(0)
        self.ethPort.grid(row=5, column=1, padx=5, pady=10, sticky='w')

        # Specify the Duration of the Scan
        self.lblDuration = Label(self.parent, anchor='w', text="Select Duration")
        self.lblDuration.grid(row=6, column=0, padx=5, pady=10, sticky='w')

        self.durationValue = StringVar()
        self.duration = ttk.Combobox(self.parent, textvariable=self.durationValue)
        self.duration['values'] = ('1-Min', '10-Min', '30-Min', 
                                   '1-Hr', '4-Hr', '8-Hr', '12-Hr', 
                                   '18-Hr', '1-Day', '2-Day', '4-Day', 
                                   '7-Day', '2-Week', '4-Week')
        
        self.duration.current(0)
        self.duration.grid(row=6, column=1, padx=5, pady=10, sticky='w')

        # Capture Packet Button

        self.ActivateSensor = Button(self.parent, text='Activate Sensor', 
                                     command=self.btnActivateSensor, 
                                     bg=BG, fg=FG , activebackground=AB, 
                                     activeforeground=AF)
        
        self.ActivateSensor.grid(row=7, column=1, padx=5, pady=5, sticky='w')
        self.ActivateSensor['state']=DISABLED

        self.CapturePackets = Button(self.parent, text='Record Baseline', 
                                     command=self.btnPerformCapture, 
                                     bg=BG, fg=FG , activebackground=AB, 
                                     activeforeground=AF)
        
        self.CapturePackets.grid(row=7, column=1, padx=130, pady=5, sticky='w')
        self.CapturePackets['state']=DISABLED

        self.StopCapture = Button(self.parent, text='STOP',
                                  command=self.btnSTOPCapture,
                                  bg=BG, fg=FG , activebackground=AB, 
                                  activeforeground=AF)
        
        self.StopCapture.grid(row=8, column=1, padx=5, pady=5, sticky='w')
        self.StopCapture['state']=DISABLED        

        self.ViewAlerts = Button(self.parent, text='View Alerts', 
                                 command=self.btnViewAlerts, 
                                 bg=BG, fg=FG , activebackground=AB, 
                                 activeforeground=AF)
        
        self.ViewAlerts.grid(row=8, column=1, padx=120, pady=5, sticky='w')
        self.ViewAlerts['state']=DISABLED           

        # SETUP a Progress Bar

        self.progressLabel = Label(self.parent, anchor='w', text="Progress")
        self.progressLabel.grid(row=9, column=0, padx=0, pady=10, sticky='e')

        self.progressBar = ttk.Progressbar(self.parent, 
                                           orient='horizontal', length=345, mode='determinate')
        self.progressBar.grid(row=9, column=1, padx=5, pady=10, sticky='w')

        # Setup Report Buttons

        # Report Setup      

        self.ReportSelection = StringVar()
        self.report = ttk.Combobox(self.parent, textvariable=self.ReportSelection)
        self.report['values'] = ('Master Report', 'MFG Report', 
                                 'Country Report', 'Port Usage Report', 
                                 'ICS Report', 'IoT Report')
        
        self.report.current(0)
        self.report.grid(row=5, column=1, padx=200, pady=10, sticky='w')

        # View Report
        self.viewReport = Button(self.parent, text='View Selected Report', 
                                 command=self.btnViewSelectedReport, 
                                 bg=BG, fg=FG , activebackground=AB, 
                                 activeforeground=AF)
        
        self.viewReport.grid(row=6, column=1, padx=200, pady=5, sticky=W)
        self.viewReport['state']=DISABLED

        # Status Message
    
        self.statusLabel = Label(self.parent, anchor='w', text="Status")
        self.statusLabel.grid(row=10, column=0, padx=0, pady=10, sticky='e')

        self.statusText = Label(self.parent, anchor='w', 
                                width=42, bd=3, 
                                bg = 'white', fg='black', 
                                relief=SUNKEN)     
        
        self.statusText.grid(row=10, column=1, padx=5, pady=5, sticky='w')
        self.update()

        ''' Attempt to Load Lookup Dictionaries'''
        try:
            with open("lookup.db",'rb') as fp:
                self.lookupList = pickle.load(fp)
                self.statusText['text'] = "Waiting... Select Report Folder and/or Baseline"
                self.update()                
        except:
            self.statusText['text'] = "Failed to Load Lookup Data ... Aborting"
            self.update()  
            LogEvent(LOG_WARN, "Program Exit via Failed to Load Lookup.db")
            time.sleep(5)
            self.parent.destroy()            

        self.update()        

    '''
    ALL Button and EVENT HANDLERS
    Code Area
    '''

    def btnSelectFile(self):
        self.fileSelection = tkFileDialog.askopenfilename(initialdir = "./",
                            title = "Select Include MAC Address List File")
        
        self.IncludeFile['text'] = self.fileSelection
        if self.fileSelection:
            self.macList = []
            self.macEnable = True
            with open(self.fileSelection) as ips:
                for eachLine in ips:
                    self.macList.append(eachLine.strip())
        else:
            self.macEnable = False
            
        self.update()
        
    # Handle Folder Browse Button Click

    def btnSelectFolder(self):
        try:
            self.folderSelection = tkFileDialog.askdirectory(initialdir="./",  
                                        title='Select Report Folder')  
            
            self.ReportFolder['text'] = self.folderSelection
            if os.path.isdir(self.folderSelection)\
                and os.access(self.folderSelection, os.W_OK):
                    
                self.reportFolderGood = True
                self.statusText['text'] = "Report Folder Selected"
                self.update()                

                ''' Ok to enable Record Baseline Button '''
                self.CapturePackets['state']=NORMAL
                if self.baselineGood:
                    self.ActivateSensor['state']=NORMAL
            else:
                self.reportFolderGood = False
                self.statusText['text'] = "Invalid Folder Selection ... Folder must exist and be writable"
                self.update()                

        except Exception as err:
            self.reportFolderGood = False

        self.update()

    def btnSelectBaseLine(self):
        self.fileSelection = tkFileDialog.askopenfilename(initialdir="./",  
                                    title='Select Baseline File')  
        self.fileBaseline['text'] = self.fileSelection

        if self.fileBaseline:
            try:
                with open(self.fileSelection, 'rb') as base:

                    try:
                        ''' Make sure we loaded a dictionary '''
                        self.baselineDictionary = pickle.load(base)    

                        ''' Make sure the elements match our structure'''
                        if type(self.baselineDictionary) is dict:
                            value = self.baselineDictionary.values()[0] 
                            if value[POV] == 'S' or value[POV] == 'D':
                                self.baselineGood = True
                            else:
                                self.baselineGood = False
                                self.statusText['text'] = "Baseline Load Failed"

                            if self.baselineGood:
                                ''' Create Quick Lookups for Country, MFG'''
                                self.statusText['text'] = "Loading Baseline Contents"
                                self.update()

                                for key, value in self.baselineDictionary.iteritems():
                                    try: 
                                        srcCC = value[SRCCC]
                                        dstCC = value[DSTCC]
                                        srcMAC = value[SRCMAC]
                                        dstMAC = value[DSTMAC]

                                        if srcCC != '' and srcCC.lower() != 'unknown':
                                            self.baselineCC[srcCC] = 1
                                        if dstCC != '' and dstCC.lower() != 'unknown':
                                            self.baselineCC[dstCC] = 1

                                        if srcMAC != '' and srcMAC.lower() != 'unknown':
                                            self.baselineMAC[srcMAC] = 1
                                        if dstMAC != '' and dstMAC.lower() != 'unknown':
                                            self.baselineMAC[dstMAC] = 1                                            
                                    except:
                                        ''' ignore errors in baseline loading'''
                                        continue

                                self.statusText['text'] = "Loading Baseline Completed"

                                ''' Ok to enable Activate Sensor Button '''
                                if self.reportFolderGood:
                                    self.ActivateSensor['state']=NORMAL    

                    except Exception as err:
                        self.statusText['text'] = "Baseline Load Failed"

            except Exception as err:
                self.statusText['text'] = "Baseline Load Failed: "+str(err)

        self.update()        

    def btnViewSelectedReport(self):

        reportName = self.report.get()

        if reportName == 'Master Report': 
            try:
                webbrowser.get(using='epiphany').open(self.MasterHTML)
            except Exception as err:
                self.statusText['text'] = "Cannot launch local web-browser "
                self.update()

        elif reportName == 'Country Report': 
            try:
                webbrowser.get(using='epiphany').open(self.CountryHTML)
            except:
                self.statusText['text'] = "Cannot launch local web-browser "              
                self.update()

        elif reportName == 'MFG Report': 
            try:
                webbrowser.get(using='epiphany').open(self.mfgHTML)
            except:
                self.statusText['text'] = "Cannot launch local web-browser "        
                self.update()
        elif reportName == 'ICS Report':
            try:
                webbrowser.get(using='epiphany').open(self.icsHTML)                
            except:
                self.statusText['text'] = "Cannot launch local web-browser "      
                self.update()
        elif reportName == 'IoT Report': 
            try:
                webbrowser.get(using='epiphany').open(self.iotHTML)
            except:
                self.statusText['text'] = "Cannot launch local web-browser "         
                self.update()
        elif reportName == 'Port Usage Report': 
            try:
                webbrowser.get(using='epiphany').open(self.portUsageHTML)
            except:
                self.statusText['text'] = "Cannot launch local web-browser "                         
                self.update()                

    def btnViewAlerts(self):

        # Handle View Alerts Button Click
        self.statusText['text'] = "Launching Alerts Report ... "
        self.update()  
        try:
            webbrowser.get(using='epiphany').open(self.alertsHTML)            
        except:
            self.statusText['text'] = "Cannot launch local web-browser "   
            
    def progressBarInit(self):
        
        durationValue = self.duration.get()
        self.durSec = CONVERT[durationValue]
        
        self.startEpoch = time.time()
        
        self.progressBar['value'] = 0    
        self.curProgress = 0
        
    def progressBarUpdate(self):
        
        ''' Update the Progress Bar on Change vs Total Time 
            return True if progress >= 100 %  else return False
        '''
        instant = time.time()
        elapsedTime = instant - self.startEpoch
        
        newProgress = int(round((elapsedTime/self.durSec * 100)))
        if newProgress > self.curProgress:
            self.progressBar['value'] = newProgress
            self.curProgress = newProgress 
            cntStr = '{:,}'.format(self.pkCnt)
            self.statusText['text'] = "Pck Cnt: " + cntStr                   
            self.update()      
            
        if self.curProgress >= 100:
            return True
        else:
            return False
            
    def progressBarReset(self):
        self.progressBar['value'] = 0    
        self.curProgress = 0
        self.update()

    def captureSetup(self):
        
        ''' Setup for a packet capture 
            used for both recording and sensor modes
        '''
        # create a packet processing object
        self.statusText['text'] = "Loading Lookups ..."
        self.update()
    
        MAC_V = self.MAC.get()
    
        try:
            if  self.baselineDictionary:
                pass
        except:
            self.baselineDictionary = {}
            
        self.packetObj = PacketProcessor(self.lookupList, self.macList, 
                                             self.macEnable, MAC_V, 
                                self.baselineDictionary)         
    
        self.statusText['text'] = "Monitoring Packets ..."
        self.update()
    
        self.alertDict = {}
    
        # Python Packet Capture
        # configure the eth0 in promiscous mode
    
        try:
    
            nic = self.ethPort.get()
    
            ret = os.system("ifconfig "+ nic + ' promisc')
    
            if ret == 0:
                LogEvent(LOG_INFO, 'Promiscious Mode Enabled on NIC: '+nic)             
    
                # create a new socket using the python socket module
                # PF_PACKET     : Specifies Protocol Family Packet Level
                # SOCK_RAW      : Specifies A raw protocol at the network layer
                # htons(0x0003) : Specifies all headers and packets
                #               : Ethernet and IP, including TCP/UDP etc
    
                # attempt to open the socket for capturing raw packets
    
                self.rawSocket=socket.socket(socket.PF_PACKET,
                                            socket.SOCK_RAW,socket.htons(0x0003))    
                
                return True
    
            else:
                self.statusText['text'] = "Failed ... Cannot Open Socket on NIC: " + nic
                self.progressBar['value'] = 0                 
                self.update()   
                self.CapturePackets['state']=NORMAL
                self.StopCapture['state']=DISABLED
                self.update()                
                return False
    
        except Exception as err:
            self.statusText['text'] = "Socket Exception ... "+str(err)
            self.progressBar['value'] = 0 
            self.CapturePackets['state']=NORMAL
            self.StopCapture['state']=DISABLED            
            self.update()  
    
            return False
        
    def btnActivateSensor(self):
        
        # Handle Active Sensor Button Click

        self.ActivateSensor['state']=DISABLED
        saveCaptureState = self.CapturePackets['state']
        self.CapturePackets['state']=DISABLED
        self.StopCapture['state']=NORMAL
        self.update()        

        self.progressBarInit()
        
        if not self.captureSetup():         # Setup network interface for capture
            return
        
        self.pkCnt = 0

        while True:

            if self.abortFlag:

                ''' User Aborted '''
                ''' Reset the Flag for next use '''
                self.abortFlag = False
                self.progressBarReset()
                break
            
            # Update the Progress Bar and check for 100%
            if self.progressBarUpdate():
                self.progressBarReset()
                break

            try:
                recvPacket=self.rawSocket.recv(65535)
                self.pkCnt += 1
                self.packetObj.PacketSENSOR(recvPacket, self.alertDict, 
                                                         self.baselineCC, self.baselineMAC)                
                
            except Exception as err:
                LogEvent(LOG_INFO,'Recv Packet Failed: '+str(err))
                continue

        # Generate Sensor Reports
        self.statusText['text'] = "Generating Alert Reports Please Wait ..."
        self.update()              

        self.GenAlerts(self.alertDict)

        ''' Enable Report Button '''    
        self.ViewAlerts['state']=NORMAL

        ''' Reset Progress Bar and Post Completed status'''
        self.progressBar['value'] = 0

        cntStr = '{:,}'.format(self.pkCnt)
        
        alertsGenerated = '{:,}'.format(len(self.alertDict))
        
        self.statusText['text'] = "Done:  Total Connections Processed: "\
             +cntStr+"  Alerts: "+alertsGenerated   

        self.CapturePackets['state'] = saveCaptureState
        self.ActivateSensor['state']=NORMAL
        self.StopCapture['state']=DISABLED
        self.update()

    def btnPerformCapture(self):

        self.CapturePackets['state']=DISABLED
        saveActivateSensor = self.ActivateSensor['state']
        self.ActivateSensor['state']=DISABLED
        self.StopCapture['state']=NORMAL
        self.update()
                
        self.pkCnt = 0
        self.progressBarInit()
        
        if not self.captureSetup():         # Setup network interface for capture
            return        

        while True:

            if self.abortFlag:

                ''' User Aborted '''
                ''' Reset the Flag for next use '''
                self.abortFlag = False
                self.progressBarReset()
                break
            
            # Update the Progress Bar and check for 100%

            if self.progressBarUpdate():
                self.progressBarReset()
                break

            try:
                recvPacket=self.rawSocket.recv(65535)
                self.pkCnt += 1
                self.packetObj.PacketRECORD(recvPacket)
                self.progressBarUpdate()
                
            except Exception as err:
                LogEvent(LOG_INFO,'Recv Packet Failed: '+str(err))
                continue
        
        self.statusText['text'] = "Generating Capture Reports and Saving Baseline Please Wait ..."
        self.update()              

        # Generate Reports and Save the Baseline

        self.SaveOb(self.packetObj.d)
        self.GenCSV(self.packetObj.d)
        self.GenHTML(self.packetObj.d)
        self.GenCOUNTRY(self.packetObj.d)
        self.GenMFG(self.packetObj.d) 
        self.GenICS(self.packetObj.d)
        self.GenIOT(self.packetObj.d)
        self.GenPortUsage(self.packetObj.d)

        ''' Enable Report Button '''    
        self.viewReport['state']=NORMAL
    
        cntStr = '{:,}'.format(self.pkCnt)
        unique = '{:,}'.format(len(self.packetObj.d))   
        
        self.statusText['text'] = "Observed: " +cntStr+" Unique: "+unique
        
        self.CapturePackets['state']=NORMAL

        # reset the ActivateSensor State
        self.ActivateSensor['state']=saveActivateSensor

        self.StopCapture['state']=DISABLED        
        self.update()           

    def SaveOb(self, d):
        ''' Save the current observation dictionary to a the specified path '''
        try:
            path = self.ReportFolder['text']
            baseDir = os.path.join(path,'baselines')
            if not os.path.isdir(baseDir):
                os.mkdir(baseDir)

            self.statusText['text'] = "Generating Serialized Baseline ..."
            self.update()           

            utc=datetime.datetime.utcnow()
            yr = str(utc.year)
            mt = '{:02d}'.format(utc.month)
            dy = '{:02d}'.format(utc.day)
            hr = '{:02d}'.format(utc.hour)
            mn = '{:02d}'.format(utc.minute)

            filename = yr+'-'+mt+'-'+dy+'--'+hr+'-'+mn+".baseline"
            outFile = os.path.join(baseDir, filename)
            with open(outFile, 'wb') as fp:
                pickle.dump(d, fp)    

        except Exception as err:
            LogEvent(LOG_ERR, "Failed to Create Baseline Output"+str(err))

    def GenCSV(self, d):
        ''' Sort the results of the master report as a CSV File'''
        path = self.ReportFolder['text']

        self.statusText['text'] = "Generating CSV Baseline ..."
        self.update()    

        utc=datetime.datetime.utcnow()
        yr = str(utc.year)
        mt = '{:02d}'.format(utc.month)
        dy = '{:02d}'.format(utc.day)
        hr = '{:02d}'.format(utc.hour)
        mn = '{:02d}'.format(utc.minute)

        filename = "Report_"+yr+mt+dy+hr+mn+".csv"        
        outFile = os.path.join(path, filename)

        with open(outFile, 'w') as csv:
            hdr = '''
            Alert,
            SRC-MAC,
            DST-MAC,
            SRC-IP,
            DST-IP,
            FRAME-TYPE,
            PROTOCOL,
            SRC-PORT,
            SRC-PORT-NAME,
            DST-PORT,
            DST-PORT-NAME,
            SRC-MFG,
            DST-MFG,
            SRC-CC,
            DST-CC,
            AVG-PKT,
            PRE-DAWN,
            MORNING,
            AFTERNOON,
            EVENING,
            WEEKEND
            '''
            hdr = hdr.replace('\n','')
            hdr = hdr+'\n'

            csv.write(hdr)

            for eachKey in d:
                value = d[eachKey]
                ''' Build Row Entry by Entry to Match Heading Above'''
                row = ''
                row = row + value[ALERT]+','
                row = row + value[SRCMAC]+','
                row = row + value[DSTMAC]+','
                row = row + eachKey[SRCIP]+','
                row = row + eachKey[DSTIP]+','                
                row = row + eachKey[FRAMETYPE]+','
                row = row + eachKey[PROTOCOL]+','
                row = row + str(value[SRCPORT])+','
                row = row + value[SRCPORTNAME]+','
                row = row + str(value[DSTPORT])+','
                row = row + value[DSTPORTNAME]+','                
                row = row + value[SRCMFG]+','
                row = row + value[DSTMFG]+','
                row = row + value[SRCCC]+','
                row = row + value[DSTCC]+','
                row = row + str(value[AVGPCKSIZE])+','
                row = row + str(value[AM12])+','
                row = row + str(value[AM6])+','
                row = row + str(value[PM12])+','
                row = row + str(value[PM6])+','
                row = row + str(value[WKEND])+'\n'

                csv.write(row)

    def GenHTML(self, d):

        ''' Produce all HTML Report using the master dictionary provided'''

        path = self.ReportFolder['text']

        utc=datetime.datetime.utcnow()
        yr = str(utc.year)
        mt = '{:02d}'.format(utc.month)
        dy = '{:02d}'.format(utc.day)
        hr = '{:02d}'.format(utc.hour)
        mn = '{:02d}'.format(utc.minute)

        ''' Produce Master HTML Report'''
        self.statusText['text'] = "Generating Master HTML Report ..."+\
             yr+'-'+mt+'-'+dy+'-'+hr+'-'+mn+"-Master.html"
        self.update()             

        filename = yr+'-'+mt+'-'+dy+'-'+hr+'-'+mn+"-Master.html"
        self.MasterHTML = os.path.join(path, filename)

        htmlContents = ''
        htmlHeader = rpt.HTML_START

        fldDate = yr+'-'+mt+'-'+dy+'@'+hr+':'+mn+" UTC"
        htmlHeader = htmlHeader.format(**locals())   
        htmlContents = htmlContents + htmlHeader

        for eachKey in d:
            htmlSection = rpt.HTML_BODY
            value = d[eachKey]
            fldAlert      = value[ALERT]
            fldSrcIP      = eachKey[SRCIP]
            fldDstIP      = eachKey[DSTIP]
            fldFrame      = eachKey[FRAMETYPE]
            fldProtocol   = eachKey[PROTOCOL]

            fldSrcPort    = value[SRCPORT]      
            fldSrcPortName= value[SRCPORTNAME]
            fldDstPort    = value[DSTPORT]      
            fldDstPortName= value[DSTPORTNAME]  
            fldSrcMAC     = value[SRCMAC]
            fldDstMAC     = value[DSTMAC]            
            fldSrcMFG     = value[SRCMFG]
            fldDstMFG     = value[DSTMFG]
            fldSrcCC      = value[SRCCC]
            fldDstCC      = value[DSTCC]
            fldPktSize    = value[AVGPCKSIZE]
            fldTwilight   = value[AM12]     
            fldMorning    = value[AM6]
            fldAfternoon  = value[PM12]
            fldEvening    = value[PM6]
            fldWeekend    = value[WKEND]
            fldTotal      = value[AM12]+value[AM6]+value[PM12]\
                                 +value[PM6]+value[WKEND]

            htmlSection = htmlSection.format(**locals())
            htmlContents = htmlContents + htmlSection

        htmlContents = htmlContents + rpt.HTML_END

        ''' Write the Report to the output file'''
        output = open(self.MasterHTML,"w")
        output.write(htmlContents)
        output.close()

    def GenCOUNTRY(self, d):

        ''' Produce all HTML Report using the master dictionary provided'''

        path = self.ReportFolder['text']

        utc=datetime.datetime.utcnow()
        yr = str(utc.year)
        mt = '{:02d}'.format(utc.month)
        dy = '{:02d}'.format(utc.day)
        hr = '{:02d}'.format(utc.hour)
        mn = '{:02d}'.format(utc.minute)

        ''' Produce Master HTML Report'''
        self.statusText['text'] = "Generating Country HTML Report ..."\
                                    +yr+'-'+mt+'-'+dy+'-'+hr+'-'\
                                    +mn+"-Country.html"
        self.update()             

        filename = yr+'-'+mt+'-'+dy+'-'+hr+'-'+mn+"-Country.html"
        self.CountryHTML = os.path.join(path, filename)

        countryDict = {}

        for eachKey in d:

            value = d[eachKey]

            fldSrcCountry = value[SRCCC]
            fldDstCountry = value[DSTCC]
            fldHits       = value[AM12]+value[AM6]+value[PM12]\
                                 +value[PM6]+value[WKEND]

            if fldSrcCountry != 'Unknown':
                try:
                    v = countryDict[fldSrcCountry]
                    totHits = v + fldHits
                    countryDict[fldSrcCountry] = totHits
                except:
                    countryDict[fldSrcCountry] = fldHits

                if fldDstCountry != 'Unknown':
                    try:
                        v = countryDict[fldDstCountry]
                        totHits = v + fldHits
                        countryDict[fldDstCountry] = totHits
                    except:
                        countryDict[fldDstCountry] = fldHits 

        countryList = []
        for key in countryDict:
            v = countryDict[key]
            countryList.append([key, v])

        countryList.sort()

        htmlContents = ''
        htmlHeader = rpt.CHTML_START

        fldDate = yr+'-'+mt+'-'+dy+'@'+hr+':'+mn+" UTC"
        htmlHeader = htmlHeader.format(**locals())   
        htmlContents = htmlContents + htmlHeader           

        for eachEntry in countryList:

            htmlSection = rpt.CHTML_BODY

            fldCountry    = eachEntry[0]
            fldHits       = eachEntry[1]

            htmlSection = htmlSection.format(**locals())
            htmlContents = htmlContents + htmlSection

        htmlContents = htmlContents + rpt.HTML_END

        ''' Write the Report to the output file'''
        output = open(self.CountryHTML,"w")
        output.write(htmlContents)
        output.close()

    def GenICS(self, d):

        ''' Produce all HTML Report using the master dictionary provided'''

        path = self.ReportFolder['text']

        utc=datetime.datetime.utcnow()
        yr = str(utc.year)
        mt = '{:02d}'.format(utc.month)
        dy = '{:02d}'.format(utc.day)
        hr = '{:02d}'.format(utc.hour)
        mn = '{:02d}'.format(utc.minute)

        ''' Produce Master HTML Report'''
        self.statusText['text'] = "Generating ICS HTML Report ..."\
                                      +yr+'-'+mt+'-'+dy+'-'+hr+'-'\
                                      +mn+"-ICS.html"
        self.update()             

        filename = yr+'-'+mt+'-'+dy+'-'+hr+'-'+mn+"-ICS.html"
        self.icsHTML = os.path.join(path, filename)

        icsList = []

        for eachKey in d:
            value = d[eachKey]

            if value[POV] == 'S':
                if str(eachKey[PORTNUM]) not in ICS_LOOKUP:
                    continue
                fldIP  = value[SRCIP]
                fldMAC = value[SRCMAC]
                fldPort= value[SRCPORT]
                fldPortName = value[SRCPORTNAME]
            else:
                if str(eachKey[PORTNUM]) not in ICS_LOOKUP:
                    continue
                fldIP      = value[DSTIP]
                fldMAC     = value[DSTMAC]
                fldPort    = value[DSTPORT]
                fldPortName = value[DSTPORTNAME]

            fldPOV        = value[POV]
            fldSrcMFG     = value[SRCMFG] 
            fldDstMFG     = value[DSTMFG]  
            fldHits       = value[AM12]+value[AM6]+value[PM12]+value[PM6]+value[WKEND]

            icsList.append([fldPOV, fldPort, fldPortName, fldMAC, 
                            fldSrcMFG, fldDstMFG, fldIP, fldHits])

        icsList.sort()

        htmlContents = ''
        htmlHeader = rpt.IHTML_START

        fldDate = yr+'-'+mt+'-'+dy+'@'+hr+':'+mn+" UTC"
        htmlHeader = htmlHeader.format(**locals())   
        htmlContents = htmlContents + htmlHeader           

        for eachEntry in icsList:

            htmlSection = rpt.IHTML_BODY

            fldPOV        = eachEntry[0]
            fldPort       = eachEntry[1]
            fldPortName   = eachEntry[2]
            fldMAC        = eachEntry[3]      
            fldSrcMFG     = eachEntry[4]
            fldDstMFG     = eachEntry[5]
            fldIP         = eachEntry[6]
            fldHits       = eachEntry[7]

            htmlSection = htmlSection.format(**locals())
            htmlContents = htmlContents + htmlSection

        htmlContents = htmlContents + rpt.HTML_END

        ''' Write the Report to the output file'''
        output = open(self.icsHTML,"w")
        output.write(htmlContents)
        output.close()

    def GenIOT(self, d):

        ''' Produce all HTML Report using the master dictionary provided'''

        path = self.ReportFolder['text']

        utc=datetime.datetime.utcnow()
        yr = str(utc.year)
        mt = '{:02d}'.format(utc.month)
        dy = '{:02d}'.format(utc.day)
        hr = '{:02d}'.format(utc.hour)
        mn = '{:02d}'.format(utc.minute)

        ''' Produce Master HTML Report'''
        self.statusText['text'] = "Generating IOT HTML Report ..."\
                                      +yr+'-'+mt+'-'+dy+'-'+hr+'-'\
                                      +mn+"-IOT.html"
        self.update()             

        filename = yr+'-'+mt+'-'+dy+'-'+hr+'-'+mn+"-IOT.html"
        self.iotHTML = os.path.join(path, filename)

        iotList = []

        for eachKey in d:
            value = d[eachKey]
            if str(eachKey[PORTNUM]) not in IOT_LOOKUP:
                continue
            fldSrcIP      = eachKey[SRCIP]
            fldDstIP      = eachKey[DSTIP]
            fldSrcMAC     = value[SRCMAC]
            fldDstMAC     = value[DSTMAC]
            fldSrcPort    = value[SRCPORT]   
            fldDstPort    = value[DSTPORT]
            fldSrcMFG     = value[SRCMFG]   
            fldDstMFG     = value[DSTMFG]
            fldSrcPortName   = value[SRCPORTNAME]
            fldDstPortName   = value[DSTPORTNAME]
            fldHits       = value[AM12]+value[AM6]+value[PM12]\
                              +value[PM6]+value[WKEND]

            iotList.append([fldSrcPort, fldSrcPortName, fldDstPort, fldDstPortName, 
                            fldSrcMAC, fldDstMAC, fldSrcMFG, fldDstMFG, 
                            fldSrcIP, fldDstIP, fldHits])

        iotList.sort()

        htmlContents = ''
        htmlHeader = rpt.THTML_START

        fldDate = yr+'-'+mt+'-'+dy+'@'+hr+':'+mn+" UTC"
        htmlHeader = htmlHeader.format(**locals())   
        htmlContents = htmlContents + htmlHeader           

        for eachEntry in iotList:

            htmlSection = rpt.THTML_BODY

            fldSrcPort    = eachEntry[0]
            fldSrcPortName= eachEntry[1]
            fldDstPort    = eachEntry[2]
            fldDstPortName   = eachEntry[3]
            fldSrcMAC     = eachEntry[4]   
            fldDstMAC     = eachEntry[5]
            fldSrcMFG     = eachEntry[6]
            fldDstMFG     = eachEntry[7]
            fldSrcIP      = eachEntry[8]
            fldDstIP      = eachEntry[9]
            fldHits       = eachEntry[10]

            htmlSection = htmlSection.format(**locals())
            htmlContents = htmlContents + htmlSection

        htmlContents = htmlContents + rpt.HTML_END

        ''' Write the Report to the output file'''
        output = open(self.iotHTML,"w")
        output.write(htmlContents)
        output.close()


    def GenMFG(self, d):

        ''' Produce all HTML Report using the master dictionary provided'''

        path = self.ReportFolder['text']

        utc=datetime.datetime.utcnow()
        yr = str(utc.year)
        mt = '{:02d}'.format(utc.month)
        dy = '{:02d}'.format(utc.day)
        hr = '{:02d}'.format(utc.hour)
        mn = '{:02d}'.format(utc.minute)

        ''' Produce Master HTML Report'''
        self.statusText['text'] = "Generating MFG HTML Report ..."\
                                     +yr+'-'+mt+'-'+dy+'-'+hr+'-'\
                                     +mn+"-ICS.html"
        self.update()             

        filename = yr+'-'+mt+'-'+dy+'-'+hr+'-'+mn+"-MFG.html"
        self.mfgHTML = os.path.join(path, filename)

        mfgList = []

        for eachKey in d:
            value = d[eachKey]

            fldSrcIP = eachKey[SRCIP]
            fldDstIP = eachKey[DSTIP]
            fldSrcMAC = value[SRCMAC]
            fldDstMAC = value[DSTMAC]
            fldSrcMFG = value[SRCMFG]
            fldDstMFG = value[DSTMFG]

            if fldSrcMFG != 'Unknown':
                mfgList.append((fldSrcMFG, fldSrcMAC, fldSrcIP))
            if fldDstMFG != 'Unknown':
                mfgList.append((fldDstMFG, fldDstMAC, fldDstIP))        

        mfgSet  = set(mfgList)
        mfgList = list(mfgSet)
        mfgList.sort()

        htmlContents = ''
        htmlHeader = rpt.MHTML_START

        fldDate = yr+'-'+mt+'-'+dy+'@'+hr+':'+mn+" UTC"
        htmlHeader = htmlHeader.format(**locals())   
        htmlContents = htmlContents + htmlHeader           

        for eachEntry in mfgList:

            htmlSection = rpt.MHTML_BODY

            fldMFG        = eachEntry[0]
            fldMAC        = eachEntry[1]      
            fldIP         = eachEntry[2]

            htmlSection = htmlSection.format(**locals())
            htmlContents = htmlContents + htmlSection

        htmlContents = htmlContents + rpt.HTML_END

        ''' Write the Report to the output file'''
        output = open(self.mfgHTML,"w")
        output.write(htmlContents)
        output.close()

    def GenPortUsage(self, d):

        ''' Produce all HTML Report using the master dictionary provided'''

        path = self.ReportFolder['text']

        utc=datetime.datetime.utcnow()
        yr = str(utc.year)
        mt = '{:02d}'.format(utc.month)
        dy = '{:02d}'.format(utc.day)
        hr = '{:02d}'.format(utc.hour)
        mn = '{:02d}'.format(utc.minute)

        ''' Produce Master HTML Report'''
        self.statusText['text'] = "Generating Port Usage HTML Report ..."\
                                      +yr+'-'+mt+'-'+dy+'-'+hr+'-'\
                                      +mn+"-PortUsage.html"
        self.update()             

        filename = yr+'-'+mt+'-'+dy+'-'+hr+'-'+mn+"-PortUsage.html"
        self.portUsageHTML = os.path.join(path, filename)

        portList = []

        for eachKey in d:
            value = d[eachKey]

            if eachKey[PORTNUM] == 'ARP' or eachKey[PORTNUM] == '':
                continue
            fldSrcIP      = eachKey[SRCIP]
            fldDstIP      = eachKey[DSTIP]
            fldPort       = eachKey[PORTNUM]
            fldFrame      = eachKey[FRAMETYPE]
            fldPortocol   = eachKey[PROTOCOL]
            if value[POV] == 'S':
                fldPortName   = value[SRCPORTNAME]
            else:
                fldPortName   = value[DSTPORTNAME]
            fldSrcMAC     = value[SRCMAC]
            fldDstMAC     = value[DSTMAC]
            fldSrcCountry = value[SRCCC]
            fldDstCountry = value[DSTCC]           
            fldSrcPort    = value[SRCPORT]      
            fldSrcPortName   = value[SRCPORTNAME]  
            fldDstPort    = value[DSTPORT]      
            fldDstPortName   = value[DSTPORTNAME]              
            fldSrcMFG     = value[SRCMFG]
            fldDstMFG     = value[DSTMFG]

            portList.append((fldPort, fldPortName, fldSrcIP, 
                               fldDstIP, fldFrame, fldPortocol))

        portSet = set(portList)
        portList = list(portSet)
        portList.sort()

        htmlContents = ''
        htmlHeader = rpt.PHTML_START

        fldDate = yr+'-'+mt+'-'+dy+'@'+hr+':'+mn+" UTC"
        htmlHeader = htmlHeader.format(**locals())   
        htmlContents = htmlContents + htmlHeader           

        for eachEntry in portList:

            htmlSection = rpt.PHTML_BODY

            fldPort       = eachEntry[0]
            fldPortName   = eachEntry[1]
            fldSrcIP      = eachEntry[2]      
            fldDstIP      = eachEntry[3]
            fldFrame      = eachEntry[4]
            fldProtocol   = eachEntry[5]

            htmlSection = htmlSection.format(**locals())
            htmlContents = htmlContents + htmlSection

        htmlContents = htmlContents + rpt.HTML_END

        ''' Write the Report to the output file'''
        output = open(self.portUsageHTML,"w")
        output.write(htmlContents)
        output.close()

    def translateAlertCodes(self, alerts):

        transList = []
        for eachAlert in alerts:
            if eachAlert == 'New':
                transList.append("New Connection Observation")
            elif eachAlert == "SCC":
                transList.append("New Src Country")
            elif eachAlert == "DCC":
                transList.append("New Dst Country")
            elif eachAlert == "SMAC":
                transList.append("New Src MAC Address")
            elif eachAlert == "DMAC":
                transList.append("New Dst MAC Address")  
            elif eachAlert == "Time":
                transList.append("Unusual Packet Time")   
            elif eachAlert == "PckSize":
                transList.append("Unusual Packet Size")    
            else:
                continue
        return transList


    def GenAlerts(self, d):

        utc=datetime.datetime.utcnow()
        yr = str(utc.year)
        mt = '{:02d}'.format(utc.month)
        dy = '{:02d}'.format(utc.day)
        hr = '{:02d}'.format(utc.hour)
        mn = '{:02d}'.format(utc.minute)

        path = self.ReportFolder['text']

        filename = yr+'-'+mt+'-'+dy+'-'+hr+'-'+mn+"-Alerts.html"

        if not os.path.isdir(os.path.join(path, 'Alerts')):
            os.mkdir(os.path.join(path, 'Alerts'))

        alertPath = os.path.join(path,'Alerts')
        self.alertsHTML = os.path.join(alertPath, filename)        

        ''' Produce Alerts HTML Report'''
        self.statusText['text'] = "Generating Alerts HTML Report ..."\
                                   +yr+'-'+mt+'-'+dy+'-'+hr\
                                   +'-'+mn+"-Alerts.html"
        self.update()             

        htmlContents = ''
        htmlHeader = rpt.AHTML_START

        fldDate = yr+'-'+mt+'-'+dy+'@'+hr+':'+mn+" UTC"
        htmlHeader = htmlHeader.format(**locals())   
        htmlContents = htmlContents + htmlHeader           

        for key in d:
            value = d[key]

            htmlSection = rpt.AHTML_BODY

            fldSrcIP     = key[0]
            fldDstIP     = key[1]
            fldFrameType = key[3]
            fldProtocol  = key[4]

            fldAlert     = value[0]
            fldAlertCnt  = value[1]
            fldTimeStamp = value[2]
            fldSrcCC     = value[4]
            fldDstCC     = value[5]
            if fldSrcCC == '':
                fldSrcCC = 'NA'
            if fldDstCC == '':
                fldDstCC = 'NA'
            fldSrcMAC    = value[6]
            fldDstMAC    = value[7]
            if fldSrcMAC == '':
                fldSrcMAC = 'NA'
            if fldDstMAC == '':
                fldDstMAC = 'NA'            
            fldSrcMFG    = value[8]
            fldDstMFG    = value[9]
            fldSrcPort   = value[10]
            fldDstPort   = value[11]
            if fldSrcPort == '':
                fldSrcPort = 'NA'
            if fldDstPort == '':
                fldDstPort = 'NA'                
            fldSrcPortName = value[12]
            fldDstPortName = value[13]
            if fldSrcPortName == '':
                fldSrcPortName = 'NA'
            if fldDstPortName == '':
                fldDstPortName = 'NA'               
            fldPckSize     = value[3]

            htmlSection = htmlSection.format(**locals())
            htmlContents = htmlContents + htmlSection

        htmlContents = htmlContents + rpt.HTML_END

        ''' Write the Report to the output file'''
        output = open(self.alertsHTML,"w")
        output.write(htmlContents)

    '''
    STOP Scanning clicked
    '''

    def btnSTOPCapture(self):
        if tkMessageBox.askyesno("Stop", "Abort the capture? ...  if yes partial results will be saved"):       
            self.abortFlag = True
        else:
            self.abortFlag = False


    def menuToolsExit(self, event=True):

        if tkMessageBox.askokcancel("Exit Request", "Exit Python Forensics Packet Sensor/Recorder?"):
            LogEvent(LOG_INFO, "Program Exit via Menu Selection")
            self.parent.destroy()
        else:
            pass        

    '''
    User About Selected
    '''
    def menuAbout(self, event=True):
        NL = "\n"
        gMsgL1 = "Python Forensics Packet Sensor/Recorder"
        gMsgL2 = "Version 1.0 Experimental"
        gMsgL3 = "Copyright 2017-2018 Python Forensics"
        gMsgL4 = "All Rights Reservered"
        tkMessageBox.showinfo("About", gMsgL1+NL+gMsgL2+NL+gMsgL3+NL+gMsgL4+NL)
        tkMessageBox.Dialog

'''
Setup a Protocol Handler to catch a User Exit
and prompt user to confirm exit
'''

def protocolhandler(): 
    if tkMessageBox.askokcancel("Exit Request", "Exit Python Forensics Packet Sensor/Recorder ?"):
        root.destroy()
    else:
        pass

'''
Search main program loop

- Establish the Root Application Window
- Establish the main window geometry and background
- Establish the run-time loop

'''
# Initialize the root TK Window
root = Tk()    
root.geometry('500x400')

def main():

    # Initialize the Forensic Log
    InitLog()

    # Specify the Main Window Icon
    # root.iconbitmap('search.ico')

    # Set the Title for the Main Window
    root.title(TITLE)   

    # Instantiate the GUI Application Object
    app = Application(root)

    # Setup and event handler if clicks to exit the main window
    root.protocol("WM_DELETE_WINDOW", protocolhandler)

    # Start App MainLoop  
    app.mainloop()

# Main Script Starts Here

if __name__ == '__main__':
    main()


