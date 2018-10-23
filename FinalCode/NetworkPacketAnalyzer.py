#!/usr/bin/python

import socket
import struct
import binascii
import os 
import time


def MAC_FORMAT(mac_raw):
    cluster_size = 2
    byte = [mac_raw[i:i+cluster_size] for i in range(0,len(mac_raw),cluster_size)]
    mac_addr = ':'.join(byte).upper()
    return mac_addr
    
IpProtocol = 0
    
class unpack:
 	def __cinit__(self):
  		self.data=None

	# Extract source and destination MAC addresses 
	def PacToMac(self, data):
		self.Eth_length = 14 # Ethernet header length.
		storeobj = data
		storeobj = struct.unpack("!6s6sH",storeobj)
		destination_mac = MAC_FORMAT(binascii.hexlify(storeobj[0]))
		source_mac = MAC_FORMAT(binascii.hexlify(storeobj[1]))
		global eth_protocol
		eth_protocol = str(storeobj[2])
		data={"Destination Mac Address":destination_mac,"Source Mac Address":source_mac,"Ethernet Protocol":eth_protocol}
		return data
		
	# IPv4 Header Extraction
 	def ipv4_header(self, data):
  		storeobj=struct.unpack("!BBHHHBBH4s4s", data)
  		Version=storeobj[0] 
  		Version_modified = Version >> 4
  		Version_modified = (Version_modified & 15) * 4 #Length of IP header.
  		IP_length = data[Version_modified:]
  		Tos=storeobj[1]
  		Total_length =storeobj[2]
  		Identification =storeobj[3]
  		Fragment_Offset =storeobj[4]
  		Ttl =storeobj[5]
  		global IpProtocol
  		IpProtocol = storeobj[6]
  		Header_checksum =storeobj[7]
  		Source_address =socket.inet_ntoa(storeobj[8])
  		Destination_address =socket.inet_ntoa(storeobj[9])

	  	data={'Version':Version,
	  	'Header_Length':Version_modified,
	  	"Tos":Tos,
	  	"Total Length":Total_length,
	  	"Identification":Identification,
	  	"Fragment":Fragment_Offset,
	  	"TTL":Ttl,
	  	"Protocol":IpProtocol,
	  	"Header CheckSum":Header_checksum,
	  	"Source Address":Source_address,
	  	"Destination Address":Destination_address}
	  	return data
	  
	# IPv6 Header Extraction
	def ipv6_header(self, data):
		storeobj=struct.unpack("BHHL6s6s",data)#("!BBHHHBBH4s4s", data)
  		Version=storeobj[0]
  		Traffic_class = storeobj[1] 
  		Flow_Label = storeobj[2]
  		Payload_length =storeobj[3]
  		Source_address =socket.inet_ntoa(storeobj[4])
  		Destination_address =socket.inet_ntoa(storeobj[5])
  		

	  	data={'Version':Version,
	  	"Traffic Class":Traffic_class,
	  	"Flow Label":Flow_Label,
	  	"Payload Length":Payload_length,
	  	"Source Address":Source_address,
	  	"Destination Address":Destination_address}
	  	return data
	# Tcp Header Extraction
	def tcp_header(self, data):
	  	storeobj=struct.unpack('!HHLLBBHHH',data)
	  	Source_port = storeobj[0] 
		Destination_port  = storeobj[1]
		Sequence_number  = storeobj[2]
		Acknowledge_number  = storeobj[3]
		Offset_reserved  = storeobj[4]
	        Tcp_flag  = storeobj[5]
		Window  = storeobj[6]
		Checksum  = storeobj[7]
	        Urgent_pointer = storeobj[8]
	        TCP_modified = storeobj[4]
            	global TCP_length
            	TCP_length = (TCP_modified >> 12) * 4 #Length of TCP header.
            	TCP_DATA = data[(TCP_length):]
		data1={"Source Port":Source_port,
		"Destination Port":Destination_port,
	        "Sequence Number":Sequence_number,
		"Acknowledge Number":Acknowledge_number,
		"Offset & Reserved":Offset_reserved,
		"Tcp Flag":Tcp_flag,
		"TCP_DATA":TCP_DATA,
		"Window":Window,
		"CheckSum":Checksum,
		"Urgent Pointer":Urgent_pointer
		}
		return data1
		
	def HTTP(self, raw_data):
		# print(raw_data)
		try:
		    self.data = raw_data.decode('utf-8')
		   # print(self.data)
		except:
		    self.data = raw_data
		   # print(self.data)
		return self.data    
		
	# ICMP  Extraction
	def icmp_header(self, data):
		icmph=struct.unpack('!BBH', data)
		icmp_type = icmph[0]
		code = icmph[1]
		checksum = icmph[2]
		data={'ICMP Type':icmp_type,
		"Code":code,
		"CheckSum":checksum}
		return data

	# UDP Header Extraction
	def udp_header(self, data):
		storeobj=struct.unpack('!HHHH', data)
		source_port = storeobj[0]
		dest_port = storeobj[1]
		length = storeobj[2]
		checksum = storeobj[3]
		data={"Source Port":source_port,
		"Destination Port":dest_port,
		"Length":length,
		"CheckSum":checksum}
		return data
	

	 
print("Creating Socket...")	
time.sleep(2)
print("Capturing packets in the network...") 
time.sleep(1)
#Creation of Socket
s=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

#Packet countf
pcount = 0   
# receive a packet
while True:

   packet = s.recvfrom(65565)
   pcount = pcount + 1
   
   flag = 0
   
   random = unpack()
   #print output on terminal
   #print packet
  
   print("\n\nPacket Number:" + str(pcount))
   print("Packet Length:" + str(len(packet[0])))
   print("\n\n--------------- MAC Addresses(Data link and Physical layer)-----------")
  
    #print data on terminal
   for i in random.PacToMac(packet[0][0:14]).iteritems():
        a,b=i
        print("{} : {}  ".format(a,b))
   

   if eth_protocol == '2048':
	    print("\n\n--------------- IPv4 Header(Network layer) --------------")
	    for  i in random.ipv4_header(packet[0][14:34]).iteritems():
	        a,b=i
	        print("{} : {}  ".format(a,b))

   elif eth_protocol == '86DD':	        
   	   print("\n\n--------------- IPv6 Header(Network layer) --------------")
	   for  i in random.ipv6_header(packet[0][14:34]).iteritems():
	        a,b=i
	        print("{} : {}  ".format(a,b))
   
   if IpProtocol == 6:  
	  
	   print("\n\n--------------- TCP Header(Transport layer) --------------")
	   for  i in random.tcp_header(packet[0][34:54]).iteritems():
		a,b=i
		if str(a) == 'TCP_DATA':
			continue
	
		print("{} : {}  ".format(a,b))
	   
	   Stack = random.tcp_header(packet[0][34:54])
	   
	   #print(Stack['TCP_DATA'])
	   if len(Stack['TCP_DATA']) > 0 :
	   
	   	if Stack['Source Port'] == 80 or Stack['Destination Port'] == 80 :
	  	 	print('\n\nHTTP Data:')
	  	 	#flag = 1
	  	 	#print(Stack['TCP_DATA'])
	  	 	#print('\n\nHTTP Data Decoded')
                        try:
                        	http = random.HTTP(Stack['TCP_DATA'])
                        	print(http)
                           	http_info = str(http).split('\n')
                            	for line in http_info:
                                	print('\n'+ str(line))
                        except:
                            	print(format_multi_line(Stack['TCP_DATA']))

	   		
   elif IpProtocol == 17:
   	print("\n\n--------------- UDP Header(Transport layer) --------------")
	for i in random.udp_header(packet[0][34:42]).iteritems():
		a,b=i
	
		print("{} : {}  ".format(a,b))
		
	#flag = 1
   	print("\n\n------------------- Data(UDP Payload) -------------------------")
   	print(str(packet[0][42:len(packet[0])]))   	
   
   elif IpProtocol == 1:
   	print("\n\n--------------- ICMP Header(Network layer supporter) --------------")
	for i in random.icmp_header(packet[0][34:38]).iteritems():
		a,b=i
	
		print("{} : {}  ".format(a,b))
		
	#flag = 1
   	print("\n\n------------------- Data(ICMP Payload) -------------------------")
   	print(str(packet[0][38:len(packet[0])]))

   if flag == 0:
   	print("\n\n------------------- Data(Payload) -------------------------")
   	print(str(packet[0][54:len(packet[0])]))   
